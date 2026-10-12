#!/usr/bin/env python3
"""Supervise one Frida listing or USB mitmweb session; clean only owned resources."""
import argparse
import json
import os
from pathlib import Path
import signal
import shlex
import subprocess
import sys
import time

from lab_common import error_code, report_metadata, run_bounded, tool_identity, utc_now


STOP_SIGNAL = 0


def request_stop(signum, _frame):
    global STOP_SIGNAL
    if not STOP_SIGNAL:
        STOP_SIGNAL = signum


def check_stop():
    if STOP_SIGNAL:
        raise InterruptedError('session interrupted')


def run(command, cancel=True):
    # adb joins shell operands into a remote command; quote values there too.
    if command[3:4] == ['shell']:
        command = command[:4] + [shlex.quote(value) for value in command[4:]]
    result = run_bounded(command, 10, check_cancel=check_stop if cancel else None)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or
                            f'command exited {result.returncode}').strip())
    return result.stdout.rstrip('\r\n')


def mapping_rows(adb, kind, cancel=True):
    rows = [line.split() for line in run(adb + [kind, '--list'], cancel=cancel).splitlines()]
    if any(len(row) != 3 for row in rows):
        raise RuntimeError(f'unrecognized {kind} listing; refusing to infer ownership')
    return rows


def create_mapping(adb, kind, source, target):
    if any(row[1] == source for row in mapping_rows(adb, kind)):
        raise RuntimeError(f'{kind} {source} is already mapped; choose an unused port')
    # No-rebind closes the race between the listing and creation.
    try:
        run(adb + [kind, '--no-rebind', source, target])
    except (OSError, RuntimeError, subprocess.SubprocessError) as failure:
        message = f'{kind} creation not confirmed; ownership unknown; inspect possible residual mapping: {failure}'
        if isinstance(failure, InterruptedError):
            raise InterruptedError(message) from failure
        raise RuntimeError(message) from failure


def remove_mapping(adb, kind, expected):
    rows = mapping_rows(adb, kind, cancel=False)
    selected = [row for row in rows if row[1] == expected[1]]
    if not selected:
        return  # A USB disconnect may already have removed this mapping.
    if kind == 'forward':
        matches = selected == [expected]
    else:
        # Reverse's first column is a transport label, not a device serial.
        # This listing and removal are scoped to the selected -s device.
        matches = len(selected) == 1 and selected[0][1:] == expected[1:]
    if not matches:
        raise RuntimeError(f'{kind} {expected[1]} changed; leaving it untouched')
    run(adb + [kind, '--remove', expected[1]], cancel=False)
    if any(row[1] == expected[1] for row in mapping_rows(adb, kind, cancel=False)):
        raise RuntimeError(f'{kind} {expected[1]} removal could not be verified')


def listeners(port):
    result = run_bounded(['lsof', '-nP', f'-iTCP:{port}', '-sTCP:LISTEN', '-Fpn'],
                         10, check_cancel=check_stop)
    if result.returncode == 1 and not result.stdout and not result.stderr:
        return []
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'listener inspection failed')
    records, pid = [], None
    for line in result.stdout.splitlines():
        if line.startswith('p'):
            pid = int(line[1:])
        elif line.startswith('n'):
            records.append((pid, line[1:]))
    if not records:
        raise RuntimeError('listener inspection returned no readable addresses')
    return records


def wait_listeners(child):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        check_stop()
        if child.poll() is not None:
            raise RuntimeError(f'mitmweb exited before readiness ({child.returncode})')
        ready = True
        for port in (8080, 8081):
            found = listeners(port)
            if any(pid != child.pid or address not in
                   (f'127.0.0.1:{port}', f'[::1]:{port}') for pid, address in found):
                raise RuntimeError(f'port {port} belongs to another process or is not loopback')
            ready = ready and bool(found)
        if ready:
            if child.poll() is not None:
                raise RuntimeError(f'mitmweb exited before readiness ({child.returncode})')
            return
        time.sleep(.1)
    raise RuntimeError('mitmweb listeners did not become ready within 10 seconds')


def stop_child(child):
    if child is None or child.poll() is not None:
        return
    # The unreaped child still reserves this process-group ID. Never signal a
    # persisted PID or an already-reaped process group.
    for signum, timeout in ((signal.SIGINT, 5), (signal.SIGTERM, 2), (signal.SIGKILL, 2)):
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=timeout)
            return
        except subprocess.TimeoutExpired:
            continue
    raise RuntimeError('owned child did not stop')


def main():
    global STOP_SIGNAL
    STOP_SIGNAL = 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--serial', required=True)
    commands = parser.add_subparsers(dest='mode', required=True)
    frida = commands.add_parser('frida')
    frida.add_argument('--port', type=int, default=27042)
    frida.add_argument('command', nargs=argparse.REMAINDER)
    capture = commands.add_parser('capture')
    capture.add_argument('directory', type=Path)
    args = parser.parse_args()
    if args.mode == 'frida' and args.command[:1] == ['--']:
        args.command = args.command[1:]
    if args.mode == 'frida' and (not 1 <= args.port <= 65535 or not args.command):
        parser.error('Frida requires a command and a port between 1 and 65535')
    adb = [args.adb, '-s', args.serial]
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, request_stop)
    metadata = report_metadata(args.mode)
    failures = []
    stage = 'prepare'

    def record_failure(failure, failure_stage):
        message = str(failure)
        cause = failure.__cause__ or failure
        failures.append({'stage': failure_stage, 'code': error_code(cause),
                         'error': message[:2048], 'error_truncated': len(message) > 2048})
        if getattr(cause, 'cleanup_errors', None):
            failures[-1]['cleanup_errors'] = cause.cleanup_errors
            cleanup_errors.extend('query process: ' + message for message in cause.cleanup_errors)

    child, owned_mapping, original_proxy = None, None, None
    proxy_attempted, directory_created = False, False
    code, error, cleanup_errors = 0, None, []
    kind = 'forward' if args.mode == 'frida' else 'reverse'
    source = f'tcp:{args.port}' if args.mode == 'frida' else 'tcp:8080'
    target = 'tcp:27042' if args.mode == 'frida' else 'tcp:8080'
    try:
        check_stop()
        if args.mode == 'capture':
            args.directory.mkdir(parents=True, exist_ok=False)
            directory_created = True
            stage = 'inspect_proxy'
            original_proxy = run(adb + ['shell', 'settings', 'get', 'global', 'http_proxy'])
            if original_proxy == '127.0.0.1:8080':
                raise RuntimeError('phone already targets this capture port; resolve the existing session first')
            stage = 'inspect_mapping'
            if any(row[1] == source for row in mapping_rows(adb, kind)):
                raise RuntimeError(f'reverse {source} is already mapped')
            stage = 'inspect_listeners'
            for port in (8080, 8081):
                if listeners(port):
                    raise RuntimeError(f'host port {port} is already occupied')
            check_stop()
            stage = 'start_process'
            child = subprocess.Popen([
                'mitmweb', '--listen-host', '127.0.0.1', '--listen-port', '8080',
                '--web-host', '127.0.0.1', '--web-port', '8081',
                '--set', 'web_open_browser=false',
                '--save-stream-file', str(args.directory / 'phone-capture.mitm')],
                start_new_session=True)
            stage = 'wait_listeners'
            wait_listeners(child)
        check_stop()
        stage = 'create_mapping'
        create_mapping(adb, kind, source, target)
        owned_mapping = [args.serial, source, target]
        check_stop()
        if args.mode == 'capture':
            if child.poll() is not None:
                raise RuntimeError(f'mitmweb exited before phone setup ({child.returncode})')
            stage = 'set_proxy'
            proxy_attempted = True  # A failed reply can follow a successful write.
            run(adb + ['shell', 'settings', 'put', 'global', 'http_proxy', '127.0.0.1:8080'])
            if run(adb + ['shell', 'settings', 'get', 'global', 'http_proxy']) != '127.0.0.1:8080':
                raise RuntimeError('phone proxy write could not be verified')
            print(f'capture ready: {args.directory}; HTTPS decryption still needs verification', file=sys.stderr)
        else:
            command = args.command[:1] + ['-H', f'127.0.0.1:{args.port}'] + args.command[1:]
            stage = 'start_process'
            child = subprocess.Popen(command, start_new_session=True)
        stage = 'run_process'
        while True:
            check_stop()
            result = child.poll()
            if result is not None:
                code = result if result >= 0 else 128 - result
                if code:
                    record_failure(RuntimeError(f'process exited {code}'), stage)
                break
            time.sleep(.05)
    except InterruptedError as failure:
        record_failure(failure, stage)
        if failure.__cause__:
            error = str(failure)[:2048]
            print('error: ' + error, file=sys.stderr)
        code = 128 + STOP_SIGNAL if STOP_SIGNAL else 2
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as failure:
        record_failure(failure, stage)
        error, code = str(failure)[:2048], 2
        print('error: ' + error, file=sys.stderr)
    finally:
        # Signals only request stop, including during cleanup. One failure must
        # not prevent the other owned resources from being released.
        if proxy_attempted:
            try:
                current = run(adb + ['shell', 'settings', 'get', 'global', 'http_proxy'], cancel=False)
                if current == '127.0.0.1:8080':
                    command = ['delete', 'global', 'http_proxy'] if original_proxy == 'null' else [
                        'put', 'global', 'http_proxy', original_proxy]
                    run(adb + ['shell', 'settings'] + command, cancel=False)
                    if run(adb + ['shell', 'settings', 'get', 'global', 'http_proxy'], cancel=False) != original_proxy:
                        raise RuntimeError('original proxy restoration could not be verified')
                elif current != original_proxy:
                    raise RuntimeError('phone proxy changed externally; leaving it untouched')
            except (OSError, RuntimeError, subprocess.SubprocessError) as failure:
                record_failure(failure, 'cleanup_proxy')
                cleanup_errors.append('proxy: ' + str(failure)[:2048])
        if owned_mapping:
            try:
                remove_mapping(adb, kind, owned_mapping)
            except (OSError, RuntimeError, subprocess.SubprocessError) as failure:
                record_failure(failure, 'cleanup_mapping')
                cleanup_errors.append('mapping: ' + str(failure)[:2048])
        try:
            stop_child(child)
        except (OSError, RuntimeError, subprocess.SubprocessError) as failure:
            record_failure(failure, 'cleanup_process')
            cleanup_errors.append('process: ' + str(failure)[:2048])
        if cleanup_errors:
            code = 2
            for failure in cleanup_errors:
                print('cleanup error: ' + failure, file=sys.stderr)
        if not code and STOP_SIGNAL:
            code = 128 + STOP_SIGNAL
        if directory_created:
            for name, command, version_args in (
                    ('adb', [args.adb], ('version',)),
                    ('mitmweb', ['mitmweb'], ('--version',))):
                try:
                    metadata['tools'][name] = tool_identity(command, version_args=version_args)
                except (OSError, subprocess.SubprocessError):
                    metadata['tools'][name] = {'path': command[0], 'version': None}
            report = {**metadata, 'finished_at': utc_now(),
                      'limitations': ['HTTPS decryption has not been verified'],
                      'failures': failures, 'serial': args.serial, 'original_proxy': original_proxy,
                      'mapping_created': owned_mapping, 'process_pid': child.pid if child else None,
                      'exit_code': code, 'error': error, 'cleanup_errors': cleanup_errors,
                      'https_decryption': 'not_tested'}
            try:
                temporary = args.directory / 'session.json.tmp'
                temporary.write_text(json.dumps(report, indent=2) + '\n')
                temporary.replace(args.directory / 'session.json')
            except OSError as failure:
                record_failure(failure, 'write_report')
                print('session report error [stage=write_report code=' + error_code(failure) +
                      ']: ' + str(failure)[:2048], file=sys.stderr)
                code = 2
    return code


if __name__ == '__main__':
    raise SystemExit(main())
