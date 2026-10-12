"""Read a bounded tail of the main log buffer for one running package PID."""

import argparse
import json
import re
import signal
import subprocess
import sys

from lab_common import error_code, report_metadata, run_bounded, tool_identity, utc_now


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('package')
    parser.add_argument('count', type=int, nargs='?', default=500)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9._]+', args.package):
        parser.error('invalid Android package name')
    if not 1 <= args.count <= 10000:
        parser.error('count must be between 1 and 10000')
    report = report_metadata('logcat-dump')
    report.update({'serial': args.serial, 'package': args.package, 'pid': None,
                   'buffer': 'main', 'requested_count': args.count, 'lines': [],
                   'coverage': 'none', 'output_truncated': False, 'failures': [], 'limitations': [
                       'Only one PID at collection time and the main buffer are inspected.',
                       'A bounded tail is partial history; empty output does not prove absence of logs.']})
    interrupted = None
    def stop(signum, _frame):
        nonlocal interrupted
        if interrupted is None:
            interrupted = signum
            raise KeyboardInterrupt
    previous = {s: signal.signal(s, stop) for s in (signal.SIGINT, signal.SIGTERM)}
    stage, code, failure_code = 'resolve_pid', 0, 'command_failed'
    try:
        report['tools']['adb'] = tool_identity([args.adb], ('version',))
        adb = [args.adb, '-s', args.serial]
        result = run_bounded(adb + ['shell', 'pidof', args.package], 10, 65536)
        if result.returncode or not result.stdout.strip():
            failure_code = 'package_not_running' if result.returncode in (0, 1) and not result.stdout.strip() and not result.stderr.strip() else 'command_failed'
            raise RuntimeError(f'{failure_code}: ' + (result.stderr.strip() or 'pidof returned no PID'))
        pids = result.stdout.split()
        if (len(pids) != 1 or not re.fullmatch(r'[1-9][0-9]{0,9}', pids[0]) or
                int(pids[0]) > 2147483647):
            failure_code = 'multiple_processes' if len(pids) > 1 else 'invalid_output'
            raise RuntimeError(f'{failure_code}: expected one positive PID; use an explicitly selected process for multi-process apps')
        report['pid'] = int(pids[0])
        stage = 'read_logs'
        result = run_bounded(adb + ['logcat', '-d', '-b', 'main', '-t', str(args.count),
                                    '--pid=' + pids[0]], 30)
        report['lines'] = result.stdout.splitlines()[-args.count:]
        report['coverage'] = 'partial'
        if result.returncode:
            failure_code = 'command_failed'
            raise RuntimeError(result.stderr or f'logcat exited {result.returncode}')
    except (OSError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        if stage == 'read_logs':
            if getattr(error, 'stdout', None) is not None:
                report['lines'] = error.stdout.splitlines()[-args.count:]
            report['coverage'] = 'partial' if report['lines'] else 'none'
            report['output_truncated'] = error_code(error) == 'output_limit'
        message = str(error) or 'log collection interrupted'
        report['failures'].append({'stage': stage, 'code': failure_code if isinstance(error, RuntimeError) else error_code(error),
                                   'error': message[:2048], 'error_truncated': len(message) > 2048})
        if getattr(error, 'cleanup_errors', None):
            report['failures'][-1]['cleanup_errors'] = error.cleanup_errors
        print('error: ' + report['failures'][0]['error'], file=sys.stderr)
        code = 1
    finally:
        report['finished_at'] = utc_now()
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return code


if __name__ == '__main__':
    sys.exit(main())
