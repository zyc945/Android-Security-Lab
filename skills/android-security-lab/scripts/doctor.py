"""Read-only host and selected-device readiness checks, including offline use."""

import argparse
import json
from pathlib import Path
import re
import shutil
import shlex
import signal
import subprocess
import sys

from lab_common import error_code, report_metadata, run_bounded, tool_identity, utc_now


def add_check(report, name, status, required=False, code=None, detail='', remediation=None):
    report['checks'].append({'name': name, 'status': status, 'required': required,
                             'code': code, 'detail': detail[:2048], 'remediation': remediation})


def probe(report, name, command, required=False, empty_ok=False):
    try:
        result = run_bounded(command, 5)
        if result.returncode != 0 and not (empty_ok and result.returncode == 1 and not result.stderr):
            add_check(report, name, 'error', required, 'command_failed',
                      (result.stderr or result.stdout or f'exit {result.returncode}'),
                      'Inspect this read-only command failure; do not repair device state automatically.')
            return None
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        add_check(report, name, 'error', required, error_code(error), str(error),
                  'Check tool access and the bounded command failure before retrying.')
        if getattr(error, 'cleanup_errors', None):
            add_check(report, name + '_cleanup', 'error', True, 'cleanup_failed',
                      '; '.join(error.cleanup_errors), 'Inspect possible residual query processes.')
        return None


def host_checks(report, args):
    add_check(report, 'python', 'ok', True, detail=report['tools']['python']['version'])
    required = {'adb'} if args.workflow != 'apk' else set()
    if args.workflow == 'capture':
        required.update(('mitmweb', 'lsof'))
    if args.workflow == 'frida':
        required.add('frida_client')
    commands = {'adb': args.adb, 'frida_client': str(args.root_dir / '.venv/bin/frida-ps'),
                'frida': str(args.root_dir / '.venv/bin/frida'),
                'mitmweb': 'mitmweb', 'lsof': 'lsof', 'scrcpy': 'scrcpy',
                'jadx': 'jadx', 'apktool': 'apktool', 'fastboot': 'fastboot',
                'mitmproxy': 'mitmproxy', 'nmap': 'nmap'}
    paths = {}
    for name, command in commands.items():
        path = shutil.which(command)
        paths[name] = path
        if not path:
            report['tools'][name] = {'path': None, 'version': None}
            add_check(report, name, 'error', name in required, 'missing_dependency', command,
                      ('Create the lab .venv and install the skill requirements.' if name in ('frida_client', 'frida')
                       else f'Install {name} or configure its executable path.'))
        else:
            # APK readiness is wholly offline; even adb version can start a daemon.
            report['tools'][name] = ({'path': path, 'version': None} if args.workflow == 'apk'
                                     else tool_identity([path], ('version',) if name == 'adb' else ('--version',)))
            add_check(report, name, 'ok', name in required, detail=path)
    return paths


def select_device(report, args, adb):
    required = args.workflow != 'apk'
    if args.workflow == 'apk' or not adb:
        add_check(report, 'selected_device', 'skipped', required, 'not_checked',
                  'Offline APK workflow.' if args.workflow == 'apk' else 'ADB is unavailable.',
                  None if args.workflow == 'apk' else 'Install ADB, then reconnect the authorized device.')
        return None
    serial = args.serial
    if not serial:
        output = probe(report, 'selected_device', [adb, 'devices'], required)
        if output is None:
            return None
        devices = []
        for line in output.splitlines():
            if not line.strip() or line.startswith('List of devices attached') or line.startswith('*'):
                continue
            parts = line.split()
            if len(parts) < 2:
                add_check(report, 'selected_device', 'unknown', required, 'invalid_device_list', line,
                          'Inspect adb devices output and explicitly select a serial.')
                return None
            devices.append(parts[:2])
        if len(devices) != 1:
            code = 'multiple_devices' if devices else 'no_device'
            add_check(report, 'selected_device', 'error', required, code,
                      f'{len(devices)} attached devices; no device was selected.',
                      'Select an authorized device with --serial.' if devices else
                      'Connect the authorized device over USB and check adb devices.')
            return None
        serial, state = devices[0]
        if state != 'device':
            device_state(report, state, required)
            return None
    output = probe(report, 'selected_device', [adb, '-s', serial, 'get-state'], required)
    if output is None:
        return None
    if output != 'device':
        device_state(report, output, required)
        return None
    report['selected_device'] = serial
    add_check(report, 'selected_device', 'ok', required, detail='Selected device is online.')
    return [adb, '-s', serial]


def device_state(report, state, required):
    code = {'unauthorized': 'device_unauthorized', 'offline': 'device_offline'}.get(state, 'unknown_device_state')
    remediation = {'unauthorized': 'Unlock the authorized device and approve its USB debugging prompt.',
                   'offline': 'Check the USB connection and device state; do not change networking automatically.'}
    add_check(report, 'selected_device', 'error' if state in remediation else 'unknown', required,
              code, state, remediation.get(state, 'Inspect adb devices and explicitly select an online device.'))


def frida_checks(report, args, device):
    required = args.workflow == 'frida'
    if args.root:
        print('Read-only root diagnostics may trigger the Android superuser authorization prompt.', file=sys.stderr)
    command = device + ['shell', 'ps', '-A']
    output = probe(report, 'frida_server_process', command, required)
    if output is not None and args.root and not any(re.search(r'\bfrida-server\b', line) for line in output.splitlines()):
        output = probe(report, 'frida_server_process', device + ['shell', 'su', '-c', shlex.quote('ps -A')], required)
    if output is not None:
        found = any(re.search(r'\bfrida-server\b', line) for line in output.splitlines())
        add_check(report, 'frida_server_process', 'ok' if found else 'unknown', required,
                  None if found else 'server_not_observed',
                  'Frida server process observed.' if found else 'Ordinary shell did not show a Frida server.',
                  None if found else 'Check the authorized server setup; shell visibility may be restricted.')
    if not args.root:
        for name in ('frida_server_listener', 'frida_version_match'):
            add_check(report, name, 'unknown', required, 'not_checked',
                      'Requires additional server evidence; ordinary shell process visibility is insufficient.',
                      'Use --root for explicit read-only root diagnostics if authorized.')
        return
    listeners = probe(report, 'frida_server_listener', device + ['shell', 'su', '-c', shlex.quote('ss -lntp')], required)
    if listeners is not None:
        lines = [line for line in listeners.splitlines() if re.search(r':27042\b', line)]
        loopback = bool(lines) and all(any(field in ('127.0.0.1:27042', '[::1]:27042', '::1:27042')
                                          for field in line.split()) for line in lines)
        owned = bool(lines) and all('frida-server' in line for line in lines)
        ready = loopback and owned
        add_check(report, 'frida_server_listener', 'ok' if ready else 'error' if lines and not loopback else 'unknown', required,
                  None if ready else 'unsafe_listener' if lines and not loopback else 'listener_not_confirmed',
                  '\n'.join(lines) or 'No Frida 27042 listener observed.',
                  None if ready else 'Confirm the Frida server owns a device loopback listener; inspect its setup.')
    version = probe(report, 'frida_version_match', device + ['shell', 'su', '-c',
                    shlex.quote('if [ -x /data/adb/modules/magisk-frida/bin/frida-server ]; then '
                    '/data/adb/modules/magisk-frida/bin/frida-server --version; '
                    'else frida-server --version; fi')], required)
    if version is not None:
        client = report['tools']['frida_client']['version']
        server_match = re.search(r'\b\d+\.\d+\.\d+\b', version)
        client_match = re.search(r'\b\d+\.\d+\.\d+\b', client or '')
        known = server_match is not None and client_match is not None
        matched = known and server_match.group() == client_match.group()
        add_check(report, 'frida_version_match', 'ok' if matched else 'error' if known else 'unknown', required,
                  None if matched else 'version_mismatch' if known else 'version_unknown',
                  f'client={client_match.group() if client_match else "unknown"}; '
                  f'server={server_match.group() if server_match else "unknown"}',
                  None if matched else 'Verify the client/server Frida versions before attachment.')


def device_checks(report, args, paths, device):
    names = ['device_properties', 'selinux']
    if args.workflow in ('audit', 'capture'):
        names.extend(('proxy', 'forward_mappings', 'reverse_mappings'))
    if args.workflow in ('audit', 'frida'):
        names.extend(('frida_server_process', 'frida_server_listener', 'frida_version_match'))
    if not device:
        for name in names:
            add_check(report, name, 'skipped', args.workflow == 'frida' and name.startswith('frida_'),
                      'not_checked', 'No online device selected.', 'Resolve selected_device before device diagnostics.')
    else:
        commands = {'device_properties': ['shell', 'getprop'], 'selinux': ['shell', 'getenforce'],
                    'proxy': ['shell', 'settings', 'get', 'global', 'http_proxy'],
                    'forward_mappings': ['forward', '--list'], 'reverse_mappings': ['reverse', '--list']}
        for name in names:
            if name not in commands:
                continue
            output = probe(report, name, device + commands[name])
            if output is not None:
                if name == 'device_properties':
                    properties = dict(re.findall(r'^\[([^\]]+)\]: \[(.*)\]$', '\n'.join(output.splitlines()), re.MULTILINE))
                    fields = {'manufacturer': 'ro.product.manufacturer', 'model': 'ro.product.model',
                              'android': 'ro.build.version.release', 'api': 'ro.build.version.sdk',
                              'patch': 'ro.build.version.security_patch', 'verified_boot': 'ro.boot.verifiedbootstate',
                              'bootloader_locked': 'ro.boot.flash.locked'}
                    output = json.dumps({key: properties.get(prop) for key, prop in fields.items()})
                    if not all(properties.get(prop) for prop in fields.values()):
                        add_check(report, name, 'unknown', code='properties_incomplete', detail=output,
                                  remediation='Inspect the requested getprop fields; unavailable values remain unknown.')
                        continue
                add_check(report, name, 'ok', detail=output or '(empty)')
        if args.workflow in ('audit', 'frida'):
            frida_checks(report, args, device)
    if args.workflow in ('audit', 'capture'):
        if paths['lsof']:
            output = probe(report, 'host_listeners', [paths['lsof'], '-nP', '-iTCP', '-sTCP:LISTEN'], empty_ok=True)
            if output is not None:
                add_check(report, 'host_listeners', 'ok', detail=output or 'No TCP listeners observed.')
        else:
            add_check(report, 'host_listeners', 'skipped', code='missing_dependency', detail='lsof is unavailable.',
                      remediation='Install lsof for a read-only listener snapshot.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--serial', default='')
    parser.add_argument('--root-dir', required=True, type=Path)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--for', dest='workflow', choices=('audit', 'adb', 'frida', 'capture', 'apk'), default='audit')
    parser.add_argument('--root', action='store_true', help='Explicit read-only Frida superuser checks.')
    args = parser.parse_args(argv)
    if not args.root_dir.is_dir():
        parser.error('--root-dir must be an existing directory')
    if not args.adb or (args.serial and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]*', args.serial)):
        parser.error('invalid adb executable or device serial')
    if args.root and args.workflow not in ('audit', 'frida'):
        parser.error('--root requires the audit or frida workflow')
    report = report_metadata('doctor')
    report.update(workflow=args.workflow, checks=[], healthy=False, limitations=[
        'Tool availability and versions do not prove successful device operations.',
        'Proxy, mappings and listeners do not prove HTTPS decryption.',
        'Capture readiness checks dependencies only; 8080/8081 availability and proxy restoration are not confirmed.',
        'Frida readiness does not prove attachment or a captured function call.'])
    previous = {}
    interrupted = False
    def on_signal(signum, frame):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, on_signal)
        paths = host_checks(report, args)
        device = select_device(report, args, paths['adb'])
        device_checks(report, args, paths, device)
    except KeyboardInterrupt as error:
        add_check(report, 'interrupted', 'error', True, 'interrupted', 'Diagnostic cancelled.', 'Run diagnostics again when ready.')
        if getattr(error, 'cleanup_errors', None):
            add_check(report, 'interrupted_cleanup', 'error', True, 'cleanup_failed',
                      '; '.join(error.cleanup_errors), 'Inspect possible residual query processes.')
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    report['healthy'] = all(check['status'] == 'ok' for check in report['checks'] if check['required'])
    report['finished_at'] = utc_now()
    if args.json:
        print(json.dumps(report, ensure_ascii=False))
    else:
        print(f"doctor: {args.workflow} {'ready' if report['healthy'] else 'not ready'}")
        for check in report['checks']:
            print(f"[{check['status']}] {check['name']}{' (required)' if check['required'] else ''}: {check['detail']}")
            if check['remediation']:
                print(f"  Fix: {check['remediation']}")
        for limitation in report['limitations']:
            print(f'Limit: {limitation}')
    return 0 if report['healthy'] else 1


if __name__ == '__main__':
    sys.exit(main())
