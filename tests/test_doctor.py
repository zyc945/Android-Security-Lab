"""Doctor contract tests with fixed fake tools; never contact a real device."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


HELPER = Path(__file__).resolve().parents[1] / 'skills/android-security-lab/scripts/doctor.py'
WRAPPER = Path(__file__).resolve().parents[1] / 'bin/android-lab'
FAKE_TOOL = r'''
import json
import os
from pathlib import Path
import sys
import time
import shlex
config = json.loads(Path(os.environ['FAKE_CONFIG']).read_text())
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with Path(os.environ['FAKE_LOG']).open('a') as log:
    log.write(json.dumps([name] + args) + '\n')
if args in (['--version'], ['version']):
    if config.get('version_failure') == name:
        sys.exit(3)
    if config.get('version_linger') == name:
        Path(config['pid_file']).write_text(str(os.getpid()))
        time.sleep(10)
    print('17.2.14' if name == 'frida-ps' else 'fake version 1.0')
    sys.exit(0)
if name != 'adb':
    sys.exit(1 if name == 'lsof' else 0)
if args == ['devices']:
    if config.get('output_limit'):
        sys.stdout.write('x' * 1100000)
        sys.exit(0)
    if config.get('linger'):
        Path(config['pid_file']).write_text(str(os.getpid()))
        time.sleep(10)
    print('List of devices attached')
    print(config.get('devices', ''))
    sys.exit(0)
assert args[0] == '-s'
args = args[2:]
if args == ['get-state']:
    print(config.get('state', 'device'))
    sys.exit(config.get('state_exit', 0))
outputs = {
    ('shell', 'getprop'): '[ro.product.manufacturer]: [Test Vendor]\n[ro.product.model]: [Test Model]\n'
                          '[ro.build.version.release]: [13]\n[ro.build.version.sdk]: [33]\n'
                          '[ro.build.version.security_patch]: [2026-10-01]\n'
                          '[ro.boot.verifiedbootstate]: [orange]\n[ro.boot.flash.locked]: [0]\n'
                          '[device.private.serial]: [do not report]',
    ('shell', 'getenforce'): 'Enforcing',
    ('shell', 'settings', 'get', 'global', 'http_proxy'): ':0',
    ('forward', '--list'): '', ('reverse', '--list'): '',
    ('shell', 'ps', '-A'): config.get('ps', 'root 123 frida-server'),
}
if args[:3] == ['shell', 'su', '-c']:
    # adb joins shell arguments; unquoted COMMAND would split at the remote shell.
    args = ['shell'] + shlex.split(' '.join(args[1:]))
    assert len(args) == 4, args
    print(config.get('root_ps', 'root 123 frida-server') if args[3] == 'ps -A' else
          config.get('listener', 'LISTEN 0 128 127.0.0.1:27042 0.0.0.0:* users:(("frida-server",pid=123,fd=3))')
          if args[3] == 'ss -lntp' else config.get('server_version', '17.2.14'))
else:
    assert tuple(args) in outputs, args
    output = outputs[tuple(args)]
    if args == ['shell', 'getprop'] and config.get('property_crlf'):
        output = output.replace('\n', '\r\n')
    print(output)
'''


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.config = self.root / 'config.json'
        self.log = self.root / 'calls.jsonl'
        self.env = dict(os.environ, PATH=str(self.bin), FAKE_CONFIG=str(self.config), FAKE_LOG=str(self.log))
        for name in ('adb', 'mitmweb', 'lsof', 'scrcpy', 'jadx', 'apktool'):
            self.tool(self.bin / name)
        self.tool(self.root / '.venv/bin/frida-ps')

    def tool(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#!' + sys.executable + '\n' + FAKE_TOOL)
        path.chmod(0o755)

    def command(self, *args):
        return [sys.executable, str(HELPER), '--root-dir', str(self.root), '--json', *args]

    def run_doctor(self, config=None, *args):
        self.config.write_text(json.dumps(config or {}))
        return subprocess.run(self.command(*args), env=self.env, text=True, capture_output=True, timeout=15)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def report(self, result):
        self.assertEqual(result.stderr, '', result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['operation'], 'doctor')
        self.assertTrue(report['started_at'])
        self.assertTrue(report['finished_at'])
        for check in report['checks']:
            self.assertEqual(set(check), {'name', 'status', 'required', 'code', 'detail', 'remediation'})
            self.assertIn(check['status'], ('ok', 'error', 'unknown', 'skipped'))
        return report

    def checks(self, report):
        return {check['name']: check for check in report['checks']}

    def test_offline_retains_host_checks_and_listener_snapshot(self):
        result = self.run_doctor()
        self.assertEqual(result.returncode, 1)
        report = self.report(result)
        checks = self.checks(report)
        self.assertFalse(report['healthy'])
        self.assertEqual(checks['selected_device']['code'], 'no_device')
        self.assertEqual(checks['proxy']['status'], 'skipped')
        self.assertEqual(checks['host_listeners']['status'], 'ok')
        for name in ('python', 'adb', 'frida_client', 'mitmweb', 'lsof', 'scrcpy', 'jadx', 'apktool'):
            self.assertEqual(checks[name]['status'], 'ok')
        self.assertTrue(any(call[0] == 'mitmweb' for call in self.calls()))

    def test_missing_adb_does_not_suppress_other_host_checks(self):
        (self.bin / 'adb').unlink()
        result = self.run_doctor()
        self.assertEqual(result.returncode, 1)
        checks = self.checks(self.report(result))
        self.assertEqual(checks['adb']['code'], 'missing_dependency')
        self.assertEqual(checks['selected_device']['status'], 'skipped')
        self.assertTrue(checks['selected_device']['required'])
        self.assertEqual(checks['mitmweb']['status'], 'ok')

    def test_multiple_devices_never_selects_one(self):
        result = self.run_doctor({'devices': 'one\tdevice\ntwo\toffline'}, '--for', 'adb')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.checks(self.report(result))['selected_device']['code'], 'multiple_devices')
        self.assertFalse(any('-s' in call for call in self.calls()))

    def test_unauthorized_and_offline_have_specific_remediation(self):
        for state in ('unauthorized', 'offline'):
            with self.subTest(state=state):
                result = self.run_doctor({'devices': 'one\t' + state})
                check = self.checks(self.report(result))['selected_device']
                self.assertEqual(check['code'], 'device_' + state)
                self.assertTrue(check['remediation'])

    def test_explicit_serial_is_verified_and_unknown_is_not_ready(self):
        result = self.run_doctor({'state': 'unknown'}, '--serial', 'chosen', '--for', 'adb')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.checks(self.report(result))['selected_device']['status'], 'unknown')
        self.assertIn(['adb', '-s', 'chosen', 'get-state'], self.calls())
        self.assertNotIn(['adb', 'devices'], self.calls())

    def test_default_never_uses_su_and_optional_unknown_is_healthy(self):
        result = self.run_doctor({'devices': 'one\tdevice', 'property_crlf': True})
        self.assertEqual(result.returncode, 0)
        checks = self.checks(self.report(result))
        self.assertEqual(checks['frida_server_listener']['status'], 'unknown')
        self.assertFalse(checks['frida_server_listener']['required'])
        self.assertFalse(any('su' in call for call in self.calls()))
        properties = json.loads(checks['device_properties']['detail'])
        self.assertEqual(properties, {'manufacturer': 'Test Vendor', 'model': 'Test Model', 'android': '13',
                                     'api': '33', 'patch': '2026-10-01', 'verified_boot': 'orange', 'bootloader_locked': '0'})
        self.assertNotIn('do not report', result.stdout)
        self.assertEqual(checks['selinux']['detail'], 'Enforcing')

    def test_frida_requires_server_evidence_not_only_a_process(self):
        result = self.run_doctor({'devices': 'one\tdevice'}, '--for', 'frida')
        self.assertEqual(result.returncode, 1)
        checks = self.checks(self.report(result))
        self.assertEqual(checks['frida_server_process']['status'], 'ok')
        self.assertEqual(checks['frida_version_match']['status'], 'unknown')
        self.assertTrue(checks['frida_version_match']['required'])

    def test_explicit_root_checks_can_confirm_listener_and_versions(self):
        result = self.run_doctor({'devices': 'one\tdevice'}, '--for', 'frida', '--root')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('superuser authorization prompt', result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(self.checks(report)['frida_server_listener']['status'], 'ok')
        self.assertEqual(self.checks(report)['frida_version_match']['status'], 'ok')
        self.assertTrue(any('su' in call for call in self.calls()))

    def test_root_listener_without_server_owner_is_unknown(self):
        result = self.run_doctor({'devices': 'one\tdevice', 'listener': 'LISTEN 0 128 127.0.0.1:27042 0.0.0.0:*'},
                                 '--for', 'frida', '--root')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.checks(json.loads(result.stdout))['frida_server_listener']['status'], 'unknown')

    def test_root_can_observe_process_after_restricted_shell(self):
        result = self.run_doctor({'devices': 'one\tdevice', 'ps': 'shell 456 sh'}, '--for', 'frida', '--root')
        self.assertEqual(result.returncode, 0)
        self.assertIn(['adb', '-s', 'one', 'shell', 'su', '-c', "'ps -A'"], self.calls())

    def test_root_rejects_exposed_listener_and_version_mismatch(self):
        for config, name, code in (
                ({'listener': 'LISTEN 0 128 0.0.0.0:27042 0.0.0.0:* users:(("frida-server",pid=123))'},
                 'frida_server_listener', 'unsafe_listener'),
                ({'server_version': '16.0.0'}, 'frida_version_match', 'version_mismatch')):
            with self.subTest(code=code):
                result = self.run_doctor(dict(config, devices='one\tdevice'), '--for', 'frida', '--root')
                self.assertEqual(result.returncode, 1)
                check = self.checks(json.loads(result.stdout))[name]
                self.assertEqual((check['status'], check['code']), ('error', code))

    def test_apk_succeeds_without_any_adb_call_or_device(self):
        result = self.run_doctor({}, '--for', 'apk')
        self.assertEqual(result.returncode, 0)
        self.assertTrue(self.report(result)['healthy'])
        self.assertFalse(any(call[0] == 'adb' for call in self.calls()))
        (self.bin / 'adb').unlink()
        (self.root / '.venv/bin/frida-ps').unlink()
        result = self.run_doctor({}, '--for', 'apk')
        self.assertEqual(result.returncode, 0)

    def test_wrapper_doctor_bypasses_device_selection_without_adb(self):
        self.config.write_text('{}')
        (self.bin / 'bash').symlink_to('/bin/bash')
        dirname = self.bin / 'dirname'
        dirname.write_text('#!' + sys.executable + '\nimport os, sys\nprint(os.path.dirname(sys.argv[1]))\n')
        dirname.chmod(0o755)
        env = dict(self.env, PYTHON=sys.executable,
                   ANDROID_LAB_ROOT=str(self.root), ANDROID_SERIAL='', ADB_BIN=str(self.root / 'missing-adb'))
        for workflow, expected in (('audit', 1), ('apk', 0)):
            with self.subTest(workflow=workflow):
                result = subprocess.run(['/bin/bash', str(WRAPPER), 'doctor', '--json', '--for', workflow],
                                        env=env, text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(self.checks(self.report(result))['selected_device']['status'], 'skipped')
        self.assertFalse(any(call[0] == 'adb' for call in self.calls()))

    def test_invalid_arguments_fail_before_tool_invocation(self):
        for args in (('--for', 'invalid'), ('--serial', 'unsafe;serial'), ('--root-dir', str(self.root / 'missing')),
                     ('--for', 'apk', '--root'), ('--adb', '')):
            with self.subTest(args=args):
                result = self.run_doctor({}, *args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(self.calls(), [])

    def test_missing_optional_tool_does_not_fail_adb_but_capture_requires_it(self):
        (self.bin / 'mitmweb').unlink()
        online = {'devices': 'one\tdevice'}
        result = self.run_doctor(online, '--for', 'adb')
        self.assertEqual(result.returncode, 0)
        self.assertFalse(self.checks(self.report(result))['mitmweb']['required'])
        result = self.run_doctor(online, '--for', 'capture')
        self.assertEqual(result.returncode, 1)
        checks = self.checks(self.report(result))
        self.assertTrue(checks['mitmweb']['required'])
        self.assertEqual(checks['proxy']['detail'], ':0')

    def test_output_limit_is_classified_and_host_checks_remain(self):
        result = self.run_doctor({'output_limit': True}, '--for', 'adb')
        self.assertEqual(result.returncode, 1)
        checks = self.checks(self.report(result))
        self.assertEqual(checks['selected_device']['code'], 'output_limit')
        self.assertEqual(checks['mitmweb']['status'], 'ok')

    def test_unknown_version_does_not_make_executable_unavailable(self):
        result = self.run_doctor({'devices': 'one\tdevice', 'version_failure': 'adb'}, '--for', 'adb')
        self.assertEqual(result.returncode, 0)
        report = self.report(result)
        self.assertIsNone(report['tools']['adb']['version'])
        self.assertEqual(self.checks(report)['adb']['status'], 'ok')
        self.assertIn(['adb', 'version'], self.calls())
        self.assertNotIn(['adb', '--version'], self.calls())

    def test_sigterm_interrupts_bounded_probe_and_reaps_its_child(self):
        for version in (False, True):
            with self.subTest(version=version):
                pid_file = self.root / ('version-pid' if version else 'probe-pid')
                config = {'pid_file': str(pid_file), 'version_linger': 'adb'} if version else {
                    'pid_file': str(pid_file), 'linger': True}
                self.config.write_text(json.dumps(config))
                process = subprocess.Popen(self.command('--for', 'adb'), env=self.env, text=True,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.addCleanup(lambda p=process: p.kill() if p.poll() is None else None)
                deadline = time.monotonic() + 5
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(pid_file.exists())
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 1, stderr)
                self.assertEqual(self.checks(json.loads(stdout))['interrupted']['code'], 'interrupted')
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pid_file.read_text()), 0)


if __name__ == '__main__':
    unittest.main()
