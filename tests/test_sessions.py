import json
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills/android-security-lab/scripts"))
ADB = r'''#!/usr/bin/env python3
import json, os, shlex, sys
from pathlib import Path
p = Path(os.environ['FAKE_STATE'])
s = json.loads(p.read_text())
a = sys.argv[1:]
if a == ['version']:
    print('fake adb 1.0')
    sys.exit(0)
serial = a[1] if a[:1] == ['-s'] else 'test-device'
if a[:1] == ['-s']: a = a[2:]
if a[:1] == ['shell']: a = ['shell'] + shlex.split(' '.join(a[1:]))
s['calls'].append([serial] + a)
code, out = 0, ''
if a == ['get-state']: out = 'device'
elif a[:1] in (['forward'], ['reverse']):
    kind = a[0]
    rows = s[kind]
    if a[1] == '--list':
        out = '\n'.join(' '.join(row) for row in rows)
    elif a[1] == '--remove':
        if s.get('slow_cleanup'):
            import time
            time.sleep(.2)
        s[kind] = [row for row in rows if row[1] != a[2]]
    else:
        norebind = a[1] == '--no-rebind'
        source, target = a[2:4] if norebind else a[1:3]
        if any(row[1] == source for row in rows) and norebind:
            code, out = 1, 'cannot rebind existing socket'
        else:
            s[kind] = [row for row in rows if row[1] != source]
            s[kind].append([serial if kind == 'forward' else 'UsbFfs', source, target])
elif a[:4] == ['shell', 'settings', 'get', 'global']:
    out = s['proxy']
    if s.get('overflow_get'): out += 'x' * (1024 * 1024 + 1)
elif a[:4] == ['shell', 'settings', 'put', 'global']:
    s['proxy'] = a[5]
    if s.get('set_fails'): code, out = 1, 'reply lost after proxy write'
    if s.get('overflow_set') and a[5] == '127.0.0.1:8080': out = 'x' * (1024 * 1024 + 1)
elif a[:4] == ['shell', 'settings', 'delete', 'global']: s['proxy'] = 'null'
else: code, out = 1, 'unexpected command: ' + repr(a)
if s.get('offline_cleanup') and a[:2] in (['reverse', '--list'], ['forward', '--list']) and Path(os.environ['FAKE_CHILD']).exists():
    code, out = 1, 'device offline'
pending = p.with_name(p.name + '.' + str(os.getpid()) + '.tmp')
pending.write_text(json.dumps(s))
pending.replace(p)
if s.get('interrupt_create') and '--no-rebind' in a:
    import signal, time
    os.kill(os.getppid(), signal.SIGTERM)
    time.sleep(30)
print(out)
sys.exit(code)
'''
CHILD = r'''#!/usr/bin/env python3
import json, os, signal, sys, time
from pathlib import Path
if sys.argv[1:] == ['--version']:
    print('fake child 1.0')
    sys.exit(0)
state = Path(os.environ['FAKE_STATE'])
marker = Path(os.environ['FAKE_CHILD'])
marker.write_text(str(os.getpid()))
mode = os.environ.get('FAKE_MODE', 'exit')
if mode == 'replace':
    s = json.loads(state.read_text())
    s['forward'] = [['other-device', 'tcp:27042', 'tcp:9999']]
    pending = state.with_name(state.name + '.' + str(os.getpid()) + '.tmp')
    pending.write_text(json.dumps(s))
    pending.replace(state)
if mode == 'exit': sys.exit(0)
if mode == 'fail': sys.exit(7)
def stop(signum, frame):
    if mode == 'external-proxy':
        s = json.loads(state.read_text())
        s['proxy'] = 'external.example:8888'
        pending = state.with_name(state.name + '.' + str(os.getpid()) + '.tmp')
        pending.write_text(json.dumps(s))
        pending.replace(state)
    Path(str(marker) + '.stopped').write_text(str(signum))
    sys.exit(0)
signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)
if mode == 'replace': sys.exit(0)
while True:
    if mode == 'delayed-fail' and json.loads(state.read_text())['proxy'] == '127.0.0.1:8080':
        sys.exit(7)
    time.sleep(.02)
'''
LSOF = r'''#!/usr/bin/env python3
import os, sys
from pathlib import Path
p = Path(os.environ['FAKE_CHILD'])
if not p.exists(): sys.exit(1)
port = next(a.split(':')[-1] for a in sys.argv if a.startswith('-iTCP:'))
pid = p.read_text()
if os.environ.get('FAKE_FOREIGN_LISTENER'): pid = '123'
print('p' + pid + '\nn127.0.0.1:' + port)
'''


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state.json'
        self.marker = self.root / 'child'
        self.state.write_text(json.dumps({'calls': [], 'forward': [], 'reverse': [],
                                         'proxy': 'null'}))
        tools = self.root / 'tools'
        tools.mkdir()
        for name, source in [('adb', ADB), ('mitmweb', CHILD), ('lsof', LSOF)]:
            path = tools / name
            path.write_text(source.replace('/usr/bin/env python3', sys.executable))
            path.chmod(0o755)
        frida = self.root / '.venv/bin/frida-ps'
        frida.parent.mkdir(parents=True)
        frida.write_text(CHILD.replace('/usr/bin/env python3', sys.executable))
        frida.chmod(0o755)
        self.env = dict(os.environ, ANDROID_LAB_ROOT=str(self.root),
                        ADB_BIN=str(tools / 'adb'), PYTHON=sys.executable,
                        FAKE_STATE=str(self.state), FAKE_CHILD=str(self.marker),
                        PATH=str(tools) + os.pathsep + os.environ['PATH'])
        self.capture = self.root / 'capture'

    def read(self):
        return json.loads(self.state.read_text())

    def update(self, **values):
        state = self.read()
        state.update(values)
        pending = self.state.with_name('test-state.tmp')
        pending.write_text(json.dumps(state))
        pending.replace(self.state)

    def command(self, *args):
        return ['bash', str(REPO / 'bin/android-lab'), '-s', 'test-device', *args]

    def run_cli(self, *args):
        return subprocess.run(self.command(*args), env=self.env, text=True,
                              capture_output=True, timeout=20)

    def start_capture(self, mode='wait'):
        self.env['FAKE_MODE'] = mode
        process = subprocess.Popen(self.command('capture', str(self.capture)),
                                   env=self.env, text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        self.addCleanup(self.stop_if_running, process)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.read()['proxy'] == '127.0.0.1:8080': return process
            if process.poll() is not None:
                self.fail('capture failed: ' + repr(process.communicate()))
            time.sleep(.02)
        self.fail('capture setup timed out')

    @staticmethod
    def stop_if_running(process):
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=15)

    def test_existing_forward_is_preserved(self):
        original = [['other-device', 'tcp:27042', 'tcp:1234']]
        self.update(forward=original)
        result = self.run_cli('frida-ps')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.read()['forward'], original)
        self.assertFalse(self.marker.exists())

    def test_frida_failure_cleans_its_forward(self):
        self.env['FAKE_MODE'] = 'fail'
        result = self.run_cli('frida-ps')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(self.read()['forward'], [])
        self.assertTrue(any('--no-rebind' in c for c in self.read()['calls']))

    def test_replaced_forward_is_preserved_and_reported(self):
        self.env['FAKE_MODE'] = 'replace'
        result = self.run_cli('frida-ps')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.read()['forward'], [['other-device', 'tcp:27042', 'tcp:9999']])
        self.assertIn('cleanup', result.stderr.lower())

    def test_invalid_frida_port_is_rejected_before_mapping(self):
        self.env['LAB_FRIDA_PORT'] = '0'
        result = self.run_cli('frida-ps')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(c[1] == 'forward' for c in self.read()['calls']))

    def test_frida_sigterm_stops_child_and_cleans_mapping(self):
        self.env['FAKE_MODE'] = 'wait'
        process = subprocess.Popen(self.command('frida-ps'), env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.stop_if_running, process)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.marker.exists(): break
            time.sleep(.02)
        self.assertTrue(self.marker.exists())
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=15)
        self.assertEqual(process.returncode, 143)
        self.assertEqual(self.read()['forward'], [])
        self.assertTrue(Path(str(self.marker) + '.stopped').exists())

    def test_capture_sigint_restores_existing_proxy_and_only_own_reverse(self):
        other = ['UsbFfs', 'tcp:9000', 'tcp:9000']
        self.update(proxy='old.example:3128', reverse=[other])
        process = self.start_capture()
        process.send_signal(signal.SIGINT)
        _, error = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 130, error)
        state = self.read()
        self.assertEqual(state['proxy'], 'old.example:3128')
        self.assertEqual(state['reverse'], [other])
        self.assertTrue(Path(str(self.marker) + '.stopped').exists())
        report = json.loads((self.capture / 'session.json').read_text())
        self.assertEqual(report['cleanup_errors'], [])
        self.assertEqual(report['https_decryption'], 'not_tested')
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['operation'], 'capture')
        self.assertLessEqual(report['started_at'], report['finished_at'])
        self.assertTrue(report['limitations'])
        self.assertEqual(report['tools']['adb']['version'], 'fake adb 1.0')
        self.assertEqual(report['tools']['mitmweb']['version'], 'fake child 1.0')
        self.assertEqual(report['failures'][0]['code'], 'interrupted')

    def test_capture_sigterm_restores_absent_proxy(self):
        process = self.start_capture()
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=15)
        self.assertEqual(process.returncode, 143)
        self.assertEqual(self.read()['proxy'], 'null')
        self.assertEqual(self.read()['reverse'], [])

    def test_capture_early_exit_restores_phone_and_preserves_child_exit(self):
        self.env['FAKE_MODE'] = 'delayed-fail'
        self.update(proxy='old.example:3128')
        result = self.run_cli('capture', str(self.capture))
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(self.read()['proxy'], 'old.example:3128')
        self.assertEqual(self.read()['reverse'], [])

    def test_original_proxy_is_quoted_at_remote_shell_boundary(self):
        original = " old.example:3128; echo 'literal value' "
        self.update(proxy=original)
        process = self.start_capture()
        process.send_signal(signal.SIGTERM)
        _, error = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 143, error)
        self.assertEqual(self.read()['proxy'], original)

    def test_proxy_cleanup_failure_does_not_skip_other_resources(self):
        self.update(proxy='old.example:3128')
        process = self.start_capture()
        self.update(set_fails=True)
        process.send_signal(signal.SIGTERM)
        _, error = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 2, error)
        self.assertEqual(self.read()['reverse'], [])
        self.assertTrue(Path(str(self.marker) + '.stopped').exists())
        report = json.loads((self.capture / 'session.json').read_text())
        self.assertEqual(len(report['cleanup_errors']), 1)

    def test_capture_existing_reverse_is_not_overwritten(self):
        original = [['UsbFfs', 'tcp:8080', 'tcp:1234']]
        self.update(reverse=original)
        result = self.run_cli('capture', str(self.capture))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.read()['reverse'], original)
        self.assertEqual(self.read()['proxy'], 'null')
        self.assertFalse(self.marker.exists())

    def test_capture_child_start_failure_does_not_change_phone(self):
        self.env['FAKE_MODE'] = 'fail'
        result = self.run_cli('capture', str(self.capture))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.read()['reverse'], [])
        self.assertEqual(self.read()['proxy'], 'null')

    def test_capture_lost_proxy_write_reply_still_restores(self):
        self.update(set_fails=True)
        self.env['FAKE_MODE'] = 'wait'
        result = self.run_cli('capture', str(self.capture))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.read()['proxy'], 'null')
        self.assertEqual(self.read()['reverse'], [])
        self.assertTrue(Path(str(self.marker) + '.stopped').exists())

    def test_capture_external_state_change_is_preserved(self):
        process = self.start_capture()
        self.update(proxy='external.example:8888',
                    reverse=[['UsbFfs', 'tcp:8080', 'tcp:7777']])
        process.send_signal(signal.SIGTERM)
        _, error = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 2, error)
        self.assertEqual(self.read()['proxy'], 'external.example:8888')
        self.assertEqual(self.read()['reverse'], [['UsbFfs', 'tcp:8080', 'tcp:7777']])
        report = json.loads((self.capture / 'session.json').read_text())
        self.assertEqual(len(report['cleanup_errors']), 2)

    def test_capture_offline_cleanup_reports_failure(self):
        process = self.start_capture()
        self.update(offline_cleanup=True)
        process.send_signal(signal.SIGTERM)
        _, error = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 2, error)
        self.assertTrue(json.loads((self.capture / 'session.json').read_text())['cleanup_errors'])
        self.assertTrue(Path(str(self.marker) + '.stopped').exists())

    def test_repeated_signals_do_not_interrupt_cleanup(self):
        process = self.start_capture()
        self.update(slow_cleanup=True)
        process.send_signal(signal.SIGTERM)
        time.sleep(.08)
        process.send_signal(signal.SIGINT)
        _, error = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 143, error)
        self.assertEqual(self.read()['proxy'], 'null')
        self.assertEqual(self.read()['reverse'], [])
        self.assertTrue(Path(str(self.marker) + '.stopped').exists())

    def test_foreign_capture_listener_is_rejected_and_child_stopped(self):
        self.env['FAKE_FOREIGN_LISTENER'] = '1'
        self.env['FAKE_MODE'] = 'wait'
        result = self.run_cli('capture', str(self.capture))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.read()['proxy'], 'null')
        self.assertEqual(self.read()['reverse'], [])
        self.assertTrue(Path(str(self.marker) + '.stopped').exists())

    def test_original_proxy_targeting_capture_is_refused(self):
        self.update(proxy='127.0.0.1:8080')
        result = self.run_cli('capture', str(self.capture))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.read()['proxy'], '127.0.0.1:8080')
        self.assertFalse(self.marker.exists())

    def test_existing_capture_directory_is_preserved(self):
        self.capture.mkdir()
        report = self.capture / 'session.json'
        report.write_text('existing evidence')
        result = self.run_cli('capture', str(self.capture))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report.read_text(), 'existing evidence')
        self.assertFalse(self.marker.exists())

    def test_mapping_creation_timeout_does_not_claim_or_delete_mapping(self):
        path = REPO / 'skills/android-security-lab/scripts/lab_session.py'
        spec = importlib.util.spec_from_file_location('lab_session_test', path)
        session = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(session)
        calls = []
        def fake_run(command, cancel=True):
            calls.append(command)
            if '--no-rebind' in command:
                raise subprocess.TimeoutExpired(command, 10)
            return ''
        argv = ['lab_session.py', '--adb', 'fake-adb', '--serial', 'test-device',
                'frida', '--', 'fake-frida']
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(session, 'run', fake_run), \
                mock.patch.object(session.signal, 'signal'), contextlib.redirect_stderr(io.StringIO()) as errors:
            code = session.main()
        self.assertEqual(code, 2)
        self.assertFalse(any('--remove' in command for command in calls))
        self.assertIn('ownership unknown', errors.getvalue())

    def test_capture_startup_output_overflow_has_structured_failure(self):
        self.update(overflow_get=True)
        result = self.run_cli('capture', str(self.capture))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.read()['reverse'], [])
        report = json.loads((self.capture / 'session.json').read_text())
        self.assertEqual((report['failures'][0]['stage'], report['failures'][0]['code']),
                         ('inspect_proxy', 'output_limit'))
        self.assertEqual(report['mapping_created'], None)

    def test_capture_output_overflow_after_proxy_write_still_cleans_resources(self):
        self.update(overflow_set=True)
        self.env['FAKE_MODE'] = 'wait'
        result = self.run_cli('capture', str(self.capture))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.read()['proxy'], 'null')
        self.assertEqual(self.read()['reverse'], [])
        self.assertTrue(Path(str(self.marker) + '.stopped').exists())
        report = json.loads((self.capture / 'session.json').read_text())
        self.assertEqual((report['failures'][0]['stage'], report['failures'][0]['code']),
                         ('set_proxy', 'output_limit'))
        self.assertEqual(report['cleanup_errors'], [])

    def test_capture_signal_during_mapping_creation_preserves_unknown_mapping(self):
        self.update(interrupt_create=True)
        self.env['FAKE_MODE'] = 'wait'
        result = self.run_cli('capture', str(self.capture))
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assertEqual(self.read()['reverse'], [['UsbFfs', 'tcp:8080', 'tcp:8080']])
        self.assertFalse(any('--remove' in call for call in self.read()['calls']))
        self.assertEqual(self.read()['proxy'], 'null')
        self.assertTrue(Path(str(self.marker) + '.stopped').exists())
        report = json.loads((self.capture / 'session.json').read_text())
        self.assertIsNone(report['mapping_created'])
        self.assertEqual((report['failures'][0]['stage'], report['failures'][0]['code']),
                         ('create_mapping', 'interrupted'))
        self.assertIn('ownership unknown', report['error'])

    def test_mapping_cancel_during_creation_does_not_claim_or_delete_mapping(self):
        path = REPO / 'skills/android-security-lab/scripts/lab_session.py'
        spec = importlib.util.spec_from_file_location('lab_session_cancel_test', path)
        session = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(session)
        calls = []

        def fake_run(command, cancel=True):
            calls.append(command)
            if '--no-rebind' in command:
                session.request_stop(signal.SIGTERM, None)
                raise InterruptedError('creation reply interrupted')
            return ''

        argv = ['lab_session.py', '--adb', 'fake-adb', '--serial', 'test-device',
                'frida', '--', 'fake-frida']
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(session, 'run', fake_run), \
                mock.patch.object(session.signal, 'signal'), contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(session.main(), 143)
        self.assertFalse(any('--remove' in command for command in calls))
        self.assertIn('ownership unknown', errors.getvalue())

    def test_mapping_cancel_keeps_query_process_cleanup_failure(self):
        path = REPO / 'skills/android-security-lab/scripts/lab_session.py'
        spec = importlib.util.spec_from_file_location('lab_session_cleanup_test', path)
        session = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(session)
        calls = []
        def fake_run(command, cancel=True):
            calls.append(command)
            if '--no-rebind' in command:
                session.request_stop(signal.SIGTERM, None)
                error = InterruptedError('creation reply interrupted')
                error.cleanup_errors = ['process group stop not confirmed: injected denial']
                raise error
            return 'null' if 'settings' in command else ''
        child = mock.Mock(pid=123, returncode=None)
        argv = ['lab_session.py', '--adb', 'fake-adb', '--serial', 'test-device',
                'capture', str(self.capture)]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(session, 'run', fake_run), \
                mock.patch.object(session, 'listeners', return_value=[]), \
                mock.patch.object(session, 'wait_listeners'), mock.patch.object(session, 'stop_child'), \
                mock.patch.object(session, 'tool_identity', return_value={'path': 'fake', 'version': None}), \
                mock.patch.object(session.subprocess, 'Popen', return_value=child), \
                mock.patch.object(session.signal, 'signal'), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(session.main(), 2)
        report = json.loads((self.capture / 'session.json').read_text())
        self.assertEqual(report['failures'][0]['code'], 'interrupted')
        self.assertIn('group stop not confirmed', report['failures'][0]['cleanup_errors'][0])
        self.assertTrue(report['cleanup_errors'])
        self.assertIsNone(report['mapping_created'])
        self.assertFalse(any('--remove' in command for command in calls))


if __name__ == '__main__':
    unittest.main()
