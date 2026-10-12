import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parents[1]
HELPER = REPO / 'skills/android-security-lab/scripts/logcat_dump.py'
WRAPPER = REPO / 'bin/android-lab'
FAKE = r'''
import json, os, sys, time
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ['CALLS']).open('a') as file:
    file.write(json.dumps(args) + '\n')
config = json.loads(Path(os.environ['CONFIG']).read_text())
if args == ['version']:
    print('Android Debug Bridge version fake')
    sys.exit(0)
assert args[:2] == ['-s', 'fake-device']
args = args[2:]
if args == ['get-state']:
    print('device')
elif args[:2] == ['shell', 'pidof']:
    print(config.get('pids', '42'))
    sys.exit(config.get('pid_exit', 0))
else:
    assert args[:5] == ['logcat', '-d', '-b', 'main', '-t']
    if config.get('linger'):
        Path(config['marker']).write_text(str(os.getpid()))
        time.sleep(5)
        Path(config['late']).touch()
    sys.stdout.write(config.get('logs', 'a\nb\nc\n'))
    sys.stderr.write(config.get('stderr', ''))
    sys.exit(config.get('log_exit', 0))
'''


class LogDumpTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.adb = self.root / 'fake adb'
        self.adb.write_text('#!' + sys.executable + '\n' + FAKE)
        self.adb.chmod(0o755)
        self.config = self.root / 'config.json'
        self.calls = self.root / 'calls.jsonl'
        self.env = dict(os.environ, CONFIG=str(self.config), CALLS=str(self.calls),
                        ADB_BIN=str(self.adb), ANDROID_SERIAL='fake-device', PYTHON=sys.executable)

    def command(self, wrapper=False, arguments=('com.example.app', '2')):
        return ([str(WRAPPER), 'logcat-dump'] if wrapper else
                [sys.executable, str(HELPER), '--adb', str(self.adb), '--serial', 'fake-device']) + list(arguments)

    def run_dump(self, config, wrapper=False, arguments=('com.example.app', '2')):
        self.config.write_text(json.dumps(config))
        return subprocess.run(self.command(wrapper, arguments), env=self.env,
                              capture_output=True, text=True, timeout=10)

    def test_wrapper_bounded_tail_and_pid(self):
        result = self.run_dump({}, wrapper=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['lines'], ['b', 'c'])
        self.assertEqual(report['pid'], 42)
        self.assertEqual(report['coverage'], 'partial')
        self.assertEqual(report['tools']['adb']['version'], 'Android Debug Bridge version fake')
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertIn(['-s', 'fake-device', 'logcat', '-d', '-b', 'main', '-t', '2', '--pid=42'], calls)

    def test_empty_logs_do_not_claim_absence(self):
        result = self.run_dump({'logs': ''})
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['coverage'], 'partial')
        self.assertEqual(report['lines'], [])

    def test_multiple_or_invalid_pid_is_refused_before_logcat(self):
        for pids, code in [('42 43', 'multiple_processes'), ('not-a-pid', 'invalid_output'), ('0', 'invalid_output'), ('²', 'invalid_output'), ('٤٢', 'invalid_output'), ('9' * 5000, 'invalid_output'), ('4294967295', 'invalid_output'), ('', 'package_not_running')]:
            with self.subTest(pids=pids):
                self.calls.unlink(missing_ok=True)
                result = self.run_dump({'pids': pids})
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(json.loads(result.stdout)['failures'][0]['code'], code)
                self.assertNotIn('logcat', self.calls.read_text())

    def test_command_failure_retains_observed_lines(self):
        result = self.run_dump({'logs': 'observed\n', 'log_exit': 7, 'stderr': 'log reader failed'})
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report['lines'], ['observed'])
        self.assertEqual(report['failures'][0]['stage'], 'read_logs')
        self.assertIn('log reader failed', report['failures'][0]['error'])

    def test_stdout_or_stderr_overflow_is_a_bounded_failure(self):
        for config in ({'logs': 'x' * (2 * 1024 * 1024)}, {'logs': '', 'stderr': 'y' * (2 * 1024 * 1024)}):
            with self.subTest(stream='stderr' if config.get('stderr') else 'stdout'):
                result = self.run_dump(config)
                self.assertEqual(result.returncode, 1)
                report = json.loads(result.stdout)
                self.assertEqual(report['failures'][0]['code'], 'output_limit')
                self.assertTrue(report['output_truncated'])
                self.assertLessEqual(sum(len(line) for line in report['lines']), 1024 * 1024)

    def test_invalid_input_never_invokes_adb(self):
        for arguments in (('bad;id',), ('com.example.app', '0'), ('com.example.app', '10001'), ('com.example.app', 'abc'), ('com.example.app', '1', 'extra')):
            for wrapper in (False, True):
                with self.subTest(arguments=arguments, wrapper=wrapper):
                    result = self.run_dump({}, wrapper=wrapper, arguments=arguments)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(self.calls.exists())

    def test_sigterm_returns_json_and_reaps_owned_adb(self):
        marker, late = self.root / 'pid', self.root / 'late'
        self.config.write_text(json.dumps({'linger': True, 'marker': str(marker), 'late': str(late)}))
        with subprocess.Popen(self.command(), env=self.env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True) as process:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(marker.exists())
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 1, stderr)
        self.assertEqual(json.loads(stdout)['failures'][0]['code'], 'interrupted')
        with self.assertRaises(ProcessLookupError):
            os.kill(int(marker.read_text()), 0)
        self.assertFalse(late.exists())


if __name__ == '__main__':
    unittest.main()
