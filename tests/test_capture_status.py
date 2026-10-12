import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills/android-security-lab/scripts'))
import capture_status


class CaptureStatusTests(unittest.TestCase):
    def test_timeout_keeps_cleanup_failure_by_check(self):
        error = subprocess.TimeoutExpired(['adb'], 10)
        error.cleanup_errors = ['process group stop not confirmed']
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', ['capture_status.py', '--serial', 'test-device']), \
                mock.patch.object(capture_status, 'run_bounded', side_effect=error), \
                contextlib.redirect_stdout(output):
            self.assertEqual(capture_status.main(), 2)
        report = json.loads(output.getvalue())
        self.assertIn('timed out', report['errors']['device'])
        self.assertEqual(report['cleanup_errors']['device'], error.cleanup_errors)
        self.assertEqual(report['https_decryption'], 'not_tested')

    def test_cancel_keeps_completed_checks_and_cleanup_failure(self):
        error = KeyboardInterrupt()
        error.cleanup_errors = ['process group stop not confirmed']
        output = io.StringIO()
        effects = [subprocess.CompletedProcess([], 0, 'device\n', ''), error]
        with mock.patch.object(sys, 'argv', ['capture_status.py', '--serial', 'test-device']), \
                mock.patch.object(capture_status, 'run_bounded', side_effect=effects), \
                contextlib.redirect_stdout(output):
            self.assertEqual(capture_status.main(), 2)
        report = json.loads(output.getvalue())
        self.assertEqual(report['observations'], {'device': 'device'})
        self.assertEqual(report['errors'], {'proxy': 'interrupted'})
        self.assertEqual(report['cleanup_errors']['proxy'], error.cleanup_errors)

    def test_idle_listener_exit_is_not_command_error(self):
        effects = [subprocess.CompletedProcess([], 0, 'device', ''),
                   subprocess.CompletedProcess([], 0, 'null', ''),
                   subprocess.CompletedProcess([], 0, '', ''),
                   subprocess.CompletedProcess([], 1, '', ''),
                   subprocess.CompletedProcess([], 1, '', '')]
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', ['capture_status.py', '--serial', 'test-device']), \
                mock.patch.object(capture_status, 'run_bounded', side_effect=effects), \
                contextlib.redirect_stdout(output):
            self.assertEqual(capture_status.main(), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report['errors'], {})
        self.assertIn('proxy_listener_missing', report['issues'])

    def test_cancel_preserves_previous_command_failure(self):
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', ['capture_status.py', '--serial', 'test-device']), \
                mock.patch.object(capture_status, 'run_bounded', side_effect=[
                    subprocess.TimeoutExpired(['adb'], 10), KeyboardInterrupt()]), \
                contextlib.redirect_stdout(output):
            self.assertEqual(capture_status.main(), 2)
        report = json.loads(output.getvalue())
        self.assertIn('timed out', report['errors']['device'])
        self.assertEqual(report['errors']['proxy'], 'interrupted')


if __name__ == '__main__':
    unittest.main()
