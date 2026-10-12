import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/android-security-lab/scripts'
sys.path.insert(0, str(SCRIPTS))
from lab_common import OutputLimitError, run_bounded, tool_identity


class BoundedProcessTests(unittest.TestCase):
    def command(self, source):
        return [sys.executable, '-c', source]

    def test_both_streams_and_exit_status(self):
        result = run_bounded(self.command("import sys; print('out'); print('err', file=sys.stderr); sys.exit(7)"), 3)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (7, 'out\n', 'err\n'))

    def test_combined_output_budget_and_reaping(self):
        for stream in ('stdout', 'stderr', 'both'):
            with self.subTest(stream=stream):
                source = "import os; " + ('os.write(1, b"x"*6000); os.write(2, b"y"*6000)' if stream == 'both'
                                                else f'os.write({1 if stream == "stdout" else 2}, b"x"*20000)')
                children = []
                popen = subprocess.Popen
                def start(*args, **kwargs):
                    child = popen(*args, **kwargs)
                    children.append(child)
                    return child
                with mock.patch('lab_common.subprocess.Popen', side_effect=start):
                    with self.assertRaises(OutputLimitError) as raised:
                        run_bounded(self.command(source + '; import time; time.sleep(5)'), 3, 8192)
                self.assertEqual(len(raised.exception.stdout) + len(raised.exception.stderr), 8192)
                self.assertIsNotNone(children[0].returncode)
                self.assertTrue(children[0].stdout.closed)
                self.assertTrue(children[0].stderr.closed)

    def test_timeout_retains_bounded_output(self):
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            run_bounded(self.command("import os, time; os.write(2, b'before timeout'); time.sleep(5)"), .3)
        self.assertEqual(raised.exception.stderr, 'before timeout')

    def test_closed_pipes_do_not_disable_deadline(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            run_bounded(self.command('import os, time; os.close(1); os.close(2); time.sleep(5)'), .3)
        self.assertLess(time.monotonic() - started, 2)

    def test_exited_leader_with_descendant_pipe_is_stopped(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / 'late-write'
            source = ("import os, time\n"
                      "if os.fork() == 0:\n"
                      f" time.sleep(.8); open({str(marker)!r}, 'w').write('escaped')\n"
                      "else: os._exit(0)\n")
            with self.assertRaises(subprocess.TimeoutExpired):
                run_bounded(self.command(source), .3)
            time.sleep(.7)
            self.assertFalse(marker.exists())

    def test_cancellation_reaps_child(self):
        children = []
        popen = subprocess.Popen
        def start(*args, **kwargs):
            child = popen(*args, **kwargs)
            children.append(child)
            return child
        def cancelled():
            raise InterruptedError('cancelled')
        with mock.patch('lab_common.subprocess.Popen', side_effect=start):
            with self.assertRaises(InterruptedError):
                run_bounded(self.command('import time; time.sleep(5)'), 3, check_cancel=cancelled)
        self.assertIsNotNone(children[0].returncode)

    def test_group_signal_denial_preserves_cancel_and_reaps_direct_child(self):
        for already_exited in (False, True):
            with self.subTest(already_exited=already_exited):
                children = []
                popen = subprocess.Popen
                def start(*args, **kwargs):
                    child = popen(*args, **kwargs)
                    children.append(child)
                    return child
                def cancelled():
                    if already_exited:
                        time.sleep(.3)  # The fast leader exits, but is not reaped.
                    raise InterruptedError('primary cancellation')
                source = 'pass' if already_exited else 'import time; time.sleep(5)'
                with mock.patch('lab_common.subprocess.Popen', side_effect=start), mock.patch(
                        'lab_common.os.killpg', side_effect=PermissionError('injected denial')):
                    with self.assertRaises(InterruptedError) as raised:
                        run_bounded(self.command(source), 3, check_cancel=cancelled)
                self.assertEqual(str(raised.exception), 'primary cancellation')
                self.assertIn('group stop not confirmed', raised.exception.cleanup_errors[0])
                self.assertIsNotNone(children[0].returncode)
                self.assertTrue(children[0].stdout.closed)
                self.assertTrue(children[0].stderr.closed)

    def test_descendant_closing_pipes_is_not_proof_of_group_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / 'late-write'
            source = ("import os, time\n"
                      "os.close(1); os.close(2)\n"
                      "if os.fork() == 0:\n"
                      f" time.sleep(.8); open({str(marker)!r}, 'w').write('escaped')\n"
                      "else: time.sleep(5)\n")
            with self.assertRaises(subprocess.TimeoutExpired):
                run_bounded(self.command(source), .3)
            time.sleep(.7)
            self.assertFalse(marker.exists())

    def test_version_failure_remains_unknown(self):
        self.assertIsNone(tool_identity(['/missing/lab/tool'])['version'])
        identity = tool_identity([sys.executable, '-c', 'import sys; sys.stdout.write("x"*20000)'])
        self.assertIsNone(identity['version'])


if __name__ == '__main__':
    unittest.main()
