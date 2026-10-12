"""CLI integration tests using a fake adb; no device is contacted."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


HELPER = Path(__file__).resolve().parents[1] / "skills/android-security-lab/scripts/pull_apk.py"
WRAPPER = Path(__file__).resolve().parents[1] / "bin/android-lab"
FAKE_ADB = r'''
import json
import os
from pathlib import Path
import signal
import sys
import time

config = json.loads(Path(os.environ["FAKE_ADB_CONFIG"]).read_text())
args = sys.argv[1:]
with Path(os.environ["FAKE_ADB_LOG"]).open("a") as log:
    log.write(json.dumps(args) + "\n")
assert args[:2] == ["-s", "fake-serial"]
args = args[2:]
if args == ["get-state"]:
    print("device")
    sys.exit(0)
if args == ["shell", "pm", "path", "com.example.app"]:
    sys.stdout.write(config["paths"])
    sys.stderr.write(config.get("pm_stderr", ""))
    sys.exit(config.get("pm_exit", 0))
assert args[0] == "pull"
remote, local = args[1:]
if remote in config.get("missing", []):
    sys.exit(0)
Path(local).write_bytes(bytes.fromhex(config.get("data", "0061706bff")))
if remote in config.get("interrupt", []):
    if config.get("linger"):
        Path(config["child_pid_file"]).write_text(str(os.getpid()))
    os.kill(os.getppid(), getattr(signal, config.get("interrupt_signal", "SIGINT")))
    if config.get("linger"):
        time.sleep(2)
        Path(local).write_bytes(b"late write")
        Path(config["late_write_file"]).touch()
    sys.exit(1)
if remote in config.get("fail", []):
    sys.stderr.write(config.get("pull_stderr", "fake pull failure\n"))
    sys.exit(1)
print("adb progress that must not appear on helper stdout")
'''


class PullApkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.adb = self.root / "fake adb"
        self.adb.write_text("#!" + sys.executable + "\n" + FAKE_ADB)
        self.adb.chmod(0o755)
        self.config = self.root / "config.json"
        self.log = self.root / "calls.jsonl"
        self.output = self.root / "output with spaces"

    def run_helper(self, config, package="com.example.app", adb=None):
        self.config.write_text(json.dumps(config))
        env = dict(os.environ, FAKE_ADB_CONFIG=str(self.config), FAKE_ADB_LOG=str(self.log))
        return subprocess.run([
            sys.executable, str(HELPER), "--adb", str(adb or self.adb),
            "--serial", "fake-serial", package, str(self.output),
        ], env=env, text=True, capture_output=True, timeout=10)

    def run_wrapper(self, config):
        self.config.write_text(json.dumps(config))
        env = dict(os.environ, FAKE_ADB_CONFIG=str(self.config), FAKE_ADB_LOG=str(self.log),
                   ADB_BIN=str(self.adb), ANDROID_SERIAL="fake-serial", PYTHON=sys.executable)
        return subprocess.run([str(WRAPPER), "pull-apk", "com.example.app", str(self.output)],
                              env=env, text=True, capture_output=True, timeout=10)

    def load_helper(self):
        spec = importlib.util.spec_from_file_location("pull_apk", HELPER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def manifest(self):
        return json.loads((self.output / "manifest.json").read_text())

    def pulls(self):
        return [json.loads(line)[3] for line in self.log.read_text().splitlines()
                if json.loads(line)[2] == "pull"]

    def test_split_hashes_and_unique_names(self):
        paths = ["/data/app/one/base.apk", "/data/app/two/base.apk", "/data/app/space name/split config.apk"]
        data = b"\x00APK\xff" * 300000
        result = self.run_helper({"paths": "".join("package:" + p + "\r\n" for p in paths), "data": data.hex()})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, str(self.output) + "\n")
        manifest = self.manifest()
        self.assertEqual(manifest["package"], "com.example.app")
        self.assertEqual(manifest["serial"], "fake-serial")
        self.assertEqual(manifest["coverage"], "complete")
        self.assertEqual(manifest["failures"], [])
        self.assertEqual(self.pulls(), paths)
        for item in manifest["artifacts"]:
            self.assertEqual(item["size_bytes"], len(data))
            self.assertEqual(item["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(Path(item["local_path"]).read_bytes(), data)
        self.assertEqual(len({item["local_path"] for item in manifest["artifacts"]}), 3)

    def test_middle_pull_failure_keeps_successes_and_continues(self):
        paths = ["/data/app/base.apk", "/data/app/bad.apk", "/data/app/last.apk"]
        result = self.run_helper({"paths": "\n".join("package:" + p for p in paths), "fail": [paths[1]], "pull_stderr": "original error\n" + "x" * 5000})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        manifest = self.manifest()
        self.assertEqual(manifest["coverage"], "partial")
        self.assertEqual([item["remote_path"] for item in manifest["artifacts"]], [paths[0], paths[2]])
        self.assertEqual(self.pulls(), paths)
        self.assertEqual(manifest["failures"][0]["remote_path"], paths[1])
        self.assertIn("original error\n", manifest["failures"][0]["error"])
        self.assertLessEqual(len(manifest["failures"][0]["error"]), 2048)
        self.assertFalse(list(self.output.glob("*.partial")))
        self.assertFalse((self.output / "2-bad.apk").exists())

    def test_pm_failure_retains_stderr_and_does_not_pull(self):
        result = self.run_helper({"paths": "package:/data/app/base.apk\n", "pm_exit": 7, "pm_stderr": "device offline\n"})
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.pulls(), [])
        manifest = self.manifest()
        self.assertEqual(manifest["coverage"], "none")
        self.assertEqual(manifest["artifacts"], [])
        self.assertIn("pm path failed (exit 7): device offline\n", manifest["failures"][0]["error"])
        self.assertNotIn("package not found", result.stderr)

    def test_empty_or_malformed_list(self):
        for index, paths in enumerate(["", "\n", "unexpected\n", "package:relative.apk\n", "package:/data/../base.apk\n", "package:/data//base.apk\n", "package:/data/directory/\n", "package:/data/file.txt\n", "package:/data/bad\t.apk\n"]):
            with self.subTest(paths=paths):
                self.output = self.root / str(index)
                result = self.run_helper({"paths": paths})
                self.assertEqual(result.returncode, 2)
                self.assertEqual(self.manifest()["coverage"], "none")
                self.assertTrue(self.manifest()["failures"])

    def test_malformed_line_does_not_hide_valid_splits(self):
        result = self.run_helper({"paths": "package:/data/base.apk\nmalformed\npackage:/data/last.apk\n"})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.manifest()["coverage"], "partial")
        self.assertEqual(self.pulls(), ["/data/base.apk", "/data/last.apk"])
        self.assertEqual(len(self.manifest()["failures"]), 1)

    def test_all_pulls_fail(self):
        result = self.run_helper({"paths": "package:/data/base.apk\n", "fail": ["/data/base.apk"]})
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.manifest()["coverage"], "none")
        self.assertEqual(sorted(p.name for p in self.output.iterdir()), ["manifest.json"])

    def test_existing_directory_is_refused_even_when_empty(self):
        self.output.mkdir()
        result = self.run_helper({"paths": "package:/data/base.apk\n"})
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.log.exists())
        self.assertEqual(list(self.output.iterdir()), [])
        sentinel = self.output / "1-base.apk"
        sentinel.write_bytes(b"keep")
        result = self.run_helper({"paths": "package:/data/base.apk\n"})
        self.assertEqual(result.returncode, 2)
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_invalid_package_is_rejected_before_adb_or_directory(self):
        result = self.run_helper({"paths": ""}, package="com.example;id")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.log.exists())

    def test_missing_adb_still_writes_manifest(self):
        result = self.run_helper({"paths": ""}, adb=self.root / "not installed")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.manifest()["coverage"], "none")
        self.assertTrue(self.manifest()["failures"])

    def test_pull_success_without_file_is_failure(self):
        result = self.run_helper({"paths": "package:/data/base.apk\n", "missing": ["/data/base.apk"]})
        self.assertEqual(result.returncode, 2)
        self.assertIn("regular file", self.manifest()["failures"][0]["error"])

    def test_interruption_keeps_completed_apk_and_removes_partial(self):
        result = self.run_helper({"paths": "package:/data/base.apk\npackage:/data/stop.apk\npackage:/data/last.apk\n", "interrupt": ["/data/stop.apk"]})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")
        manifest = self.manifest()
        self.assertEqual(manifest["coverage"], "partial")
        self.assertEqual([item["remote_path"] for item in manifest["artifacts"]], ["/data/base.apk"])
        self.assertEqual(manifest["failures"][0], {"remote_path": "/data/stop.apk", "error": "APK extraction interrupted (SIGINT)"})
        self.assertEqual(self.pulls(), ["/data/base.apk", "/data/stop.apk"])
        self.assertFalse(list(self.output.glob("*.partial")))

    def test_sigterm_keeps_manifest_and_cleans_partial(self):
        pid_file = self.root / "child.pid"
        late_write_file = self.root / "late-write"
        result = self.run_helper({"paths": "package:/data/base.apk\npackage:/data/stop.apk\npackage:/data/last.apk\n", "interrupt": ["/data/stop.apk"], "interrupt_signal": "SIGTERM", "linger": True, "child_pid_file": str(pid_file), "late_write_file": str(late_write_file)})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.manifest()["coverage"], "partial")
        self.assertEqual(self.manifest()["failures"][0]["error"], "APK extraction interrupted (SIGTERM)")
        self.assertEqual(self.pulls(), ["/data/base.apk", "/data/stop.apk"])
        self.assertFalse(list(self.output.glob("*.partial")))
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)
        self.assertFalse(late_write_file.exists())

    def test_wrapper_complete_success(self):
        paths = ["/data/base.apk", "/data/split.apk"]
        result = self.run_wrapper({"paths": "\n".join("package:" + p for p in paths)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, str(self.output) + "\n")
        self.assertEqual(self.manifest()["coverage"], "complete")
        self.assertEqual([item["remote_path"] for item in self.manifest()["artifacts"]], paths)

    def test_wrapper_partial_success(self):
        paths = ["/data/base.apk", "/data/bad.apk", "/data/last.apk"]
        result = self.run_wrapper({"paths": "\n".join("package:" + p for p in paths), "fail": [paths[1]]})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(self.manifest()["coverage"], "partial")
        self.assertEqual([item["remote_path"] for item in self.manifest()["artifacts"]], [paths[0], paths[2]])
        self.assertEqual(self.pulls(), paths)

    def test_pull_timeout_continues_without_waiting(self):
        helper = self.load_helper()
        calls = []

        def fake_run(adb, serial, *args, timeout):
            calls.append((args, timeout))
            if args[0] == "shell":
                return subprocess.CompletedProcess(args, 0, "package:/data/slow.apk\npackage:/data/last.apk\n", "")
            Path(args[-1]).write_bytes(b"apk")
            if args[1] == "/data/slow.apk":
                raise subprocess.TimeoutExpired(args, timeout, stderr=b"timeout detail\n")
            return subprocess.CompletedProcess(args, 0, "", "")

        with mock.patch.object(sys, "argv", [str(HELPER), "--adb", str(self.adb), "--serial", "fake-serial", "com.example.app", str(self.output)]), mock.patch.object(helper, "run_adb", side_effect=fake_run), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(helper.main(), 1)
        self.assertEqual([timeout for _, timeout in calls], [20, 600, 600])
        self.assertEqual(self.manifest()["coverage"], "partial")
        self.assertEqual(self.manifest()["artifacts"][0]["remote_path"], "/data/last.apk")
        self.assertIn("timeout detail\n", self.manifest()["failures"][0]["error"])
        self.assertFalse(list(self.output.glob("*.partial")))

    def test_run_adb_timeout_reaps_child_and_retains_stderr(self):
        helper = self.load_helper()
        process = mock.MagicMock()
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(["adb"], 600), ("progress", "timeout stderr\n"),
        ]
        process.__enter__.return_value = process
        with mock.patch.object(helper.subprocess, "Popen", return_value=process):
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                helper.run_adb("adb", "fake-serial", "pull", "/data/base.apk", "local", timeout=600)
        self.assertEqual(process.method_calls[:3], [
            mock.call.communicate(timeout=600), mock.call.kill(), mock.call.communicate(),
        ])
        self.assertEqual(raised.exception.stderr, "timeout stderr\n")

    def test_manifest_write_failure_returns_two(self):
        helper = self.load_helper()

        def fake_adb(adb, serial, *args, timeout):
            if args[0] == "shell":
                return subprocess.CompletedProcess([], 0, "package:/data/base.apk\n", "")
            Path(args[-1]).write_bytes(b"apk")
            return subprocess.CompletedProcess([], 0, "", "")

        with mock.patch.object(sys, "argv", [str(HELPER), "--adb", str(self.adb), "--serial", "fake-serial", "com.example.app", str(self.output)]), mock.patch.object(helper, "run_adb", side_effect=fake_adb), mock.patch.object(Path, "replace", side_effect=OSError("atomic replace failed")), contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(helper.main(), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("cannot write manifest", stderr.getvalue())
        self.assertFalse((self.output / "manifest.json").exists())
        self.assertFalse((self.output / ".manifest.json.tmp").exists())
        self.assertEqual((self.output / "1-base.apk").read_bytes(), b"apk")

    def test_signal_during_interrupted_manifest_commit_does_not_abort(self):
        helper = self.load_helper()
        write_text = Path.write_text
        replace = Path.replace

        def write_with_signal(path, text, *args, **kwargs):
            signal.raise_signal(signal.SIGTERM)
            return write_text(path, text, *args, **kwargs)

        with mock.patch.object(sys, "argv", [str(HELPER), "--adb", str(self.adb), "--serial", "fake-serial", "com.example.app", str(self.output)]), mock.patch.object(helper, "run_adb", side_effect=KeyboardInterrupt), mock.patch.object(Path, "write_text", autospec=True, side_effect=write_with_signal), mock.patch.object(Path, "replace", autospec=True, side_effect=replace) as commit, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(helper.main(), 2)
        commit.assert_called_once()
        self.assertEqual(self.manifest()["coverage"], "none")
        self.assertIn("interrupted", self.manifest()["failures"][0]["error"])

    def test_first_sigint_during_completed_manifest_commit_does_not_abort(self):
        helper = self.load_helper()
        write_text = Path.write_text
        replace = Path.replace
        previous = [signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)]

        def fake_adb(adb, serial, *args, timeout):
            if args[0] == "shell":
                return subprocess.CompletedProcess([], 0, "package:/data/base.apk\n", "")
            Path(args[-1]).write_bytes(b"apk")
            return subprocess.CompletedProcess([], 0, "", "")

        def write_with_signal(path, text, *args, **kwargs):
            signal.raise_signal(signal.SIGINT)
            return write_text(path, text, *args, **kwargs)

        with mock.patch.object(sys, "argv", [str(HELPER), "--adb", str(self.adb), "--serial", "fake-serial", "com.example.app", str(self.output)]), mock.patch.object(helper, "run_adb", side_effect=fake_adb), mock.patch.object(Path, "write_text", autospec=True, side_effect=write_with_signal), mock.patch.object(Path, "replace", autospec=True, side_effect=replace) as commit, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(helper.main(), 0)
        commit.assert_called_once()
        self.assertEqual(self.manifest()["coverage"], "complete")
        self.assertEqual([signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)], previous)

    def test_repeated_signals_do_not_interrupt_child_reaping(self):
        helper = self.load_helper()
        process = mock.MagicMock()
        process.__enter__.return_value = process
        calls = []

        def communicate(timeout=None):
            calls.append(timeout)
            if timeout is not None:
                signal.raise_signal(signal.SIGTERM)
            signal.raise_signal(signal.SIGINT)
            return "", ""

        process.communicate.side_effect = communicate
        process.kill.side_effect = lambda: signal.raise_signal(signal.SIGTERM)
        with mock.patch.object(sys, "argv", [str(HELPER), "--adb", str(self.adb), "--serial", "fake-serial", "com.example.app", str(self.output)]), mock.patch.object(helper.subprocess, "Popen", return_value=process), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(helper.main(), 2)
        self.assertEqual(calls, [20, None])
        self.assertEqual(process.method_calls[:3], [
            mock.call.communicate(timeout=20), mock.call.kill(), mock.call.communicate(),
        ])
        self.assertEqual(self.manifest()["failures"][0]["error"], "APK extraction interrupted (SIGTERM)")


if __name__ == "__main__":
    unittest.main()
