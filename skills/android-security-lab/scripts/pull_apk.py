#!/usr/bin/env python3
"""Pull package APKs into a new directory and retain a manifest on failure."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys

from lab_common import error_code, report_metadata, run_bounded, tool_identity, utc_now


ERROR_LIMIT = 2048


def run_adb(adb, serial, *args, timeout):
    limit = 64 * 1024 if args[:3] == ("shell", "pm", "path") else 1024 * 1024
    return run_bounded([adb, "-s", serial, *args], timeout, limit)


def valid_apk_path(value):
    parts = value.split("/")
    return (
        value.startswith("/")
        and all(part and part not in (".", "..") for part in parts[1:])
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
        and PurePosixPath(value).name.endswith(".apk")
        and PurePosixPath(value).name != ".apk"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("package")
    parser.add_argument("output_dir", help="new directory; existing directories are refused")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9._]+", args.package):
        parser.error("invalid Android package name")

    output_dir = Path(args.output_dir)
    try:
        output_dir.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        print("error: cannot create output directory: " + str(exc), file=sys.stderr)
        return 2

    manifest = {
        **report_metadata("pull_apk"),
        "package": args.package, "serial": args.serial,
        "coverage": "none", "artifacts": [], "failures": [],
        "limitations": ["APK files only; application data is not included"],
    }

    def fail(remote_path, error, stage, code=None):
        message = str(error)
        stderr = getattr(error, "stderr", None)
        if stderr:
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            message += ": " + stderr
        manifest["failures"].append({
            "remote_path": remote_path, "stage": stage,
            "code": code or error_code(error), "error": message[:ERROR_LIMIT],
            "error_truncated": len(message) > ERROR_LIMIT,
        })
        if getattr(error, "cleanup_errors", None):
            manifest["failures"][-1]["cleanup_errors"] = error.cleanup_errors

    def cleanup_partial():
        nonlocal partial_path, stage
        if partial_path is not None:
            stage = "cleanup"
            try:
                partial_path.unlink(missing_ok=True)
            except OSError as exc:
                fail(remote_path, "cannot remove partial file: " + str(exc), "cleanup", "io_error")
            partial_path = None

    remote_path = None
    partial_path = None
    manifest_written = False
    interrupted_signal = None
    cleaning_up = False
    stage = "resolve_paths"

    def stop(signum, frame):
        nonlocal interrupted_signal
        if interrupted_signal is None:
            interrupted_signal = signum
            if not cleaning_up:
                raise KeyboardInterrupt

    previous_sigint = signal.signal(signal.SIGINT, stop)
    previous_sigterm = signal.signal(signal.SIGTERM, stop)
    try:
        result = run_adb(args.adb, args.serial, "shell", "pm", "path", args.package, timeout=20)
        paths = []
        if result.returncode:
            fail(None, "pm path failed (exit {}): {}".format(result.returncode, result.stderr), stage, "command_failed")
        else:
            lines = result.stdout.split("\n")
            if lines[-1] == "":
                lines.pop()
            if not lines:
                fail(None, "pm path returned no APK paths", stage, "empty_paths")
            for index, line in enumerate(lines, 1):
                line = line.removesuffix("\r")
                value = line.removeprefix("package:")
                if not line.startswith("package:") or not valid_apk_path(value):
                    fail(value, "invalid pm path line: " + repr(line), stage, "invalid_output")
                else:
                    paths.append((index, value))

        for index, remote_path in paths:
            local_path = output_dir / "{}-{}".format(index, PurePosixPath(remote_path).name)
            partial_path = local_path.with_name(local_path.name + ".partial")
            stage = "pull"
            try:
                result = run_adb(args.adb, args.serial, "pull", remote_path, str(partial_path), timeout=600)
                if result.returncode:
                    raise RuntimeError("adb pull failed (exit {}): {}".format(result.returncode, result.stderr))
                if partial_path.is_symlink() or not partial_path.is_file():
                    fail(remote_path, "adb pull did not produce a regular file", stage, "invalid_output")
                    cleanup_partial()
                    continue
                stage = "digest"
                digest = hashlib.sha256()
                size = 0
                with partial_path.open("rb") as apk:
                    for chunk in iter(lambda: apk.read(1024 * 1024), b""):
                        digest.update(chunk)
                        size += len(chunk)
                stage = "finalize"
                partial_path.rename(local_path)
                manifest["artifacts"].append({
                    "remote_path": remote_path, "local_path": str(local_path),
                    "relative_path": local_path.name,
                    "size_bytes": size, "sha256": digest.hexdigest(),
                })
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                fail(remote_path, exc, stage, "io_error" if isinstance(exc, OSError) else None)
            cleanup_partial()
            remote_path = None
    except KeyboardInterrupt as error:
        reason = "APK extraction interrupted"
        if interrupted_signal is not None:
            reason += " ({})".format(signal.Signals(interrupted_signal).name)
        fail(remote_path, reason, stage, "interrupted")
        if getattr(error, "cleanup_errors", None):
            manifest["failures"][-1]["cleanup_errors"] = error.cleanup_errors
    except (OSError, subprocess.SubprocessError) as exc:
        fail(remote_path, exc, stage)
    finally:
        cleaning_up = True
        cleanup_partial()
        if manifest["artifacts"]:
            manifest["coverage"] = "partial" if manifest["failures"] else "complete"
        try:
            manifest["tools"]["adb"] = tool_identity([args.adb], version_args=("version",))
        except (OSError, subprocess.SubprocessError, KeyboardInterrupt):
            manifest["tools"]["adb"] = {"path": args.adb, "version": None}
        manifest["finished_at"] = utc_now()
        manifest_temp = output_dir / ".manifest.json.tmp"
        try:
            manifest_temp.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
            )
            manifest_temp.replace(output_dir / "manifest.json")
            manifest_written = True
        except OSError as exc:
            fail(None, exc, "write_manifest", "io_error")
            failure = manifest["failures"][-1]
            print("error: cannot write manifest [stage=write_manifest code=io_error]: " +
                  failure["error"], file=sys.stderr)
            try:
                manifest_temp.unlink(missing_ok=True)
            except OSError:
                pass
        finally:
            signal.signal(signal.SIGINT, previous_sigint)
            signal.signal(signal.SIGTERM, previous_sigterm)

    if not manifest_written:
        return 2
    if manifest["coverage"] == "complete":
        print(args.output_dir)
        return 0
    print("error: APK extraction {}; see {}".format(
        manifest["coverage"], output_dir / "manifest.json",
    ), file=sys.stderr)
    return 1 if manifest["artifacts"] else 2


if __name__ == "__main__":
    sys.exit(main())
