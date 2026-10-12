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


ERROR_LIMIT = 2048


def run_adb(adb, serial, *args, timeout):
    command = [adb, "-s", serial, *args]
    with subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            exc.output, exc.stderr = process.communicate()
            raise
        except KeyboardInterrupt:
            process.kill()
            process.communicate()
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


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
        "package": args.package, "serial": args.serial,
        "coverage": "none", "artifacts": [], "failures": [],
    }

    def fail(remote_path, error):
        message = str(error)
        if isinstance(error, subprocess.TimeoutExpired) and error.stderr:
            stderr = error.stderr
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            message += ": " + stderr
        manifest["failures"].append({
            "remote_path": remote_path, "error": message[:ERROR_LIMIT],
        })

    remote_path = None
    partial_path = None
    manifest_written = False
    interrupted_signal = None
    cleaning_up = False

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
            fail(None, "pm path failed (exit {}): {}".format(result.returncode, result.stderr))
        else:
            lines = result.stdout.split("\n")
            if lines[-1] == "":
                lines.pop()
            if not lines:
                fail(None, "pm path returned no APK paths")
            for index, line in enumerate(lines, 1):
                line = line.removesuffix("\r")
                value = line.removeprefix("package:")
                if not line.startswith("package:") or not valid_apk_path(value):
                    fail(value, "invalid pm path line: " + repr(line))
                else:
                    paths.append((index, value))

        for index, remote_path in paths:
            local_path = output_dir / "{}-{}".format(index, PurePosixPath(remote_path).name)
            partial_path = local_path.with_name(local_path.name + ".partial")
            try:
                result = run_adb(args.adb, args.serial, "pull", remote_path, str(partial_path), timeout=600)
                if result.returncode:
                    raise RuntimeError("adb pull failed (exit {}): {}".format(result.returncode, result.stderr))
                if partial_path.is_symlink() or not partial_path.is_file():
                    raise RuntimeError("adb pull did not produce a regular file")
                digest = hashlib.sha256()
                size = 0
                with partial_path.open("rb") as apk:
                    for chunk in iter(lambda: apk.read(1024 * 1024), b""):
                        digest.update(chunk)
                        size += len(chunk)
                partial_path.rename(local_path)
                manifest["artifacts"].append({
                    "remote_path": remote_path, "local_path": str(local_path),
                    "size_bytes": size, "sha256": digest.hexdigest(),
                })
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                fail(remote_path, exc)
            if partial_path.exists() or partial_path.is_symlink():
                partial_path.unlink()
            partial_path = None
            remote_path = None
    except KeyboardInterrupt:
        reason = "APK extraction interrupted"
        if interrupted_signal is not None:
            reason += " ({})".format(signal.Signals(interrupted_signal).name)
        fail(remote_path, reason)
    except (OSError, subprocess.SubprocessError) as exc:
        fail(remote_path, exc)
    finally:
        cleaning_up = True
        if partial_path is not None:
            try:
                partial_path.unlink(missing_ok=True)
            except OSError as exc:
                fail(remote_path, "cannot remove partial file: " + str(exc))
        if manifest["artifacts"]:
            manifest["coverage"] = "partial" if manifest["failures"] else "complete"
        manifest_temp = output_dir / ".manifest.json.tmp"
        try:
            manifest_temp.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
            )
            manifest_temp.replace(output_dir / "manifest.json")
            manifest_written = True
        except OSError as exc:
            print("error: cannot write manifest: " + str(exc), file=sys.stderr)
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
