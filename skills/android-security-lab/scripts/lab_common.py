"""Small report and subprocess helpers for the lab's fixed commands."""

from datetime import datetime, timezone
import os
import platform
import selectors
import signal
import subprocess
import sys
import time


class OutputLimitError(subprocess.SubprocessError):
    def __init__(self, command, limit, stdout, stderr):
        super().__init__(f'command output exceeded {limit} bytes')
        self.stdout, self.stderr = stdout, stderr


def run_bounded(command, timeout, max_output_bytes=1024 * 1024, check_cancel=None):
    """Capture both pipes within one byte/deadline budget; reap owned children."""
    output = [bytearray(), bytearray()]
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    def decoded():
        return tuple(bytes(part).decode('utf-8', errors='replace') for part in output)

    try:
        with selectors.DefaultSelector() as selector:
            for index, pipe in enumerate((process.stdout, process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, index)
            while selector.get_map():
                if check_cancel is not None:
                    check_cancel()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout, *decoded())
                for key, _ in selector.select(min(remaining, .05)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    available = max_output_bytes - sum(map(len, output))
                    output[key.data].extend(chunk[:available])
                    if len(chunk) > available:
                        raise OutputLimitError(command, max_output_bytes, *decoded())
            while process.returncode is None:
                remaining = deadline - time.monotonic()
                try:
                    # EOF can precede reaping an already-exited leader. Observe
                    # completion before cancellation would signal its empty group.
                    process.wait(timeout=max(0, min(remaining, .05)))
                except subprocess.TimeoutExpired:
                    if check_cancel is not None:
                        check_cancel()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout, *decoded())
        return subprocess.CompletedProcess(command, process.returncode, *decoded())
    finally:
        # No poll() before pipe completion: an exited leader stays unreaped,
        # reserving the process-group identity while descendants hold pipes.
        primary = sys.exc_info()[1]
        cleanup_errors = []
        try:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    cleanup_errors.append(f'process group stop not confirmed: {error}')
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    except OSError as direct_error:
                        cleanup_errors.append(f'direct child stop not confirmed: {direct_error}')
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    cleanup_errors.append('direct child could not be reaped within 2 seconds')
        finally:
            process.stdout.close()
            process.stderr.close()
        if cleanup_errors:
            if primary is not None:
                primary.cleanup_errors = cleanup_errors
            else:
                raise RuntimeError('; '.join(cleanup_errors))


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def tool_identity(command, version_args=('--version',)):
    try:
        result = run_bounded(command + list(version_args), 2, 16384)
        version = (result.stdout or result.stderr).strip()[:1024] if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError) as error:
        identity = {'path': command[0], 'version': None}
        if getattr(error, 'cleanup_errors', None):
            identity['cleanup_errors'] = error.cleanup_errors
        return identity
    return {'path': command[0], 'version': version or None}


def report_metadata(operation):
    return {'schema_version': 1, 'operation': operation, 'started_at': utc_now(),
            'tools': {'python': {'path': sys.executable, 'version': platform.python_version()}}}


def error_code(error):
    if isinstance(error, OutputLimitError):
        return 'output_limit'
    if isinstance(error, subprocess.TimeoutExpired):
        return 'timeout'
    if isinstance(error, (KeyboardInterrupt, InterruptedError)):
        return 'interrupted'
    if isinstance(error, PermissionError):
        return 'access_denied'
    if isinstance(error, FileNotFoundError):
        return 'missing_dependency'
    if isinstance(error, OSError):
        return 'io_error'
    return 'command_failed'
