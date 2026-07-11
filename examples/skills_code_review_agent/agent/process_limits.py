# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Fail-closed subprocess supervision with bounded output capture."""

from __future__ import annotations

import base64
import ctypes
import json
import math
import os
import signal
import stat
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from typing import Mapping
from typing import Sequence

_READ_CHUNK_BYTES = 64 * 1024
_POLL_SECONDS = 0.01
_OUTPUT_POLL_SECONDS = 0.02
_TERMINATION_GRACE_SECONDS = 2.0
_READER_GRACE_SECONDS = 2.0


@dataclass(frozen=True)
class CappedProcessResult:
    """Public, bounded result returned by :func:`run_capped_process`."""

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    failure_kind: str
    termination_reason: str
    termination_confirmed: bool
    execution_started: bool
    stdout_truncated: bool
    stderr_truncated: bool
    output_truncated: bool
    stdout_bytes_observed: int
    stderr_bytes_observed: int
    output_bytes_observed: int


class _BoundedCapture:
    """Thread-safe capture that never retains more than its byte budget."""

    def __init__(self, *, limit_bytes: int) -> None:
        if type(limit_bytes) is not int or limit_bytes < 0:
            raise ValueError("capture byte limit must be a non-negative integer")
        self.limit_bytes = limit_bytes
        self.overflowed = threading.Event()
        self.failed = threading.Event()
        self._lock = threading.Lock()
        self._retained = bytearray()
        self._observed_bytes = 0

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        with self._lock:
            self._observed_bytes += len(chunk)
            remaining = max(0, self.limit_bytes - len(self._retained))
            if remaining:
                self._retained.extend(chunk[:remaining])
            if self._observed_bytes > self.limit_bytes:
                self.overflowed.set()

    @property
    def observed_bytes(self) -> int:
        with self._lock:
            return self._observed_bytes

    def retained_bytes(self) -> bytes:
        with self._lock:
            return bytes(self._retained)


@dataclass
class _ProcessTree:
    """A supervised process tree whose identity survives root-process exit."""

    process: subprocess.Popen[bytes]
    posix_pgid: int | None = None
    windows_job: "_WindowsJob | None" = None


@dataclass
class _StdinWriter:
    """A bounded-lifetime stdin delivery thread with explicit failure state."""

    thread: threading.Thread
    failed: threading.Event


class _JobBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JobExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _JobBasicAccountingInformation(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong),
        ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


class _WindowsJob:
    """Minimal Windows Job Object wrapper with kill-on-close semantics."""

    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9

    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError("Windows Job Objects are only available on Windows")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        self._kernel32 = kernel32
        self._handle = kernel32.CreateJobObjectW(None, None)
        if not self._handle:
            self._raise_last_error("CreateJobObjectW")
        information = _JobExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = self._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
                self._handle,
                self._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(information),
                ctypes.sizeof(information),
        ):
            try:
                self._raise_last_error("SetInformationJobObject")
            finally:
                self.close()

    @staticmethod
    def _raise_last_error(operation: str) -> None:
        error = ctypes.get_last_error()
        raise OSError(error, f"{operation} failed: {ctypes.FormatError(error)}")

    def assign(self, process: subprocess.Popen[bytes]) -> None:
        if self._handle is None:
            raise RuntimeError("Windows Job Object is closed")
        process_handle = wintypes.HANDLE(int(process._handle))  # type: ignore[attr-defined]
        if not self._kernel32.AssignProcessToJobObject(self._handle, process_handle):
            self._raise_last_error("AssignProcessToJobObject")

    def terminate(self, *, exit_code: int) -> None:
        if self._handle is None:
            raise RuntimeError("Windows Job Object is closed")
        if not self._kernel32.TerminateJobObject(self._handle, exit_code):
            self._raise_last_error("TerminateJobObject")

    def active_process_count(self) -> int:
        if self._handle is None:
            raise RuntimeError("Windows Job Object is closed")
        information = _JobBasicAccountingInformation()
        returned = wintypes.DWORD()
        if not self._kernel32.QueryInformationJobObject(
                self._handle,
                self._JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                ctypes.byref(information),
                ctypes.sizeof(information),
                ctypes.byref(returned),
        ):
            self._raise_last_error("QueryInformationJobObject")
        return int(information.ActiveProcesses)

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            self._kernel32.CloseHandle(handle)


_WINDOWS_SUPERVISOR = r"""
import base64
import json
import subprocess
import sys

try:
    payload = json.loads(sys.stdin.buffer.readline())
    argv = payload["argv"]
    cwd = payload["cwd"]
    env = payload["env"]
    stdin_data = base64.b64decode(payload["stdin"])
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=sys.stdout.buffer,
        stderr=sys.stderr.buffer,
    )
    process.communicate(stdin_data)
    status = process.returncode
except BaseException as exc:
    sys.stderr.write("sandbox target launch failed: " + type(exc).__name__ + "\n")
    status = 125
raise SystemExit(status)
"""


def _supervisor_payload(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    stdin_bytes: bytes,
) -> bytes:
    return json.dumps(
        {
            "argv": list(argv),
            "cwd": str(cwd),
            "env": dict(env),
            "stdin": base64.b64encode(stdin_bytes).decode("ascii"),
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"


def _spawn_process_tree(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    stdin_bytes: bytes,
) -> tuple[_ProcessTree, bytes]:
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    # Build the gate payload before spawning.  Serialization failure is a
    # pre-start error and must not leave a supervisor blocked on stdin.
    payload = _supervisor_payload(argv, cwd=cwd, env=env, stdin_bytes=stdin_bytes)

    process = subprocess.Popen(
        [sys.executable, "-I", "-S", "-c", _WINDOWS_SUPERVISOR],
        cwd=str(cwd),
        env=os.environ.copy(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creation_flags,
        start_new_session=os.name != "nt",
    )
    if os.name != "nt":
        return _ProcessTree(process=process, posix_pgid=process.pid), payload

    job: _WindowsJob | None = None
    try:
        job = _WindowsJob()
        job.assign(process)
        return _ProcessTree(process=process, windows_job=job), payload
    except BaseException:
        if job is not None:
            try:
                job.terminate(exit_code=1)
            except OSError:
                pass
            job.close()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        raise


def _start_stdin_writer(process: subprocess.Popen[bytes], payload: bytes) -> _StdinWriter | None:
    if process.stdin is None:
        return None
    failed = threading.Event()

    def write() -> None:
        try:
            if payload:
                process.stdin.write(payload)
                process.stdin.flush()
        except (BrokenPipeError, OSError):
            failed.set()
        finally:
            try:
                process.stdin.close()
            except OSError:
                failed.set()

    thread = threading.Thread(target=write, name="sandbox-stdin-writer", daemon=True)
    thread.start()
    return _StdinWriter(thread=thread, failed=failed)


def _start_reader(stream: BinaryIO, capture: _BoundedCapture, *, name: str) -> threading.Thread:

    def read() -> None:
        try:
            while True:
                chunk = stream.read(_READ_CHUNK_BYTES)
                if not chunk:
                    return
                capture.feed(chunk)
        except (OSError, ValueError):
            capture.failed.set()
            return

    thread = threading.Thread(target=read, name=name, daemon=True)
    thread.start()
    return thread


def _scan_output_bytes(output_paths: Sequence[Path]) -> int:
    files: dict[str, Path] = {}

    def remember(candidate: Path) -> None:
        try:
            metadata = candidate.stat()
            if stat.S_ISREG(metadata.st_mode):
                files[str(candidate.resolve(strict=False))] = candidate
        except FileNotFoundError:
            return

    for raw_path in output_paths:
        path = Path(raw_path)
        try:
            metadata = path.stat()
            if stat.S_ISREG(metadata.st_mode):
                remember(path)
            elif stat.S_ISDIR(metadata.st_mode):
                for candidate in path.rglob("*"):
                    remember(candidate)
        except FileNotFoundError:
            continue
    total = 0
    for path in files.values():
        try:
            total += path.stat().st_size
        except FileNotFoundError:
            continue
    return total


class _OutputWatch:

    def __init__(self, output_paths: Sequence[Path], *, limit_bytes: int) -> None:
        self.output_paths = tuple(Path(path) for path in output_paths)
        self.limit_bytes = limit_bytes
        self.overflowed = threading.Event()
        self.failed = threading.Event()
        self._stopped = threading.Event()
        self._lock = threading.Lock()
        self._max_observed = 0
        self._thread = threading.Thread(target=self._watch, name="sandbox-output-watch", daemon=True)
        self._started = False

    def start(self) -> None:
        self._started = True
        self._thread.start()

    def _observe(self) -> int:
        observed = _scan_output_bytes(self.output_paths)
        with self._lock:
            self._max_observed = max(self._max_observed, observed)
        if observed > self.limit_bytes:
            self.overflowed.set()
        return observed

    def _watch(self) -> None:
        try:
            while not self._stopped.is_set():
                self._observe()
                self._stopped.wait(_OUTPUT_POLL_SECONDS)
        except Exception:  # pragma: no cover - defensive against platform I/O failures
            self.failed.set()

    def final_observation(self) -> int:
        return self._observe()

    @property
    def max_observed(self) -> int:
        with self._lock:
            return self._max_observed

    def stop(self) -> None:
        self._stopped.set()
        if not self._started:
            return
        self._thread.join(timeout=1)
        if self._thread.is_alive():
            raise RuntimeError("output watchdog did not stop")


def _tree_active(tree: _ProcessTree) -> bool:
    if os.name == "nt":
        if tree.windows_job is None:
            raise RuntimeError("Windows execution is missing its Job Object")
        return tree.windows_job.active_process_count() > 0
    if tree.posix_pgid is None:
        raise RuntimeError("POSIX execution is missing its process group")
    try:
        os.killpg(tree.posix_pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _kill_process_tree(tree: _ProcessTree) -> None:
    """Kill the saved process tree even if its original leader has exited."""
    if os.name == "nt":
        if tree.windows_job is None:
            raise RuntimeError("Windows execution is missing its Job Object")
        tree.windows_job.terminate(exit_code=1)
    else:
        if tree.posix_pgid is None:
            raise RuntimeError("POSIX execution is missing its process group")
        try:
            os.killpg(tree.posix_pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if tree.process.poll() is None:
        tree.process.wait(timeout=5)


def _wait_for_empty_tree(tree: _ProcessTree, *, timeout: float = _TERMINATION_GRACE_SECONDS) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        tree.process.poll()
        try:
            if not _tree_active(tree):
                return True
        except OSError:
            return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(_POLL_SECONDS)


def _terminate_and_confirm(tree: _ProcessTree) -> bool:
    try:
        _kill_process_tree(tree)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return False
    return _wait_for_empty_tree(tree)


def _close_reader_stream(stream: BinaryIO | None) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except OSError:
        pass


def _join_reader(thread: threading.Thread, stream: BinaryIO | None, tree: _ProcessTree) -> bool:
    thread.join(timeout=_READER_GRACE_SECONDS)
    if not thread.is_alive():
        return True
    _terminate_and_confirm(tree)
    _close_reader_stream(stream)
    thread.join(timeout=_READER_GRACE_SECONDS)
    return not thread.is_alive()


def _decode_capture(capture: _BoundedCapture) -> str:
    raw = capture.retained_bytes()
    text = raw.decode("utf-8", errors="replace")
    encoded = text.encode("utf-8")[:capture.limit_bytes]
    return encoded.decode("utf-8", errors="ignore")


def _finalize_capped_result(
    *,
    tree: _ProcessTree,
    stdout_capture: _BoundedCapture,
    stderr_capture: _BoundedCapture,
    stdout_reader: threading.Thread,
    stderr_reader: threading.Thread,
    stdin_writer: _StdinWriter | None,
    output_watch: _OutputWatch,
    timed_out: bool,
    termination_reason: str,
) -> CappedProcessResult:
    """Close final-poll and descendant races before publishing a result."""
    orchestration_failed = False
    try:
        active = _tree_active(tree)
    except (OSError, RuntimeError):
        active = True
        orchestration_failed = True
    # Windows Job accounting can lag very briefly behind a reaped clean
    # supervisor.  Give a naturally exiting tree a bounded drain window before
    # treating remaining members as escaped descendants.
    if active and tree.process.poll() is not None and not orchestration_failed:
        active = not _wait_for_empty_tree(tree, timeout=0.1)
    if active:
        if not termination_reason:
            termination_reason = "orchestration_error"
        if not _terminate_and_confirm(tree):
            orchestration_failed = True
    termination_confirmed = _wait_for_empty_tree(tree, timeout=0.1)

    try:
        output_watch.stop()
    except RuntimeError:
        orchestration_failed = True
    readers_finished = _join_reader(stdout_reader, tree.process.stdout, tree)
    readers_finished = _join_reader(stderr_reader, tree.process.stderr, tree) and readers_finished
    if stdin_writer is not None:
        stdin_writer.thread.join(timeout=_READER_GRACE_SECONDS)
        readers_finished = readers_finished and not stdin_writer.thread.is_alive()
    if not readers_finished:
        orchestration_failed = True
        termination_reason = "orchestration_error"
        termination_confirmed = _terminate_and_confirm(tree)

    stdin_failed = stdin_writer is not None and stdin_writer.failed.is_set()
    if (stdout_capture.failed.is_set() or stderr_capture.failed.is_set() or output_watch.failed.is_set()
            or stdin_failed):
        orchestration_failed = True
        termination_reason = "orchestration_error"
        termination_confirmed = _terminate_and_confirm(tree)

    final_output_bytes = output_watch.final_observation()
    output_bytes_observed = max(final_output_bytes, output_watch.max_observed)
    output_breached = output_bytes_observed > output_watch.limit_bytes
    stream_breached = stdout_capture.overflowed.is_set() or stderr_capture.overflowed.is_set()
    if stream_breached or output_breached:
        termination_reason = "output_limit_exceeded"
        termination_confirmed = _terminate_and_confirm(tree)
        if not termination_confirmed:
            orchestration_failed = True

    root_exit_code = tree.process.poll()
    if root_exit_code is None:
        termination_confirmed = _terminate_and_confirm(tree)
        root_exit_code = tree.process.poll()
        orchestration_failed = True
    if root_exit_code is None:
        root_exit_code = -1

    if orchestration_failed or not termination_confirmed:
        failure_kind = "orchestration_error"
        termination_reason = "orchestration_error"
    elif stream_breached or output_breached:
        failure_kind = "output_limit_exceeded"
    elif timed_out:
        failure_kind = "execution_timeout"
    elif termination_reason == "orchestration_error":
        failure_kind = "orchestration_error"
    elif root_exit_code != 0:
        failure_kind = "execution_nonzero"
    else:
        failure_kind = ""

    public_exit_code = int(root_exit_code)
    if failure_kind and public_exit_code == 0:
        public_exit_code = 1
    return CappedProcessResult(
        exit_code=public_exit_code,
        stdout=_decode_capture(stdout_capture),
        stderr=_decode_capture(stderr_capture),
        timed_out=timed_out,
        failure_kind=failure_kind,
        termination_reason=termination_reason,
        termination_confirmed=termination_confirmed,
        execution_started=True,
        stdout_truncated=stdout_capture.overflowed.is_set(),
        stderr_truncated=stderr_capture.overflowed.is_set(),
        output_truncated=output_breached,
        stdout_bytes_observed=stdout_capture.observed_bytes,
        stderr_bytes_observed=stderr_capture.observed_bytes,
        output_bytes_observed=output_bytes_observed,
    )


def _orchestration_failure_result(
    *,
    tree: _ProcessTree,
    stdout_capture: _BoundedCapture,
    stderr_capture: _BoundedCapture,
    stdout_reader: threading.Thread | None,
    stderr_reader: threading.Thread | None,
    stdin_writer: _StdinWriter | None,
    output_watch: _OutputWatch,
) -> CappedProcessResult:
    """Return a bounded audit row after an internal post-spawn failure."""
    confirmed = _terminate_and_confirm(tree)
    try:
        output_watch.stop()
    except RuntimeError:
        confirmed = False
    for thread, stream in (
        (stdout_reader, tree.process.stdout),
        (stderr_reader, tree.process.stderr),
    ):
        if thread is not None and not _join_reader(thread, stream, tree):
            confirmed = False
    if stdin_writer is not None:
        stdin_writer.thread.join(timeout=_READER_GRACE_SECONDS)
        confirmed = confirmed and not stdin_writer.thread.is_alive()
    try:
        output_observed = max(output_watch.max_observed, output_watch.final_observation())
    except Exception:  # pragma: no cover - defensive against platform I/O failures
        output_observed = output_watch.max_observed
    exit_code = tree.process.poll()
    return CappedProcessResult(
        exit_code=int(exit_code) if exit_code not in (None, 0) else 1,
        stdout=_decode_capture(stdout_capture),
        stderr=_decode_capture(stderr_capture),
        timed_out=False,
        failure_kind="orchestration_error",
        termination_reason="orchestration_error",
        termination_confirmed=confirmed,
        execution_started=True,
        stdout_truncated=stdout_capture.overflowed.is_set(),
        stderr_truncated=stderr_capture.overflowed.is_set(),
        output_truncated=output_observed > output_watch.limit_bytes,
        stdout_bytes_observed=stdout_capture.observed_bytes,
        stderr_bytes_observed=stderr_capture.observed_bytes,
        output_bytes_observed=output_observed,
    )


def run_capped_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
    stdout_limit_bytes: int,
    stderr_limit_bytes: int,
    output_paths: Sequence[Path],
    output_limit_bytes: int,
    stdin: str | bytes = b"",
) -> CappedProcessResult:
    """Execute ``argv`` while enforcing timeout and byte budgets live."""
    if not argv:
        raise ValueError("process argv must not be empty")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise ValueError("process timeout must be a finite non-negative number")
    if not math.isfinite(float(timeout_seconds)) or timeout_seconds < 0:
        raise ValueError("process timeout must be a finite non-negative number")
    for value in (stdout_limit_bytes, stderr_limit_bytes, output_limit_bytes):
        if type(value) is not int or value < 0:
            raise ValueError("process byte limits must be non-negative integers")
    stdin_bytes = stdin.encode("utf-8") if isinstance(stdin, str) else bytes(stdin)
    tree, release_payload = _spawn_process_tree(
        argv,
        cwd=Path(cwd),
        env=env,
        stdin_bytes=stdin_bytes,
    )
    if tree.process.stdout is None or tree.process.stderr is None:
        _terminate_and_confirm(tree)
        if tree.windows_job is not None:
            tree.windows_job.close()
        raise RuntimeError("sandbox process pipes were not created")

    stdout_capture = _BoundedCapture(limit_bytes=stdout_limit_bytes)
    stderr_capture = _BoundedCapture(limit_bytes=stderr_limit_bytes)
    stdout_reader: threading.Thread | None = None
    stderr_reader: threading.Thread | None = None
    stdin_writer: _StdinWriter | None = None
    output_watch = _OutputWatch(output_paths, limit_bytes=output_limit_bytes)
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    termination_reason = ""
    try:
        stdout_reader = _start_reader(tree.process.stdout, stdout_capture, name="sandbox-stdout-reader")
        stderr_reader = _start_reader(tree.process.stderr, stderr_capture, name="sandbox-stderr-reader")
        output_watch.start()
        if timeout_seconds == 0:
            timed_out = True
            termination_reason = "execution_timeout"
            _terminate_and_confirm(tree)
        else:
            stdin_writer = _start_stdin_writer(tree.process, release_payload)
        while tree.process.poll() is None:
            stdin_failed = stdin_writer is not None and stdin_writer.failed.is_set()
            if (stdout_capture.failed.is_set() or stderr_capture.failed.is_set() or output_watch.failed.is_set()
                    or stdin_failed):
                termination_reason = "orchestration_error"
                _terminate_and_confirm(tree)
                break
            if stdout_capture.overflowed.is_set() or stderr_capture.overflowed.is_set():
                termination_reason = "output_limit_exceeded"
                _terminate_and_confirm(tree)
                break
            if output_watch.overflowed.is_set():
                termination_reason = "output_limit_exceeded"
                _terminate_and_confirm(tree)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                termination_reason = "execution_timeout"
                _terminate_and_confirm(tree)
                break
            time.sleep(_POLL_SECONDS)
        return _finalize_capped_result(
            tree=tree,
            stdout_capture=stdout_capture,
            stderr_capture=stderr_capture,
            stdout_reader=stdout_reader,
            stderr_reader=stderr_reader,
            stdin_writer=stdin_writer,
            output_watch=output_watch,
            timed_out=timed_out,
            termination_reason=termination_reason,
        )
    except Exception:  # pylint: disable=broad-except
        return _orchestration_failure_result(
            tree=tree,
            stdout_capture=stdout_capture,
            stderr_capture=stderr_capture,
            stdout_reader=stdout_reader,
            stderr_reader=stderr_reader,
            stdin_writer=stdin_writer,
            output_watch=output_watch,
        )
    finally:
        try:
            if _tree_active(tree):
                _terminate_and_confirm(tree)
        except (OSError, RuntimeError):
            pass
        for stream in (tree.process.stdin, tree.process.stdout, tree.process.stderr):
            _close_reader_stream(stream)
        if tree.windows_job is not None:
            tree.windows_job.close()


__all__ = ["CappedProcessResult", "run_capped_process"]
