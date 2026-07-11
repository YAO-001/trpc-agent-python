# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Execution-time limits for the local code-review sandbox."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import agent.process_limits as process_limits
from agent.agent_factory import prepare_execution_plan
from agent.filter_policy import ReviewExecutionPolicy
from agent.input_resolver import EXAMPLE_DIR
from agent.models import SandboxRun
from agent.process_limits import _BoundedCapture
from agent.process_limits import _OutputWatch
from agent.process_limits import _StdinWriter
from agent.process_limits import _finalize_capped_result
from agent.process_limits import _scan_output_bytes
from agent.redaction_boundary import RedactionBoundary
from agent.sandbox_runner import SandboxRunner
from agent.sandbox_runner import _read_output_file
from agent.sandbox_runner import _run_capped_process
from agent.sandbox_runner import _sanitize_stream
from agent.sandbox_runner import _validated_returned_run
from agent.secret_redactor import SecretRedactor


def _pid_exists(pid: int) -> bool:
    if os.name == "nt":
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
            check=False,
            capture_output=True,
            text=True,
        )
        return str(pid) in result.stdout
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _run(
    tmp_path: Path,
    code: str,
    *,
    timeout_seconds: float = 5,
    output_paths: list[Path] | None = None,
):
    return _run_capped_process(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env={},
        timeout_seconds=timeout_seconds,
        stdout_limit_bytes=4096,
        stderr_limit_bytes=4096,
        output_paths=output_paths or [],
        output_limit_bytes=4096,
    )


def test_bounded_capture_retains_only_budget_and_counts_every_observed_byte():
    capture = _BoundedCapture(limit_bytes=4)

    capture.feed(b"abc")
    capture.feed(b"def")

    assert capture.retained_bytes() == b"abcd"
    assert capture.observed_bytes == 6
    assert capture.overflowed.is_set()


def _finished_thread() -> threading.Thread:
    thread = threading.Thread(target=lambda: None)
    thread.start()
    thread.join()
    return thread


def _finalize_fixture(tmp_path: Path, *, output_limit: int = 4):
    process = SimpleNamespace(stdout=None, stderr=None, poll=lambda: 0)
    tree = SimpleNamespace(process=process, posix_pgid=1, windows_job=None)
    return {
        "tree": tree,
        "stdout_capture": _BoundedCapture(limit_bytes=4),
        "stderr_capture": _BoundedCapture(limit_bytes=4),
        "stdout_reader": _finished_thread(),
        "stderr_reader": _finished_thread(),
        "stdin_writer": None,
        "output_watch": _OutputWatch([], limit_bytes=output_limit),
        "timed_out": False,
        "termination_reason": "",
    }


def test_finalizer_promotes_late_capture_overflow(monkeypatch, tmp_path):
    fixture = _finalize_fixture(tmp_path)
    fixture["stdout_capture"].feed(b"abcde")
    terminated = []
    monkeypatch.setattr(process_limits, "_tree_active", lambda tree: False)
    monkeypatch.setattr(process_limits, "_wait_for_empty_tree", lambda tree, timeout: True)
    monkeypatch.setattr(
        process_limits,
        "_terminate_and_confirm",
        lambda tree: terminated.append(tree) or True,
    )

    result = _finalize_capped_result(**fixture)

    assert result.failure_kind == "output_limit_exceeded"
    assert result.exit_code != 0
    assert terminated == [fixture["tree"]]


def test_finalizer_promotes_final_artifact_scan(monkeypatch, tmp_path):
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"abcde")
    fixture = _finalize_fixture(tmp_path)
    fixture["output_watch"] = _OutputWatch([artifact], limit_bytes=4)
    monkeypatch.setattr(process_limits, "_tree_active", lambda tree: False)
    monkeypatch.setattr(process_limits, "_wait_for_empty_tree", lambda tree, timeout: True)
    monkeypatch.setattr(process_limits, "_terminate_and_confirm", lambda tree: True)

    result = _finalize_capped_result(**fixture)

    assert result.failure_kind == "output_limit_exceeded"
    assert result.output_bytes_observed == 5


def test_finalizer_kills_descendant_before_joining_readers(monkeypatch, tmp_path):
    fixture = _finalize_fixture(tmp_path)
    waits = iter([False, True])
    terminated = []
    monkeypatch.setattr(process_limits, "_tree_active", lambda tree: True)
    monkeypatch.setattr(process_limits, "_wait_for_empty_tree", lambda tree, timeout: next(waits))
    monkeypatch.setattr(
        process_limits,
        "_terminate_and_confirm",
        lambda tree: terminated.append(tree) or True,
    )

    result = _finalize_capped_result(**fixture)

    assert result.failure_kind == "orchestration_error"
    assert result.termination_confirmed is True
    assert terminated == [fixture["tree"]]


def test_finalizer_output_limit_wins_timeout_race(monkeypatch, tmp_path):
    fixture = _finalize_fixture(tmp_path)
    fixture["stdout_capture"].feed(b"abcde")
    fixture["timed_out"] = True
    fixture["termination_reason"] = "execution_timeout"
    monkeypatch.setattr(process_limits, "_tree_active", lambda tree: False)
    monkeypatch.setattr(process_limits, "_wait_for_empty_tree", lambda tree, timeout: True)
    monkeypatch.setattr(process_limits, "_terminate_and_confirm", lambda tree: True)

    result = _finalize_capped_result(**fixture)

    assert result.failure_kind == "output_limit_exceeded"
    assert result.termination_reason == "output_limit_exceeded"


def test_finalizer_failed_confirmation_is_orchestration_error(monkeypatch, tmp_path):
    fixture = _finalize_fixture(tmp_path)
    fixture["stdout_capture"].feed(b"abcde")
    monkeypatch.setattr(process_limits, "_tree_active", lambda tree: False)
    monkeypatch.setattr(process_limits, "_wait_for_empty_tree", lambda tree, timeout: True)
    monkeypatch.setattr(process_limits, "_terminate_and_confirm", lambda tree: False)

    result = _finalize_capped_result(**fixture)

    assert result.failure_kind == "orchestration_error"
    assert result.termination_reason == "orchestration_error"
    assert result.termination_confirmed is False


def test_finalizer_fails_closed_when_stdin_delivery_fails(monkeypatch, tmp_path):
    fixture = _finalize_fixture(tmp_path)
    writer_failed = threading.Event()
    writer_failed.set()
    fixture["stdin_writer"] = _StdinWriter(
        thread=_finished_thread(),
        failed=writer_failed,
    )
    monkeypatch.setattr(process_limits, "_tree_active", lambda tree: False)
    monkeypatch.setattr(process_limits, "_wait_for_empty_tree", lambda tree, timeout: True)
    monkeypatch.setattr(process_limits, "_terminate_and_confirm", lambda tree: True)

    result = _finalize_capped_result(**fixture)

    assert result.failure_kind == "orchestration_error"
    assert result.termination_reason == "orchestration_error"
    assert result.termination_confirmed is True


def test_output_scan_propagates_real_io_failures(monkeypatch, tmp_path):
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"data")
    real_stat = Path.stat

    def denied(path, *args, **kwargs):
        if path == artifact:
            raise PermissionError("denied")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", denied)

    with pytest.raises(PermissionError, match="denied"):
        _scan_output_bytes([artifact])


def test_output_watch_io_failure_terminates_process_fail_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(
        process_limits,
        "_scan_output_bytes",
        lambda paths: (_ for _ in ()).throw(PermissionError("denied")),
    )
    started = time.monotonic()

    result = _run(tmp_path, "import time;time.sleep(30)")

    assert time.monotonic() - started < 4
    assert result.failure_kind == "orchestration_error"
    assert result.termination_reason == "orchestration_error"
    assert result.termination_confirmed is True


def test_stdin_delivery_failure_terminates_process_fail_closed(monkeypatch, tmp_path):

    def failed_writer(process, payload):
        del process, payload
        failed = threading.Event()
        failed.set()
        return _StdinWriter(thread=_finished_thread(), failed=failed)

    monkeypatch.setattr(process_limits, "_start_stdin_writer", failed_writer)
    started = time.monotonic()

    result = _run(tmp_path, "import time;time.sleep(30)")

    assert time.monotonic() - started < 4
    assert result.failure_kind == "orchestration_error"
    assert result.termination_reason == "orchestration_error"
    assert result.termination_confirmed is True


def test_stderr_limit_is_enforced_while_process_is_running(tmp_path):
    marker = tmp_path / "stderr-late.txt"
    code = ("import pathlib,sys,time;"
            "sys.stderr.buffer.write(b'x' * 200000);sys.stderr.flush();"
            "time.sleep(1);"
            f"pathlib.Path({str(marker)!r}).write_text('alive')")

    result = _run(tmp_path, code)

    time.sleep(1.2)
    assert result.failure_kind == "output_limit_exceeded"
    assert result.stderr_truncated is True
    assert result.stderr_bytes_observed > 4096
    assert len(result.stderr.encode("utf-8")) <= 4096
    assert not marker.exists()


def test_clean_process_reports_execution_and_observed_counts(tmp_path):
    result = _run(tmp_path, "import sys;sys.stdout.write('ok')")

    assert result.exit_code == 0
    assert result.failure_kind == ""
    assert result.execution_started is True
    assert result.stdout == "ok"
    assert result.stdout_bytes_observed == 2
    assert result.termination_confirmed is True


def test_zero_timeout_starts_then_terminates_process(tmp_path):
    marker = tmp_path / "zero-timeout.txt"
    code = f"import pathlib;pathlib.Path({str(marker)!r}).write_text('late')"

    result = _run(tmp_path, code, timeout_seconds=0)

    assert result.execution_started is True
    assert result.timed_out is True
    assert result.failure_kind == "execution_timeout"
    assert result.termination_confirmed is True
    assert not marker.exists()


@pytest.mark.parametrize("timeout", [True, -1, float("nan"), float("inf")])
def test_invalid_timeout_is_rejected_before_process_start(tmp_path, timeout):
    with pytest.raises(ValueError, match="timeout"):
        _run(tmp_path, "pass", timeout_seconds=timeout)


@pytest.mark.parametrize("limit", [True, -1])
def test_invalid_byte_limit_is_rejected_before_process_start(tmp_path, limit):
    with pytest.raises(ValueError, match="byte limits"):
        _run_capped_process(
            [sys.executable, "-c", "pass"],
            cwd=tmp_path,
            env={},
            timeout_seconds=1,
            stdout_limit_bytes=limit,
            stderr_limit_bytes=4096,
            output_paths=[],
            output_limit_bytes=4096,
        )


def _overflow_run(request, *, artifact: str = "{}") -> SandboxRun:
    return SandboxRun(
        run_id="sandbox-limit",
        task_id=request.task_id,
        request_id=request.request_id,
        runtime=request.runtime,
        command=list(request.command_argv),
        exit_code=1,
        stdout="x" * 4096,
        output_files={request.output_spec.globs[0]: artifact},
        stdout_truncated=True,
        termination_reason="output_limit_exceeded",
        termination_confirmed=True,
        execution_started=True,
        stdout_bytes_observed=200000,
        output_bytes_observed=len(artifact.encode("utf-8")),
        failure_kind="output_limit_exceeded",
    )


def test_returned_run_preserves_evidence_backed_output_limit_failure():
    review_input = {"task_id": "task-limit-return", "fixture_names": []}
    with prepare_execution_plan(
            task_id="task-limit-return",
            runtime="local",
            review_input=review_input,
            redactor=SecretRedactor(),
    ) as plan:
        request = plan.requests[0]
        safe = _validated_returned_run(
            _overflow_run(request),
            request,
            boundary=SandboxRunner(
                example_dir=EXAMPLE_DIR,
                policy=ReviewExecutionPolicy(dry_run=True),
                redactor=SecretRedactor(),
            ).boundary,
        )

    assert safe.failure_kind == "output_limit_exceeded"
    assert safe.termination_reason == "output_limit_exceeded"
    assert safe.execution_started is True


def test_clean_returned_run_clears_stale_failure_kind():
    review_input = {"task_id": "task-clean-return", "fixture_names": []}
    with prepare_execution_plan(
            task_id="task-clean-return",
            runtime="local",
            review_input=review_input,
            redactor=SecretRedactor(),
    ) as plan:
        request = plan.requests[0]
        returned = SandboxRun(
            run_id="sandbox-clean",
            task_id=request.task_id,
            request_id=request.request_id,
            runtime=request.runtime,
            command=list(request.command_argv),
            exit_code=0,
            execution_started=True,
            termination_confirmed=True,
            failure_kind="output_limit_exceeded",
        )
        safe = _validated_returned_run(
            returned,
            request,
            boundary=SandboxRunner(
                example_dir=EXAMPLE_DIR,
                policy=ReviewExecutionPolicy(dry_run=True),
                redactor=SecretRedactor(),
            ).boundary,
        )

    assert safe.failure_kind == ""
    assert safe.termination_reason == ""


@pytest.mark.parametrize(
    ("run_updates", "expected_failure"),
    [
        ({}, "artifact_invalid"),
        ({
            "exit_code": 2,
            "failure_kind": "stale"
        }, "execution_nonzero"),
        (
            {
                "exit_code": 1,
                "timed_out": True,
                "termination_reason": "execution_timeout",
                "failure_kind": "artifact_invalid",
            },
            "execution_timeout",
        ),
        (
            {
                "exit_code": 1,
                "termination_reason": "output_limit_exceeded",
                "stdout_bytes_observed": 200000,
                "failure_kind": "execution_nonzero",
            },
            "output_limit_exceeded",
        ),
        (
            {
                "exit_code": 1,
                "termination_reason": "orchestration_error",
                "termination_confirmed": False,
                "stdout_bytes_observed": 200000,
                "failure_kind": "output_limit_exceeded",
            },
            "orchestration_error",
        ),
    ],
)
def test_invalid_artifact_preserves_primary_execution_failure(
    monkeypatch,
    run_updates,
    expected_failure,
):
    review_input = {"task_id": "task-limit-artifact", "fixture_names": []}
    runner = SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        redactor=SecretRedactor(),
    )

    with prepare_execution_plan(
            task_id="task-limit-artifact",
            runtime="local",
            review_input=review_input,
            redactor=SecretRedactor(),
    ) as plan:
        request = plan.requests[0]

        class Harness:

            def execute_one(self, **kwargs):
                del kwargs
                payload = {
                    "run_id": "sandbox-limit",
                    "task_id": request.task_id,
                    "request_id": request.request_id,
                    "runtime": request.runtime,
                    "command": list(request.command_argv),
                    "exit_code": 0,
                    "output_files": {
                        request.output_spec.globs[0]: "{"
                    },
                    "termination_confirmed": True,
                    "execution_started": True,
                }
                payload.update(run_updates)
                return SandboxRun(**payload)

        monkeypatch.setattr(runner, "_harness_for_runtime", lambda **kwargs: Harness())
        result = runner.run(
            task_id=request.task_id,
            review_input=review_input,
            runtime="local",
            dry_run=True,
            requests=[request],
            policy_context=plan.policy_context,
        )

    assert result.runs[0].failure_kind == expected_failure
    if expected_failure != "artifact_invalid":
        assert any(warning.title == "sandbox command failed" for warning in result.candidates.needs_human_review)


def test_output_limit_kills_process_before_late_marker(tmp_path):
    marker = tmp_path / "late.txt"
    child_pid = tmp_path / "child.pid"
    child_code = ("import pathlib,time;"
                  "time.sleep(1);"
                  f"pathlib.Path({str(marker)!r}).write_text('alive')")
    code = ("import pathlib,subprocess,sys,time;"
            f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]);"
            f"pathlib.Path({str(child_pid)!r}).write_text(str(p.pid));"
            "sys.stdout.write('x' * 200000);sys.stdout.flush();"
            "time.sleep(30)")

    result = _run(tmp_path, code)

    time.sleep(1.2)
    assert result.termination_reason == "output_limit_exceeded"
    assert result.stdout_truncated is True
    assert len(result.stdout.encode("utf-8")) <= 4096
    assert not marker.exists()
    pid = int(child_pid.read_text(encoding="utf-8"))
    assert not _pid_exists(pid)


def test_timeout_kills_process_before_late_marker(tmp_path):
    marker = tmp_path / "late.txt"
    code = ("import pathlib,time;"
            "time.sleep(1);"
            f"pathlib.Path({str(marker)!r}).write_text('alive')")

    result = _run(tmp_path, code, timeout_seconds=0.1)

    time.sleep(1.2)
    assert result.timed_out is True
    assert result.termination_reason == "execution_timeout"
    assert not marker.exists()


def test_output_file_reader_never_calls_read_bytes(tmp_path, monkeypatch):
    path = tmp_path / "artifact.json"
    path.write_bytes(b"x" * 10000)
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda self: (_ for _ in ()).throw(AssertionError("full read")),
    )

    text, truncated, observed = _read_output_file(path, limit_bytes=1024)

    assert len(text.encode("utf-8")) <= 1024
    assert truncated is True
    assert observed == 10000


@pytest.mark.parametrize(
    ("raw", "limit", "expected", "truncated"),
    [
        ("\u4f60a".encode("utf-8"), 4, "\u4f60a", False),
        ("\u4f60a".encode("utf-8"), 2, "", True),
        (b"\xff" * 100, 4, "\ufffd", True),
    ],
)
def test_output_file_reader_keeps_valid_utf8_within_byte_budget(
    tmp_path,
    raw,
    limit,
    expected,
    truncated,
):
    path = tmp_path / "artifact.bin"
    path.write_bytes(raw)

    text, was_truncated, observed = _read_output_file(path, limit_bytes=limit)

    assert text == expected
    assert was_truncated is truncated
    assert observed == len(raw)
    assert len(text.encode("utf-8")) <= limit


@pytest.mark.parametrize("limit", [True, -1])
def test_output_file_reader_rejects_invalid_budget(tmp_path, limit):
    path = tmp_path / "artifact.json"
    path.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="limit"):
        _read_output_file(path, limit_bytes=limit)


def test_sanitized_stream_respects_utf8_byte_budget():
    text, truncated = _sanitize_stream(
        "€" * 4,
        boundary=RedactionBoundary(),
        limit=5,
    )

    assert truncated is True
    assert len(text.encode("utf-8")) <= 5


def test_artifact_budget_kills_writer_before_late_marker(tmp_path):
    marker = tmp_path / "late.txt"
    artifact = tmp_path / "out" / "large.bin"
    code = ("import pathlib,time;"
            f"p=pathlib.Path({str(artifact)!r});p.parent.mkdir();"
            "p.write_bytes(b'x' * 200000);"
            "time.sleep(1);"
            f"pathlib.Path({str(marker)!r}).write_text('alive')")

    result = _run(tmp_path, code, output_paths=[artifact])

    time.sleep(1.2)
    assert result.termination_reason == "output_limit_exceeded"
    assert result.termination_confirmed is True
    assert result.output_bytes_observed > 4096
    assert not marker.exists()


def test_immediate_exit_after_stdout_overflow_still_fails(tmp_path):
    code = "import sys;sys.stdout.buffer.write(b'x' * 200000);sys.stdout.flush()"

    result = _run(tmp_path, code)

    assert result.exit_code != 0
    assert result.failure_kind == "output_limit_exceeded"
    assert result.termination_reason == "output_limit_exceeded"
    assert result.termination_confirmed is True
    assert result.stdout_bytes_observed > 4096
    assert len(result.stdout.encode("utf-8")) <= 4096


def test_immediate_exit_after_artifact_overflow_still_fails(tmp_path):
    artifact = tmp_path / "out" / "large.bin"
    code = ("import pathlib;"
            f"p=pathlib.Path({str(artifact)!r});p.parent.mkdir();"
            "p.write_bytes(b'x' * 200000)")

    result = _run(tmp_path, code, output_paths=[artifact])

    assert result.exit_code != 0
    assert result.failure_kind == "output_limit_exceeded"
    assert result.termination_reason == "output_limit_exceeded"
    assert result.termination_confirmed is True
    assert result.output_bytes_observed > 4096


def test_parent_exit_after_overflow_cannot_leave_descendant(tmp_path):
    marker = tmp_path / "escaped-child.txt"
    child_pid = tmp_path / "escaped-child.pid"
    child_code = ("import pathlib,time;"
                  "time.sleep(1);"
                  f"pathlib.Path({str(marker)!r}).write_text('escaped')")
    parent_code = ("import pathlib,subprocess,sys;"
                   f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]);"
                   f"pathlib.Path({str(child_pid)!r}).write_text(str(p.pid));"
                   "sys.stdout.buffer.write(b'x' * 200000);sys.stdout.flush()")

    result = _run(tmp_path, parent_code)

    time.sleep(1.2)
    assert result.failure_kind == "output_limit_exceeded"
    assert result.termination_confirmed is True
    assert not marker.exists()
    assert not _pid_exists(int(child_pid.read_text(encoding="utf-8")))


def test_parent_exit_with_descendant_holding_pipe_does_not_deadlock(tmp_path):
    child_pid = tmp_path / "pipe-child.pid"
    child_code = "import time;time.sleep(30)"
    parent_code = ("import pathlib,subprocess,sys;"
                   f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]);"
                   f"pathlib.Path({str(child_pid)!r}).write_text(str(p.pid))")
    started = time.monotonic()

    result = _run(tmp_path, parent_code)

    assert time.monotonic() - started < 4
    assert result.failure_kind == "orchestration_error"
    assert result.termination_confirmed is True
    assert not _pid_exists(int(child_pid.read_text(encoding="utf-8")))
