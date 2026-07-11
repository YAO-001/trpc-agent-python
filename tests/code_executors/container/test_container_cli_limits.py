import os
import subprocess
import sys
import threading
import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import trpc_agent_sdk.code_executors.container._container_cli as container_cli
from trpc_agent_sdk.code_executors.container._container_cli import CommandArgs
from trpc_agent_sdk.code_executors.container._container_cli import ContainerClient
from trpc_agent_sdk.code_executors.container._container_cli import ContainerExecResult
from trpc_agent_sdk.code_executors.container._container_cli import _consume_bounded_frames
from trpc_agent_sdk.code_executors.container._container_cli import _decode_bounded
from trpc_agent_sdk.utils import CommandExecResult


def test_bounded_demux_stops_at_budget_and_requests_termination():
    terminated = []
    frames = [
        (b"a" * 3000, None),
        (b"b" * 3000, None),
        (b"must-not-be-retained", None),
    ]

    result = _consume_bounded_frames(
        frames,
        stdout_limit_bytes=4096,
        stderr_limit_bytes=4096,
        terminate=lambda: terminated.append(True),
    )

    assert len(result.stdout) == 4096
    assert result.stdout_bytes_observed > 4096
    assert result.stdout_truncated is True
    assert terminated == [True]


def test_bounded_demux_tracks_stderr_independently():
    result = _consume_bounded_frames(
        [(b"ok", b"error")],
        stdout_limit_bytes=2,
        stderr_limit_bytes=3,
        terminate=lambda: None,
    )

    assert result.stdout == b"ok"
    assert result.stderr == b"err"
    assert result.stderr_bytes_observed == 5
    assert result.stderr_truncated is True


def test_bounded_demux_zero_budget_terminates_on_first_byte():
    terminated = []
    result = _consume_bounded_frames([(b"x", None)],
                                     stdout_limit_bytes=0,
                                     stderr_limit_bytes=0,
                                     terminate=lambda: terminated.append(True))
    assert result.stdout == b""
    assert result.stdout_bytes_observed == 1
    assert terminated == [True]


def test_invalid_utf8_replacement_does_not_expand_public_budget():
    text = _decode_bounded(b"\xff\xffa", 3)
    assert len(text.encode("utf-8")) <= 3


def test_legacy_four_field_result_remains_supported():
    client = ContainerClient.__new__(ContainerClient)
    client._container = SimpleNamespace(exec_run=lambda **kwargs: CommandExecResult("out", "err", 7, False))

    result = client._stream_exec(["legacy"], CommandArgs(), {})

    assert result.stdout == "out"
    assert result.stderr == "err"
    assert result.exit_code == 7
    assert result.failure_kind == "execution_nonzero"


def test_relative_output_glob_is_rejected_before_docker_exec():
    client = ContainerClient.__new__(ContainerClient)
    api = MagicMock()
    client._client = object()
    client._container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))

    with pytest.raises(ValueError, match="absolute"):
        client._stream_exec(["true"], CommandArgs(output_globs=("relative/*.json", )), {})
    api.exec_create.assert_not_called()


async def test_timeout_terminates_group_and_waits_for_reader():
    client = ContainerClient.__new__(ContainerClient)
    release = threading.Event()
    reader_finished = threading.Event()
    terminate_calls = []

    def blocked_reader(cmd, args, state):
        del cmd, args
        state.update(exec_id="exec-1", pid_file="/tmp/pid", ready=True, low_level_started=True)
        release.wait(timeout=5)
        reader_finished.set()
        return ContainerExecResult("", "", -1, False, execution_started=True)

    client._stream_exec = blocked_reader
    client._terminate_exec_group = lambda path: terminate_calls.append(path) or release.set() or True
    client._exec_stopped = lambda exec_id: reader_finished.is_set()

    result = await client.exec_run(["python3", "-c", "pass"], CommandArgs(timeout=0.01))

    assert result.is_timeout is True
    assert result.failure_kind == "execution_timeout"
    assert result.termination_confirmed is True
    assert terminate_calls == ["/tmp/pid"]
    assert reader_finished.is_set()


async def test_zero_timeout_without_pid_kills_container_and_waits_for_reader():
    client = ContainerClient.__new__(ContainerClient)
    release = threading.Event()
    reader_finished = threading.Event()
    kill_calls = []

    def blocked_reader(cmd, args, state):
        del cmd, args
        state.update(exec_id="exec-zero", low_level_started=True)
        release.wait(timeout=5)
        reader_finished.set()
        return ContainerExecResult("", "", -1, False)

    client._stream_exec = blocked_reader
    client._terminate_exec_group = lambda path: False
    client._kill_container = lambda: kill_calls.append(True) or release.set() or True
    client._exec_stopped = lambda exec_id: reader_finished.is_set()

    result = await client.exec_run(["python3", "-c", "pass"], CommandArgs(timeout=0))

    assert result.is_timeout is True
    assert result.failure_kind == "execution_timeout"
    assert result.termination_confirmed is True
    assert kill_calls == [True]
    assert reader_finished.is_set()


async def test_cancellation_terminates_group_and_waits_for_reader():
    client = ContainerClient.__new__(ContainerClient)
    release = threading.Event()
    reader_started = threading.Event()
    reader_finished = threading.Event()

    def blocked_reader(cmd, args, state):
        del cmd, args
        state.update(exec_id="exec-cancel", pid_file="/tmp/pid", ready=True, low_level_started=True)
        reader_started.set()
        release.wait(timeout=5)
        reader_finished.set()
        return ContainerExecResult("", "", -1, False, execution_started=True)

    client._stream_exec = blocked_reader
    client._terminate_exec_group = lambda path: release.set() or True
    client._kill_container = lambda: False
    task = asyncio.create_task(client.exec_run(["python3", "-c", "pass"], CommandArgs(timeout=None)))
    while not reader_started.is_set():
        await asyncio.sleep(0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert release.is_set()
    assert reader_finished.is_set()


async def test_output_limit_wins_timeout_race():
    client = ContainerClient.__new__(ContainerClient)
    release = threading.Event()

    def overflowing_reader(cmd, args, state):
        del cmd, args
        state.update(exec_id="exec-race", pid_file="/tmp/pid", ready=True, low_level_started=True)
        release.wait(timeout=5)
        return ContainerExecResult(
            "x",
            "",
            1,
            False,
            stdout_truncated=True,
            stdout_bytes_observed=2,
            execution_started=True,
            failure_kind="output_limit_exceeded",
            termination_reason="output_limit_exceeded",
        )

    client._stream_exec = overflowing_reader
    client._terminate_exec_group = lambda path: release.set() or True
    client._exec_stopped = lambda exec_id: True

    result = await client.exec_run(["python3", "-c", "pass"], CommandArgs(timeout=0.01))

    assert result.failure_kind == "output_limit_exceeded"
    assert result.is_timeout is False


async def test_final_artifact_reason_survives_timeout_socket_error():
    client = ContainerClient.__new__(ContainerClient)
    release = threading.Event()

    def failing_reader(cmd, args, state):
        del cmd, args
        state.update(exec_id="exec-final-artifact",
                     pid_file="/tmp/pid",
                     reason_file="/tmp/reason",
                     ready=True,
                     low_level_started=True)
        release.wait(timeout=5)
        raise OSError("socket closed")

    client._stream_exec = failing_reader
    client._terminate_exec_group = lambda path: release.set() or True
    client._exec_stopped = lambda exec_id: True
    client._read_control_file = lambda path: "output_limit_exceeded"

    result = await client.exec_run(["python3", "-c", "pass"], CommandArgs(timeout=0.01))

    assert result.failure_kind == "output_limit_exceeded"
    assert result.termination_reason == "output_limit_exceeded"
    assert result.termination_confirmed is True
    assert result.is_timeout is False


def test_clean_leader_with_orphan_reason_is_not_success(monkeypatch):
    client = ContainerClient.__new__(ContainerClient)
    api = MagicMock()
    api.exec_create.return_value = {"Id": "exec-orphan"}
    api.exec_start.return_value = SimpleNamespace(shutdown=lambda how: None, close=lambda: None)
    api.exec_inspect.return_value = {"Running": False, "ExitCode": 0}
    container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))
    client._client = object()
    client._container = container
    client._wait_for_ready = lambda path: True
    client._read_control_file = lambda path: "orchestration_error" if path.endswith(".reason") else "123"
    client._exec_group_absent = lambda path: True
    monkeypatch.setattr(container_cli, "frames_iter", lambda sock, tty: iter(()))

    result = client._stream_exec(["python3", "-c", "pass"], CommandArgs(), {})

    assert result.exit_code != 0
    assert result.failure_kind == "orchestration_error"
    assert result.termination_confirmed is True


def test_overflow_cleanup_failure_is_orchestration_not_confirmed(monkeypatch):
    client = ContainerClient.__new__(ContainerClient)
    api = MagicMock()
    api.exec_create.return_value = {"Id": "exec-overflow-failed-cleanup"}
    api.exec_start.return_value = SimpleNamespace(shutdown=lambda how: None, close=lambda: None)
    api.exec_inspect.return_value = {"Running": False, "ExitCode": 0}
    container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))
    client._client = object()
    client._container = container
    client._wait_for_ready = lambda path: True
    client._read_control_file = lambda path: "orchestration_error" if path.endswith(".reason") else "123"
    client._terminate_exec_group = lambda path: False
    client._kill_container = lambda: False
    client._exec_group_absent = lambda path: False
    monkeypatch.setattr(container_cli, "frames_iter", lambda sock, tty: iter(((1, b"xx"), )))

    result = client._stream_exec(["python3", "-c", "pass"], CommandArgs(stdout_limit_bytes=1), {})

    assert result.failure_kind == "orchestration_error"
    assert result.termination_reason == "orchestration_error"
    assert result.termination_confirmed is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX supervisor uses process groups")
def test_supervisor_artifact_glob_ignores_directories(tmp_path):
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "small.txt").write_text("ok", encoding="utf-8")
    client = ContainerClient.__new__(ContainerClient)
    command, pid_file, reason_file = client._supervised_command(
        [sys.executable, "-c", "pass"],
        CommandArgs(output_globs=(str(output_dir / "**"), ), output_limit_bytes=1024),
        f"test-{os.getpid()}",
    )
    try:
        completed = subprocess.run(command, check=False, capture_output=True, timeout=5)
        assert completed.returncode == 0, completed.stderr
    finally:
        for path in (pid_file, reason_file):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


async def test_reader_failure_after_start_cleans_group_and_fails_orchestration(monkeypatch):
    client = ContainerClient.__new__(ContainerClient)
    api = MagicMock()
    api.exec_create.return_value = {"Id": "exec-reader-error"}
    api.exec_start.return_value = SimpleNamespace(shutdown=lambda how: None, close=lambda: None)
    container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))
    client._client = object()
    client._container = container
    client._wait_for_ready = lambda path: True
    terminated = []
    client._terminate_exec_group = lambda path: terminated.append(path) or True
    monkeypatch.setattr(
        container_cli,
        "frames_iter",
        lambda sock, tty: (_ for _ in ()).throw(OSError("reader failed")),
    )

    result = await client.exec_run(["python3", "-c", "pass"], CommandArgs(timeout=None))

    assert result.failure_kind == "orchestration_error"
    assert result.execution_started is True
    assert result.termination_confirmed is True
    assert len(terminated) == 1


async def test_missing_ready_evidence_fails_closed_before_reading(monkeypatch):
    client = ContainerClient.__new__(ContainerClient)
    api = MagicMock()
    api.exec_create.return_value = {"Id": "exec-not-ready"}
    api.exec_start.return_value = SimpleNamespace(shutdown=lambda how: None, close=lambda: None)
    container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))
    client._client = object()
    client._container = container
    client._wait_for_ready = lambda path: False
    client._terminate_exec_group = lambda path: False
    client._kill_container = lambda: True
    monkeypatch.setattr(container_cli, "frames_iter", lambda sock, tty: (_ for _ in ()))

    result = await client.exec_run(["python3", "-c", "pass"], CommandArgs(timeout=None))

    assert result.execution_started is False
    assert result.failure_kind == "orchestration_error"
    assert result.termination_confirmed is True
    assert api.exec_inspect.call_count == 0


async def test_exec_start_failure_is_unstarted_runtime_failure():
    client = ContainerClient.__new__(ContainerClient)
    api = MagicMock()
    api.exec_create.return_value = {"Id": "exec-start-failed"}
    api.exec_start.side_effect = OSError("start failed")
    container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))
    client._client = object()
    client._container = container
    terminated = []
    client._terminate_exec_group = lambda path: terminated.append(path) or True

    result = await client.exec_run(["python3", "-c", "pass"], CommandArgs(timeout=None))

    assert result.execution_started is False
    assert result.failure_kind == "runtime_unavailable"
    assert result.termination_confirmed is False
    assert terminated == []


async def test_stdin_writer_failure_terminates_blocked_reader(monkeypatch):
    client = ContainerClient.__new__(ContainerClient)
    released = threading.Event()

    class FailingSocket:

        def sendall(self, data):
            del data
            raise OSError("write failed")

        def shutdown(self, how):
            del how

        def close(self):
            pass

    api = MagicMock()
    api.exec_create.return_value = {"Id": "exec-writer-error"}
    api.exec_start.return_value = FailingSocket()
    container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))
    client._client = object()
    client._container = container
    client._wait_for_ready = lambda path: True
    client._terminate_exec_group = lambda path: released.set() or True

    def blocked_frames(sock, tty):
        del sock, tty
        released.wait(timeout=5)
        return iter(())

    monkeypatch.setattr(container_cli, "frames_iter", blocked_frames)

    result = await client.exec_run(["python3", "-c", "pass"], CommandArgs(stdin="payload", timeout=None))

    assert released.is_set()
    assert result.failure_kind == "orchestration_error"
    assert result.execution_started is True
    assert result.termination_confirmed is True
