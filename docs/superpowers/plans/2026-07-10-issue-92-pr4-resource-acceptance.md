# Issue #92 PR4 Resource Limits and Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that execution limits are enforced while a process is running and turn every Issue #92 acceptance threshold into reproducible test evidence.

**Architecture:** Local and container executors share byte-budget and termination semantics: bounded readers retain at most the approved bytes, signal a limit breach, kill the process group, and report observed/retained counts. The code-review container is created with fixed CPU, memory, PID, network, read-only-root, and temporary-disk restrictions. Independent labeled corpora drive recall, false-positive, and redaction metrics; required CI runs the real Docker path.

**Tech Stack:** Python subprocess/threading/signals, Docker SDK low-level exec API, Pydantic v2, pytest, GitHub Actions, JSON corpora.

---

### Task 1: Enforce local timeout and byte budgets during execution

**Files:**
- Create: `examples/skills_code_review_agent/agent/process_limits.py`
- Modify: `examples/skills_code_review_agent/agent/sandbox_runner.py:43-295`
- Modify: `examples/skills_code_review_agent/agent/models.py:135-163`
- Create: `tests/examples/test_skills_code_review_agent_limits.py`

- [ ] **Step 1: Write failing output-limit and timeout termination tests**

Create:

```python
from __future__ import annotations

import sys
import os
import subprocess
import time
from pathlib import Path

from agent.sandbox_runner import _read_output_file
from agent.sandbox_runner import _run_capped_process


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


def test_output_limit_kills_process_before_late_marker(tmp_path):
    marker = tmp_path / "late.txt"
    child_pid = tmp_path / "child.pid"
    child_code = (
        "import pathlib,time;"
        "time.sleep(1);"
        f"pathlib.Path({str(marker)!r}).write_text('alive')"
    )
    code = (
        "import pathlib,subprocess,sys,time;"
        f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]);"
        f"pathlib.Path({str(child_pid)!r}).write_text(str(p.pid));"
        "sys.stdout.write('x' * 200000);sys.stdout.flush();"
        "time.sleep(30)"
    )
    result = _run_capped_process(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env={},
        timeout_seconds=5,
        stdout_limit_bytes=4096,
        stderr_limit_bytes=4096,
        output_paths=[],
        output_limit_bytes=4096,
    )
    time.sleep(1.2)
    assert result.termination_reason == "output_limit_exceeded"
    assert result.stdout_truncated is True
    assert len(result.stdout) <= 4096
    assert not marker.exists()
    pid = int(child_pid.read_text(encoding="utf-8"))
    assert not _pid_exists(pid)


def test_timeout_kills_process_before_late_marker(tmp_path):
    marker = tmp_path / "late.txt"
    code = (
        "import pathlib,time;"
        "time.sleep(1);"
        f"pathlib.Path({str(marker)!r}).write_text('alive')"
    )
    result = _run_capped_process(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env={},
        timeout_seconds=0.1,
        stdout_limit_bytes=4096,
        stderr_limit_bytes=4096,
        output_paths=[],
        output_limit_bytes=4096,
    )
    time.sleep(1.2)
    assert result.timed_out is True
    assert result.termination_reason == "execution_timeout"
    assert not marker.exists()


def test_output_file_reader_never_calls_read_bytes(tmp_path, monkeypatch):
    path = tmp_path / "artifact.json"
    path.write_bytes(b"x" * 10000)
    monkeypatch.setattr(Path, "read_bytes", lambda self: (_ for _ in ()).throw(AssertionError("full read")))
    text, truncated, observed = _read_output_file(path, limit_bytes=1024)
    assert len(text.encode("utf-8")) <= 1024
    assert truncated is True
    assert observed == 10000


def test_artifact_budget_kills_writer_before_late_marker(tmp_path):
    marker = tmp_path / "late.txt"
    artifact = tmp_path / "out" / "large.bin"
    code = (
        "import pathlib,time;"
        f"p=pathlib.Path({str(artifact)!r});p.parent.mkdir();"
        "p.write_bytes(b'x' * 200000);"
        "time.sleep(1);"
        f"pathlib.Path({str(marker)!r}).write_text('alive')"
    )
    result = _run_capped_process(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env={},
        timeout_seconds=5,
        stdout_limit_bytes=4096,
        stderr_limit_bytes=4096,
        output_paths=[artifact],
        output_limit_bytes=4096,
    )
    time.sleep(1.2)
    assert result.termination_reason == "output_limit_exceeded"
    assert result.termination_confirmed is True
    assert not marker.exists()


def test_immediate_exit_after_stdout_overflow_still_fails(tmp_path):
    code = "import sys;sys.stdout.buffer.write(b'x' * 200000);sys.stdout.flush()"
    result = _run_capped_process(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env={},
        timeout_seconds=5,
        stdout_limit_bytes=4096,
        stderr_limit_bytes=4096,
        output_paths=[],
        output_limit_bytes=4096,
    )
    assert result.exit_code != 0
    assert result.failure_kind == "output_limit_exceeded"
    assert result.termination_reason == "output_limit_exceeded"
    assert result.termination_confirmed is True
    assert result.stdout_bytes_observed > 4096
    assert len(result.stdout) <= 4096


def test_immediate_exit_after_artifact_overflow_still_fails(tmp_path):
    artifact = tmp_path / "out" / "large.bin"
    code = (
        "import pathlib;"
        f"p=pathlib.Path({str(artifact)!r});p.parent.mkdir();"
        "p.write_bytes(b'x' * 200000)"
    )
    result = _run_capped_process(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env={},
        timeout_seconds=5,
        stdout_limit_bytes=4096,
        stderr_limit_bytes=4096,
        output_paths=[artifact],
        output_limit_bytes=4096,
    )
    assert result.exit_code != 0
    assert result.failure_kind == "output_limit_exceeded"
    assert result.termination_reason == "output_limit_exceeded"
    assert result.termination_confirmed is True
    assert result.output_bytes_observed > 4096


def test_parent_exit_after_overflow_cannot_leave_descendant(tmp_path):
    marker = tmp_path / "escaped-child.txt"
    child_pid = tmp_path / "escaped-child.pid"
    child_code = (
        "import pathlib,time;"
        "time.sleep(1);"
        f"pathlib.Path({str(marker)!r}).write_text('escaped')"
    )
    parent_code = (
        "import pathlib,subprocess,sys;"
        f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]);"
        f"pathlib.Path({str(child_pid)!r}).write_text(str(p.pid));"
        "sys.stdout.buffer.write(b'x' * 200000);sys.stdout.flush()"
    )
    result = _run_capped_process(
        [sys.executable, "-c", parent_code],
        cwd=tmp_path,
        env={},
        timeout_seconds=5,
        stdout_limit_bytes=4096,
        stderr_limit_bytes=4096,
        output_paths=[],
        output_limit_bytes=4096,
    )
    time.sleep(1.2)
    assert result.failure_kind == "output_limit_exceeded"
    assert result.termination_confirmed is True
    assert not marker.exists()
    assert not _pid_exists(int(child_pid.read_text(encoding="utf-8")))


def test_parent_exit_with_descendant_holding_pipe_does_not_deadlock(tmp_path):
    child_pid = tmp_path / "pipe-child.pid"
    child_code = "import time;time.sleep(30)"
    parent_code = (
        "import pathlib,subprocess,sys;"
        f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]);"
        f"pathlib.Path({str(child_pid)!r}).write_text(str(p.pid))"
    )
    started = time.monotonic()
    result = _run_capped_process(
        [sys.executable, "-c", parent_code],
        cwd=tmp_path,
        env={},
        timeout_seconds=5,
        stdout_limit_bytes=4096,
        stderr_limit_bytes=4096,
        output_paths=[],
        output_limit_bytes=4096,
    )
    assert time.monotonic() - started < 4
    assert result.failure_kind == "orchestration_error"
    assert result.termination_confirmed is True
    assert not _pid_exists(int(child_pid.read_text(encoding="utf-8")))
```

- [ ] **Step 2: Run the tests and verify local collection is post-hoc**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_limits.py -v
```

Expected: collection fails because `_run_capped_process` does not exist and `_read_output_file` uses `Path.read_bytes()`.

- [ ] **Step 3: Implement bounded binary readers and process-tree termination**

Add these result fields to `SandboxRun`:

```python
termination_reason: str = ""
termination_confirmed: bool = False
execution_started: bool = False
stdout_bytes_observed: int = 0
stderr_bytes_observed: int = 0
output_bytes_observed: int = 0
```

Create `process_limits.py` and implement `_BoundedCapture` there with a lock, retained `bytearray`, observed byte count, and an overflow event. Reader threads call `feed(chunk)`; `feed` stores only the remaining budget and sets `overflowed` as soon as observed bytes exceed the limit. Export `run_capped_process`; `sandbox_runner.py` imports it and keeps a private compatibility alias for the focused tests.

Represent the supervised tree independently from the root process, and never use root liveness as a reason to skip descendant cleanup:

```python
@dataclass
class _ProcessTree:
    process: subprocess.Popen[bytes]
    posix_pgid: int | None = None
    windows_job: _WindowsJob | None = None


def _kill_process_tree(tree: _ProcessTree) -> None:
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
```

On POSIX, start `Popen` with `start_new_session=True` and save `posix_pgid=process.pid`; `killpg` is attempted even after the group leader exits. On Windows, implement a stdlib-`ctypes` `_WindowsJob` wrapper with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `TerminateJobObject`, and an active-process query. Launch a tiny Python supervisor that blocks on a one-byte ready pipe, assign that still-blocked supervisor to the Job Object, and only then release it to spawn the requested argv. The target and every descendant consequently enter the same non-breakaway job before untrusted code begins. The supervisor forwards inherited stdout/stderr and exits with the target status. Do not rely on `taskkill /T` after a root PID has disappeared.

Start stdout/stderr reader threads plus an output-directory watchdog that totals the declared output paths every 20 ms. The main loop must:

```python
while process.poll() is None:
    if stdout_capture.overflowed.is_set() or stderr_capture.overflowed.is_set():
        termination_reason = "output_limit_exceeded"
        _kill_process_tree(tree)
        break
    if output_watch.overflowed.is_set():
        termination_reason = "output_limit_exceeded"
        _kill_process_tree(tree)
        break
    if time.monotonic() >= deadline:
        timed_out = True
        termination_reason = "execution_timeout"
        _kill_process_tree(tree)
        break
    time.sleep(0.01)
```

After the loop, do not join stream readers yet: a descendant may still hold inherited stdout/stderr handles after the leader exits. First inspect the saved POSIX process group or Windows Job active-process count. If anything remains, classify it as the already-observed timeout/output breach or, for an otherwise clean leader exit, `orchestration_error`; terminate the saved tree and confirm it is empty. Only then stop/join the output watcher and join both stream readers with a bounded grace period. If a reader still does not finish, close the parent pipe handle, invoke fail-closed tree termination again, and join it before returning; no result may escape with a live reader thread.

Once readers have reached EOF, perform a mandatory final breach check in this order: inspect both capture overflow events; rescan every declared output path and compare the final total with `output_limit_bytes`; finally evaluate the timeout/exit code. Extract this logic into a small `_finalize_capped_result` helper and unit-test it with a fake clean-exited tree plus (a) a pre-overflowed capture, (b) an oversized final artifact, and (c) a descendant-active/inherited-pipe state. The first two return `output_limit_exceeded`; the third kills the tree before joining the fake reader and returns `orchestration_error`.

The final check must override a zero process exit with `failure_kind="output_limit_exceeded"`, `termination_reason="output_limit_exceeded"`, and a synthetic non-zero public exit code. Always invoke the saved tree/group terminator on a breach, even if the root has exited. Set `termination_confirmed=True` only after the Windows active-process count is zero or POSIX `killpg(pgid, 0)` raises `ProcessLookupError`; a live group after the grace period is `orchestration_error`, never a successful return. On an otherwise clean command, check for and terminate leftover descendants before closing the Job handle; leftover processes likewise make the run non-zero. This closes both the final-poll race and parent-exit/descendant-escape race.

Decode only retained bytes. Replace `subprocess.run(capture_output=True)` in `LocalSkillHarness._run_command` with this helper. The two immediate-exit regressions above must fail with `output_limit_exceeded`, not complete successfully.

- [ ] **Step 4: Read artifacts with a hard upper bound**

Replace `Path.read_bytes()`:

```python
def _read_output_file(path: Path, *, limit_bytes: int = MAX_OUTPUT_FILE_BYTES) -> tuple[str, bool, int]:
    observed = path.stat().st_size
    with path.open("rb") as stream:
        raw = stream.read(limit_bytes)
    truncated = observed > limit_bytes
    text = raw.decode("utf-8", errors="replace")
    while len(text.encode("utf-8")) > limit_bytes:
        text = text[:-1]
    return text, truncated, observed
```

Thread observed and retained counts into `SandboxRun`. Set `execution_started=True` immediately after `Popen` succeeds; PR2's `runtime_unavailable` rows retain the false default. A watchdog breach sets `failure_kind="output_limit_exceeded"`, a non-zero exit code, and the same `termination_reason`.

- [ ] **Step 5: Run local limits and e2e tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_limits.py -v
python -m pytest tests/examples/test_skills_code_review_agent_e2e.py -k "local_sandbox" -v
```

Expected: all selected tests pass and both late markers remain absent.

- [ ] **Step 6: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/sandbox_runner.py',
  'examples/skills_code_review_agent/agent/process_limits.py',
  'examples/skills_code_review_agent/agent/models.py',
  'tests/examples/test_skills_code_review_agent_limits.py'
)
git add @stage
git commit -m "fix(review): enforce local execution budgets"
```

### Task 2: Stream container exec and kill timed-out or overflowing process groups

**Files:**
- Modify: `trpc_agent_sdk/code_executors/_types.py:125-173`
- Modify: `trpc_agent_sdk/code_executors/_base_workspace_runtime.py:175-255`
- Modify: `trpc_agent_sdk/code_executors/container/_container_cli.py:45-313`
- Modify: `trpc_agent_sdk/code_executors/container/_container_ws_runtime.py:626-850`
- Modify: `trpc_agent_sdk/skills/tools/_skill_run.py:309-365,699-739,756-806`
- Modify: `examples/skills_code_review_agent/agent/agent_factory.py:16-42`
- Modify: `examples/skills_code_review_agent/agent/sandbox_runner.py:384-437`
- Modify: `tests/examples/test_skills_code_review_agent_limits.py`
- Create: `tests/code_executors/container/test_container_cli_limits.py`
- Modify: `tests/code_executors/container/test_container_cli.py`
- Modify: `tests/code_executors/container/test_container_ws_runtime.py`
- Modify: `tests/skills/tools/test_skill_run.py`

- [ ] **Step 1: Add failing bounded-demux and archive-stream tests**

Create unit tests with fake Docker API objects:

```python
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


@pytest.mark.asyncio
async def test_timeout_terminates_exec_group_and_waits_for_reader(fake_container):
    fake_container.reader_blocks_until_terminated = True
    result = await fake_container.client.exec_run(
        ["python3", "-c", "import time; time.sleep(30)"],
        CommandArgs(timeout=0.01, stdout_limit_bytes=4096, stderr_limit_bytes=4096),
    )
    assert result.is_timeout is True
    assert result.termination_reason == "execution_timeout"
    assert fake_container.terminate_calls == 1
    assert fake_container.reader_finished is True


def test_copy_file_out_streams_archive_without_join(runtime_fs, monkeypatch):
    chunks = _counting_tar_chunks(payload=b"x" * 10000, chunk_size=512)
    runtime_fs.container.client.api.get_archive.return_value = (chunks, {})
    data, raw_size, _ = runtime_fs._copy_file_out("/workspace/out/large.bin", max_bytes=1024)
    assert len(data) == 1024
    assert raw_size == 10000
    assert chunks.consumed_bytes < chunks.total_bytes


@pytest.mark.asyncio
async def test_clean_leader_exit_with_orphan_reason_is_not_success(fake_container):
    fake_container.exec_exit_code = 0
    fake_container.reason_file = "orchestration_error"
    fake_container.process_group_exists = False
    result = await fake_container.client.exec_run(
        ["python3", "-c", "pass"],
        CommandArgs(timeout=5),
    )
    assert result.exit_code != 0
    assert result.failure_kind == "orchestration_error"
    assert result.termination_confirmed is True


def test_runner_closes_harness_once_when_execute_raises(
    tmp_path,
    monkeypatch,
):
    harness = _ClosingHarness(
        execute_error=RuntimeError("synthetic execution failure")
    )
    runner, request, context = _runner_request_and_context(
        tmp_path,
        harness=harness,
    )
    runner.run(
        task_id=request.task_id,
        review_input={"task_id": request.task_id},
        runtime="container",
        dry_run=True,
        requests=[request],
        policy_context=context,
    )
    assert harness.close_calls == 1
```

Define `_ClosingHarness.execute_one` to raise the supplied error and `close` to increment `close_calls`; reuse the real PR2 request/policy helpers so the request reaches execution. Add an SDK-side test that two calls to `ContainerWorkspaceRuntime.close()` result in exactly one container stop/remove sequence.

- [ ] **Step 2: Run the focused container unit tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_limits.py -v
python -m pytest tests/code_executors/container/test_container_cli_limits.py -v
python -m pytest tests/code_executors/container/test_container_ws_runtime.py -k "copy_file_out" -v
```

Expected: FAIL because the harness has no owned close path, Docker output is fully consumed, timeout does not kill the exec, a clean leader status ignores the supervisor's orphan reason, and archive chunks are joined into memory.

- [ ] **Step 3: Add container-specific result metadata without changing the public tuple**

Leave `trpc_agent_sdk.utils.CommandExecResult` and its exact four-field tuple API unchanged. Add in `_container_cli.py`:

```python
@dataclass(frozen=True)
class ContainerExecResult:
    stdout: str
    stderr: str
    exit_code: int
    is_timeout: bool
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    stdout_bytes_observed: int = 0
    stderr_bytes_observed: int = 0
    execution_started: bool = False
    failure_kind: str = ""
    termination_confirmed: bool = True
    termination_reason: str = ""
```

`ContainerClient.exec_run` returns this internal type. It sets `execution_started=True` only after the supervised child reports ready; create/start errors remain false with a canonical `failure_kind`. Existing mocks returning the legacy tuple remain supported by reading new metadata with `getattr(result, field, default)`. Update the existing container CLI type assertion and run that suite; do not modify `tests/utils/test_execute_cmd.py`. Add matching fields, including `execution_started`, `failure_kind`, and `termination_confirmed`, to `WorkspaceRunResult`. Add `stdout_limit_bytes`, `stderr_limit_bytes`, `output_globs`, and `output_limit_bytes` to `WorkspaceRunProgramSpec` and `CommandArgs`, defaulting to zero/empty for backward compatibility.

Add a default no-op, idempotent `close()` to `BaseWorkspaceRuntime`. Expose an idempotent public `ContainerClient.close()` that unregisters its atexit hook, stops/removes the container once, clears its handle, and remains safe after fail-closed `container.kill()`; `ContainerWorkspaceRuntime.close()` delegates to it. Keep `_cleanup_container` only as an atexit adapter that calls public `close()`, not as a second cleanup implementation.

- [ ] **Step 4: Supervise every Docker exec with a killable process group**

Before `exec_create`, wrap the target argv in a Python supervisor. It starts the target with `start_new_session=True`, writes the saved process-group ID to `/tmp/trpc-exec-<uuid>.pid`, starts a thread that totals files matching the absolute output globs, and waits for the group leader. If that total exceeds `output_limit_bytes`, the thread kills the saved process group and writes `output_limit_exceeded` to a reason file.

After the leader exits, the supervisor must stop/join the watcher, rescan final artifact sizes, and inspect the saved group with `os.killpg(pgid, 0)`. A final artifact breach overrides a zero exit, kills the group, and records `output_limit_exceeded`. Any descendant still alive after an otherwise clean leader exit is killed and recorded as `orchestration_error`; the supervisor exits non-zero and does not delete the PID/reason files. It confirms the group is absent before exiting. This mirrors Task 1's post-exit finalizer and prevents an early-exiting parent from orphaning work inside the long-lived container.

`_terminate_exec_group` runs a second short Docker exec that reads the saved PGID and calls `os.killpg(pgid, signal.SIGKILL)` without first checking whether the original leader PID is alive.

Use the low-level Docker API for both stdin and non-stdin executions:

```python
resp = self.container.client.api.exec_create(
    self.container.id,
    cmd=supervised_cmd,
    stdout=True,
    stderr=True,
    stdin=bool(stdin),
    tty=False,
    environment=environment,
)
exec_id = resp["Id"]
sock = self.container.client.api.exec_start(
    exec_id,
    detach=False,
    tty=False,
    stream=False,
    socket=True,
    demux=False,
)
```

Iterate `frames_iter`/`demux_adaptor` one frame at a time into bounded captures. On the first stream overflow, call `_terminate_exec_group(pid_file)`, close the socket, inspect the exec, and return `termination_reason="output_limit_exceeded"`. After the reader finishes, perform the same mandatory final capture-overflow check before accepting a zero exec status. Read the reason file to detect final artifact-budget or orphan-descendant termination. For timeout, use `asyncio.wait` between the executor future and a timer. If the PID file is not yet present, group termination fails, exec still reports running after a short grace period, or the reader does not finish, fail closed with `self.container.kill()`, reload the Docker object, close the socket, and await the reader future to completion. Set `termination_confirmed=True` only after `exec_inspect(exec_id)["Running"]` is false and the saved process group is absent, or container status is not running. Add a zero-delay timeout regression that exercises the missing-PID fallback and asserts `container.kill()` was called.

- [ ] **Step 5: Stream tar extraction**

Implement an `io.RawIOBase` adapter over Docker's archive iterator and open it with streaming tar mode:

```python
stream, _ = self.container.client.api.get_archive(self.container.container.id, full_path)
reader = _IteratorReader(stream)
with tarfile.open(fileobj=io.BufferedReader(reader), mode="r|*") as archive:
    for member in archive:
        if not member.isfile():
            continue
        extracted = archive.extractfile(member)
        if extracted is None:
            continue
        data = extracted.read(max_bytes)
        return data, member.size, self._detect_mime_type(data)
```

`_IteratorReader.close` must call `close` on the Docker iterator/response so the remaining archive is not drained.

Add `size_bytes` and `truncated` to `ManifestFileRef`. In `BaseWorkspaceFS._build_manifest_output`, set them from the fetcher's raw size and retained length for every manifest entry; tests assert the metadata survives both inline and manifest output paths.

- [ ] **Step 6: Propagate limits through SkillRun**

Use declarative `outputs.max_total_bytes` as the stream and artifact budget, falling back to the SDK constants. Resolve `outputs.globs` against the workspace and pass those absolute globs plus all limits into `WorkspaceRunProgramSpec`. Add observed byte counts, truncation booleans, `execution_started`, `termination_confirmed`, and `failure_kind` to `SkillRunOutput`. `TrpcSkillToolSetHarness._run_from_skill_output` copies them into `SandboxRun` without manufacturing `execution_started=True`, and preserves per-file `size_bytes/truncated`. Do not re-truncate already bounded stdout/stderr with `_truncate_output`; retain that fallback only for runtimes that return zero limits metadata.

Refactor the example's `create_skill_tool_set` into an owned context that retains the workspace runtime. `TrpcSkillToolSetHarness` opens that context once for the complete allowed-request batch and implements idempotent `close()`. `SandboxRunner.run` enters `finally` after all requests, including execution and callback exceptions, then uses `close = getattr(harness, "close", None)` and calls it only when callable. The production container harness must implement it, LocalSkillHarness implements an explicit no-op, and legacy/injected test harnesses without `close` remain compatible. Cleanup finishes before PR1's temporary execution-plan input context exits. A single production review therefore owns at most one container runtime and leaves no container for atexit cleanup.

- [ ] **Step 7: Run SDK regressions**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_limits.py -v
python -m pytest tests/examples -o addopts= -q
python -m pytest tests/code_executors/container/test_container_cli_limits.py -v
python -m pytest tests/code_executors/container/test_container_cli.py -v
python -m pytest tests/code_executors/container/test_container_ws_runtime.py -v
python -m pytest tests/skills/tools/test_skill_run.py -v
python -m pytest tests/utils/test_execute_cmd.py -v
```

Expected: all selected tests pass; no test relies on a live Docker daemon.

- [ ] **Step 8: Commit**

```powershell
$stage = @(
  'trpc_agent_sdk/code_executors/_types.py',
  'trpc_agent_sdk/code_executors/_base_workspace_runtime.py',
  'trpc_agent_sdk/code_executors/container/_container_cli.py',
  'trpc_agent_sdk/code_executors/container/_container_ws_runtime.py',
  'trpc_agent_sdk/skills/tools/_skill_run.py',
  'examples/skills_code_review_agent/agent/agent_factory.py',
  'examples/skills_code_review_agent/agent/sandbox_runner.py',
  'tests/examples/test_skills_code_review_agent_limits.py',
  'tests/code_executors/container/test_container_cli_limits.py',
  'tests/code_executors/container/test_container_cli.py',
  'tests/code_executors/container/test_container_ws_runtime.py',
  'tests/skills/tools/test_skill_run.py'
)
git add @stage
git commit -m "fix(executor): terminate bounded container runs"
```

### Task 3: Apply code-review container resource isolation

**Files:**
- Modify: `trpc_agent_sdk/code_executors/container/_container_cli.py:137-176`
- Modify: `trpc_agent_sdk/code_executors/container/_container_ws_runtime.py:949-957`
- Modify: `examples/skills_code_review_agent/agent/agent_factory.py:16-42,53-91`
- Create: `tests/examples/test_skills_code_review_agent_container_config.py`
- Modify: `tests/examples/test_skills_code_review_agent_policy.py`

- [ ] **Step 1: Write failing host-config and output-spec tests**

```python
from agent.agent_factory import REVIEW_CONTAINER_HOST_CONFIG
from agent.agent_factory import build_skill_run_calls


def test_review_container_has_all_required_limits():
    assert REVIEW_CONTAINER_HOST_CONFIG == {
        "network_mode": "none",
        "mem_limit": "256m",
        "memswap_limit": "256m",
        "nano_cpus": 1_000_000_000,
        "pids_limit": 64,
        "read_only": True,
        "tmpfs": {
            "/tmp": "rw,nosuid,nodev,noexec,size=64m",
        },
    }


def test_each_call_declares_one_bounded_output():
    for call in build_skill_run_calls("/tmp/review.json"):
        assert call["output_files"] == []
        assert call["outputs"]["max_files"] == 1
        assert call["outputs"]["max_file_bytes"] == 256 * 1024
        assert call["outputs"]["max_total_bytes"] == 256 * 1024
        assert len(call["outputs"]["globs"]) == 1


def test_runtime_capabilities_report_isolation_truthfully():
    capabilities = _runtime_with_review_config().describe()
    assert capabilities.network_allowed is False
    assert capabilities.max_disk_bytes == 64 * 1024 * 1024
```

In the Docker client test, mock `containers.run` and assert the same six resource keys are forwarded.

- [ ] **Step 2: Run config tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_container_config.py -v
python -m pytest tests/examples/test_skills_code_review_agent_policy.py -k "output" -v
```

Expected: the output-spec regression already passes from PR1; the resource-config and truthful-capabilities tests fail.

- [ ] **Step 3: Forward an explicit Docker host-config allowlist**

In `ContainerClient._init_container`, forward only:

```python
for key in (
    "mem_limit",
    "memswap_limit",
    "nano_cpus",
    "pids_limit",
    "read_only",
    "tmpfs",
    "shm_size",
):
    if key in self.host_config:
        run_kwargs[key] = self.host_config[key]
```

Keep `network_mode="none"` as the default and never pass arbitrary host-config keys. Change `ContainerWorkspaceRuntime.describe` to derive `network_allowed` and `max_disk_bytes` from the applied config instead of returning `network_allowed=True`.

- [ ] **Step 4: Configure the review runtime and bounded outputs**

Define the exact `REVIEW_CONTAINER_HOST_CONFIG` from the test and pass it to `create_container_workspace_runtime(host_config=...)`. Keep each PR1 SkillRun call in this bounded declarative shape:

```python
"output_files": [],
"outputs": {
    "globs": [f"{workspace_path}/out/findings.json"],
    "max_files": 1,
    "max_file_bytes": 256 * 1024,
    "max_total_bytes": 256 * 1024,
    "save": False,
    "inline": True,
},
```

Use the matching output filename for the other two commands. PR1 already introduced immutable `ExecutionRequest.output_spec` and PolicyGate budget validation; keep those tests here as regression coverage rather than redefining the model.

- [ ] **Step 5: Run config, policy, and SkillRun tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_container_config.py -v
python -m pytest tests/examples/test_skills_code_review_agent_policy.py -v
python -m pytest tests/skills/tools/test_skill_run.py -v
```

Expected: all selected tests pass.

- [ ] **Step 6: Commit**

```powershell
$stage = @(
  'trpc_agent_sdk/code_executors/container/_container_cli.py',
  'trpc_agent_sdk/code_executors/container/_container_ws_runtime.py',
  'examples/skills_code_review_agent/agent/agent_factory.py',
  'tests/examples/test_skills_code_review_agent_container_config.py',
  'tests/examples/test_skills_code_review_agent_policy.py'
)
git add @stage
git commit -m "fix(review): isolate code review containers"
```

### Task 4: Report truthful execution telemetry

**Files:**
- Modify: `examples/skills_code_review_agent/agent/models.py:135-220`
- Modify: `examples/skills_code_review_agent/agent/sandbox_runner.py:384-556`
- Modify: `examples/skills_code_review_agent/agent/telemetry.py:20-52`
- Modify: `examples/skills_code_review_agent/agent/report_builder.py:24-263`
- Modify: `examples/skills_code_review_agent/schema.sql`
- Create: `examples/skills_code_review_agent/migrations/004_review_telemetry.sql`
- Modify: `examples/skills_code_review_agent/agent/storage.py`
- Modify: `tests/examples/test_skills_code_review_agent_lifecycle.py`
- Modify: `tests/examples/test_skills_code_review_agent_storage.py`

- [ ] **Step 1: Add a failing telemetry accounting test**

```python
def _finding(severity: str):
    return Finding(
        severity=severity,
        category="security",
        file="app.py",
        line=1,
        title="unsafe call",
        evidence="unsafe()",
        recommendation="use safe call",
        confidence=0.9,
        source=["test"],
    )


def _intercept(decision: str, index: int):
    error_kind = {
        "allow": "",
        "deny": "policy_denied",
        "needs_human_review": "approval_required",
    }[decision]
    return FilterIntercept(
        intercept_id=f"filter-{index}",
        task_id="task-1",
        request_id=f"task-1:skill-run:{index}",
        decision=decision,
        error_kind=error_kind,
        reason=decision,
        runtime="container",
        created_at=DRY_RUN_TIMESTAMP,
    )


def _run(
    *,
    index: int,
    duration_ms: int = 0,
    failure_kind: str = "",
    execution_started: bool = True,
):
    return SandboxRun(
        run_id=f"sandbox-{index}",
        task_id="task-1",
        request_id=f"task-1:skill-run:{index}",
        runtime="container",
        decision="allow",
        duration_ms=duration_ms,
        failure_kind=failure_kind,
        execution_started=execution_started,
        created_at=DRY_RUN_TIMESTAMP,
    )


def test_telemetry_counts_attempts_execution_time_and_failure_kinds():
    telemetry = build_telemetry(
        task_id="task-1",
        task_status=ReviewTaskStatus.BLOCKED,
        task_failure_kind="",
        parsed_diff=ParsedDiff(changed_files=["a.py"], total_added_lines=2),
        findings=[_finding("high")],
        warnings=[],
        needs_human_review=[],
        filter_intercepts=[
            _intercept("allow", 1),
            _intercept("deny", 2),
            _intercept("allow", 3),
            _intercept("allow", 4),
            _intercept("needs_human_review", 5),
        ],
        sandbox_runs=[
            _run(index=1, duration_ms=30),
            _run(index=3, duration_ms=20, failure_kind="output_limit_exceeded"),
            _run(
                index=4,
                failure_kind="runtime_unavailable",
                execution_started=False,
            ),
        ],
        redaction_summary=RedactionSummary(total_redactions=2),
        debug_dropped_count=1,
        elapsed_ms=75,
        dry_run=False,
    )
    assert telemetry.orchestration_elapsed_ms == 75
    assert telemetry.sandbox_elapsed_ms == 50
    assert telemetry.tool_attempts_count == 5
    assert telemetry.tool_executed_count == 2
    assert telemetry.exception_kind_distribution == {
        "approval_required": 1,
        "output_limit_exceeded": 1,
        "policy_denied": 1,
        "runtime_unavailable": 1,
    }
    assert telemetry.severity_distribution == {"high": 1}
    assert telemetry.output_limit_exceeded_count == 1
```

- [ ] **Step 2: Run lifecycle/storage tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_lifecycle.py tests/examples/test_skills_code_review_agent_storage.py -k "telemetry" -v
```

Expected: FAIL because the new counters do not exist.

- [ ] **Step 3: Add canonical counters and schema migration**

Keep PR2's required `task_status` and add to `TelemetrySummary`:

```python
orchestration_elapsed_ms: int = 0
sandbox_elapsed_ms: int = 0
tool_attempts_count: int = 0
tool_executed_count: int = 0
severity_distribution: dict[str, int] = Field(default_factory=dict)
exception_kind_distribution: dict[str, int] = Field(default_factory=dict)
output_limit_exceeded_count: int = 0
```

Keep `elapsed_ms` as a deprecated alias equal to `orchestration_elapsed_ms` for report-schema compatibility. Add required `task_failure_kind` beside PR2's required `task_status`. Compute attempts from all persisted Filter decisions, execution count from runs whose `execution_started` is true, sandbox time from run durations, and exception kinds from the union of non-empty `FilterIntercept.error_kind`, `SandboxRun.failure_kind`, and that task failure kind. A runtime-unavailable row is an audited attempt but not an execution. Count `policy_denied`, `approval_required`, startup failures, timeouts, non-zero exits, artifact validation failures, output-limit termination, storage errors, and orchestration errors with their canonical names; do not substitute raw exception class/message strings.

Migration 004 adds `execution_started`, observed-byte, and termination columns to `sandbox_runs`. The versioned migration runner introduced in PR2 applies it to old SQLite databases, backfills `execution_started=1` except for `failure_kind='runtime_unavailable'`, and the storage round-trip test asserts every new field. A fresh-database test asserts migration versions `002_review_lifecycle`, `003_request_identity`, and `004_review_telemetry` each have exactly one row after two `ReviewStorage` initializations. Do not reintroduce `_ensure_schema_compat`.

- [ ] **Step 4: Upgrade report schema and presentation**

Retain PR2's `ReviewReport.schema_version="2.0"` and required task status. Add attempts/executions, total/sandbox time, severity distribution, exception distribution, observed/retained bytes, and termination reason to JSON and Markdown. The report conclusion still follows PR2 terminal status before findings.

- [ ] **Step 5: Run telemetry and report regressions**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_lifecycle.py -v
python -m pytest tests/examples/test_skills_code_review_agent_storage.py -v
python -m pytest tests/examples/test_skills_code_review_agent_e2e.py -k "report" -v
```

Expected: all selected tests pass and stored/JSON/Markdown failure totals agree.

- [ ] **Step 6: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/models.py',
  'examples/skills_code_review_agent/agent/sandbox_runner.py',
  'examples/skills_code_review_agent/agent/telemetry.py',
  'examples/skills_code_review_agent/agent/report_builder.py',
  'examples/skills_code_review_agent/agent/storage.py',
  'examples/skills_code_review_agent/schema.sql',
  'examples/skills_code_review_agent/migrations/004_review_telemetry.sql',
  'tests/examples/test_skills_code_review_agent_lifecycle.py',
  'tests/examples/test_skills_code_review_agent_storage.py',
  'tests/examples/test_skills_code_review_agent_e2e.py'
)
git add @stage
git commit -m "feat(review): report execution telemetry"
```

### Task 5: Measure independent labeled acceptance corpora

**Files:**
- Create: `examples/skills_code_review_agent/eval/high_risk_cases.json`
- Create: `examples/skills_code_review_agent/eval/safe_cases.json`
- Create: `examples/skills_code_review_agent/eval/secret_cases.json`
- Create: `examples/skills_code_review_agent/agent/evaluator.py`
- Create: `tests/examples/test_skills_code_review_agent_acceptance.py`
- Modify: `examples/skills_code_review_agent/agent/cli.py`

- [ ] **Step 1: Create immutable labels before running the evaluator**

`high_risk_cases.json` contains these ten IDs and one explicit expected `(file,line,category)` key per case:

```text
shell_format_variant -> src/edge/archive.py:13:security
os_system_header_variant -> src/edge/cleanup.py:27:security
eval_query_variant -> src/edge/formula.py:41:security
yaml_loader_variant -> src/edge/importer.py:55:security
pickle_cookie_variant -> src/edge/session.py:69:security
sql_percent_variant -> src/edge/accounts.py:83:security
sqlite_lifecycle_variant -> src/edge/cache.py:97:database
aiohttp_lifecycle_variant -> src/edge/gateway.py:111:async_resource
production_secret_variant -> src/edge/runtime.py:125:secret
missing_tests_variant -> src/edge/feature.py:139:test
```

Each JSON row contains manually frozen `changed_files` and `added_lines` variants with new IDs, paths, line numbers, and source spellings; none is copied or imported from `tests/examples/test_skills_code_review_agent_hidden_like.py`. Add a test that `evaluator.py` imports only files under `examples/skills_code_review_agent/eval` and never imports a test module.

`safe_cases.json` contains fifteen labeled safe locations: argv subprocess, parameterized DB-API SQL, SQLAlchemy bindparam, context-managed file, context-managed aiohttp session, SQLite try/finally close, `yaml.safe_load`, trusted local pickle bytes, test-fixture API key, test-fixture password, escaped shell text with `shell=False`, async context manager file, transaction context manager, production change with matching test, and documentation-only change. Every non-documentation production-safe case includes a matching test path in its frozen `changed_files`, so the independent missing-test rule is not accidentally counted against an otherwise safe construct.

`secret_cases.json` contains twenty synthetic values covering password, passwd, pwd, token, access_token, refresh_token, api_key, apiKey, client_secret, authorization Bearer, JSON, YAML, dotenv, shell export, Python assignment, URL credentials, query-string token, spaces in passwords, dummy values, and repeated occurrences. Each row contains `id`, `text`, and the exact `raw_value`; none is a real credential.

- [ ] **Step 2: Write failing metric and independence tests**

```python
def test_labeled_acceptance_thresholds(tmp_path):
    summary = evaluate_corpora(
        output_dir=tmp_path,
        db_url=f"sqlite:///{tmp_path / 'acceptance.db'}",
    )
    assert summary.high_risk_recall >= 0.80
    assert summary.safe_false_positive_rate <= 0.15
    assert summary.secret_redaction_recall >= 0.95
    assert summary.raw_secret_leaks == []


def test_expected_labels_are_not_derived_from_predictions():
    expected = {("app.py", 7, "security")}
    predictions = {("app.py", 7, "database")}
    assert detection_recall(expected, predictions) == 0.0


def test_safe_false_positive_rate_counts_every_wrong_finding():
    safe_locations = 10
    predictions = {
        ("a.py", 1, "security"),
        ("b.py", 2, "database"),
    }
    assert false_positive_rate(safe_locations, predictions) == 0.2


def test_all_public_fixtures_have_reports_and_audit_rows(tmp_path):
    summary = evaluate_public_fixtures(
        output_dir=tmp_path,
        db_url=f"sqlite:///{tmp_path / 'fixtures.db'}",
    )
    assert {item.fixture for item in summary.fixtures} == set(FIXTURE_ORDER)
    for item in summary.fixtures:
        assert Path(item.json_path).exists()
        assert Path(item.markdown_path).exists()
        assert item.audit_counts["tasks"] == 1
        assert item.audit_counts["inputs"] == 1
        assert item.audit_counts["filter_intercepts"] == 3
        assert item.audit_counts["sandbox_runs"] == 3
        assert item.audit_counts["findings"] == item.findings_count
        assert item.audit_counts["telemetry_summaries"] == 1
        assert item.audit_counts["reports"] == 1
    assert sum(item.findings_count for item in summary.fixtures) > 0


def test_dry_run_acceptance_finishes_under_120_seconds(tmp_path):
    started = time.monotonic()
    evaluate_acceptance(
        output_dir=tmp_path,
        db_url=f"sqlite:///{tmp_path / 'full.db'}",
        include_fixtures=True,
    )
    assert time.monotonic() - started < 120
```

- [ ] **Step 3: Implement metric primitives**

```python
def detection_recall(expected: set[ResultKey], predictions: set[ResultKey]) -> float:
    return 1.0 if not expected else len(expected & predictions) / len(expected)


def false_positive_rate(safe_locations: int, predictions: set[ResultKey]) -> float:
    if safe_locations <= 0:
        raise ValueError("safe corpus must contain labeled locations")
    return len(predictions) / safe_locations
```

`evaluate_corpora` loads JSON labels and evaluates each high-risk/safe case in isolation so a test file in one case cannot suppress another case's missing-test rule. A predicted detection key comes from the union of normalized findings, warnings, and needs-human-review items, excluding operational `category="sandbox"` warnings. Compare those keys to stored labels. For secrets, redaction recall is the count whose `sha256(raw_value)` digest appears in `RedactionSummary.events`, divided by twenty. It writes every report/database under the passed output directory/database URL and scans JSON, Markdown, and `ReviewStorage.dump_task_text` for every raw value.

Return and write `acceptance_summary.json` with counts, numerators, denominators, ratios, per-case misses/false positives, and raw leak locations. Never calculate expected keys from emitted findings.

`evaluate_public_fixtures` runs all eight fixture names into distinct output directories, queries each task ID, and returns the exact table counts and report paths used by the fixture audit test.

- [ ] **Step 4: Add the acceptance CLI**

Add:

```powershell
$testOut = Join-Path $env:TEMP ('issue-92-acceptance-' + [guid]::NewGuid().ToString('N'))
$testDb = 'sqlite:///' + (Join-Path $testOut 'acceptance.db').Replace('\', '/')
python examples/skills_code_review_agent/run_review.py eval-acceptance --dry-run --runtime local --include-fixtures --output-dir $testOut --db-url $testDb
```

The command exits non-zero when any threshold fails and prints the summary path. `--include-fixtures` runs corpora and all eight public fixtures inside the same monotonic wall-clock interval and records `wall_clock_seconds`; this single full interval must be below 120 seconds.

- [ ] **Step 5: Run corpus tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_acceptance.py -v
$testOut = Join-Path $env:TEMP ('issue-92-acceptance-' + [guid]::NewGuid().ToString('N'))
$testDb = 'sqlite:///' + (Join-Path $testOut 'acceptance.db').Replace('\', '/')
python examples/skills_code_review_agent/run_review.py eval-acceptance --dry-run --runtime local --include-fixtures --output-dir $testOut --db-url $testDb
```

Expected: tests and CLI exit 0, all three ratios meet thresholds, and no raw secret location is reported.

- [ ] **Step 6: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/eval/high_risk_cases.json',
  'examples/skills_code_review_agent/eval/safe_cases.json',
  'examples/skills_code_review_agent/eval/secret_cases.json',
  'examples/skills_code_review_agent/agent/evaluator.py',
  'examples/skills_code_review_agent/agent/cli.py',
  'tests/examples/test_skills_code_review_agent_acceptance.py'
)
git add @stage
git commit -m "test(review): add independent acceptance corpora"
```

### Task 6: Require real Docker and full Issue #92 evidence in CI

**Files:**
- Create: `tests/examples/test_skills_code_review_agent_docker.py`
- Modify: `tests/examples/test_skills_code_review_agent_acceptance.py`
- Modify: `pyproject.toml`
- Modify: `.github/workflows/ci.yml`
- Modify: `examples/skills_code_review_agent/DESIGN.md`
- Modify: `examples/skills_code_review_agent/README.md`
- Modify: `examples/skills_code_review_agent/skills/code-review/scripts/smoke_test.py`

- [ ] **Step 1: Write the required Docker and documentation tests**

```python
import re
import time

import pytest


@pytest.mark.docker_required
def test_real_container_review_stages_executes_collects_and_persists(tmp_path):
    started = time.monotonic()
    report = ReviewOrchestrator(
        db_url=f"sqlite:///{tmp_path / 'review.db'}",
        output_dir=tmp_path / "out",
    ).review(fixture="security", runtime="container", dry_run=True)
    rows = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}").query_task(report.task_id)
    assert report.task_status == "completed"
    assert len(report.sandbox_runs) == 3
    assert all(item.runtime == "container" for item in report.sandbox_runs)
    assert all(item.output_files for item in report.sandbox_runs)
    smoke_run = next(
        item for item in report.sandbox_runs
        if item.command[1] == "scripts/smoke_test.py"
    )
    smoke = json.loads(next(iter(smoke_run.output_files.values())))
    assert smoke["input_contained"] is True
    assert smoke["network_disabled"] is True
    assert len(rows["sandbox_runs"]) == 3
    assert (tmp_path / "out" / "review_report.json").exists()
    assert time.monotonic() - started < 120


def test_design_contains_300_to_500_han_characters():
    text = (EXAMPLE_DIR / "DESIGN.md").read_text(encoding="utf-8")
    han_count = len(re.findall(r"[\u3400-\u4dbf\u4e00-\u9fff]", text))
    assert 300 <= han_count <= 500
```

Update `smoke_test.py` to resolve its input path and assert it is under `$SKILLS_DIR/code-review/work/inputs` (equivalently `$WORKSPACE_DIR/skills/code-review/work/inputs`), and not under the Skill scripts directory or any serialized host source path. It also attempts a short socket connection to a fixed external test address and reports `network_disabled=True` only when the attempt fails. These booleans are evidence fields, not findings.

Add a live Docker resource test that creates `ContainerClient(ContainerConfig(host_config=REVIEW_CONTAINER_HOST_CONFIG))`, reloads `container.attrs`, and asserts `NetworkMode=none`, `Memory=268435456`, `MemorySwap=268435456`, `NanoCpus=1000000000`, `PidsLimit=64`, `ReadonlyRootfs=True`, and a 64 MiB `/tmp` tmpfs. It then runs timeout, stream-overflow, artifact-overflow, and “leader exits while descendant sleeps” probes whose child PID files are read and checked after termination; the last probe must report `orchestration_error` and its late marker must remain absent. Wrap the client in `try/finally` and call public `close()`. For the orchestration path, capture the created container ID and assert Docker inspection reports it absent after `review()` returns; this is the live counterpart of Task 2's close-on-exception regression.

- [ ] **Step 2: Register and run Docker tests locally when available**

Register `docker_required` in pytest configuration. These tests may be deselected in the fast unit job, but must not call `pytest.skip`; Docker connection failure is a test failure.

```powershell
docker info
python -m pytest tests/examples/test_skills_code_review_agent_docker.py -m docker_required -v
```

Expected: Docker info and all real-container tests pass.

- [ ] **Step 3: Expand lint and whitespace scope**

In CI, collect changed Python files under:

```text
trpc_agent_sdk/
examples/skills_code_review_agent/
tests/examples/
tests/code_executors/
tests/skills/
```

Run YAPF and flake8 on that complete set. With checkout `fetch-depth: 0`, add this unconditional whitespace step:

```bash
if [ "${{ github.event_name }}" = "pull_request" ]; then
  BASE="origin/${{ github.base_ref }}"
else
  BASE="$(git rev-parse HEAD^)"
fi
git diff --check "$BASE"...HEAD
```

- [ ] **Step 4: Add a required Docker integration job**

Add a non-optional job on the Docker-capable self-hosted runner:

```yaml
  code-review-docker:
    runs-on: [self-hosted, trpc-agent-python-ci]
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - run: pip install -r requirements-test.txt
      - run: docker info
      - run: python -m pytest tests/examples/test_skills_code_review_agent_docker.py -m docker_required -v
```

The normal unit job keeps the existing coverage report and `--cov-fail-under=80` while adding `-m "not docker_required"`. Requiring both jobs in branch protection is a repository-setting handoff after the workflow lands; record it in the PR checklist rather than claiming YAML can configure branch protection.

- [ ] **Step 5: Update the 300-500 Han-character design and acceptance matrix**

Replace `DESIGN.md` with this checked content:

```markdown
# 设计说明

本示例把自动代码审查组织为七段固定流水线：输入解析、脱敏边界、策略门禁、沙箱执行、结果规范化、审计存储和报告生成。输入解析器支持补丁、仓库和受仓库根目录约束的文件列表；仓库模式同时收集暂存、未暂存与未跟踪改动。任何原始内容进入沙箱前都先脱敏，异常、日志、输出文件、数据库连接信息和最终报告在持久化前还会再次经过同一边界。

每次工具调用都被转换成不可变请求，命令、工作目录、输入映射、输出预算、环境变量、网络和超时必须整体通过策略检查。拒绝或需要人工批准的请求不会暂存文件，也不会执行。自动运行模式只选择容器一次，容器不可用时停止并记录失败，不会暗中降级到本地；本地模式仅供显式开发验证。

任务按照已创建、运行中、完成、带错误完成、已阻止和失败流转。每个策略决定与每次允许的执行尝试都会立即写入审计表，启动失败也保留运行记录；终态、指标和报告在同一事务提交。主机规则与沙箱产物统一执行结构校验、脱敏、置信度分流和按文件、行号、类别去重。

执行器在运行期间限制标准输出、错误输出和产物字节数，超时或超限会终止进程组并确认停止。容器同时限制处理器、内存、进程数、网络和临时磁盘。验收使用独立冻结语料计算高风险召回率、安全样例误报率和秘密脱敏召回率，并通过真实容器、八个公开样例、数据库查询及两种报告验证完整链路。
```

Update README commands and replace every “optional container” or “auto falls back local” statement with the final required behavior.

- [ ] **Step 6: Run the full acceptance gate**

```powershell
python -m pytest tests/examples -m "not docker_required" -o addopts= -q
python -m pytest tests/code_executors/container -o addopts= -q
python -m pytest tests/skills/tools/test_skill_run.py -o addopts= -q
$testOut = Join-Path $env:TEMP ('issue-92-acceptance-' + [guid]::NewGuid().ToString('N'))
$testDb = 'sqlite:///' + (Join-Path $testOut 'acceptance.db').Replace('\', '/')
$started = Get-Date
python examples/skills_code_review_agent/run_review.py eval-acceptance --dry-run --runtime local --include-fixtures --output-dir $testOut --db-url $testDb
$elapsed = (Get-Date) - $started
if ($elapsed.TotalSeconds -ge 120) { throw "dry-run acceptance exceeded 120 seconds" }
docker info
python -m pytest tests/examples/test_skills_code_review_agent_docker.py -m docker_required -v
$files = @(git diff --name-only --diff-filter=ACM origin/main...HEAD -- '*.py')
if ($files) {
  python -m flake8 @files
  python -m yapf --diff @files
}
git diff --check origin/main...HEAD
```

Expected: every command exits 0, YAPF and whitespace checks print no diff, and elapsed time is below 120 seconds.

- [ ] **Step 7: Commit**

```powershell
$stage = @(
  '.github/workflows/ci.yml',
  'pyproject.toml',
  'examples/skills_code_review_agent/DESIGN.md',
  'examples/skills_code_review_agent/README.md',
  'examples/skills_code_review_agent/skills/code-review/scripts/smoke_test.py',
  'tests/examples/test_skills_code_review_agent_docker.py',
  'tests/examples/test_skills_code_review_agent_acceptance.py'
)
git add @stage
git diff --cached --check
git commit -m "test(review): require issue 92 acceptance gates"
```

## PR4 exit checklist

- [ ] Local and container timeout tests prove the supervised process group is gone.
- [ ] stdout, stderr, and archive readers retain and read at most their configured bound; truncation markers remain structured metadata.
- [ ] Output-directory growth beyond the task budget terminates the execution and records `output_limit_exceeded`.
- [ ] Live Docker inspection proves CPU, memory, PID, network, read-only-root, and 64 MiB temporary-disk limits.
- [ ] Telemetry includes total/sandbox time, attempts/executions, findings/severity, failure kinds, truncations, and redactions.
- [ ] Independent high-risk recall is at least 0.80, safe false-positive rate at most 0.15, and secret recall at least 0.95 with zero persisted raw leaks.
- [ ] All eight fixtures write JSON, Markdown, and the complete SQL audit chain.
- [ ] The required Docker CI job, full lint scope, YAPF, and `git diff --check` pass.
- [ ] `DESIGN.md` contains 300-500 Chinese Han characters and the dry-run acceptance gate finishes in under 120 seconds.
