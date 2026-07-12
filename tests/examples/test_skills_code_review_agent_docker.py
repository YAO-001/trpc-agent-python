from __future__ import annotations

import json
import time
from contextlib import contextmanager
from pathlib import Path

import docker
import pytest

from agent.agent_factory import REVIEW_CONTAINER_HOST_CONFIG
from agent import agent_factory
from agent.orchestrator import ReviewOrchestrator
from agent.report_builder import ReportBuilder
from agent.storage import ReviewStorage
from trpc_agent_sdk.code_executors.container._container_cli import CommandArgs
from trpc_agent_sdk.code_executors.container._container_cli import ContainerClient
from trpc_agent_sdk.code_executors.container._container_cli import ContainerConfig


def _assert_container_removed(docker_client, container_id: str) -> None:
    deadline = time.monotonic() + 5
    while True:
        try:
            docker_client.containers.get(container_id)
        except docker.errors.NotFound:
            return
        if time.monotonic() >= deadline:
            pytest.fail(f"container {container_id} remained inspectable")
        time.sleep(0.05)


@pytest.mark.docker_required
def test_real_container_review_stages_executes_collects_and_persists(tmp_path):
    started = time.monotonic()
    report = ReviewOrchestrator(db_url=f"sqlite:///{tmp_path / 'review.db'}",
                                output_dir=tmp_path / "out").review(fixture="security",
                                                                    runtime="container",
                                                                    dry_run=True)
    rows = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}").query_task(report.task_id)
    assert report.task_status.value == "completed"
    assert len(report.sandbox_runs) == 3
    assert all(item.runtime == "container" and item.output_files for item in report.sandbox_runs)
    smoke_run = next(item for item in report.sandbox_runs if item.command[1] == "scripts/smoke_test.py")
    smoke = json.loads(next(iter(smoke_run.output_files.values())))
    assert smoke["input_contained"] is True
    assert smoke["network_probe_blocked"] is True
    assert len(rows["sandbox_runs"]) == 3
    assert (tmp_path / "out" / "review_report.json").exists()
    assert time.monotonic() - started < 120


@pytest.mark.docker_required
@pytest.mark.asyncio
async def test_live_container_limits_and_termination(tmp_path):
    del tmp_path
    client = ContainerClient(ContainerConfig(host_config=REVIEW_CONTAINER_HOST_CONFIG))
    try:
        client.container.reload()
        host = client.container.attrs["HostConfig"]
        assert host["NetworkMode"] == "none"
        assert host["Memory"] == 268435456
        assert host["MemorySwap"] == 268435456
        assert host["NanoCpus"] == 1000000000
        assert host["PidsLimit"] == 64
        assert host["ReadonlyRootfs"] is True
        assert "size=64m" in host["Tmpfs"]["/tmp"]

        def assert_pid_dead(pid_file):
            script = (f"test -s {pid_file} || exit 1; pid=$(cat {pid_file}); "
                      "case \"$pid\" in ''|*[!0-9]*) exit 1;; esac; "
                      "! kill -0 \"$pid\" 2>/dev/null")
            check = client.container.exec_run(["sh", "-c", script])
            assert check.exit_code == 0

        timeout_pid = "/tmp/issue92-timeout.pid"
        timeout_code = ("import os,pathlib,time;"
                        f"pathlib.Path({timeout_pid!r}).write_text(str(os.getpid()));time.sleep(30)")
        timeout = await client.exec_run(["python3", "-c", timeout_code], CommandArgs(timeout=1))
        assert timeout.failure_kind == "execution_timeout"
        assert timeout.termination_confirmed is True
        assert_pid_dead(timeout_pid)

        stream_pid = "/tmp/issue92-stream.pid"
        stream_code = (f"import os,pathlib,sys;pathlib.Path({stream_pid!r}).write_text(str(os.getpid()));"
                       "sys.stdout.write('x'*200000);sys.stdout.flush()")
        stream = await client.exec_run(
            ["python3", "-c", stream_code],
            CommandArgs(timeout=5, stdout_limit_bytes=4096, stderr_limit_bytes=4096),
        )
        assert stream.failure_kind == "output_limit_exceeded"
        assert stream.stdout_bytes_observed > 4096
        assert stream.termination_confirmed is True
        assert_pid_dead(stream_pid)

        artifact = "/tmp/issue92-large.bin"
        artifact_pid = "/tmp/issue92-artifact.pid"
        artifact_code = (f"import os,pathlib;pathlib.Path({artifact_pid!r}).write_text(str(os.getpid()));"
                         f"open({artifact!r},'wb').write(b'x'*200000)")
        artifact_result = await client.exec_run(
            ["python3", "-c", artifact_code],
            CommandArgs(timeout=5, output_globs=(artifact, ), output_limit_bytes=4096),
        )
        assert artifact_result.failure_kind == "output_limit_exceeded"
        assert artifact_result.termination_confirmed is True
        assert_pid_dead(artifact_pid)

        pid_file = "/tmp/issue92-child.pid"
        marker = "/tmp/issue92-late-marker"
        child = f"import pathlib,time;time.sleep(1);pathlib.Path({marker!r}).write_text('late')"
        parent = ("import pathlib,subprocess,sys;"
                  f"p=subprocess.Popen([sys.executable,'-c',{child!r}]);"
                  f"pathlib.Path({pid_file!r}).write_text(str(p.pid))")
        orphan = await client.exec_run(["python3", "-c", parent], CommandArgs(timeout=5))
        assert orphan.failure_kind == "orchestration_error"
        assert orphan.termination_confirmed is True
        assert_pid_dead(pid_file)
        time.sleep(1.2)
        marker_check = client.container.exec_run(["test", "!", "-e", marker])
        assert marker_check.exit_code == 0
    finally:
        container_id = client.container.id if client.container is not None else ""
        docker_client = client.client
        client.close()
        if container_id:
            _assert_container_removed(docker_client, container_id)


@pytest.mark.docker_required
@pytest.mark.parametrize("publication_error", [False, True])
def test_review_orchestration_removes_owned_container(tmp_path, monkeypatch, publication_error):
    observed: list[tuple[str, object]] = []
    original_factory = agent_factory.create_owned_skill_tool_set

    @contextmanager
    def observable_factory(runtime="container"):
        with original_factory(runtime) as tool_set:
            workspace_runtime = tool_set.repository.workspace_runtime
            owned_client = workspace_runtime.container
            observed.append((owned_client.container.id, owned_client.client))
            yield tool_set

    monkeypatch.setattr(agent_factory, "create_owned_skill_tool_set", observable_factory)
    if publication_error:
        monkeypatch.setattr(
            ReportBuilder, "commit", lambda *args, **kwargs:
            (_ for _ in ()).throw(RuntimeError("synthetic publication failure")))

    runner = ReviewOrchestrator(db_url=f"sqlite:///{tmp_path / 'review.db'}", output_dir=tmp_path / "out")
    if publication_error:
        with pytest.raises(RuntimeError, match="synthetic publication failure"):
            runner.review(fixture="security", runtime="container", dry_run=True)
    else:
        report = runner.review(fixture="security", runtime="container", dry_run=True)
        assert report.task_status.value == "completed"

    assert len(observed) == 1
    container_id, docker_client = observed[0]
    _assert_container_removed(docker_client, container_id)


def test_design_contains_300_to_500_han_characters():
    import re
    example_dir = Path(__file__).resolve().parents[2] / "examples" / "skills_code_review_agent"
    text = (example_dir / "DESIGN.md").read_text(encoding="utf-8")
    assert 300 <= len(re.findall(r"[\u3400-\u4dbf\u4e00-\u9fff]", text)) <= 500
    assert not any(marker in text for marker in ("锟", "鈥", "銆", "璁捐", "鏈"))
    assert not {"锛", "銆", "鈥", "鏈"} & set(text)
