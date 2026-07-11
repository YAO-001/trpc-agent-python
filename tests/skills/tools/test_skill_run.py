# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.

import logging
import os
from unittest.mock import AsyncMock, MagicMock

import pytest
from trpc_agent_sdk.code_executors import BaseWorkspaceRuntime
from trpc_agent_sdk.code_executors import WorkspaceCapabilities
from trpc_agent_sdk.code_executors import WorkspaceInfo
from trpc_agent_sdk.code_executors import WorkspaceRunResult
from trpc_agent_sdk.context import create_agent_context
from trpc_agent_sdk.skills._common import loaded_state_key
from trpc_agent_sdk.skills.stager import SkillStageResult
from trpc_agent_sdk.skills.tools import _skill_run as skill_run_module
from trpc_agent_sdk.skills.tools._common import inline_json_schema_refs
from trpc_agent_sdk.skills.tools._skill_run import ArtifactInfo
from trpc_agent_sdk.skills.tools._skill_run import SkillRunFile
from trpc_agent_sdk.skills.tools._skill_run import SkillRunInput
from trpc_agent_sdk.skills.tools._skill_run import SkillRunOutput
from trpc_agent_sdk.skills.tools._skill_run import SkillRunTool
from trpc_agent_sdk.skills.tools._skill_run import _build_editor_wrapper_script
from trpc_agent_sdk.skills.tools._skill_run import _filter_failed_empty_outputs
from trpc_agent_sdk.skills.tools._skill_run import _is_text_mime
from trpc_agent_sdk.skills.tools._skill_run import _select_primary_output
from trpc_agent_sdk.skills.tools._skill_run import _should_inline_file_content
from trpc_agent_sdk.skills.tools._skill_run import _split_command_line
from trpc_agent_sdk.skills.tools._skill_run import _truncate_output
from trpc_agent_sdk.skills.tools._skill_run import _workspace_ref


def _make_tool() -> SkillRunTool:
    repo = MagicMock()
    repo.workspace_runtime = MagicMock()
    return SkillRunTool(repository=repo)


class TestSchemaHelpers:

    def test_inline_json_schema_refs(self):
        schema = {"$defs": {"X": {"type": "string"}}, "properties": {"x": {"$ref": "#/$defs/X"}}}
        out = inline_json_schema_refs(schema)
        assert "$defs" not in out
        assert out["properties"]["x"]["type"] == "string"


class TestModuleHelpers:

    def test_is_text_mime(self):
        assert _is_text_mime("text/plain") is True
        assert _is_text_mime("application/json") is True
        assert _is_text_mime("image/png") is False

    def test_should_inline_file_content(self):
        from trpc_agent_sdk.code_executors import CodeFile
        f = CodeFile(name="a.txt", content="ok", mime_type="text/plain", size_bytes=2)
        assert _should_inline_file_content(f) is True

    def test_truncate_output(self):
        s, truncated = _truncate_output("x" * 20000)
        assert truncated is True
        assert len(s) <= 16 * 1024

    def test_workspace_ref(self):
        assert _workspace_ref("a.txt") == "workspace://a.txt"

    def test_filter_failed_empty_outputs(self):
        files = [SkillRunFile(name="a.txt", content="", size_bytes=0)]
        kept, warns = _filter_failed_empty_outputs(1, False, files)
        assert kept == []
        assert warns

    def test_select_primary_output(self):
        files = [
            SkillRunFile(name="b.txt", content="2", mime_type="text/plain"),
            SkillRunFile(name="a.txt", content="1", mime_type="text/plain"),
        ]
        best = _select_primary_output(files)
        assert best is not None
        assert best.name == "a.txt"

    def test_split_command_line(self):
        assert _split_command_line("python run.py") == ["python", "run.py"]
        with pytest.raises(ValueError):
            _split_command_line("a | b")

    def test_build_editor_wrapper_script(self):
        script = _build_editor_wrapper_script("/tmp/file")
        assert script.startswith("#!/bin/sh")
        assert "/tmp/file" in script


class TestModels:

    def test_run_models(self):
        inp = SkillRunInput(skill="s", command="echo hi")
        out = SkillRunOutput()
        art = ArtifactInfo(name="a.txt", version=1)
        assert inp.skill == "s"
        assert out.exit_code == 0
        assert art.version == 1


class TestSkillRunToolBasics:

    def test_resolve_cwd(self):
        tool = _make_tool()
        assert tool._resolve_cwd("", "skills/x") == "skills/x"
        assert tool._resolve_cwd("sub", "skills/x") == os.path.join("skills/x", "sub")

    def test_build_command(self):
        tool = _make_tool()
        cmd, args = tool._build_command("python run.py", "/tmp/ws", "skills/x")
        assert cmd == "bash"
        assert "-c" in args

    def test_get_repository(self):
        repo = MagicMock()
        repo.workspace_runtime = MagicMock()
        tool = SkillRunTool(repository=repo)
        ctx = MagicMock()
        assert tool._get_repository(ctx) is repo

    def test_repository_get_workspace_runtime_is_used(self):
        repo_runtime = MagicMock()
        repo = MagicMock()
        repo.workspace_runtime = repo_runtime
        resolved_runtime = MagicMock()
        repo.get_workspace_runtime = MagicMock(return_value=resolved_runtime)
        ctx = MagicMock()

        tool = SkillRunTool(repository=repo)

        assert tool._get_repository(ctx).get_workspace_runtime(ctx) is resolved_runtime
        repo.get_workspace_runtime.assert_called_once_with(ctx)

    def test_is_skill_loaded(self):
        tool = _make_tool()
        ctx = MagicMock()
        ctx.agent_name = ""
        ctx.actions = MagicMock()
        key = loaded_state_key(ctx, "test")
        ctx.actions.state_delta = {key: True}
        ctx.session_state = {}
        assert tool._is_skill_loaded(ctx, "test") is True


async def test_nonzero_stderr_is_not_logged(caplog, monkeypatch):
    raw = "raw-sdk-log-secret-987"

    class FakeWorkspaceRuntime(BaseWorkspaceRuntime):

        def __init__(self):
            self._manager = MagicMock()
            self._manager.create_workspace = AsyncMock(return_value=WorkspaceInfo(id="ws-1", path="/workspace"))
            self._fs = MagicMock()
            self._fs.collect = AsyncMock(return_value=[])
            self._runner = MagicMock()
            self._runner.run_program = AsyncMock(return_value=WorkspaceRunResult(
                stdout="fixture-result-path",
                stderr=f"client_secret={raw}",
                exit_code=7,
                duration=0.01,
            ))

        def manager(self, ctx=None):
            del ctx
            return self._manager

        def fs(self, ctx=None):
            del ctx
            return self._fs

        def runner(self, ctx=None):
            del ctx
            return self._runner

        def describe(self, ctx=None):
            del ctx
            return WorkspaceCapabilities()

    class FakeStager:

        async def stage_skill(self, request):
            del request
            return SkillStageResult(workspace_skill_dir="skills/fixture")

    runtime = FakeWorkspaceRuntime()
    repo = MagicMock()
    repo.get_workspace_runtime.return_value = runtime
    repo.skill_run_env.return_value = {}
    tool = SkillRunTool(
        repository=repo,
        skill_stager=FakeStager(),
        create_ws_name_cb=lambda _ctx: "ws-1",
    )
    ctx = MagicMock()
    ctx.agent_context = create_agent_context()
    ctx.agent_name = ""
    ctx.actions.state_delta = {}
    ctx.session_state = {}
    audit_logger = logging.getLogger("test.skill_run.audit")
    caplog.set_level(logging.DEBUG, logger=audit_logger.name)
    for level in ("debug", "info", "warning", "error", "fatal"):
        monkeypatch.setattr(skill_run_module.logger, level, getattr(audit_logger, level))

    payload = await tool._run_async_impl(
        tool_context=ctx,
        args={
            "skill": "fixture",
            "command": "python check.py"
        },
    )

    assert payload["stdout"] == "fixture-result-path"
    assert raw in payload["stderr"]
    stderr_bytes = len(payload["stderr"].encode("utf-8", errors="replace"))
    assert f"Skill program failed: exit_code=7, stderr_bytes={stderr_bytes}" in caplog.text
    assert caplog.records
    assert all(raw not in record.getMessage() for record in caplog.records)
