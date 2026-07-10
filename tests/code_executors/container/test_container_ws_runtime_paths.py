# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Regression tests for container workspace runtime path handling."""

from __future__ import annotations

import pytest

from trpc_agent_sdk.code_executors.container._container_ws_runtime import (
    ContainerWorkspaceFS, )
from trpc_agent_sdk.code_executors.container._container_ws_runtime import RuntimeConfig
from trpc_agent_sdk.code_executors.container._container_ws_runtime import _container_name
from trpc_agent_sdk.code_executors.container._container_ws_runtime import _container_parent
from trpc_agent_sdk.code_executors.container._container_ws_runtime import _container_path
from trpc_agent_sdk.code_executors.container._container_ws_runtime import _shell_quote


class _ExecResult:
    exit_code = 0
    stderr = ""


class _FakeContainer:

    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    async def exec_run(self, *, cmd, command_args):  # noqa: ANN001
        self.commands.append(cmd)
        return _ExecResult()


def test_container_path_joins_posix_segments():
    assert _container_path("/tmp/ws", "skills", "code-review") == "/tmp/ws/skills/code-review"


def test_container_path_normalizes_windows_separators():
    assert (_container_path("/tmp/ws", "skills\\code-review",
                            "out\\findings.json") == "/tmp/ws/skills/code-review/out/findings.json")


def test_container_parent_and_name():
    path = "/tmp/ws/skills/code-review/out/findings.json"
    assert _container_parent(path) == "/tmp/ws/skills/code-review/out"
    assert _container_name(path) == "findings.json"


def test_container_path_collapses_redundant_slashes_without_host_separators():
    path = _container_path("/tmp//ws/", "/skills//", "code-review//out\\findings.json")

    assert path == "/tmp/ws/skills/code-review/out/findings.json"
    assert "\\" not in path


@pytest.mark.asyncio
async def test_stage_workspace_input_shell_quotes_container_paths():
    container = _FakeContainer()
    fs = ContainerWorkspaceFS(container, RuntimeConfig())
    src = "/tmp/ws/skills/code review/it's.txt"
    dst = "/tmp/ws/work/inputs/out file's.txt"

    await fs._stage_workspace_input(src, dst, "copy")

    command = container.commands[0][-1]
    assert _shell_quote(src) in command
    assert _shell_quote(dst) in command
