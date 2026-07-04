# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Path normalization tests for the Docker container workspace runtime."""

from __future__ import annotations

from trpc_agent_sdk.code_executors.container._container_ws_runtime import _container_name
from trpc_agent_sdk.code_executors.container._container_ws_runtime import _container_parent
from trpc_agent_sdk.code_executors.container._container_ws_runtime import _container_path


def test_container_path_normalizes_windows_separators():
    assert _container_path("/tmp/run", "skills\\code-review", "out\\x.json") == (
        "/tmp/run/skills/code-review/out/x.json"
    )


def test_container_parent_uses_posix_semantics():
    assert _container_parent("/tmp/run/skills\\code-review/out/x.json") == (
        "/tmp/run/skills/code-review/out"
    )


def test_container_name_uses_posix_semantics():
    assert _container_name("skills\\code-review\\work\\inputs\\review_input.json") == "review_input.json"
