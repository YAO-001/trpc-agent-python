# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Resource-isolation configuration for the code-review container."""

from __future__ import annotations

from unittest.mock import MagicMock

from agent.agent_factory import REVIEW_CONTAINER_HOST_CONFIG
from agent.agent_factory import build_skill_run_calls
from trpc_agent_sdk.code_executors.container._container_cli import ContainerClient
from trpc_agent_sdk.code_executors.container._container_ws_runtime import ContainerWorkspaceRuntime


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
    runtime = ContainerWorkspaceRuntime(container=MagicMock(), host_config=REVIEW_CONTAINER_HOST_CONFIG)

    capabilities = runtime.describe()

    assert capabilities.network_allowed is False
    assert capabilities.max_disk_bytes == 64 * 1024 * 1024


def test_writable_root_or_bind_does_not_claim_a_tmpfs_disk_cap():
    writable_root = ContainerWorkspaceRuntime(
        container=MagicMock(),
        host_config={"tmpfs": {
            "/tmp": "size=64m"
        }},
    )
    writable_bind = ContainerWorkspaceRuntime(
        container=MagicMock(),
        host_config={
            **REVIEW_CONTAINER_HOST_CONFIG,
            "Binds": ["/host/data:/data:rw"],
        },
    )

    assert writable_root.describe().max_disk_bytes == 0
    assert writable_bind.describe().max_disk_bytes == 0


def test_docker_client_forwards_only_explicit_resource_allowlist():
    client = ContainerClient.__new__(ContainerClient)
    client._client = MagicMock()
    client._container = None
    client.image = "review-image"
    client.docker_path = None
    client.host_config = {
        **REVIEW_CONTAINER_HOST_CONFIG,
        "shm_size": "32m",
        "privileged": True,
        "cap_add": ["SYS_ADMIN"],
    }
    container = MagicMock(id="review-container")
    client._client.containers.run.return_value = container
    client._verify_python_installation = MagicMock()

    client._init_container()

    kwargs = client._client.containers.run.call_args.kwargs
    for key in (
            "mem_limit",
            "memswap_limit",
            "nano_cpus",
            "pids_limit",
            "read_only",
            "tmpfs",
            "shm_size",
    ):
        assert kwargs[key] == client.host_config[key]
    assert kwargs["network_mode"] == "none"
    assert "privileged" not in kwargs
    assert "cap_add" not in kwargs
