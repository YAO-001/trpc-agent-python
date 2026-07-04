# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Optional tRPC-Agent SkillToolSet wiring for the code-review skill."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .filter_policy import ReviewExecutionPolicy


EXAMPLE_DIR = Path(__file__).resolve().parents[1]


def create_skill_tool_set(runtime: str = "container"):
    from trpc_agent_sdk.code_executors import create_container_workspace_runtime
    from trpc_agent_sdk.code_executors import create_local_workspace_runtime
    from trpc_agent_sdk.skills import FsSkillRepository
    from trpc_agent_sdk.skills import SkillToolSet

    if runtime not in {"container", "local"}:
        raise ValueError(f"unsupported SkillToolSet runtime {runtime!r}")
    if runtime == "local":
        workspace_runtime = create_local_workspace_runtime(read_only_staged_skill=True)
    else:
        workspace_runtime = create_container_workspace_runtime()
    repository = FsSkillRepository(str(EXAMPLE_DIR / "skills"), workspace_runtime=workspace_runtime)
    return SkillToolSet(
        repository=repository,
        allowed_cmds=["python3"],
        run_tool_kwargs={"timeout": 60, "save_as_artifacts": False, "omit_inline_content": False},
    )


def _input_specs(input_path: str | None) -> list[dict[str, str]]:
    if not input_path:
        return []
    return [
        {
            "src": f"host://{Path(input_path).resolve().as_posix()}",
            "dst": "work/inputs/review_input.json",
            "mode": "copy",
        }
    ]


def build_skill_run_calls(input_path: str | None = None) -> list[dict[str, Any]]:
    inputs = _input_specs(input_path)
    return [
        {
            "skill": "code-review",
            "cwd": "$SKILLS_DIR/code-review",
            "command": (
                "python3 scripts/run_static_review.py --input work/inputs/review_input.json "
                "--output out/findings.json"
            ),
            "output_files": ["out/findings.json"],
            "inputs": inputs,
            "timeout": 30,
        },
        {
            "skill": "code-review",
            "cwd": "$SKILLS_DIR/code-review",
            "command": "python3 scripts/secret_scan.py --input work/inputs/review_input.json --output out/secrets.json",
            "output_files": ["out/secrets.json"],
            "inputs": inputs,
            "timeout": 30,
        },
        {
            "skill": "code-review",
            "cwd": "$SKILLS_DIR/code-review",
            "command": "python3 scripts/smoke_test.py --input work/inputs/review_input.json --output out/smoke.json",
            "output_files": ["out/smoke.json"],
            "inputs": inputs,
            "timeout": 30,
        },
    ]


def review_before_tool_callback(context, tool, args: dict, response=None):  # pylint: disable=unused-argument
    if getattr(tool, "name", "") != "skill_run":
        return None
    command = str(args.get("command", "")).split()
    output_files = list(args.get("output_files") or [])
    env = dict(args.get("env") or {})
    timeout = int(args.get("timeout") or 30)
    decision = ReviewExecutionPolicy(max_timeout_sec=60).evaluate(
        command=command,
        runtime="container",
        output_files=output_files,
        env=env,
        timeout=timeout,
    )
    if decision.decision == "allow":
        return None
    return {
        "blocked": True,
        "decision": decision.decision,
        "reason": decision.intercept.reason,
        "intercept": decision.intercept.model_dump(mode="json"),
    }
