# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Optional tRPC-Agent SkillToolSet wiring for the code-review skill."""

from __future__ import annotations

import copy
import json
import shlex
import tempfile
from contextlib import contextmanager
from collections.abc import Iterator
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .execution_request import ExecutionPlan
from .execution_request import ExecutionRequest
from .execution_request import PolicyContext
from .filter_policy import PolicyDecision
from .filter_policy import ReviewExecutionPolicy
from .redaction_boundary import RedactionBoundary
from .secret_redactor import SecretRedactor

EXAMPLE_DIR = Path(__file__).resolve().parents[1]


def create_skill_tool_set(runtime: str = "container"):
    from trpc_agent_sdk.code_executors import create_container_workspace_runtime
    from trpc_agent_sdk.code_executors import create_local_workspace_runtime
    from trpc_agent_sdk.skills import FsSkillRepository
    from trpc_agent_sdk.skills import SkillToolSet
    from trpc_agent_sdk.skills.tools import CopySkillStager

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
        skill_stager=CopySkillStager() if runtime == "container" else None,
    )


def _input_specs(input_path: str | None, *, workspace_path: str) -> list[dict[str, Any]]:
    if not input_path:
        return []
    return [{
        "src": f"host://{Path(input_path).resolve().as_posix()}",
        "dst": f"{workspace_path}/work/inputs/review_input.json",
        "mode": "copy",
        "pin": False,
    }]


def _output_spec(path: str) -> dict[str, Any]:
    return {
        "globs": [path],
        "max_files": 1,
        "max_file_bytes": 256 * 1024,
        "max_total_bytes": 256 * 1024,
        "save": False,
        "inline": True,
        "name_template": "",
    }


def build_skill_run_calls(
    input_path: str | None = None,
    *,
    workspace_path: str = "skills/code-review",
) -> list[dict[str, Any]]:
    inputs = _input_specs(input_path, workspace_path=workspace_path)
    cwd = "$SKILLS_DIR/code-review"
    return [
        {
            "skill":
            "code-review",
            "command": ("python3 scripts/run_static_review.py --input work/inputs/review_input.json "
                        "--output out/findings.json"),
            "cwd":
            cwd,
            "env": {
                "PYTHONUNBUFFERED": "1"
            },
            "stdin":
            "",
            "editor_text":
            "",
            "output_files": [],
            "timeout":
            30,
            "save_as_artifacts":
            False,
            "omit_inline_content":
            False,
            "artifact_prefix":
            "",
            "inputs":
            inputs,
            "outputs":
            _output_spec(f"{workspace_path}/out/findings.json"),
            "network_access":
            False,
        },
        {
            "skill": "code-review",
            "command": "python3 scripts/secret_scan.py --input work/inputs/review_input.json --output out/secrets.json",
            "cwd": cwd,
            "env": {
                "PYTHONUNBUFFERED": "1"
            },
            "stdin": "",
            "editor_text": "",
            "output_files": [],
            "timeout": 30,
            "save_as_artifacts": False,
            "omit_inline_content": False,
            "artifact_prefix": "",
            "inputs": inputs,
            "outputs": _output_spec(f"{workspace_path}/out/secrets.json"),
            "network_access": False,
        },
        {
            "skill": "code-review",
            "command": "python3 scripts/smoke_test.py --input work/inputs/review_input.json --output out/smoke.json",
            "cwd": cwd,
            "env": {
                "PYTHONUNBUFFERED": "1"
            },
            "stdin": "",
            "editor_text": "",
            "output_files": [],
            "timeout": 30,
            "save_as_artifacts": False,
            "omit_inline_content": False,
            "artifact_prefix": "",
            "inputs": inputs,
            "outputs": _output_spec(f"{workspace_path}/out/smoke.json"),
            "network_access": False,
        },
    ]


def build_execution_requests(
    task_id: str,
    runtime: str,
    input_path: str,
) -> tuple[ExecutionRequest, ...]:
    normalized_runtime = "container" if runtime == "auto" else runtime
    if normalized_runtime not in {"container", "local"}:
        raise ValueError(f"unsupported execution runtime {runtime!r}")
    return tuple(
        ExecutionRequest.from_skill_run_args(
            request_id=f"{task_id}:skill-run:{index}",
            task_id=task_id,
            runtime=normalized_runtime,
            args=args,
        ) for index, args in enumerate(build_skill_run_calls(input_path), start=1))


@contextmanager
def prepare_execution_plan(
    *,
    task_id: str,
    runtime: str,
    review_input: dict[str, Any],
    boundary: RedactionBoundary | None = None,
    redactor: SecretRedactor | None = None,
) -> Iterator[ExecutionPlan]:
    if boundary is not None and redactor is not None:
        raise ValueError("pass either boundary or redactor, not both")
    active_boundary = boundary or RedactionBoundary(redactor=redactor)
    normalized_runtime = "container" if runtime == "auto" else runtime
    with tempfile.TemporaryDirectory(prefix="skills_code_review_input_") as tmp:
        input_path = Path(tmp) / "review_input.json"
        cleaned = active_boundary.clean(review_input)
        input_path.write_text(
            json.dumps(cleaned, ensure_ascii=False, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        requests = build_execution_requests(task_id, normalized_runtime, str(input_path))
        input_uri = f"host://{input_path.resolve().as_posix()}"
        policy_context = PolicyContext(
            task_id=task_id,
            runtime=normalized_runtime,
            allowed_input_sources=frozenset({input_uri}),
        )
        yield ExecutionPlan(requests=requests, policy_context=policy_context)


def _blocked_tool_response(decision: PolicyDecision) -> dict[str, Any]:
    return {
        "blocked": True,
        "decision": decision.decision,
        "reason": decision.intercept.reason,
        "intercept": decision.intercept.model_dump(mode="json"),
    }


def make_review_before_tool_callback(
    policy: ReviewExecutionPolicy,
    policy_context: PolicyContext,
    requests_by_command: Mapping[tuple[str, ...], ExecutionRequest],
    *,
    canonical_args_by_command: Mapping[tuple[str, ...], Mapping[str, Any]] | None = None,
):
    """Build an SDK callback that guards an already-approved request."""
    expected_by_command = {tuple(command): request for command, request in requests_by_command.items()}
    if not expected_by_command:
        raise ValueError("requests_by_command must contain at least one validated request")
    if canonical_args_by_command is None:
        canonical_by_command = {
            command: request.to_skill_run_args()
            for command, request in expected_by_command.items()
        }
    else:
        canonical_by_command = {
            tuple(command): copy.deepcopy(dict(args))
            for command, args in canonical_args_by_command.items()
        }
        if set(canonical_by_command) != set(expected_by_command):
            raise ValueError("canonical arguments must match every validated request")
        for command, expected_request in expected_by_command.items():
            canonical_request = ExecutionRequest.from_skill_run_args(
                request_id=expected_request.request_id,
                task_id=expected_request.task_id,
                runtime=expected_request.runtime,
                args=canonical_by_command[command],
            )
            if canonical_request != expected_request:
                raise ValueError("canonical arguments do not match validated request")
    representative_request = next(iter(expected_by_command.values()))

    def before_tool_callback(context, tool, args, response=None):  # pylint: disable=unused-argument
        if getattr(tool, "name", "") != "skill_run":
            return None
        expected = representative_request
        if type(args) is not dict:
            return _blocked_tool_response(
                policy._decision(
                    "deny",
                    "invalid skill_run request",
                    representative_request,
                    policy_context,
                ))
        try:
            raw_args = dict(args)
            raw_command = raw_args.get("command")
            if not isinstance(raw_command, str):
                raise TypeError("skill_run command must be a string")
            command_argv = tuple(shlex.split(raw_command, posix=True))
            expected = expected_by_command.get(command_argv)
            if expected is None:
                unknown = representative_request.model_copy(update={
                    "request_id": "unknown",
                    "command_argv": command_argv,
                })
                return _blocked_tool_response(policy._decision("deny", "unknown request", unknown, policy_context))
            actual = ExecutionRequest.from_skill_run_args(
                request_id=expected.request_id,
                task_id=expected.task_id,
                runtime=expected.runtime,
                args=raw_args,
            )
        except (TypeError, ValueError, ValidationError):
            invalid = expected or representative_request
            return _blocked_tool_response(policy._decision("deny", "invalid skill_run request", invalid,
                                                           policy_context))

        decision = policy.evaluate(actual, policy_context)
        if actual != expected:
            return _blocked_tool_response(
                policy._decision("deny", "request changed after validation", actual, policy_context))
        if decision.decision == "allow":
            args.clear()
            args.update(copy.deepcopy(canonical_by_command[expected.command_argv]))
            return None
        return _blocked_tool_response(decision)

    return before_tool_callback
