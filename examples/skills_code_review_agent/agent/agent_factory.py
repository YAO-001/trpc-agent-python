# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Optional tRPC-Agent SkillToolSet wiring for the code-review skill."""

from __future__ import annotations

import json
import tempfile
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .execution_request import ExecutionPlan
from .execution_request import ExecutionRequest
from .execution_request import PolicyContext
from .filter_policy import ReviewExecutionPolicy
from .secret_redactor import SecretRedactor

EXAMPLE_DIR = Path(__file__).resolve().parents[1]
_SENSITIVE_INPUT_FIELDS = frozenset({"password", "token", "api_key", "secret"})


def _redact_json_value(
    value: Any,
    *,
    redactor: SecretRedactor,
    field_name: str | None = None,
) -> Any:
    if isinstance(value, str):
        safe_value = redactor.redact_text(value).text
        if field_name is not None and field_name.casefold() in _SENSITIVE_INPUT_FIELDS:
            prefix = f"{field_name}="
            contextual = redactor.redact_text(f"{prefix}{safe_value}").text
            if contextual.startswith(prefix):
                safe_value = contextual[len(prefix):]
        return safe_value
    if isinstance(value, dict):
        return {
            key: _redact_json_value(
                item,
                redactor=redactor,
                field_name=key if isinstance(key, str) else None,
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json_value(item, redactor=redactor, field_name=field_name) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_json_value(item, redactor=redactor, field_name=field_name) for item in value)
    return value


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
    return tuple(
        ExecutionRequest.from_skill_run_args(
            request_id=f"{task_id}:skill-run:{index}",
            task_id=task_id,
            runtime=runtime,
            args=args,
        ) for index, args in enumerate(build_skill_run_calls(input_path), start=1))


@contextmanager
def prepare_execution_plan(
    *,
    task_id: str,
    runtime: str,
    review_input: dict[str, Any],
    redactor: SecretRedactor,
) -> Iterator[ExecutionPlan]:
    normalized_runtime = "container" if runtime == "auto" else runtime
    with tempfile.TemporaryDirectory(prefix="skills_code_review_input_") as tmp:
        input_path = Path(tmp) / "review_input.json"
        safe_review_input = _redact_json_value(review_input, redactor=redactor)
        serialized = json.dumps(safe_review_input, ensure_ascii=False, sort_keys=True)
        cleaned = json.loads(serialized)
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
        network_access=bool(args.get("network_access")),
    )
    if decision.decision == "allow":
        return None
    return {
        "blocked": True,
        "decision": decision.decision,
        "reason": decision.intercept.reason,
        "intercept": decision.intercept.model_dump(mode="json"),
    }
