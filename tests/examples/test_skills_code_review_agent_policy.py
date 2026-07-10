# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Execution-request policy tests for the skills code-review example."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agent.execution_request import ExecutionPlan
from agent.execution_request import ExecutionEnv
from agent.execution_request import ExecutionInput
from agent.execution_request import ExecutionOutputSpec
from agent.execution_request import ExecutionRequest
from agent.execution_request import MODELED_SKILL_RUN_FIELDS
from agent.execution_request import PolicyContext
from agent.agent_factory import build_execution_requests
from agent.agent_factory import build_skill_run_calls
from agent.agent_factory import prepare_execution_plan
from agent.secret_redactor import SecretRedactor

OUTPUT_BUDGET_BYTES = 256 * 1024


def _canonical_skill_run_args() -> dict[str, Any]:
    return {
        "skill":
        "code-review",
        "command": ("python3 scripts/run_static_review.py --input work/inputs/review_input.json "
                    "--output out/findings.json"),
        "cwd":
        "$SKILLS_DIR/code-review",
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
        "inputs": [{
            "src": "host:///tmp/task-1/review_input.json",
            "dst": "skills/code-review/work/inputs/review_input.json",
            "mode": "copy",
            "pin": False,
        }],
        "outputs": {
            "globs": ["skills/code-review/out/findings.json"],
            "max_files": 1,
            "max_file_bytes": OUTPUT_BUDGET_BYTES,
            "max_total_bytes": OUTPUT_BUDGET_BYTES,
            "save": False,
            "inline": True,
            "name_template": "",
        },
        "network_access":
        False,
    }


def _request() -> ExecutionRequest:
    return _request_from_args(_canonical_skill_run_args())


def _request_from_args(args: dict[str, Any]) -> ExecutionRequest:
    return ExecutionRequest.from_skill_run_args(
        request_id="task-1:skill-run:1",
        task_id="task-1",
        runtime="container",
        args=args,
    )


def test_execution_request_and_nested_values_are_frozen():
    request = _request()

    with pytest.raises(ValidationError):
        request.timeout_seconds = 31
    with pytest.raises(ValidationError):
        request.inputs[0].src = "host:///tmp/changed.json"
    with pytest.raises(ValidationError):
        request.env[0].value = "0"


def test_execution_input_requires_explicit_mode():
    args = _canonical_skill_run_args()
    del args["inputs"][0]["mode"]

    with pytest.raises(ValidationError):
        _request_from_args(args)


def test_execution_output_spec_defaults_are_safe_and_empty():
    assert ExecutionOutputSpec() == ExecutionOutputSpec(
        globs=(),
        max_files=0,
        max_file_bytes=0,
        max_total_bytes=0,
        save=False,
        inline=False,
        name_template="",
    )


def test_missing_inline_output_flag_does_not_match_canonical_request():
    expected = _request()
    args = _canonical_skill_run_args()
    del args["outputs"]["inline"]

    actual = _request_from_args(args)

    assert actual.output_spec.inline is False
    assert actual.output_spec != expected.output_spec


def test_from_skill_run_args_preserves_every_modeled_field():
    request = _request()

    assert request.request_id == "task-1:skill-run:1"
    assert request.task_id == "task-1"
    assert request.runtime == "container"
    assert request.skill == "code-review"
    assert request.command_argv == (
        "python3",
        "scripts/run_static_review.py",
        "--input",
        "work/inputs/review_input.json",
        "--output",
        "out/findings.json",
    )
    assert request.cwd == "$SKILLS_DIR/code-review"
    assert request.stdin == ""
    assert request.editor_text == ""
    assert request.inputs == (ExecutionInput(
        src="host:///tmp/task-1/review_input.json",
        dst="skills/code-review/work/inputs/review_input.json",
        mode="copy",
        pin=False,
    ), )
    assert request.legacy_output_files == ()
    assert request.output_spec == ExecutionOutputSpec(
        globs=("skills/code-review/out/findings.json", ),
        max_files=1,
        max_file_bytes=OUTPUT_BUDGET_BYTES,
        max_total_bytes=OUTPUT_BUDGET_BYTES,
        save=False,
        inline=True,
        name_template="",
    )
    assert request.env == (ExecutionEnv(name="PYTHONUNBUFFERED", value="1"), )
    assert request.network_access is False
    assert request.timeout_seconds == 30
    assert request.output_budget_bytes == OUTPUT_BUDGET_BYTES
    assert request.save_as_artifacts is False
    assert request.omit_inline_content is False
    assert request.artifact_prefix == ""


def test_from_skill_run_args_is_keyword_only():
    with pytest.raises(TypeError):
        ExecutionRequest.from_skill_run_args(
            "task-1:skill-run:1",
            "task-1",
            "container",
            _canonical_skill_run_args(),
        )


def test_from_skill_run_args_normalizes_environment_and_legacy_outputs():
    args = _canonical_skill_run_args()
    args["env"] = {7: 9}
    args["output_files"] = [11, True]

    request = _request_from_args(args)

    assert request.env == (ExecutionEnv(name="7", value="9"), )
    assert request.legacy_output_files == ("11", "True")
    assert request.to_skill_run_args()["env"] == {"7": "9"}
    assert request.to_skill_run_args()["output_files"] == ["11", "True"]


@pytest.mark.parametrize("env", ([], ["x"], 1, "KEY=value"))
def test_from_skill_run_args_rejects_non_mapping_environment(env: Any):
    args = _canonical_skill_run_args()
    args["env"] = env

    with pytest.raises(ValueError):
        _request_from_args(args)


@pytest.mark.parametrize("timeout", (float("inf"), float("-inf")))
def test_from_skill_run_args_normalizes_timeout_overflow(timeout: float):
    args = _canonical_skill_run_args()
    args["timeout"] = timeout

    with pytest.raises(ValueError):
        _request_from_args(args)


def test_frozen_models_forbid_unknown_fields():
    with pytest.raises(ValidationError):
        ExecutionInput(
            src="host:///tmp/input.json",
            dst="skills/code-review/work/inputs/review_input.json",
            mode="copy",
            future_unmodeled_field=True,
        )
    with pytest.raises(ValidationError):
        ExecutionOutputSpec(
            globs=(),
            max_files=0,
            max_file_bytes=0,
            max_total_bytes=0,
            future_unmodeled_field=True,
        )
    with pytest.raises(ValidationError):
        ExecutionRequest.model_validate({
            **_request().model_dump(),
            "future_unmodeled_field": True,
        })


def test_modeled_skill_run_fields_are_exhaustive():
    assert MODELED_SKILL_RUN_FIELDS == frozenset({
        "skill",
        "command",
        "cwd",
        "env",
        "stdin",
        "editor_text",
        "output_files",
        "timeout",
        "save_as_artifacts",
        "omit_inline_content",
        "artifact_prefix",
        "inputs",
        "outputs",
        "network_access",
    })


def test_build_skill_run_calls_include_complete_safe_arguments(tmp_path: Path):
    input_path = tmp_path / "review_input.json"
    input_path.write_text("{}", encoding="utf-8")
    source = f"host://{input_path.resolve().as_posix()}"
    expected_commands_and_outputs = (
        (
            "python3 scripts/run_static_review.py --input work/inputs/review_input.json --output out/findings.json",
            "skills/code-review/out/findings.json",
        ),
        (
            "python3 scripts/secret_scan.py --input work/inputs/review_input.json --output out/secrets.json",
            "skills/code-review/out/secrets.json",
        ),
        (
            "python3 scripts/smoke_test.py --input work/inputs/review_input.json --output out/smoke.json",
            "skills/code-review/out/smoke.json",
        ),
    )

    calls = build_skill_run_calls(str(input_path))

    assert len(calls) == 3
    for call, (command, output_glob) in zip(calls, expected_commands_and_outputs):
        assert set(call) == MODELED_SKILL_RUN_FIELDS
        assert call == {
            "skill":
            "code-review",
            "command":
            command,
            "cwd":
            "$SKILLS_DIR/code-review",
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
            "inputs": [{
                "src": source,
                "dst": "skills/code-review/work/inputs/review_input.json",
                "mode": "copy",
                "pin": False,
            }],
            "outputs": {
                "globs": [output_glob],
                "max_files": 1,
                "max_file_bytes": OUTPUT_BUDGET_BYTES,
                "max_total_bytes": OUTPUT_BUDGET_BYTES,
                "save": False,
                "inline": True,
                "name_template": "",
            },
            "network_access":
            False,
        }


def test_build_execution_requests_is_deterministic(tmp_path: Path):
    input_path = tmp_path / "review_input.json"
    input_path.write_text("{}", encoding="utf-8")

    first = build_execution_requests("task-1", "container", str(input_path))
    second = build_execution_requests("task-1", "container", str(input_path))

    assert first == second
    assert len(first) == 3
    assert tuple(request.request_id for request in first) == (
        "task-1:skill-run:1",
        "task-1:skill-run:2",
        "task-1:skill-run:3",
    )


def test_skill_run_args_round_trip_and_reject_unmodeled_fields():
    args = _canonical_skill_run_args()

    assert _request().to_skill_run_args() == args

    args["future_unmodeled_field"] = "must not disappear"
    with pytest.raises(ValueError, match="unmodeled SkillRun fields"):
        ExecutionRequest.from_skill_run_args(
            request_id="task-1:skill-run:1",
            task_id="task-1",
            runtime="container",
            args=args,
        )


def test_prepare_execution_plan_is_keyword_only():
    with pytest.raises(TypeError):
        prepare_execution_plan("task-1", "auto", {}, SecretRedactor())


def test_policy_context_and_execution_plan_are_deeply_frozen():
    request = _request()
    context = PolicyContext(
        task_id="task-1",
        runtime="container",
        allowed_input_sources=frozenset({request.inputs[0].src}),
    )
    plan = ExecutionPlan(requests=(request, ), policy_context=context)

    with pytest.raises(ValidationError):
        plan.requests = ()
    with pytest.raises(ValidationError):
        plan.policy_context.max_timeout_seconds = 30
    with pytest.raises(ValidationError):
        plan.requests[0].timeout_seconds = 10


def test_prepare_execution_plan_redacts_structured_input_before_serializing():
    secrets = {
        "aws": "AKIA1234567890123456",
        "embedded_password": "supersecret123",
        "direct_password": "abcdefghijk",
        "nested_token": "nested-token-value",
        "nested_list_password": "list-password-value",
        "list_api_key": "listsecret123",
    }
    review_input = {
        "aws": secrets["aws"],
        "note": f'password="{secrets["embedded_password"]}"',
        "password": secrets["direct_password"],
        "nested": {
            "ToKeN": secrets["nested_token"],
            "password": [secrets["nested_list_password"]],
        },
        "items": [f'api_key="{secrets["list_api_key"]}"', {
            "label": "public"
        }],
        "safe": {
            "list": [1, True, None, "public"],
            "tuple": ("safe", 2),
        },
    }

    with prepare_execution_plan(task_id="task-1",
                                runtime="container",
                                review_input=review_input,
                                redactor=SecretRedactor()) as plan:
        input_path = Path(plan.requests[0].inputs[0].src.removeprefix("host://"))
        raw = input_path.read_text(encoding="utf-8")
        cleaned = json.loads(raw)
        leaked = {name for name, value in secrets.items() if value in raw}

        assert not leaked
        assert cleaned["aws"].startswith("[REDACTED:SECRET:aws_access_key:")
        assert "[REDACTED:SECRET:generic_assignment:" in cleaned["note"]
        assert cleaned["password"].startswith("[REDACTED:SECRET:generic_assignment:")
        assert cleaned["nested"]["ToKeN"].startswith("[REDACTED:SECRET:generic_assignment:")
        assert cleaned["nested"]["password"][0].startswith("[REDACTED:SECRET:generic_assignment:")
        assert "[REDACTED:SECRET:generic_assignment:" in cleaned["items"][0]
        assert cleaned["items"][1] == {"label": "public"}
        assert cleaned["safe"] == {
            "list": [1, True, None, "public"],
            "tuple": ["safe", 2],
        }


def test_prepare_execution_plan_owns_a_redacted_input_file():
    review_input = {
        "task_id": "task-1",
        "secret": "AKIA1234567890123456",
    }

    with prepare_execution_plan(task_id="task-1", runtime="auto", review_input=review_input,
                                redactor=SecretRedactor()) as plan:
        source = plan.requests[0].inputs[0].src
        input_path = Path(source.removeprefix("host://"))
        tampered_request = plan.requests[0].model_copy(
            update={"inputs": (plan.requests[0].inputs[0].model_copy(update={"src": "host:///tmp/untrusted.json"}), )})

        assert input_path.is_file()
        serialized = input_path.read_text(encoding="utf-8")
        assert json.loads(serialized)["secret"].startswith("[REDACTED:SECRET:")
        assert "AKIA1234567890123456" not in serialized
        assert all(request.runtime == "container" for request in plan.requests)
        assert plan.policy_context.task_id == "task-1"
        assert plan.policy_context.runtime == "container"
        assert plan.policy_context.allowed_input_sources == frozenset({source})
        assert tampered_request.inputs[0].src not in plan.policy_context.allowed_input_sources
        assert plan.policy_context.allowed_cwd == "$SKILLS_DIR/code-review"
        assert plan.policy_context.max_timeout_seconds == 60
        assert plan.policy_context.max_output_bytes == OUTPUT_BUDGET_BYTES

    assert not input_path.exists()
