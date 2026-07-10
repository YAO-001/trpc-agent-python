# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Execution-request policy tests for the skills code-review example."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from agent import agent_factory
from agent import filter_policy
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
from agent.filter_policy import ReviewExecutionPolicy
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


def _context(request: ExecutionRequest | None = None) -> PolicyContext:
    request = request or _request()
    return PolicyContext(
        task_id=request.task_id,
        runtime=request.runtime,
        allowed_input_sources=frozenset({request.inputs[0].src}),
    )


def _valid_request(**changes: Any) -> ExecutionRequest:
    return _request().model_copy(update=changes)


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


def _input_with(**changes: Any) -> ExecutionInput:
    return _request().inputs[0].model_copy(update=changes)


def _output_with(**changes: Any) -> ExecutionOutputSpec:
    return _request().output_spec.model_copy(update=changes)


@pytest.mark.parametrize(
    ("changes", "reason"),
    (
        ({
            "task_id": "other"
        }, "task id"),
        ({
            "runtime": "local"
        }, "runtime"),
        ({
            "skill": "other"
        }, "skill"),
        ({
            "cwd": "/"
        }, "cwd"),
        ({
            "stdin": "unexpected"
        }, "stdin"),
        ({
            "editor_text": "unexpected"
        }, "editor"),
        ({
            "inputs": ()
        }, "exactly one input"),
        ({
            "inputs": (_request().inputs[0], _request().inputs[0])
        }, "exactly one input"),
        ({
            "inputs": (ExecutionInput.model_construct(
                src=_request().inputs[0].src,
                dst=_request().inputs[0].dst,
                mode="link",
                pin=False,
            ), )
        }, "input mode"),
        ({
            "inputs": (_input_with(src="host:///root/.ssh/id_rsa"), )
        }, "input source"),
        ({
            "inputs": (_input_with(dst="skills/code-review/scripts/replace.py"), )
        }, "input destination"),
        ({
            "inputs": (_input_with(dst="../review.json"), )
        }, "input destination"),
        ({
            "inputs": (_input_with(dst="skills\\code-review\\..\\review.json"), )
        }, "input destination"),
        ({
            "inputs": (_input_with(pin=True), )
        }, "input pin"),
        ({
            "command_argv": ("python3", "unapproved.py")
        }, "command"),
        ({
            "legacy_output_files": ("out/legacy.json", )
        }, "legacy output"),
        ({
            "env": (ExecutionEnv(name="FOO", value="bar"), )
        }, "environment"),
        ({
            "env": (ExecutionEnv(name="PYTHONPATH", value="/tmp/evil"), )
        }, "environment"),
        ({
            "network_access": True
        }, "network"),
        ({
            "timeout_seconds": 0
        }, "timeout"),
        ({
            "timeout_seconds": -1
        }, "timeout"),
        ({
            "timeout_seconds": 61
        }, "timeout"),
        ({
            "output_spec": _output_with(globs=())
        }, "exactly one output"),
        ({
            "output_spec":
            _output_with(globs=("skills/code-review/out/findings.json", "skills/code-review/out/other.json"))
        }, "exactly one output"),
        ({
            "output_spec": _output_with(globs=("skills/code-review/out/secrets.json", ))
        }, "command output"),
        ({
            "output_spec": _output_with(max_files=2)
        }, "output file count"),
        ({
            "output_spec": _output_with(max_file_bytes=0)
        }, "output budget"),
        ({
            "output_spec": _output_with(max_file_bytes=262145)
        }, "output budget"),
        ({
            "output_spec": _output_with(max_total_bytes=0)
        }, "output budget"),
        ({
            "output_spec": _output_with(max_total_bytes=262145)
        }, "output budget"),
        ({
            "output_spec": _output_with(save=True)
        }, "output save"),
        ({
            "output_spec": _output_with(inline=False)
        }, "output inline"),
        ({
            "output_spec": _output_with(name_template="named")
        }, "output name"),
        ({
            "output_budget_bytes": 1
        }, "output budget"),
        ({
            "save_as_artifacts": True
        }, "artifact persistence"),
        ({
            "omit_inline_content": True
        }, "inline content"),
        ({
            "artifact_prefix": "saved"
        }, "artifact prefix"),
    ),
)
def test_policy_denies_every_invalid_request_field(changes: dict[str, Any], reason: str):
    request = _valid_request(**changes)

    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context())

    assert decision.decision == "deny"
    assert reason in decision.intercept.reason
    expected_request_id = ("invalid-request" if {"task_id", "runtime"} & changes.keys() else request.request_id)
    assert decision.intercept.metadata == {
        "request_id": expected_request_id,
        "error_kind": "policy_denied",
    }


def test_policy_contract_constants_are_exact():
    assert filter_policy.COMMAND_CONTRACTS == {
        (
            "python3",
            "scripts/run_static_review.py",
            "--input",
            "work/inputs/review_input.json",
            "--output",
            "out/findings.json",
        ):
        "skills/code-review/out/findings.json",
        (
            "python3",
            "scripts/secret_scan.py",
            "--input",
            "work/inputs/review_input.json",
            "--output",
            "out/secrets.json",
        ):
        "skills/code-review/out/secrets.json",
        (
            "python3",
            "scripts/smoke_test.py",
            "--input",
            "work/inputs/review_input.json",
            "--output",
            "out/smoke.json",
        ):
        "skills/code-review/out/smoke.json",
    }
    assert filter_policy.ALLOWED_ENV == {("PYTHONUNBUFFERED", "1")}
    assert filter_policy.APPROVAL_REQUIRED_PROGRAMS == {"pip", "pip3", "npm", "yarn", "pnpm"}
    assert filter_policy.DECISION_ERROR_KIND == {
        "allow": "",
        "deny": "policy_denied",
        "needs_human_review": "approval_required",
    }


def test_all_canonical_requests_are_allowed_only_with_their_bound_output(tmp_path: Path):
    input_path = tmp_path / "review_input.json"
    input_path.write_text("{}", encoding="utf-8")
    requests = build_execution_requests("task-1", "container", str(input_path))
    context = PolicyContext(
        task_id="task-1",
        runtime="container",
        allowed_input_sources=frozenset({requests[0].inputs[0].src}),
    )

    decisions = [ReviewExecutionPolicy(dry_run=True).evaluate(request, context) for request in requests]

    assert [decision.decision for decision in decisions] == ["allow", "allow", "allow"]
    for request, decision in zip(requests, decisions):
        assert request.output_spec.globs == (filter_policy.COMMAND_CONTRACTS[request.command_argv], )
        assert decision.intercept.task_id == request.task_id
        assert decision.intercept.runtime == request.runtime
        assert decision.intercept.metadata == {
            "request_id": request.request_id,
            "error_kind": "",
        }


@pytest.mark.parametrize("command", (("pip", "install", "x"), ("npm", "install", "x")))
def test_only_explicit_approval_programs_need_human_review(command: tuple[str, ...]):
    request = _valid_request(command_argv=command)

    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context())

    assert decision.decision == "needs_human_review"
    assert "package" in decision.intercept.reason
    assert decision.intercept.metadata["error_kind"] == "approval_required"


def test_policy_metadata_never_contains_host_source_or_environment_values():
    request = _valid_request(env=(ExecutionEnv(name="API_TOKEN", value="raw-secret-value"), ))

    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context())
    metadata = json.dumps(decision.intercept.metadata, sort_keys=True)

    assert request.inputs[0].src not in metadata
    assert "API_TOKEN" not in metadata
    assert "raw-secret-value" not in metadata


def test_policy_rejects_traversing_host_source_even_if_literal_source_is_trusted():
    source = "host:///tmp/../review_input.json"
    request = _valid_request(inputs=(_input_with(src=source), ))
    context = _context().model_copy(update={"allowed_input_sources": frozenset({source})})

    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, context)

    assert decision.decision == "deny"
    assert "input source" in decision.intercept.reason


def test_policy_rejects_per_file_budget_larger_than_total_budget():
    output = _output_with(max_file_bytes=2, max_total_bytes=1)
    request = _valid_request(output_spec=output, output_budget_bytes=1)

    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context())

    assert decision.decision == "deny"
    assert "output budget" in decision.intercept.reason


def _constructed_input(**changes: Any) -> ExecutionInput:
    values = _request().inputs[0].model_dump()
    values.update(changes)
    return ExecutionInput.model_construct(**values)


def _constructed_output(**changes: Any) -> ExecutionOutputSpec:
    values = _request().output_spec.model_dump()
    values.update(changes)
    return ExecutionOutputSpec.model_construct(**values)


@pytest.mark.parametrize(
    ("changes", "reason"),
    (
        ({
            "request_id": []
        }, "request id"),
        ({
            "task_id": 1
        }, "task id"),
        ({
            "runtime": 1
        }, "runtime"),
        ({
            "skill": 1
        }, "skill"),
        ({
            "cwd": 1
        }, "cwd"),
        ({
            "stdin": []
        }, "stdin"),
        ({
            "editor_text": []
        }, "editor"),
        ({
            "inputs": 1
        }, "exactly one input"),
        ({
            "inputs": [None]
        }, "exactly one input"),
        ({
            "inputs": (1, )
        }, "input"),
        ({
            "inputs": (_constructed_input(mode=["copy"]), )
        }, "input mode"),
        ({
            "inputs": (_constructed_input(src=[]), )
        }, "input source"),
        ({
            "inputs": (_constructed_input(dst=[]), )
        }, "input destination"),
        ({
            "inputs": (_constructed_input(pin=[]), )
        }, "input pin"),
        ({
            "legacy_output_files": []
        }, "legacy output"),
        ({
            "output_spec": 1
        }, "output"),
        ({
            "output_spec": _constructed_output(globs=["skills/code-review/out/findings.json"])
        }, "exactly one output"),
        ({
            "output_spec": _constructed_output(globs=(["nested"], ))
        }, "command output"),
        ({
            "output_spec": _constructed_output(max_files=False)
        }, "output file count"),
        ({
            "output_spec": _constructed_output(max_file_bytes=False)
        }, "output budget"),
        ({
            "output_spec": _constructed_output(max_total_bytes=False)
        }, "output budget"),
        ({
            "output_spec": _constructed_output(save=[])
        }, "output save"),
        ({
            "output_spec": _constructed_output(inline=1)
        }, "output inline"),
        ({
            "output_spec": _constructed_output(name_template=[])
        }, "output name"),
        ({
            "env": []
        }, "environment"),
        ({
            "env": (1, )
        }, "environment"),
        ({
            "env": (ExecutionEnv.model_construct(name=[], value="1"), )
        }, "environment"),
        ({
            "env": (ExecutionEnv.model_construct(name="PYTHONUNBUFFERED", value=[]), )
        }, "environment"),
        ({
            "network_access": []
        }, "network"),
        ({
            "timeout_seconds": False
        }, "timeout"),
        ({
            "output_budget_bytes": False
        }, "output budget"),
        ({
            "save_as_artifacts": []
        }, "artifact persistence"),
        ({
            "omit_inline_content": 0
        }, "inline content"),
        ({
            "artifact_prefix": []
        }, "artifact prefix"),
        ({
            "command_argv": []
        }, "command"),
        ({
            "command_argv": ()
        }, "command"),
        ({
            "command_argv": (1, )
        }, "command"),
        ({
            "command_argv": (["python3"], )
        }, "command"),
    ),
)
def test_policy_malformed_model_copy_is_always_a_structured_deny(changes: dict[str, Any], reason: str):
    request = _valid_request(**changes)

    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context())

    assert decision.decision == "deny"
    assert reason in decision.intercept.reason
    assert decision.intercept.metadata["error_kind"] == "policy_denied"


def test_policy_rejects_non_execution_request_without_raising():
    decision = ReviewExecutionPolicy(dry_run=True).evaluate(object(), _context())

    assert decision.decision == "deny"
    assert "request" in decision.intercept.reason
    assert decision.intercept.task_id == "task-1"
    assert decision.intercept.runtime == "container"


@pytest.mark.parametrize(
    "request_id",
    (
        "",
        "other:skill-run:1",
        "task-1/skill-run/1",
        "task-1\\skill-run\\1",
        "task-1:skill run:1",
        "task-1:\ncontrol",
        "x" * 129,
    ),
)
def test_policy_rejects_unsafe_or_unscoped_request_id(request_id: str):
    request = _valid_request(request_id=request_id)

    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context())

    assert decision.decision == "deny"
    assert "request id" in decision.intercept.reason


def test_policy_invalid_request_id_is_not_copied_into_metadata():
    raw_request_id = "host:///owned/private/review_input.json"
    request = _valid_request(request_id=raw_request_id)

    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context())
    metadata = json.dumps(decision.intercept.metadata, sort_keys=True)

    assert decision.decision == "deny"
    assert raw_request_id not in metadata
    assert "host://" not in metadata


def test_policy_safe_projection_drops_host_uri_from_malformed_command():
    raw_host_uri = "host:///owned/private/review_input.json"
    request = _valid_request(command_argv=("python3", raw_host_uri))

    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context())
    serialized = json.dumps(decision.intercept.model_dump(mode="json"), sort_keys=True)

    assert decision.decision == "deny"
    assert raw_host_uri not in serialized


@pytest.mark.parametrize(
    "changes",
    (
        {
            "task_id": 1
        },
        {
            "runtime": 1
        },
        {
            "runtime": []
        },
        {
            "request_id": []
        },
        {
            "command_argv": ["python3"]
        },
    ),
)
def test_policy_malformed_identity_projection_uses_only_trusted_placeholders(changes: dict[str, Any]):
    decision = ReviewExecutionPolicy(dry_run=True).evaluate(_valid_request(**changes), _context())

    assert decision.decision == "deny"
    assert decision.intercept.task_id == "task-1"
    assert decision.intercept.runtime == "container"
    assert decision.intercept.metadata["request_id"] == "invalid-request"
    assert decision.intercept.command == []


@pytest.mark.parametrize(
    ("request_changes", "context_changes"),
    (
        pytest.param({"task_id": "other"}, {}, id="task-id-mismatch"),
        pytest.param({"runtime": "container"}, {"runtime": "local"}, id="runtime-mismatch"),
    ),
)
def test_policy_identity_mismatch_projects_only_trusted_context(request_changes: dict[str, Any],
                                                                context_changes: dict[str, Any]):
    request = _valid_request(**request_changes)
    context = _context().model_copy(update=context_changes)

    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, context)

    assert decision.decision == "deny"
    assert decision.intercept.task_id == context.task_id
    assert decision.intercept.runtime == context.runtime
    assert decision.intercept.metadata["request_id"] == "invalid-request"
    assert decision.intercept.command == []


def test_policy_accepts_canonical_demo_filter_request_id():
    request = _valid_request(request_id="task-1:demo-filter")

    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context())

    assert decision.decision == "allow"


def _callback_for(request: ExecutionRequest | None = None):
    expected = request or _request()
    return agent_factory.make_review_before_tool_callback(
        ReviewExecutionPolicy(dry_run=True),
        _context(expected),
        {expected.command_argv: expected},
    )


def test_integrity_callback_allows_only_the_identical_canonical_request():
    request = _request()
    callback = _callback_for(request)

    assert callback(None, SimpleNamespace(name="other"), request.to_skill_run_args()) is None
    assert callback(None, SimpleNamespace(name="skill_run"), request.to_skill_run_args()) is None

    changed = request.to_skill_run_args()
    del changed["outputs"]["inline"]
    blocked = callback(None, SimpleNamespace(name="skill_run"), changed)

    assert blocked["blocked"] is True
    assert blocked["decision"] == "deny"
    assert "request changed after validation" in blocked["reason"]


@pytest.mark.parametrize(
    "change",
    (
        {
            "future_unmodeled_field": True
        },
        {
            "command": "\"unterminated"
        },
        {
            "env": ["PYTHONUNBUFFERED=1"]
        },
        {
            "timeout": float("inf")
        },
        {
            "inputs": [{
                "src": "host:///tmp/task-1/review_input.json",
                "dst": "skills/code-review/work/inputs/review_input.json",
                "mode": "link",
                "pin": False,
            }]
        },
        {
            "outputs": {
                "globs": ["skills/code-review/out/findings.json"],
                "max_files": "invalid",
                "max_file_bytes": OUTPUT_BUDGET_BYTES,
                "max_total_bytes": OUTPUT_BUDGET_BYTES,
                "save": False,
                "inline": True,
                "name_template": "",
            }
        },
    ),
)
def test_integrity_callback_blocks_malformed_requests_without_raising(change: dict[str, Any]):
    args = _request().to_skill_run_args()
    args.update(change)

    blocked = _callback_for()(None, SimpleNamespace(name="skill_run"), args)

    assert blocked["blocked"] is True
    assert blocked["decision"] == "deny"
    assert "invalid skill_run request" in blocked["reason"]


def test_integrity_callback_blocks_unknown_command_as_unknown_request():
    args = _request().to_skill_run_args()
    args["command"] = "python3 unapproved.py"

    blocked = _callback_for()(None, SimpleNamespace(name="skill_run"), args)

    assert blocked["blocked"] is True
    assert blocked["decision"] == "deny"
    assert "unknown request" in blocked["reason"]


def test_integrity_callback_preserves_nonallow_policy_decision_for_equal_request():
    request = _valid_request(command_argv=("pip", "install", "unapproved-package"))

    blocked = _callback_for(request)(None, SimpleNamespace(name="skill_run"), request.to_skill_run_args())

    assert blocked["blocked"] is True
    assert blocked["decision"] == "needs_human_review"
    assert blocked["intercept"]["metadata"]["error_kind"] == "approval_required"


class _ExplodingStatefulMapping(Mapping):

    def __getitem__(self, key):
        raise AssertionError(f"stateful mapping was consumed: {key}")

    def __iter__(self):
        raise AssertionError("stateful mapping was iterated")

    def __len__(self):
        raise AssertionError("stateful mapping length was read")


class _ModelLikeArgs:

    def __init__(self, result: Any = None, error: Exception | None = None):
        self.result = result
        self.error = error
        self.calls = 0

    def model_dump(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


@pytest.mark.parametrize(
    "args",
    (
        _ExplodingStatefulMapping(),
        _ModelLikeArgs(result=None),
        _ModelLikeArgs(error=RuntimeError("model_dump must not run")),
        type("StatefulDict", (dict, ), {})(_canonical_skill_run_args()),
    ),
)
def test_integrity_callback_rejects_every_non_plain_dict_without_consuming_it(args):
    blocked = _callback_for()(None, SimpleNamespace(name="skill_run"), args)

    assert blocked["blocked"] is True
    assert blocked["decision"] == "deny"
    assert "invalid skill_run request" in blocked["reason"]
    if isinstance(args, _ModelLikeArgs):
        assert args.calls == 0


def test_integrity_callback_canonicalizes_allowed_plain_dict_in_place():
    request = _request()
    args = request.to_skill_run_args()
    args["command"] = ("python3 'scripts/run_static_review.py' --input work/inputs/review_input.json "
                       "--output out/findings.json")
    args["inputs"] = tuple(args["inputs"])

    result = _callback_for(request)(None, SimpleNamespace(name="skill_run"), args)

    assert result is None
    assert args == request.to_skill_run_args()
