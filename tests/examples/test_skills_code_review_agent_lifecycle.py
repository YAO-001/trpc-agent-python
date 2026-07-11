# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Lifecycle state-machine tests for the skills code review agent example."""

from __future__ import annotations

import hashlib
import json
from itertools import product

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from agent.agent_factory import build_execution_requests
from agent.execution_request import PolicyContext
from agent.filter_policy import ReviewExecutionPolicy
from agent.input_resolver import EXAMPLE_DIR
from agent.models import DRY_RUN_TIMESTAMP
from agent.models import FilterIntercept
from agent.models import RedactionSummary
from agent.models import ReviewTask
from agent.models import ReviewTaskStatus
from agent.models import SandboxRun
from agent.models import TERMINAL_TASK_STATUSES
from agent.redaction_boundary import RedactionBoundary
from agent.sandbox_runner import SandboxRunner
from agent.storage import ReviewStorage
from agent.task_state import transition_task

STATUSES = list(ReviewTaskStatus)
ALLOWED = {
    (ReviewTaskStatus.CREATED, ReviewTaskStatus.RUNNING),
    (ReviewTaskStatus.RUNNING, ReviewTaskStatus.COMPLETED),
    (ReviewTaskStatus.RUNNING, ReviewTaskStatus.COMPLETED_WITH_ERRORS),
    (ReviewTaskStatus.RUNNING, ReviewTaskStatus.BLOCKED),
    (ReviewTaskStatus.RUNNING, ReviewTaskStatus.FAILED),
}


def _request(tmp_path, *, task_id="task-1", runtime="container"):
    path = tmp_path / f"{task_id}.json"
    path.write_text("{}", encoding="utf-8")
    return build_execution_requests(task_id, runtime, str(path))[0]


def _three_valid_requests(tmp_path, *, task_id: str, runtime: str):
    path = tmp_path / f"{task_id}-review.json"
    path.write_text("{}", encoding="utf-8")
    return build_execution_requests(task_id, runtime, str(path))


def _context(request):
    return PolicyContext(
        task_id=request.task_id,
        runtime=request.runtime,
        allowed_input_sources=frozenset({request.inputs[0].src}),
    )


def _runner(harness=None):
    runner = SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        boundary=RedactionBoundary(),
    )
    if harness is not None:
        runner._harness_for_runtime = lambda runtime: harness
    return runner


def _successful_run(request):
    return SandboxRun(
        run_id=f"sandbox-{request.request_id}",
        task_id=request.task_id,
        request_id=request.request_id,
        runtime=request.runtime,
        command=list(request.command_argv),
        exit_code=0,
        created_at=DRY_RUN_TIMESTAMP,
    )


def _running_task_with_three_requests(tmp_path):
    task = ReviewTask(
        task_id="task-three-decisions",
        input_type="fixture",
        runtime="container",
        dry_run=True,
    )
    input_path = tmp_path / "review_input.json"
    input_path.write_text("{}", encoding="utf-8")
    requests = build_execution_requests(task.task_id, task.runtime, str(input_path))
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    storage.create_task_with_input(
        task=task,
        redacted_diff="",
        changed_files=[],
        redaction_summary=RedactionSummary(),
        input_metadata={},
    )
    running = transition_task(task, ReviewTaskStatus.RUNNING)
    storage.update_task(running)
    return storage, running, requests


def test_task_statuses_and_terminal_set_are_complete():
    actual = {status.value for status in ReviewTaskStatus}

    assert actual == {
        "created",
        "running",
        "completed",
        "completed_with_errors",
        "blocked",
        "failed",
    }
    assert TERMINAL_TASK_STATUSES == frozenset({
        ReviewTaskStatus.COMPLETED,
        ReviewTaskStatus.COMPLETED_WITH_ERRORS,
        ReviewTaskStatus.BLOCKED,
        ReviewTaskStatus.FAILED,
    })


@pytest.mark.parametrize(("source", "target"), list(product(STATUSES, STATUSES)))
def test_every_task_transition_is_explicit(source, target):
    task = ReviewTask(
        task_id="task-1",
        input_type="fixture",
        runtime="container",
        status=source,
        dry_run=True,
    )
    if (source, target) in ALLOWED:
        changed = transition_task(task, target)
        assert changed.status == target
        assert changed.updated_at == "1970-01-01T00:00:00+00:00"
    else:
        with pytest.raises(ValueError, match="illegal task transition"):
            transition_task(task, target)


@pytest.mark.parametrize(
    "status",
    [status for status in ReviewTaskStatus if status is not ReviewTaskStatus.FAILED],
)
def test_failure_details_are_rejected_outside_failed_status(status):
    with pytest.raises(ValueError, match="failure details require failed task status"):
        ReviewTask(
            task_id="task-1",
            input_type="fixture",
            status=status,
            failure_kind="storage_error",
            failure_reason_redacted="redacted persistence failure",
        )


def test_failed_status_accepts_redacted_failure_details():
    task = ReviewTask(
        task_id="task-1",
        input_type="fixture",
        status=ReviewTaskStatus.FAILED,
        failure_kind="storage_error",
        failure_reason_redacted="redacted persistence failure",
    )

    assert task.failure_kind == "storage_error"
    assert task.failure_reason_redacted == "redacted persistence failure"


def test_sandbox_request_identity_is_required():
    with pytest.raises(ValidationError):
        SandboxRun(run_id="run-1", task_id="task-1", runtime="container")


def test_build_execution_requests_normalizes_auto_to_container(tmp_path):
    requests = _three_valid_requests(
        tmp_path,
        task_id="task-auto-requests",
        runtime="auto",
    )

    assert len(requests) == 3
    assert {item.runtime for item in requests} == {"container"}


def test_auto_runtime_records_each_request_when_container_start_fails(tmp_path):
    created = []
    raw = "runtime-construction-secret-987"

    def fail_factory(runtime):
        created.append(runtime)
        raise RuntimeError(f"client_secret={raw}")

    requests = _three_valid_requests(
        tmp_path,
        task_id="task-auto-runtime",
        runtime="container",
    )
    saved = []
    runner = _runner()
    runner._harness_for_runtime = fail_factory

    result = runner.run(
        task_id="task-auto-runtime",
        review_input={"task_id": "task-auto-runtime"},
        runtime="auto",
        dry_run=True,
        requests=requests,
        policy_context=_context(requests[0]),
        on_run=saved.append,
    )

    assert created == ["container"]
    assert result.effective_runtime == "container"
    assert len(result.runs) == len(saved) == 3
    assert saved == result.runs
    assert [item.request_id for item in result.runs] == [item.request_id for item in requests]
    assert {item.failure_kind for item in result.runs} == {"runtime_unavailable"}
    assert all(item.runtime == "container" for item in result.runs)
    assert all(item.decision == "allow" and item.exit_code == -1 for item in result.runs)
    assert [item.command for item in result.runs] == [list(item.command_argv) for item in requests]
    assert [item.run_id for item in result.runs] == [
        "sandbox_" + hashlib.sha256(f"{item.task_id}:{item.request_id}".encode("utf-8")).hexdigest()[:24]
        for item in requests
    ]
    assert raw not in json.dumps([item.model_dump(mode="json") for item in result.runs], sort_keys=True)


def test_successful_local_runs_keep_request_identity(tmp_path):
    requests = _three_valid_requests(
        tmp_path,
        task_id="task-local-identity",
        runtime="local",
    )

    result = _runner().run(
        task_id="task-local-identity",
        review_input={"task_id": "task-local-identity"},
        runtime="local",
        dry_run=True,
        requests=requests,
        policy_context=_context(requests[0]),
    )

    assert [item.request_id for item in result.runs] == [item.request_id for item in requests]
    assert [item.command for item in result.runs] == [list(item.command_argv) for item in requests]
    assert {item.runtime for item in result.runs} == {"local"}


def test_request_execution_exception_records_failure_and_continues(tmp_path):
    requests = _three_valid_requests(
        tmp_path,
        task_id="task-execution-error",
        runtime="container",
    )
    calls = []
    saved = []
    raw = "orchestration-secret-987"

    class PerRequestHarness:

        def execute_one(self, **kwargs):
            request = kwargs["request"]
            calls.append(request.request_id)
            if request.request_id == requests[1].request_id:
                raise RuntimeError(f"client_secret={raw}")
            return _successful_run(request)

    runner = _runner(harness=PerRequestHarness())
    result = runner.run(
        task_id="task-execution-error",
        review_input={"task_id": "task-execution-error"},
        runtime="container",
        dry_run=True,
        requests=requests,
        policy_context=_context(requests[0]),
        on_run=saved.append,
    )

    assert calls == [item.request_id for item in requests]
    assert saved == result.runs
    assert [item.request_id for item in result.runs] == [item.request_id for item in requests]
    assert [item.failure_kind for item in result.runs] == ["", "orchestration_error", ""]
    assert raw not in json.dumps([item.model_dump(mode="json") for item in result.runs], sort_keys=True)


@pytest.mark.parametrize(
    "changes",
    (
        pytest.param({"task_id": "other-task"}, id="task-id"),
        pytest.param({"request_id": "task-returned-identity:other"}, id="request-id"),
        pytest.param({"runtime": "local"}, id="runtime"),
        pytest.param({"decision": "deny"}, id="decision"),
    ),
)
def test_returned_run_identity_mismatch_becomes_orchestration_error(tmp_path, changes):
    request = _three_valid_requests(
        tmp_path,
        task_id="task-returned-identity",
        runtime="container",
    )[0]

    class MismatchedHarness:

        def execute_one(self, **kwargs):
            return _successful_run(kwargs["request"]).model_copy(update=changes)

    saved = []
    result = _runner(harness=MismatchedHarness()).run(
        task_id=request.task_id,
        review_input={"task_id": request.task_id},
        runtime="container",
        dry_run=True,
        requests=[request],
        policy_context=_context(request),
        on_run=saved.append,
    )

    assert saved == result.runs
    assert len(result.runs) == 1
    assert result.runs[0].task_id == request.task_id
    assert result.runs[0].request_id == request.request_id
    assert result.runs[0].runtime == request.runtime
    assert result.runs[0].decision == "allow"
    assert result.runs[0].failure_kind == "orchestration_error"


def test_successful_returned_run_discards_stale_failure_fields(tmp_path):
    request = _three_valid_requests(
        tmp_path,
        task_id="task-success-audit",
        runtime="container",
    )[0]
    raw = "returned-success-secret-987"

    class StaleFailureHarness:

        def execute_one(self, **kwargs):
            return _successful_run(kwargs["request"]).model_copy(
                update={
                    "failure_kind": "execution_nonzero",
                    "failure_reason": f"stale failure client_secret={raw}",
                    "warning": f"advisory client_secret={raw}",
                })

    saved = []
    result = _runner(harness=StaleFailureHarness()).run(
        task_id=request.task_id,
        review_input={"task_id": request.task_id},
        runtime="container",
        dry_run=True,
        requests=[request],
        policy_context=_context(request),
        on_run=saved.append,
    )

    assert saved == result.runs
    assert len(result.runs) == 1
    assert result.runs[0].failure_kind == ""
    assert result.runs[0].failure_reason == ""
    assert result.runs[0].warning.startswith("advisory ")
    assert raw not in json.dumps(result.runs[0].model_dump(mode="json"), sort_keys=True)


@pytest.mark.parametrize(
    ("changes", "failure_kind", "reason_field", "raw"),
    (
        pytest.param(
            {
                "timed_out": True,
                "exit_code": -1,
                "failure_kind": "runtime_unavailable",
                "failure_reason": "stale failure client_secret=returned-timeout-secret-987",
                "warning": "timeout warning client_secret=returned-timeout-secret-987",
                "stderr": "timeout stderr client_secret=returned-timeout-secret-987",
            },
            "execution_timeout",
            "warning",
            "returned-timeout-secret-987",
            id="timeout"),
        pytest.param(
            {
                "timed_out": False,
                "exit_code": 7,
                "failure_kind": "runtime_unavailable",
                "failure_reason": "stale failure client_secret=returned-nonzero-secret-987",
                "warning": "",
                "stderr": "nonzero stderr client_secret=returned-nonzero-secret-987",
            },
            "execution_nonzero",
            "stderr",
            "returned-nonzero-secret-987",
            id="nonzero"),
    ),
)
def test_returned_run_failure_is_classified(tmp_path, changes, failure_kind, reason_field, raw):
    request = _three_valid_requests(
        tmp_path,
        task_id="task-run-classification",
        runtime="container",
    )[0]

    class ClassifiedHarness:

        def execute_one(self, **kwargs):
            return _successful_run(kwargs["request"]).model_copy(update=changes)

    result = _runner(harness=ClassifiedHarness()).run(
        task_id=request.task_id,
        review_input={"task_id": request.task_id},
        runtime="container",
        dry_run=True,
        requests=[request],
        policy_context=_context(request),
    )

    assert len(result.runs) == 1
    assert result.runs[0].request_id == request.request_id
    assert result.runs[0].failure_kind == failure_kind
    assert result.runs[0].failure_reason == getattr(result.runs[0], reason_field)
    assert result.runs[0].failure_reason
    assert "stale failure" not in result.runs[0].failure_reason
    assert raw not in json.dumps(result.runs[0].model_dump(mode="json"), sort_keys=True)


def test_same_decision_is_unique_across_tasks(tmp_path):
    policy = ReviewExecutionPolicy(dry_run=True)
    first_request = _request(tmp_path, task_id="task-a")
    second_request = _request(tmp_path, task_id="task-b")

    first = policy.evaluate(first_request, _context(first_request)).intercept
    second = policy.evaluate(second_request, _context(second_request)).intercept

    assert first.decision == second.decision == "allow"
    assert first.intercept_id != second.intercept_id
    assert len(first.intercept_id.removeprefix("filter_")) == 24
    assert len(second.intercept_id.removeprefix("filter_")) == 24
    assert first.task_id == "task-a"
    assert second.task_id == "task-b"
    assert first.request_id == first_request.request_id
    assert second.request_id == second_request.request_id


@pytest.mark.parametrize(
    ("decision", "error_kind"),
    (
        ("allow", ""),
        ("deny", "policy_denied"),
        ("needs_human_review", "approval_required"),
    ),
)
def test_filter_decision_model_accepts_only_exact_taxonomy_pairs(decision, error_kind):
    item = FilterIntercept(
        intercept_id=f"decision-{decision}",
        task_id="task-1",
        request_id="task-1:skill-run:1",
        decision=decision,
        error_kind=error_kind,
        reason="canonical decision",
    )

    assert item.error_kind == error_kind


@pytest.mark.parametrize(
    ("missing", "decision", "error_kind"),
    (
        ("task_id", "allow", ""),
        ("request_id", "allow", ""),
        ("error_kind", "allow", ""),
        (None, "allow", "policy_denied"),
        (None, "deny", ""),
        (None, "needs_human_review", "policy_denied"),
        (None, "unknown", ""),
    ),
)
def test_filter_decision_model_rejects_missing_or_mismatched_taxonomy(missing, decision, error_kind):
    payload = {
        "intercept_id": "decision-1",
        "task_id": "task-1",
        "request_id": "task-1:skill-run:1",
        "decision": decision,
        "error_kind": error_kind,
        "reason": "canonical decision",
    }
    if missing is not None:
        del payload[missing]

    with pytest.raises(ValidationError):
        FilterIntercept.model_validate(payload)


def test_filter_decision_error_taxonomy_is_persisted(tmp_path):
    storage, task, requests = _running_task_with_three_requests(tmp_path)
    policy = ReviewExecutionPolicy(dry_run=True)
    commands = (
        requests[0].command_argv,
        ("rm", "-rf", "/"),
        ("pip", "install", "unapproved-package"),
    )
    for request, command in zip(requests, commands):
        evaluated = request.model_copy(update={"command_argv": command})
        item = policy.evaluate(evaluated, _context(request)).intercept
        storage.save_filter_decision(item)

    rows = storage.query_task(task.task_id)["filter_intercepts"]

    assert {
        row["decision"]: row["error_kind"]
        for row in rows
    } == {
        "allow": "",
        "deny": "policy_denied",
        "needs_human_review": "approval_required",
    }


def test_filter_decision_metadata_excludes_raw_input_and_environment(tmp_path):
    request = _request(tmp_path)

    item = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context(request)).intercept

    assert request.inputs[0].src not in item.metadata.values()
    assert all(env.name not in item.metadata for env in request.env)
    assert all(env.value not in item.metadata.values() for env in request.env)


def test_duplicate_task_request_decision_is_an_integrity_error(tmp_path):
    storage, _, requests = _running_task_with_three_requests(tmp_path)
    request = requests[0]
    item = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context(request)).intercept
    duplicate = item.model_copy(update={"intercept_id": item.intercept_id + "-duplicate"})
    storage.save_filter_decision(item)

    with pytest.raises(IntegrityError):
        storage.save_filter_decision(duplicate)


@pytest.mark.parametrize("field", ("intercept_id", "task_id", "request_id"))
@pytest.mark.parametrize("empty_value", ("", "   "))
def test_filter_decision_model_rejects_empty_identity_fields(field, empty_value):
    payload = {
        "intercept_id": "decision-1",
        "task_id": "task-1",
        "request_id": "task-1:skill-run:1",
        "decision": "allow",
        "error_kind": "",
        "reason": "canonical decision",
    }
    payload[field] = empty_value

    with pytest.raises(ValidationError):
        FilterIntercept.model_validate(payload)


def test_filter_decision_storage_revalidates_model_copy_identity(tmp_path):
    storage, task, requests = _running_task_with_three_requests(tmp_path)
    item = ReviewExecutionPolicy(dry_run=True).evaluate(requests[0], _context(requests[0])).intercept
    invalid_singular = item.model_copy(update={
        "intercept_id": "invalid-singular",
        "request_id": "",
    })
    invalid_bulk = item.model_copy(update={
        "intercept_id": "invalid-bulk",
        "request_id": "",
    })

    with pytest.raises(ValidationError):
        storage.save_filter_decision(invalid_singular)
    with pytest.raises(ValidationError):
        storage.save_filter_intercepts([invalid_bulk])

    assert storage.query_task(task.task_id)["filter_intercepts"] == []


def test_distinct_invalid_request_decisions_are_audited_without_raw_identity(tmp_path):
    storage, task, requests = _running_task_with_three_requests(tmp_path)
    base = requests[0]
    first_raw = "bad id one"
    second_raw = "bad id two"
    policy = ReviewExecutionPolicy(dry_run=True)
    first = policy.evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    second = policy.evaluate(
        base.model_copy(update={"request_id": second_raw}),
        _context(base),
    ).intercept

    storage.save_filter_decision(first)
    storage.save_filter_decision(second)
    repeated = ReviewExecutionPolicy(dry_run=True).evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    rows = storage.query_task(task.task_id)["filter_intercepts"]
    serialized = json.dumps(rows, ensure_ascii=False, sort_keys=True)

    assert first.decision == second.decision == "deny"
    assert first.reason == second.reason == "request id is invalid"
    assert first.request_id != second.request_id
    assert first.intercept_id != second.intercept_id
    assert first.request_id.startswith("invalid-")
    assert second.request_id.startswith("invalid-")
    assert len(first.request_id.removeprefix("invalid-")) == 24
    assert len(second.request_id.removeprefix("invalid-")) == 24
    assert int(first.request_id.removeprefix("invalid-"), 16) >= 0
    assert int(second.request_id.removeprefix("invalid-"), 16) >= 0
    assert repeated.request_id == first.request_id
    assert repeated.intercept_id == first.intercept_id
    assert len(rows) == 2
    assert first_raw not in serialized
    assert second_raw not in serialized
    with pytest.raises(IntegrityError):
        storage.save_filter_decision(repeated)


def test_distinct_invalid_container_request_decisions_are_audited_without_raw_identity(tmp_path):
    storage, task, requests = _running_task_with_three_requests(tmp_path)
    base = requests[0]
    first_raw = [1]
    second_raw = [2]
    policy = ReviewExecutionPolicy(dry_run=True)
    first = policy.evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    second = policy.evaluate(
        base.model_copy(update={"request_id": second_raw}),
        _context(base),
    ).intercept

    storage.save_filter_decision(first)
    storage.save_filter_decision(second)
    repeated = ReviewExecutionPolicy(dry_run=True).evaluate(
        base.model_copy(update={"request_id": [1]}),
        _context(base),
    ).intercept
    rows = storage.query_task(task.task_id)["filter_intercepts"]
    serialized = json.dumps(
        {
            "first": first.model_dump(mode="json"),
            "second": second.model_dump(mode="json"),
            "rows": rows,
        },
        ensure_ascii=False,
        sort_keys=True,
    )

    assert first.decision == second.decision == "deny"
    assert first.reason == second.reason == "request id is invalid"
    assert first.request_id != second.request_id
    assert first.intercept_id != second.intercept_id
    for item in (first, second):
        request_digest = item.request_id.removeprefix("invalid-")
        intercept_digest = item.intercept_id.removeprefix("filter_")
        assert item.request_id.startswith("invalid-")
        assert item.intercept_id.startswith("filter_")
        assert len(request_digest) == len(intercept_digest) == 24
        assert int(request_digest, 16) >= 0
        assert int(intercept_digest, 16) >= 0
    assert repeated.request_id == first.request_id
    assert repeated.intercept_id == first.intercept_id
    assert len(rows) == 2
    assert str(first_raw) not in serialized
    assert str(second_raw) not in serialized
    with pytest.raises(IntegrityError):
        storage.save_filter_decision(repeated)


@pytest.mark.parametrize(
    ("first_raw", "second_raw", "secret"),
    (
        pytest.param(
            {"1": "typed-key-secret"},
            {1: "typed-key-secret"},
            "typed-key-secret",
            id="dict-string-int-key",
        ),
        pytest.param(
            {"null": "typed-null-secret"},
            {None: "typed-null-secret"},
            "typed-null-secret",
            id="dict-string-none-key",
        ),
        pytest.param(
            {"true": "typed-bool-secret"},
            {True: "typed-bool-secret"},
            "typed-bool-secret",
            id="dict-string-bool-key",
        ),
        pytest.param(
            [("typed-sequence-secret", )],
            [["typed-sequence-secret"]],
            "typed-sequence-secret",
            id="nested-tuple-list",
        ),
        pytest.param(
            {"value": ("typed-value-secret", )},
            {"value": ["typed-value-secret"]},
            "typed-value-secret",
            id="dict-value-tuple-list",
        ),
    ),
)
def test_typed_invalid_container_request_decisions_are_distinct_and_replay_stable(tmp_path, first_raw, second_raw,
                                                                                  secret):
    storage, task, requests = _running_task_with_three_requests(tmp_path)
    base = requests[0]
    policy = ReviewExecutionPolicy(dry_run=True)
    first = policy.evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    second = policy.evaluate(
        base.model_copy(update={"request_id": second_raw}),
        _context(base),
    ).intercept

    storage.save_filter_decision(first)
    storage.save_filter_decision(second)
    repeated = ReviewExecutionPolicy(dry_run=True).evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    rows = storage.query_task(task.task_id)["filter_intercepts"]
    serialized = json.dumps(
        {
            "first": first.model_dump(mode="json"),
            "second": second.model_dump(mode="json"),
            "rows": rows,
        },
        ensure_ascii=False,
        sort_keys=True,
    )

    assert first.decision == second.decision == "deny"
    assert first.reason == second.reason == "request id is invalid"
    assert first.request_id != second.request_id
    assert first.intercept_id != second.intercept_id
    for item in (first, second):
        request_digest = item.request_id.removeprefix("invalid-")
        intercept_digest = item.intercept_id.removeprefix("filter_")
        assert item.request_id.startswith("invalid-")
        assert item.intercept_id.startswith("filter_")
        assert len(request_digest) == len(intercept_digest) == 24
        assert int(request_digest, 16) >= 0
        assert int(intercept_digest, 16) >= 0
    assert repeated.request_id == first.request_id
    assert repeated.intercept_id == first.intercept_id
    assert len(rows) == 2
    assert secret not in serialized
    assert repr(first_raw) not in serialized
    assert repr(second_raw) not in serialized
    with pytest.raises(IntegrityError):
        storage.save_filter_decision(repeated)


def test_typed_invalid_container_dict_order_is_replay_stable(tmp_path):
    storage, _, requests = _running_task_with_three_requests(tmp_path)
    base = requests[0]
    first_raw = {
        "z": ("typed-order-secret", ),
        "a": [1],
    }
    reordered_raw = {
        "a": [1],
        "z": ("typed-order-secret", ),
    }
    policy = ReviewExecutionPolicy(dry_run=True)
    first = policy.evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    reordered = policy.evaluate(
        base.model_copy(update={"request_id": reordered_raw}),
        _context(base),
    ).intercept

    storage.save_filter_decision(first)

    assert reordered.request_id == first.request_id
    assert reordered.intercept_id == first.intercept_id
    assert "typed-order-secret" not in json.dumps(first.model_dump(mode="json"), sort_keys=True)
    with pytest.raises(IntegrityError):
        storage.save_filter_decision(reordered)


def test_typed_invalid_cyclic_container_identity_is_replay_stable(tmp_path):
    storage, _, requests = _running_task_with_three_requests(tmp_path)
    base = requests[0]
    first_raw = ["typed-cycle-secret"]
    first_raw.append(first_raw)
    replay_raw = ["typed-cycle-secret"]
    replay_raw.append(replay_raw)
    policy = ReviewExecutionPolicy(dry_run=True)
    first = policy.evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    replay = policy.evaluate(
        base.model_copy(update={"request_id": replay_raw}),
        _context(base),
    ).intercept

    storage.save_filter_decision(first)

    assert replay.request_id == first.request_id
    assert replay.intercept_id == first.intercept_id
    assert "typed-cycle-secret" not in json.dumps(first.model_dump(mode="json"), sort_keys=True)
    with pytest.raises(IntegrityError):
        storage.save_filter_decision(replay)


def test_allow_decision_is_saved_before_execution(tmp_path):
    events = []
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    task = ReviewTask(
        task_id="task-1",
        input_type="fixture",
        runtime="container",
        dry_run=True,
    )
    storage.create_task_with_input(
        task=task,
        redacted_diff="",
        changed_files=[],
        redaction_summary=RedactionSummary(),
        input_metadata={},
    )
    storage.update_task(transition_task(task, ReviewTaskStatus.RUNNING))

    class OrderingHarness:

        def execute_one(self, **kwargs):
            request = kwargs["request"]
            rows = storage.query_task(task.task_id)
            assert rows["filter_intercepts"][0]["request_id"] == request.request_id
            events.append("execute")
            return _successful_run(request)

    request = _request(tmp_path, task_id=task.task_id)
    runner = _runner(harness=OrderingHarness())
    runner.run(
        task_id=task.task_id,
        review_input={"task_id": task.task_id},
        runtime="container",
        dry_run=True,
        requests=[request],
        policy_context=_context(request),
        on_decision=storage.save_filter_decision,
        on_run=storage.save_sandbox_run,
    )

    assert events == ["execute"]
