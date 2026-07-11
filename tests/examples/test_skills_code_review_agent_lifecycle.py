# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Lifecycle state-machine tests for the skills code review agent example."""

from __future__ import annotations

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
from agent.sandbox_runner import HarnessExecutionResult
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


def test_sandbox_request_and_failure_fields_remain_temporarily_optional():
    run = SandboxRun(run_id="run-1", task_id="task-1", runtime="container")

    assert run.request_id == ""
    assert run.failure_kind == ""


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
            return HarnessExecutionResult(runs=[_successful_run(request)])

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
