# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Lifecycle state-machine tests for the skills code review agent example."""

from __future__ import annotations

from itertools import product

import pytest

from agent.models import FilterIntercept
from agent.models import ReviewTask
from agent.models import ReviewTaskStatus
from agent.models import SandboxRun
from agent.models import TERMINAL_TASK_STATUSES
from agent.task_state import transition_task

STATUSES = list(ReviewTaskStatus)
ALLOWED = {
    (ReviewTaskStatus.CREATED, ReviewTaskStatus.RUNNING),
    (ReviewTaskStatus.RUNNING, ReviewTaskStatus.COMPLETED),
    (ReviewTaskStatus.RUNNING, ReviewTaskStatus.COMPLETED_WITH_ERRORS),
    (ReviewTaskStatus.RUNNING, ReviewTaskStatus.BLOCKED),
    (ReviewTaskStatus.RUNNING, ReviewTaskStatus.FAILED),
}


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


def test_request_and_error_fields_remain_temporarily_optional():
    run = SandboxRun(run_id="run-1", task_id="task-1", runtime="container")
    intercept = FilterIntercept(
        intercept_id="decision-1",
        task_id="task-1",
        decision="allow",
        reason="canonical request",
    )

    assert run.request_id == ""
    assert run.failure_kind == ""
    assert intercept.request_id == ""
    assert intercept.error_kind == ""
