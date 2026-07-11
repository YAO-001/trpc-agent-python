# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Explicit lifecycle transitions for review tasks."""

from __future__ import annotations

from .models import ReviewTask
from .models import ReviewTaskStatus
from .models import TERMINAL_TASK_STATUSES
from .models import utc_now

_ALLOWED = {
    ReviewTaskStatus.CREATED: {ReviewTaskStatus.RUNNING},
    ReviewTaskStatus.RUNNING: set(TERMINAL_TASK_STATUSES),
}


def transition_task(task: ReviewTask, target: ReviewTaskStatus) -> ReviewTask:
    current = ReviewTaskStatus(task.status)
    target = ReviewTaskStatus(target)
    if target not in _ALLOWED.get(current, set()):
        raise ValueError(f"illegal task transition: {current.value} -> {target.value}")
    return task.model_copy(update={
        "status": target,
        "updated_at": utc_now(task.dry_run),
    })
