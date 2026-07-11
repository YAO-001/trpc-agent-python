# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Telemetry aggregation for the code review example."""

from __future__ import annotations

from collections import Counter

from .models import FilterIntercept
from .models import Finding
from .models import ParsedDiff
from .models import RedactionSummary
from .models import ReviewWarning
from .models import ReviewTaskStatus
from .models import SandboxRun
from .models import TelemetrySummary
from .models import utc_now


def build_telemetry(
    *,
    task_id: str,
    task_status: ReviewTaskStatus,
    task_failure_kind: str,
    parsed_diff: ParsedDiff,
    findings: list[Finding],
    warnings: list[ReviewWarning],
    needs_human_review: list[ReviewWarning],
    filter_intercepts: list[FilterIntercept],
    sandbox_runs: list[SandboxRun],
    redaction_summary: RedactionSummary,
    debug_dropped_count: int,
    elapsed_ms: int,
    dry_run: bool,
) -> TelemetrySummary:
    orchestration_elapsed_ms = 0 if dry_run else elapsed_ms
    # Count audit events at each layer, not distinct labels: the same label on a
    # run and on its task is two independently persisted failure observations.
    exception_kinds = Counter(item.error_kind for item in filter_intercepts if item.error_kind)
    exception_kinds.update(item.failure_kind for item in sandbox_runs if item.failure_kind)
    if task_failure_kind:
        exception_kinds[task_failure_kind] += 1
    severity_distribution = Counter(item.severity for item in findings)
    return TelemetrySummary(
        task_id=task_id,
        task_status=task_status,
        task_failure_kind=task_failure_kind,
        orchestration_elapsed_ms=orchestration_elapsed_ms,
        sandbox_elapsed_ms=sum(item.duration_ms for item in sandbox_runs if item.execution_started),
        tool_attempts_count=len(filter_intercepts),
        tool_executed_count=sum(1 for item in sandbox_runs if item.execution_started),
        severity_distribution=dict(sorted(severity_distribution.items())),
        exception_kind_distribution=dict(sorted(exception_kinds.items())),
        output_limit_exceeded_count=sum(1 for item in sandbox_runs if item.failure_kind == "output_limit_exceeded"),
        elapsed_ms=orchestration_elapsed_ms,
        files_changed=len(parsed_diff.changed_files),
        lines_added=parsed_diff.total_added_lines,
        findings_count=len(findings),
        warnings_count=len(warnings),
        needs_human_review_count=len(needs_human_review),
        filter_denied_count=sum(1 for item in filter_intercepts if item.decision == "deny"),
        filter_needs_review_count=sum(1 for item in filter_intercepts if item.decision == "needs_human_review"),
        sandbox_runs_count=len(sandbox_runs),
        sandbox_failures_count=sum(1 for item in sandbox_runs
                                   if item.failure_kind or item.exit_code != 0 or item.timed_out),
        stdout_truncated_count=sum(1 for item in sandbox_runs if item.stdout_truncated),
        stderr_truncated_count=sum(1 for item in sandbox_runs if item.stderr_truncated),
        output_truncated_count=sum(1 for item in sandbox_runs if item.output_truncated),
        redaction_count=redaction_summary.total_redactions,
        debug_dropped_count=debug_dropped_count,
        created_at=utc_now(dry_run),
    )
