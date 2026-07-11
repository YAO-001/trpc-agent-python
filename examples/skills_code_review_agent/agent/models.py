# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Pydantic models used by the deterministic code review example."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import datetime
from datetime import timezone
from enum import Enum
from typing import Any
from typing import Literal

from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator
from pydantic import model_validator

DRY_RUN_TIMESTAMP = "1970-01-01T00:00:00+00:00"


def utc_now(dry_run: bool = False) -> str:
    if dry_run:
        return DRY_RUN_TIMESTAMP
    return datetime.now(timezone.utc).isoformat()


def normalize_title(title: str) -> str:
    return re.sub(r"\s+", " ", title.strip().lower())


def finding_dedupe_key(file: str, line: int, category: str) -> str:
    payload = f"{file}:{line}:{category}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


FindingSeverity = Literal["info", "low", "medium", "high", "critical"]
ReviewCategory = Literal["security", "secret", "async_resource", "database", "test", "sandbox"]


def _canonical_sources(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set, frozenset)):
        values = list(value)
    else:
        raise ValueError("source must be a string or a sequence of strings")
    if not all(isinstance(item, str) for item in values):
        raise ValueError("source entries must be strings")
    return sorted({item for item in values if item})


class ReviewTaskStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    BLOCKED = "blocked"
    FAILED = "failed"


TERMINAL_TASK_STATUSES = frozenset({
    ReviewTaskStatus.COMPLETED,
    ReviewTaskStatus.COMPLETED_WITH_ERRORS,
    ReviewTaskStatus.BLOCKED,
    ReviewTaskStatus.FAILED,
})


class ReviewTask(BaseModel):
    task_id: str
    input_type: str
    input_ref: str = ""
    runtime: str = "container"
    dry_run: bool = False
    status: ReviewTaskStatus = ReviewTaskStatus.CREATED
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)
    failure_kind: str = ""
    failure_reason_redacted: str = ""

    @model_validator(mode="after")
    def _validate_failure_details(self) -> "ReviewTask":
        if self.status != ReviewTaskStatus.FAILED and (self.failure_kind or self.failure_reason_redacted):
            raise ValueError("failure details require failed task status")
        return self


class ChangedLine(BaseModel):
    file: str
    old_file: str = ""
    line: int
    content: str
    hunk_header: str = ""
    context_before: list[str] = Field(default_factory=list)
    context_after: list[str] = Field(default_factory=list)


class FileChange(BaseModel):
    old_file: str = ""
    new_file: str = ""
    is_deleted: bool = False
    is_new: bool = False
    added_lines: list[ChangedLine] = Field(default_factory=list)


class ParsedDiff(BaseModel):
    files: list[FileChange] = Field(default_factory=list)
    added_lines: list[ChangedLine] = Field(default_factory=list)
    changed_files: list[str] = Field(default_factory=list)
    total_added_lines: int = 0


class Finding(BaseModel):
    severity: FindingSeverity
    category: ReviewCategory
    file: str
    line: int = Field(ge=0, strict=True)
    title: str
    evidence: str
    recommendation: str
    confidence: float = Field(ge=0.0, le=1.0, allow_inf_nan=False, strict=True)
    source: list[str] = Field(default_factory=list)
    dedupe_key: str = ""

    @field_validator("source", mode="before")
    @classmethod
    def _coerce_source(cls, value: Any) -> list[str]:
        return _canonical_sources(value)

    @model_validator(mode="after")
    def _set_dedupe_key(self) -> "Finding":
        self.dedupe_key = finding_dedupe_key(self.file, self.line, self.category)
        return self


class ReviewWarning(BaseModel):
    category: ReviewCategory
    title: str
    message: str
    file: str = ""
    line: int = Field(default=0, ge=0, strict=True)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, allow_inf_nan=False, strict=True)
    source: list[str] = Field(default_factory=list)
    needs_human_review: bool = False

    @field_validator("source", mode="before")
    @classmethod
    def _coerce_source(cls, value: Any) -> list[str]:
        return _canonical_sources(value)


class FilterIntercept(BaseModel):
    intercept_id: str
    task_id: str
    request_id: str
    decision: str
    error_kind: str
    reason: str
    command: list[str] = Field(default_factory=list)
    runtime: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=utc_now)

    @field_validator("intercept_id", "task_id", "request_id")
    @classmethod
    def _require_nonempty_identity(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("filter identity fields must not be empty")
        return value

    @model_validator(mode="after")
    def _validate_error_kind(self) -> "FilterIntercept":
        expected = {
            "allow": "",
            "deny": "policy_denied",
            "needs_human_review": "approval_required",
        }.get(self.decision)
        if expected is None or self.error_kind != expected:
            raise ValueError("filter decision and error kind do not match")
        return self


class SandboxRun(BaseModel):
    run_id: str
    task_id: str = ""
    request_id: str
    runtime: str
    command: list[str] = Field(default_factory=list)
    decision: str = "allow"
    exit_code: int = 0
    timed_out: bool = False
    duration_ms: int = 0
    stdout: str = ""
    stderr: str = ""
    output_files: dict[str, str] = Field(default_factory=dict)
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    output_truncated: bool = False
    output_file_count: int = 0
    output_bytes: int = 0
    termination_reason: str = ""
    termination_confirmed: bool = False
    execution_started: bool = False
    stdout_bytes_observed: int = 0
    stderr_bytes_observed: int = 0
    output_bytes_observed: int = 0
    failure_kind: str = ""
    failure_reason: str = ""
    warning: str = ""
    created_at: str = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _set_output_summary(self) -> "SandboxRun":
        self.output_file_count = len(self.output_files)
        self.output_bytes = sum(len(content.encode("utf-8")) for content in self.output_files.values())
        if not self.failure_reason and (self.exit_code != 0 or self.timed_out):
            self.failure_reason = self.warning or self.stderr or self.stdout or "sandbox command failed or timed out"
        return self


def terminal_status(
    *,
    task_id: str,
    required_request_ids: set[str],
    decisions: list[FilterIntercept],
    runs: list[SandboxRun],
) -> ReviewTaskStatus:
    """Derive a truthful terminal state from the complete execution audit."""
    if not required_request_ids:
        return ReviewTaskStatus.FAILED
    if any(item.task_id != task_id or item.request_id not in required_request_ids
           or item.decision not in {"allow", "deny", "needs_human_review"} for item in decisions):
        return ReviewTaskStatus.FAILED
    decision_counts = Counter(item.request_id for item in decisions)
    if set(decision_counts) != required_request_ids or any(count != 1 for count in decision_counts.values()):
        return ReviewTaskStatus.FAILED
    allow_ids = {item.request_id for item in decisions if item.decision == "allow"}
    non_allow_ids = {item.request_id for item in decisions if item.decision in {"deny", "needs_human_review"}}
    if any(item.task_id != task_id or item.request_id not in allow_ids or item.decision != "allow" for item in runs):
        return ReviewTaskStatus.FAILED
    run_counts = Counter(item.request_id for item in runs)
    if set(run_counts) != allow_ids or any(count != 1 for count in run_counts.values()):
        return ReviewTaskStatus.FAILED
    if non_allow_ids:
        return ReviewTaskStatus.BLOCKED
    run_by_request = {item.request_id: item for item in runs}
    required_runs = [run_by_request[item] for item in sorted(allow_ids)]
    if any(item.failure_kind in {"runtime_unavailable", "orchestration_error"} for item in required_runs):
        return ReviewTaskStatus.FAILED
    if any(item.failure_kind or item.exit_code != 0 or item.timed_out for item in required_runs):
        return ReviewTaskStatus.COMPLETED_WITH_ERRORS
    return ReviewTaskStatus.COMPLETED


class TelemetrySummary(BaseModel):
    task_id: str
    task_status: ReviewTaskStatus
    elapsed_ms: int = 0
    files_changed: int = 0
    lines_added: int = 0
    findings_count: int = 0
    warnings_count: int = 0
    needs_human_review_count: int = 0
    filter_denied_count: int = 0
    filter_needs_review_count: int = 0
    sandbox_runs_count: int = 0
    sandbox_failures_count: int = 0
    stdout_truncated_count: int = 0
    stderr_truncated_count: int = 0
    output_truncated_count: int = 0
    redaction_count: int = 0
    debug_dropped_count: int = 0
    created_at: str = Field(default_factory=utc_now)


class RedactionEvent(BaseModel):
    secret_type: str
    sha256: str
    placeholder: str
    count: int = 1
    likely_placeholder: bool = False


class RedactionSummary(BaseModel):
    total_redactions: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    events: list[RedactionEvent] = Field(default_factory=list)


class ReviewReport(BaseModel):
    schema_version: str = "2.0"
    task_id: str
    task_status: ReviewTaskStatus
    conclusion: str
    findings: list[Finding] = Field(default_factory=list)
    warnings: list[ReviewWarning] = Field(default_factory=list)
    needs_human_review: list[ReviewWarning] = Field(default_factory=list)
    filter_intercepts: list[FilterIntercept] = Field(default_factory=list)
    sandbox_runs: list[SandboxRun] = Field(default_factory=list)
    telemetry: TelemetrySummary
    severity_distribution: dict[str, int] = Field(default_factory=dict)
    section_summary: dict[str, Any] = Field(default_factory=dict)
    redaction_summary: RedactionSummary = Field(default_factory=RedactionSummary)
    recommendations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_terminal_identity(self) -> "ReviewReport":
        if self.telemetry.task_id != self.task_id:
            raise ValueError("report and telemetry task identity must match")
        if self.telemetry.task_status != self.task_status:
            raise ValueError("report and telemetry task status must match")
        return self

    database_query: str = ""
    report_paths: dict[str, str] = Field(default_factory=dict)
    input_summary: dict[str, Any] = Field(default_factory=dict)
