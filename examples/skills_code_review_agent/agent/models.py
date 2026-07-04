# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Pydantic models used by the deterministic code review example."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from datetime import timezone
from typing import Any

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


def finding_dedupe_key(file: str, line: int, category: str, title: str) -> str:
    payload = f"{file}:{line}:{category}:{normalize_title(title)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ReviewTask(BaseModel):
    task_id: str
    input_type: str
    input_ref: str = ""
    runtime: str = "container"
    dry_run: bool = False
    status: str = "created"
    created_at: str = Field(default_factory=utc_now)


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
    severity: str
    category: str
    file: str
    line: int
    title: str
    evidence: str
    recommendation: str
    confidence: float
    source: list[str] = Field(default_factory=list)
    dedupe_key: str = ""

    @field_validator("source", mode="before")
    @classmethod
    def _coerce_source(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return list(value)

    @model_validator(mode="after")
    def _set_dedupe_key(self) -> "Finding":
        if not self.dedupe_key:
            self.dedupe_key = finding_dedupe_key(self.file, self.line, self.category, self.title)
        self.source = sorted({str(item) for item in self.source if str(item)})
        return self


class ReviewWarning(BaseModel):
    category: str
    title: str
    message: str
    file: str = ""
    line: int = 0
    confidence: float = 0.0
    source: list[str] = Field(default_factory=list)
    needs_human_review: bool = False

    @field_validator("source", mode="before")
    @classmethod
    def _coerce_source(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return list(value)


class FilterIntercept(BaseModel):
    intercept_id: str
    task_id: str = ""
    decision: str
    reason: str
    command: list[str] = Field(default_factory=list)
    runtime: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=utc_now)


class SandboxRun(BaseModel):
    run_id: str
    task_id: str = ""
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


class TelemetrySummary(BaseModel):
    task_id: str
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


class RedactionSummary(BaseModel):
    total_redactions: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    events: list[RedactionEvent] = Field(default_factory=list)


class ReviewReport(BaseModel):
    schema_version: str = "1.0"
    task_id: str
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
    database_query: str = ""
    report_paths: dict[str, str] = Field(default_factory=dict)
    input_summary: dict[str, Any] = Field(default_factory=dict)
