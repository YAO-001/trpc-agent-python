# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""SQL persistence for review tasks and reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import Float
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import Text
from sqlalchemy import create_engine
from sqlalchemy import delete
from sqlalchemy import select
from sqlalchemy import text

from .models import FilterIntercept
from .models import Finding
from .models import RedactionSummary
from .models import ReviewReport
from .models import ReviewTask
from .models import SandboxRun
from .models import TelemetrySummary
from .redaction_boundary import RedactionBoundary

DEFAULT_DB_URL = "sqlite:///examples/skills_code_review_agent/review.db"
_JSON_BLOB_FIELDS = frozenset({
    "changed_files_json",
    "command_json",
    "input_metadata_json",
    "json_report",
    "metadata_json",
    "metrics_json",
    "output_files_json",
    "redaction_summary_json",
    "source_json",
    "summary_json",
})
metadata = MetaData()

review_tasks = Table(
    "review_tasks",
    metadata,
    Column("task_id", String(128), primary_key=True),
    Column("input_type", String(64), nullable=False),
    Column("input_ref", Text, nullable=False),
    Column("runtime", String(64), nullable=False),
    Column("dry_run", Boolean, nullable=False),
    Column("status", String(64), nullable=False),
    Column("created_at", String(64), nullable=False),
)
review_inputs = Table(
    "review_inputs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("task_id", String(128), nullable=False),
    Column("redacted_diff", Text, nullable=False),
    Column("changed_files_json", Text, nullable=False),
    Column("redaction_summary_json", Text, nullable=False),
    Column("input_metadata_json", Text, nullable=False),
)
sandbox_runs = Table(
    "sandbox_runs",
    metadata,
    Column("run_id", String(160), primary_key=True),
    Column("task_id", String(128), nullable=False),
    Column("runtime", String(64), nullable=False),
    Column("command_json", Text, nullable=False),
    Column("decision", String(64), nullable=False),
    Column("exit_code", Integer, nullable=False),
    Column("timed_out", Boolean, nullable=False),
    Column("duration_ms", Integer, nullable=False),
    Column("stdout", Text, nullable=False),
    Column("stderr", Text, nullable=False),
    Column("output_files_json", Text, nullable=False),
    Column("stdout_truncated", Boolean, nullable=False, default=False),
    Column("stderr_truncated", Boolean, nullable=False, default=False),
    Column("output_truncated", Boolean, nullable=False, default=False),
    Column("output_file_count", Integer, nullable=False, default=0),
    Column("output_bytes", Integer, nullable=False, default=0),
    Column("failure_reason", Text, nullable=True),
    Column("warning", Text, nullable=False),
    Column("created_at", String(64), nullable=False),
)
findings = Table(
    "findings",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("task_id", String(128), nullable=False),
    Column("dedupe_key", String(64), nullable=False),
    Column("severity", String(32), nullable=False),
    Column("category", String(64), nullable=False),
    Column("file", Text, nullable=False),
    Column("line", Integer, nullable=False),
    Column("title", Text, nullable=False),
    Column("evidence", Text, nullable=False),
    Column("recommendation", Text, nullable=False),
    Column("confidence", Float, nullable=False),
    Column("source_json", Text, nullable=False),
)
filter_intercepts = Table(
    "filter_intercepts",
    metadata,
    Column("intercept_id", String(160), primary_key=True),
    Column("task_id", String(128), nullable=False),
    Column("decision", String(64), nullable=False),
    Column("reason", Text, nullable=False),
    Column("command_json", Text, nullable=False),
    Column("runtime", String(64), nullable=False),
    Column("metadata_json", Text, nullable=False),
    Column("created_at", String(64), nullable=False),
)
telemetry_summaries = Table(
    "telemetry_summaries",
    metadata,
    Column("task_id", String(128), primary_key=True),
    Column("metrics_json", Text, nullable=False),
    Column("created_at", String(64), nullable=False),
)
reports = Table(
    "reports",
    metadata,
    Column("task_id", String(128), primary_key=True),
    Column("json_report", Text, nullable=False),
    Column("markdown_report", Text, nullable=False),
    Column("json_path", Text, nullable=False),
    Column("markdown_path", Text, nullable=False),
    Column("summary_json", Text, nullable=False, default="{}"),
    Column("created_at", String(64), nullable=False),
)


class ReviewStorage:

    def __init__(self, db_url: str = DEFAULT_DB_URL, boundary: RedactionBoundary | None = None) -> None:
        self.db_url = db_url
        self.boundary = boundary or RedactionBoundary()
        self._ensure_sqlite_parent(db_url)
        self.engine = create_engine(db_url, future=True)
        metadata.create_all(self.engine)
        self._ensure_schema_compat()

    def _safe_row(self, row: dict[str, Any]) -> dict[str, Any]:
        ordinary = {key: value for key, value in row.items() if key not in _JSON_BLOB_FIELDS}
        safe = self.boundary.clean(ordinary)
        if not isinstance(safe, dict):  # pragma: no cover - caller contract
            raise TypeError("storage row must remain a mapping after redaction")
        for field, value in row.items():
            if field not in _JSON_BLOB_FIELDS:
                continue
            safe_field = self.boundary.text(field).text
            safe[safe_field] = self._safe_json_blob(field, value)
        return safe

    def _safe_json_blob(self, field: str, value: Any) -> str:
        if isinstance(value, str):
            try:
                payload = json.loads(value)
            except json.JSONDecodeError:
                raise ValueError(f"{field} must contain valid JSON") from None
        else:
            payload = value
        cleaned = self.boundary.clean(payload)
        try:
            return json.dumps(cleaned, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            raise ValueError(f"{field} must contain JSON-serializable data") from None

    @staticmethod
    def _ensure_sqlite_parent(db_url: str) -> None:
        if not db_url.startswith("sqlite:///") or db_url == "sqlite:///:memory:":
            return
        path = Path(db_url.removeprefix("sqlite:///"))
        if path.parent:
            path.parent.mkdir(parents=True, exist_ok=True)

    def _ensure_schema_compat(self) -> None:
        if self.engine.dialect.name != "sqlite":
            return
        required = {
            "stdout_truncated": "BOOLEAN NOT NULL DEFAULT 0",
            "stderr_truncated": "BOOLEAN NOT NULL DEFAULT 0",
            "output_truncated": "BOOLEAN NOT NULL DEFAULT 0",
            "output_file_count": "INTEGER NOT NULL DEFAULT 0",
            "output_bytes": "INTEGER NOT NULL DEFAULT 0",
            "failure_reason": "TEXT",
        }
        with self.engine.begin() as conn:
            rows = conn.execute(text("PRAGMA table_info(sandbox_runs)")).mappings().all()
            existing = {row["name"] for row in rows}
            for column, definition in required.items():
                if column not in existing:
                    conn.execute(text(f"ALTER TABLE sandbox_runs ADD COLUMN {column} {definition}"))
            report_rows = conn.execute(text("PRAGMA table_info(reports)")).mappings().all()
            report_columns = {row["name"] for row in report_rows}
            if "summary_json" not in report_columns:
                conn.execute(text("ALTER TABLE reports ADD COLUMN summary_json TEXT NOT NULL DEFAULT '{}'"))

    def reset_task(self, task_id: str) -> None:
        task_id = self.boundary.text(task_id).text
        with self.engine.begin() as conn:
            for table in [
                    reports,
                    telemetry_summaries,
                    filter_intercepts,
                    findings,
                    sandbox_runs,
                    review_inputs,
                    review_tasks,
            ]:
                conn.execute(delete(table).where(table.c.task_id == task_id))

    def save_task(self, task: ReviewTask) -> None:
        row = self._safe_row(task.model_dump(mode="json"))
        with self.engine.begin() as conn:
            conn.execute(review_tasks.insert().values(**row))

    def save_input(
        self,
        *,
        task_id: str,
        redacted_diff: str,
        changed_files: list[str],
        redaction_summary: RedactionSummary,
        input_metadata: dict[str, Any],
    ) -> None:
        payload = self._safe_row({
            "task_id": task_id,
            "redacted_diff": redacted_diff,
            "changed_files": changed_files,
            "redaction_summary": redaction_summary.model_dump(mode="json"),
            "input_metadata": input_metadata,
        })
        row = self._safe_row({
            "task_id":
            payload["task_id"],
            "redacted_diff":
            payload["redacted_diff"],
            "changed_files_json":
            json.dumps(payload["changed_files"], ensure_ascii=False, sort_keys=True),
            "redaction_summary_json":
            json.dumps(payload["redaction_summary"], ensure_ascii=False, sort_keys=True),
            "input_metadata_json":
            json.dumps(payload["input_metadata"], ensure_ascii=False, sort_keys=True),
        })
        with self.engine.begin() as conn:
            conn.execute(review_inputs.insert().values(**row))

    def save_findings(self, task_id: str, items: list[Finding]) -> None:
        if not items:
            return
        rows = []
        for item in items:
            payload = self._safe_row(item.model_dump(mode="json"))
            rows.append(
                self._safe_row({
                    "task_id": task_id,
                    "dedupe_key": payload["dedupe_key"],
                    "severity": payload["severity"],
                    "category": payload["category"],
                    "file": payload["file"],
                    "line": payload["line"],
                    "title": payload["title"],
                    "evidence": payload["evidence"],
                    "recommendation": payload["recommendation"],
                    "confidence": payload["confidence"],
                    "source_json": json.dumps(payload["source"], ensure_ascii=False, sort_keys=True),
                }))
        with self.engine.begin() as conn:
            conn.execute(findings.insert(), rows)

    def save_sandbox_runs(self, items: list[SandboxRun]) -> None:
        if not items:
            return
        rows = []
        for item in items:
            payload = SandboxRun.model_validate(self._safe_row(item.model_dump(mode="json"))).model_dump(mode="json")
            rows.append(
                self._safe_row({
                    "run_id":
                    payload["run_id"],
                    "task_id":
                    payload["task_id"],
                    "runtime":
                    payload["runtime"],
                    "command_json":
                    json.dumps(payload["command"], ensure_ascii=False, sort_keys=True),
                    "decision":
                    payload["decision"],
                    "exit_code":
                    payload["exit_code"],
                    "timed_out":
                    payload["timed_out"],
                    "duration_ms":
                    payload["duration_ms"],
                    "stdout":
                    payload["stdout"],
                    "stderr":
                    payload["stderr"],
                    "output_files_json":
                    json.dumps(payload["output_files"], ensure_ascii=False, sort_keys=True),
                    "stdout_truncated":
                    payload["stdout_truncated"],
                    "stderr_truncated":
                    payload["stderr_truncated"],
                    "output_truncated":
                    payload["output_truncated"],
                    "output_file_count":
                    payload["output_file_count"],
                    "output_bytes":
                    payload["output_bytes"],
                    "failure_reason":
                    payload["failure_reason"] or None,
                    "warning":
                    payload["warning"],
                    "created_at":
                    payload["created_at"],
                }))
        with self.engine.begin() as conn:
            conn.execute(sandbox_runs.insert(), rows)

    def save_filter_intercepts(self, items: list[FilterIntercept]) -> None:
        rows = []
        for item in items:
            payload = self._safe_row(item.model_dump(mode="json"))
            rows.append(
                self._safe_row({
                    "intercept_id": payload["intercept_id"],
                    "task_id": payload["task_id"],
                    "decision": payload["decision"],
                    "reason": payload["reason"],
                    "command_json": json.dumps(payload["command"], ensure_ascii=False, sort_keys=True),
                    "runtime": payload["runtime"],
                    "metadata_json": json.dumps(payload["metadata"], ensure_ascii=False, sort_keys=True),
                    "created_at": payload["created_at"],
                }))
        if rows:
            with self.engine.begin() as conn:
                conn.execute(filter_intercepts.insert(), rows)

    def save_telemetry(self, telemetry: TelemetrySummary) -> None:
        payload = self._safe_row(telemetry.model_dump(mode="json"))
        safe_telemetry = TelemetrySummary.model_validate(payload)
        row = self._safe_row({
            "task_id": safe_telemetry.task_id,
            "metrics_json": json.dumps(payload, ensure_ascii=False, sort_keys=True),
            "created_at": safe_telemetry.created_at,
        })
        with self.engine.begin() as conn:
            conn.execute(telemetry_summaries.insert().values(**row))

    def save_report(
        self,
        *,
        report: ReviewReport,
        json_report: str,
        markdown_report: str,
        json_path: str,
        markdown_path: str,
    ) -> None:
        safe_report = ReviewReport.model_validate(self._safe_row(report.model_dump(mode="json")))
        row = self._safe_row({
            "task_id":
            safe_report.task_id,
            "json_report":
            json_report,
            "markdown_report":
            markdown_report,
            "json_path":
            json_path,
            "markdown_path":
            markdown_path,
            "summary_json":
            json.dumps(
                {
                    "conclusion": safe_report.conclusion,
                    "findings": len(safe_report.findings),
                    "warnings": len(safe_report.warnings),
                    "needs_human_review": len(safe_report.needs_human_review),
                    "filter_intercepts": len(safe_report.filter_intercepts),
                    "sandbox_runs": len(safe_report.sandbox_runs),
                    "schema_version": safe_report.schema_version,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            "created_at":
            safe_report.telemetry.created_at,
        })
        with self.engine.begin() as conn:
            conn.execute(reports.insert().values(**row))

    def query_task(self, task_id: str) -> dict[str, Any]:
        task_id = self.boundary.text(task_id).text
        result: dict[str, Any] = {}
        with self.engine.connect() as conn:
            for name, table in [
                ("review_tasks", review_tasks),
                ("review_inputs", review_inputs),
                ("sandbox_runs", sandbox_runs),
                ("findings", findings),
                ("filter_intercepts", filter_intercepts),
                ("telemetry_summaries", telemetry_summaries),
                ("reports", reports),
            ]:
                rows = conn.execute(select(table).where(table.c.task_id == task_id)).mappings().all()
                result[name] = [self._safe_row(dict(row)) for row in rows]
        result["task"] = result["review_tasks"][0] if result["review_tasks"] else {}
        result["input"] = result["review_inputs"][0] if result["review_inputs"] else {}
        result["telemetry"] = result["telemetry_summaries"][0] if result["telemetry_summaries"] else {}
        result["report"] = result["reports"][0] if result["reports"] else {}
        return result

    def dump_task_text(self, task_id: str) -> str:
        return json.dumps(self.query_task(task_id), ensure_ascii=False, sort_keys=True)
