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

DEFAULT_DB_URL = "sqlite:///examples/skills_code_review_agent/review.db"
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

    def __init__(self, db_url: str = DEFAULT_DB_URL) -> None:
        self.db_url = db_url
        self._ensure_sqlite_parent(db_url)
        self.engine = create_engine(db_url, future=True)
        metadata.create_all(self.engine)
        self._ensure_schema_compat()

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
        with self.engine.begin() as conn:
            conn.execute(review_tasks.insert().values(**task.model_dump()))

    def save_input(
        self,
        *,
        task_id: str,
        redacted_diff: str,
        changed_files: list[str],
        redaction_summary: RedactionSummary,
        input_metadata: dict[str, Any],
    ) -> None:
        with self.engine.begin() as conn:
            conn.execute(review_inputs.insert().values(
                task_id=task_id,
                redacted_diff=redacted_diff,
                changed_files_json=json.dumps(changed_files, ensure_ascii=False, sort_keys=True),
                redaction_summary_json=redaction_summary.model_dump_json(),
                input_metadata_json=json.dumps(input_metadata, ensure_ascii=False, sort_keys=True),
            ))

    def save_findings(self, task_id: str, items: list[Finding]) -> None:
        if not items:
            return
        rows = [{
            "task_id": task_id,
            "dedupe_key": item.dedupe_key,
            "severity": item.severity,
            "category": item.category,
            "file": item.file,
            "line": item.line,
            "title": item.title,
            "evidence": item.evidence,
            "recommendation": item.recommendation,
            "confidence": item.confidence,
            "source_json": json.dumps(item.source, ensure_ascii=False, sort_keys=True),
        } for item in items]
        with self.engine.begin() as conn:
            conn.execute(findings.insert(), rows)

    def save_sandbox_runs(self, items: list[SandboxRun]) -> None:
        if not items:
            return
        rows = [{
            "run_id": item.run_id,
            "task_id": item.task_id,
            "runtime": item.runtime,
            "command_json": json.dumps(item.command, ensure_ascii=False, sort_keys=True),
            "decision": item.decision,
            "exit_code": item.exit_code,
            "timed_out": item.timed_out,
            "duration_ms": item.duration_ms,
            "stdout": item.stdout,
            "stderr": item.stderr,
            "output_files_json": json.dumps(item.output_files, ensure_ascii=False, sort_keys=True),
            "stdout_truncated": item.stdout_truncated,
            "stderr_truncated": item.stderr_truncated,
            "output_truncated": item.output_truncated,
            "output_file_count": item.output_file_count,
            "output_bytes": item.output_bytes,
            "failure_reason": item.failure_reason or None,
            "warning": item.warning,
            "created_at": item.created_at,
        } for item in items]
        with self.engine.begin() as conn:
            conn.execute(sandbox_runs.insert(), rows)

    def save_filter_intercepts(self, items: list[FilterIntercept]) -> None:
        rows = [{
            "intercept_id": item.intercept_id,
            "task_id": item.task_id,
            "decision": item.decision,
            "reason": item.reason,
            "command_json": json.dumps(item.command, ensure_ascii=False, sort_keys=True),
            "runtime": item.runtime,
            "metadata_json": json.dumps(item.metadata, ensure_ascii=False, sort_keys=True),
            "created_at": item.created_at,
        } for item in items if item.decision in {"deny", "needs_human_review"}]
        if rows:
            with self.engine.begin() as conn:
                conn.execute(filter_intercepts.insert(), rows)

    def save_telemetry(self, telemetry: TelemetrySummary) -> None:
        with self.engine.begin() as conn:
            conn.execute(telemetry_summaries.insert().values(
                task_id=telemetry.task_id,
                metrics_json=telemetry.model_dump_json(),
                created_at=telemetry.created_at,
            ))

    def save_report(
        self,
        *,
        report: ReviewReport,
        json_report: str,
        markdown_report: str,
        json_path: str,
        markdown_path: str,
    ) -> None:
        with self.engine.begin() as conn:
            conn.execute(reports.insert().values(
                task_id=report.task_id,
                json_report=json_report,
                markdown_report=markdown_report,
                json_path=json_path,
                markdown_path=markdown_path,
                summary_json=json.dumps(
                    {
                        "conclusion": report.conclusion,
                        "findings": len(report.findings),
                        "warnings": len(report.warnings),
                        "needs_human_review": len(report.needs_human_review),
                        "filter_intercepts": len(report.filter_intercepts),
                        "sandbox_runs": len(report.sandbox_runs),
                        "schema_version": report.schema_version,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                created_at=report.telemetry.created_at,
            ))

    def query_task(self, task_id: str) -> dict[str, Any]:
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
                result[name] = [dict(row) for row in rows]
        result["task"] = result["review_tasks"][0] if result["review_tasks"] else {}
        result["input"] = result["review_inputs"][0] if result["review_inputs"] else {}
        result["telemetry"] = result["telemetry_summaries"][0] if result["telemetry_summaries"] else {}
        result["report"] = result["reports"][0] if result["reports"] else {}
        return result

    def dump_task_text(self, task_id: str) -> str:
        return json.dumps(self.query_task(task_id), ensure_ascii=False, sort_keys=True, default=str)
