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
from sqlalchemy import CheckConstraint
from sqlalchemy import Column
from sqlalchemy import Float
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import Text
from sqlalchemy import UniqueConstraint
from sqlalchemy import create_engine
from sqlalchemy import delete
from sqlalchemy import event
from sqlalchemy import func
from sqlalchemy import inspect
from sqlalchemy import select

from .models import FilterIntercept
from .models import Finding
from .models import RedactionSummary
from .models import ReviewReport
from .models import ReviewTask
from .models import ReviewTaskStatus
from .models import SandboxRun
from .models import TelemetrySummary
from .redaction_boundary import RedactionBoundary

DEFAULT_DB_URL = "sqlite:///examples/skills_code_review_agent/review.db"
MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"
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
_IDENTITY_FIELDS = frozenset({
    "task_id",
    "request_id",
    "run_id",
    "intercept_id",
})
metadata = MetaData()

schema_migrations = Table(
    "schema_migrations",
    metadata,
    Column("version", String(128), primary_key=True),
    Column("applied_at", String(64), nullable=False, server_default=func.current_timestamp()),
)
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
    Column("updated_at", String(64), nullable=False),
    Column("failure_kind", String(64), nullable=False, server_default=""),
    Column("failure_reason_redacted", Text, nullable=False, server_default=""),
)
review_inputs = Table(
    "review_inputs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("task_id", String(128), ForeignKey("review_tasks.task_id", ondelete="CASCADE"), nullable=False),
    Column("redacted_diff", Text, nullable=False),
    Column("changed_files_json", Text, nullable=False),
    Column("redaction_summary_json", Text, nullable=False),
    Column("input_metadata_json", Text, nullable=False),
)
sandbox_runs = Table(
    "sandbox_runs",
    metadata,
    Column("run_id", String(160), primary_key=True),
    Column("task_id", String(128), ForeignKey("review_tasks.task_id", ondelete="CASCADE"), nullable=False),
    Column("request_id", String(160), nullable=False),
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
    Column("failure_kind", String(64), nullable=False, server_default=""),
    Column("failure_reason", Text, nullable=True),
    Column("warning", Text, nullable=False),
    Column("created_at", String(64), nullable=False),
    CheckConstraint("request_id <> ''", name="ck_sandbox_runs_request_id_nonempty"),
    UniqueConstraint("task_id", "request_id", name="uq_sandbox_runs_task_request"),
)
findings = Table(
    "findings",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("task_id", String(128), ForeignKey("review_tasks.task_id", ondelete="CASCADE"), nullable=False),
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
    Column("task_id", String(128), ForeignKey("review_tasks.task_id", ondelete="CASCADE"), nullable=False),
    Column("request_id", String(160), nullable=False),
    Column("decision", String(64), nullable=False),
    Column("error_kind", String(64), nullable=False),
    Column("reason", Text, nullable=False),
    Column("command_json", Text, nullable=False),
    Column("runtime", String(64), nullable=False),
    Column("metadata_json", Text, nullable=False),
    Column("created_at", String(64), nullable=False),
    CheckConstraint("request_id <> ''", name="ck_filter_intercepts_request_id_nonempty"),
    CheckConstraint(
        "(decision = 'allow' AND error_kind = '') OR "
        "(decision = 'deny' AND error_kind = 'policy_denied') OR "
        "(decision = 'needs_human_review' AND error_kind = 'approval_required')",
        name="ck_filter_intercepts_decision_error_kind",
    ),
    UniqueConstraint("task_id", "request_id", name="uq_filter_intercepts_task_request"),
)
telemetry_summaries = Table(
    "telemetry_summaries",
    metadata,
    Column(
        "task_id",
        String(128),
        ForeignKey("review_tasks.task_id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("metrics_json", Text, nullable=False),
    Column("created_at", String(64), nullable=False),
)
reports = Table(
    "reports",
    metadata,
    Column(
        "task_id",
        String(128),
        ForeignKey("review_tasks.task_id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("json_report", Text, nullable=False),
    Column("markdown_report", Text, nullable=False),
    Column("json_path", Text, nullable=False),
    Column("markdown_path", Text, nullable=False),
    Column("summary_json", Text, nullable=False, default="{}"),
    Column("created_at", String(64), nullable=False),
)

Index("idx_review_inputs_task_id", review_inputs.c.task_id)
Index("idx_sandbox_runs_task_id", sandbox_runs.c.task_id)
Index("idx_findings_task_id", findings.c.task_id)
Index("idx_filter_intercepts_task_id", filter_intercepts.c.task_id)
Index("idx_telemetry_summaries_task_id", telemetry_summaries.c.task_id)
Index("idx_reports_task_id", reports.c.task_id)


def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class ReviewStorage:

    def __init__(self, db_url: str = DEFAULT_DB_URL, boundary: RedactionBoundary | None = None) -> None:
        self.db_url = db_url
        self.boundary = boundary or RedactionBoundary()
        self._ensure_sqlite_parent(db_url)
        self.engine = create_engine(db_url, future=True)
        if self.engine.dialect.name == "sqlite":
            event.listen(self.engine, "connect", _enable_sqlite_foreign_keys)
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        migrations = sorted(MIGRATIONS_DIR.glob("*.sql")) if MIGRATIONS_DIR.is_dir() else []
        versions = [path.stem for path in migrations]
        existing_tables = set(inspect(self.engine).get_table_names())
        if not existing_tables:
            with self.engine.begin() as conn:
                metadata.create_all(conn)
                if versions:
                    conn.execute(schema_migrations.insert(), [{"version": version} for version in versions])
            return

        if self.engine.dialect.name != "sqlite":
            metadata.create_all(self.engine)
            return

        if "schema_migrations" in existing_tables:
            with self.engine.connect() as conn:
                applied = set(conn.execute(select(schema_migrations.c.version)).scalars())
        else:
            applied = set()
        for path in migrations:
            if path.stem not in applied:
                self._run_sqlite_migration(path)
        metadata.create_all(self.engine)

    def _run_sqlite_migration(self, path: Path) -> None:
        raw_connection = self.engine.raw_connection()
        cursor = raw_connection.cursor()
        try:
            self._preflight_sqlite_migration(cursor, path)
            cursor.executescript(path.read_text(encoding="utf-8"))
            driver_connection = getattr(raw_connection, "driver_connection", raw_connection)
            if not driver_connection.in_transaction:
                raise RuntimeError(f"migration {path.stem} did not leave its transaction open")
            cursor.execute("PRAGMA foreign_key_check")
            violations = cursor.fetchall()
            if violations:
                raise RuntimeError(f"foreign key check failed after migration {path.stem}: {violations}")
            cursor.execute("INSERT INTO schema_migrations (version) VALUES (?)", (path.stem, ))
            raw_connection.commit()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA foreign_keys")
            if cursor.fetchone()[0] != 1:
                raise RuntimeError(f"foreign keys were not restored after migration {path.stem}")
            cursor.execute("PRAGMA foreign_key_check")
            post_commit_violations = cursor.fetchall()
            if post_commit_violations:
                raise RuntimeError(
                    f"foreign key check failed after committing migration {path.stem}: {post_commit_violations}")
        except BaseException:
            raw_connection.rollback()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            except BaseException:
                pass
            raise
        finally:
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            except BaseException:
                pass
            cursor.close()
            raw_connection.close()

    @staticmethod
    def _preflight_sqlite_migration(cursor, path: Path) -> None:
        if path.stem != "002_review_lifecycle":
            return
        orphan_counts = {}
        for table in (
                "review_inputs",
                "sandbox_runs",
                "findings",
                "filter_intercepts",
                "telemetry_summaries",
                "reports",
        ):
            cursor.execute(f"SELECT count(*) FROM {table} AS child "
                           "LEFT JOIN review_tasks AS task ON task.task_id = child.task_id "
                           "WHERE task.task_id IS NULL")
            count = cursor.fetchone()[0]
            if count:
                orphan_counts[table] = count
        if orphan_counts:
            details = ", ".join(f"{table}={count}" for table, count in orphan_counts.items())
            raise RuntimeError(f"orphan task rows prevent migration {path.stem}: {details}")

    def _safe_identity(self, field: str, value: object) -> str:
        safe = self.boundary.text(value).text
        if safe != value:
            raise ValueError(f"{field} must not contain secret material")
        return safe

    def _safe_row(self, row: dict[str, Any]) -> dict[str, Any]:
        prepared = dict(row)
        for field in _IDENTITY_FIELDS & prepared.keys():
            prepared[field] = self._safe_identity(field, prepared[field])
        ordinary = {key: value for key, value in prepared.items() if key not in _JSON_BLOB_FIELDS}
        safe = self.boundary.clean(ordinary)
        if not isinstance(safe, dict):  # pragma: no cover - caller contract
            raise TypeError("storage row must remain a mapping after redaction")
        for field, value in prepared.items():
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

    def _task_row(self, task: ReviewTask) -> dict[str, Any]:
        payload = self._safe_row(task.model_dump(mode="json"))
        return ReviewTask.model_validate(payload).model_dump(mode="json")

    def _input_row(
        self,
        task_id: str,
        *,
        redacted_diff: str,
        changed_files: list[str],
        redaction_summary: RedactionSummary,
        input_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        payload = self._safe_row({
            "task_id": task_id,
            "redacted_diff": redacted_diff,
            "changed_files": changed_files,
            "redaction_summary": redaction_summary.model_dump(mode="json"),
            "input_metadata": input_metadata,
        })
        return self._safe_row({
            "task_id":
            payload["task_id"],
            "redacted_diff":
            payload["redacted_diff"],
            "changed_files_json":
            json.dumps(payload["changed_files"], ensure_ascii=False, sort_keys=True),
            "redaction_summary_json":
            json.dumps(
                payload["redaction_summary"],
                ensure_ascii=False,
                sort_keys=True,
            ),
            "input_metadata_json":
            json.dumps(payload["input_metadata"], ensure_ascii=False, sort_keys=True),
        })

    def _filter_row(self, item: FilterIntercept) -> dict[str, Any]:
        safe_item = FilterIntercept.model_validate(self._safe_row(item.model_dump(mode="json")))
        payload = safe_item.model_dump(mode="json")
        return self._safe_row({
            "intercept_id": payload["intercept_id"],
            "task_id": payload["task_id"],
            "request_id": payload["request_id"],
            "decision": payload["decision"],
            "error_kind": payload["error_kind"],
            "reason": payload["reason"],
            "command_json": json.dumps(payload["command"], ensure_ascii=False, sort_keys=True),
            "runtime": payload["runtime"],
            "metadata_json": json.dumps(payload["metadata"], ensure_ascii=False, sort_keys=True),
            "created_at": payload["created_at"],
        })

    def _sandbox_row(self, item: SandboxRun) -> dict[str, Any]:
        safe_item = SandboxRun.model_validate(self._safe_row(item.model_dump(mode="json")))
        payload = safe_item.model_dump(mode="json")
        return self._safe_row({
            "run_id":
            payload["run_id"],
            "task_id":
            payload["task_id"],
            "request_id":
            payload["request_id"],
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
            "failure_kind":
            payload["failure_kind"],
            "failure_reason":
            payload["failure_reason"] or None,
            "warning":
            payload["warning"],
            "created_at":
            payload["created_at"],
        })

    def reset_task(self, task_id: str) -> None:
        task_id = self._safe_identity("task_id", task_id)
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
            conn.execute(review_tasks.insert().values(**self._task_row(task)))

    def create_task_with_input(
        self,
        *,
        task: ReviewTask,
        redacted_diff: str,
        changed_files: list[str],
        redaction_summary: RedactionSummary,
        input_metadata: dict[str, Any],
    ) -> None:
        if task.status != ReviewTaskStatus.CREATED:
            raise ValueError("initial task must be created")
        with self.engine.begin() as conn:
            conn.execute(review_tasks.insert().values(**self._task_row(task)))
            conn.execute(review_inputs.insert().values(**self._input_row(
                task.task_id,
                redacted_diff=redacted_diff,
                changed_files=changed_files,
                redaction_summary=redaction_summary,
                input_metadata=input_metadata,
            )))

    def update_task(self, task: ReviewTask) -> None:
        row = self._task_row(task)
        with self.engine.begin() as conn:
            result = conn.execute(review_tasks.update().where(review_tasks.c.task_id == row["task_id"]).values(**row))
            if result.rowcount != 1:
                raise KeyError(f"unknown review task {row['task_id']}")

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
            conn.execute(review_inputs.insert().values(**self._input_row(
                task_id,
                redacted_diff=redacted_diff,
                changed_files=changed_files,
                redaction_summary=redaction_summary,
                input_metadata=input_metadata,
            )))

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
        rows = [self._sandbox_row(item) for item in items]
        with self.engine.begin() as conn:
            conn.execute(sandbox_runs.insert(), rows)

    def save_sandbox_run(self, item: SandboxRun) -> None:
        with self.engine.begin() as conn:
            conn.execute(sandbox_runs.insert().values(**self._sandbox_row(item)))

    def save_filter_intercepts(self, items: list[FilterIntercept]) -> None:
        rows = [self._filter_row(item) for item in items]
        if rows:
            with self.engine.begin() as conn:
                conn.execute(filter_intercepts.insert(), rows)

    def save_filter_decision(self, item: FilterIntercept) -> None:
        with self.engine.begin() as conn:
            conn.execute(filter_intercepts.insert().values(**self._filter_row(item)))

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
        task_id = self._safe_identity("task_id", task_id)
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
