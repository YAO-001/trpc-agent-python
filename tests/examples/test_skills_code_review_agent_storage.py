# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""SQL storage tests for the skills code review agent example."""

from __future__ import annotations

import sqlite3

import pytest
from sqlalchemy.exc import IntegrityError

from agent.models import Finding
from agent.models import RedactionSummary
from agent.models import ReviewTask
from agent.models import ReviewTaskStatus
from agent.models import SandboxRun
from agent.models import TelemetrySummary
from agent.storage import MIGRATIONS_DIR
from agent.storage import ReviewStorage
from agent.task_state import transition_task

LEGACY_SCHEMA = """
CREATE TABLE review_tasks (
    task_id VARCHAR(128) PRIMARY KEY,
    input_type VARCHAR(64) NOT NULL,
    input_ref TEXT NOT NULL,
    runtime VARCHAR(64) NOT NULL,
    dry_run BOOLEAN NOT NULL,
    status VARCHAR(64) NOT NULL,
    created_at VARCHAR(64) NOT NULL
);
CREATE TABLE review_inputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id VARCHAR(128) NOT NULL,
    redacted_diff TEXT NOT NULL,
    changed_files_json TEXT NOT NULL,
    redaction_summary_json TEXT NOT NULL,
    input_metadata_json TEXT NOT NULL
);
CREATE TABLE sandbox_runs (
    run_id VARCHAR(160) PRIMARY KEY,
    task_id VARCHAR(128) NOT NULL,
    runtime VARCHAR(64) NOT NULL,
    command_json TEXT NOT NULL,
    decision VARCHAR(64) NOT NULL,
    exit_code INTEGER NOT NULL,
    timed_out BOOLEAN NOT NULL,
    duration_ms INTEGER NOT NULL,
    stdout TEXT NOT NULL,
    stderr TEXT NOT NULL,
    output_files_json TEXT NOT NULL,
    stdout_truncated BOOLEAN NOT NULL DEFAULT 0,
    stderr_truncated BOOLEAN NOT NULL DEFAULT 0,
    output_truncated BOOLEAN NOT NULL DEFAULT 0,
    output_file_count INTEGER NOT NULL DEFAULT 0,
    output_bytes INTEGER NOT NULL DEFAULT 0,
    failure_reason TEXT,
    warning TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL
);
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id VARCHAR(128) NOT NULL,
    dedupe_key VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    category VARCHAR(64) NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    title TEXT NOT NULL,
    evidence TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    confidence FLOAT NOT NULL,
    source_json TEXT NOT NULL
);
CREATE TABLE filter_intercepts (
    intercept_id VARCHAR(160) PRIMARY KEY,
    task_id VARCHAR(128) NOT NULL,
    decision VARCHAR(64) NOT NULL,
    reason TEXT NOT NULL,
    command_json TEXT NOT NULL,
    runtime VARCHAR(64) NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL
);
CREATE TABLE telemetry_summaries (
    task_id VARCHAR(128) PRIMARY KEY,
    metrics_json TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL
);
CREATE TABLE reports (
    task_id VARCHAR(128) PRIMARY KEY,
    json_report TEXT NOT NULL,
    markdown_report TEXT NOT NULL,
    json_path TEXT NOT NULL,
    markdown_path TEXT NOT NULL,
    summary_json TEXT NOT NULL DEFAULT '{}',
    created_at VARCHAR(64) NOT NULL
);
"""


def _create_legacy_database(tmp_path) -> str:
    db_path = tmp_path / "legacy.db"
    created_at = "2026-07-10T00:00:00+00:00"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(LEGACY_SCHEMA)
        conn.execute(
            "INSERT INTO review_tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("legacy-task", "fixture", "fixture:clean", "container", 1, "completed", created_at),
        )
        conn.execute(
            "INSERT INTO review_inputs "
            "(task_id, redacted_diff, changed_files_json, redaction_summary_json, input_metadata_json) "
            "VALUES (?, ?, ?, ?, ?)",
            ("legacy-task", "redacted diff", '["legacy.py"]', "{}", '{"fixture_names": ["clean"]}'),
        )
        conn.execute(
            "INSERT INTO sandbox_runs VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "legacy-run",
                "legacy-task",
                "container",
                '["python3", "scripts/run_static_review.py"]',
                "allow",
                0,
                0,
                12,
                "legacy stdout",
                "",
                '{"out/findings.json": "{}"}',
                0,
                0,
                0,
                1,
                2,
                None,
                "",
                created_at,
            ),
        )
        conn.execute(
            "INSERT INTO findings "
            "(task_id, dedupe_key, severity, category, file, line, title, evidence, "
            "recommendation, confidence, source_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "legacy-task",
                "legacy-dedupe",
                "low",
                "legacy",
                "legacy.py",
                1,
                "legacy finding",
                "legacy evidence",
                "review it",
                0.8,
                '["legacy"]',
            ),
        )
        conn.execute(
            "INSERT INTO filter_intercepts VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "legacy-intercept",
                "legacy-task",
                "deny",
                "legacy policy denial",
                '["python3", "unknown.py"]',
                "container",
                "{}",
                created_at,
            ),
        )
        conn.execute(
            "INSERT INTO telemetry_summaries VALUES (?, ?, ?)",
            ("legacy-task", '{"task_id": "legacy-task"}', created_at),
        )
        conn.execute(
            "INSERT INTO reports VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "legacy-task",
                '{"task_id": "legacy-task"}',
                "# Legacy report\n",
                "out/legacy.json",
                "out/legacy.md",
                '{"conclusion": "legacy"}',
                created_at,
            ),
        )
    return f"sqlite:///{db_path}"


def _column_names(conn, table: str) -> set[str]:
    return {row[1] for row in conn.exec_driver_sql(f'PRAGMA table_info("{table}")').all()}


def _foreign_key(conn, table: str, column: str) -> tuple[str, str] | None:
    for row in conn.exec_driver_sql(f'PRAGMA foreign_key_list("{table}")').all():
        if row[3] == column:
            return row[2], row[6]
    return None


def _index_exists(
    conn,
    table: str,
    columns: list[str],
    *,
    unique: bool | None = None,
    partial: bool | None = None,
) -> bool:
    for row in conn.exec_driver_sql(f'PRAGMA index_list("{table}")').all():
        if unique is not None and bool(row[2]) is not unique:
            continue
        if partial is not None and bool(row[4]) is not partial:
            continue
        indexed = [item[2] for item in conn.exec_driver_sql(f'PRAGMA index_info("{row[1]}")').all()]
        if indexed == columns:
            return True
    return False


def test_new_database_records_all_bundled_migrations(tmp_path):
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")

    with storage.engine.connect() as conn:
        versions = conn.exec_driver_sql("SELECT version FROM schema_migrations ORDER BY version").scalars().all()

    assert versions == ["002_review_lifecycle", "003_request_identity"]


def _storage_with_constraint_parent(tmp_path, database_kind):
    if database_kind == "legacy":
        storage = ReviewStorage(_create_legacy_database(tmp_path))
        return storage, "legacy-task"
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    task = ReviewTask(
        task_id="constraint-task",
        input_type="fixture",
        dry_run=True,
    )
    storage.save_task(task)
    return storage, task.task_id


@pytest.mark.parametrize("database_kind", ("fresh", "legacy"))
@pytest.mark.parametrize("table", ("sandbox_runs", "filter_intercepts"))
def test_database_rejects_empty_request_identity(tmp_path, database_kind, table):
    storage, task_id = _storage_with_constraint_parent(tmp_path, database_kind)
    if table == "sandbox_runs":
        statement = """
            INSERT INTO sandbox_runs (
                run_id, task_id, request_id, runtime, command_json, decision,
                exit_code, timed_out, duration_ms, stdout, stderr,
                output_files_json, stdout_truncated, stderr_truncated,
                output_truncated, output_file_count, output_bytes, failure_kind,
                failure_reason, warning, created_at
            ) VALUES (
                :row_id, :task_id, '', 'container', '[]', 'allow',
                0, 0, 0, '', '', '{}', 0, 0, 0, 0, 0, '', '', '', :created_at
            )
        """
    else:
        statement = """
            INSERT INTO filter_intercepts (
                intercept_id, task_id, request_id, decision, error_kind,
                reason, command_json, runtime, metadata_json, created_at
            ) VALUES (
                :row_id, :task_id, '', 'allow', '',
                'canonical decision', '[]', 'container', '{}', :created_at
            )
        """
    with pytest.raises(IntegrityError):
        with storage.engine.begin() as conn:
            conn.exec_driver_sql(
                statement,
                {
                    "row_id": f"{database_kind}-{table}-empty",
                    "task_id": task_id,
                    "created_at": "1970-01-01T00:00:00+00:00",
                },
            )


@pytest.mark.parametrize("database_kind", ("fresh", "legacy"))
def test_database_rejects_mismatched_filter_decision_error_kind(tmp_path, database_kind):
    storage, task_id = _storage_with_constraint_parent(tmp_path, database_kind)

    with pytest.raises(IntegrityError):
        with storage.engine.begin() as conn:
            conn.exec_driver_sql(
                """
                INSERT INTO filter_intercepts (
                    intercept_id, task_id, request_id, decision, error_kind,
                    reason, command_json, runtime, metadata_json, created_at
                ) VALUES (
                    :row_id, :task_id, :request_id, 'allow', 'policy_denied',
                    'mismatched taxonomy', '[]', 'container', '{}', :created_at
                )
                """,
                {
                    "row_id": f"{database_kind}-mismatched-filter",
                    "task_id": task_id,
                    "request_id": f"{task_id}:mismatched-filter",
                    "created_at": "1970-01-01T00:00:00+00:00",
                },
            )


def test_legacy_database_migrates_without_losing_audit_rows(tmp_path):
    db_url = _create_legacy_database(tmp_path)
    storage = ReviewStorage(db_url)
    task_owned_tables = (
        "review_inputs",
        "sandbox_runs",
        "findings",
        "filter_intercepts",
        "telemetry_summaries",
        "reports",
    )

    with storage.engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert {
            "updated_at",
            "failure_kind",
            "failure_reason_redacted",
        } <= _column_names(conn, "review_tasks")
        assert {"request_id", "failure_kind"} <= _column_names(conn, "sandbox_runs")
        assert {"request_id", "error_kind"} <= _column_names(conn, "filter_intercepts")
        for table in task_owned_tables:
            assert _foreign_key(conn, table, "task_id") == ("review_tasks", "CASCADE")
            assert _index_exists(conn, table, ["task_id"])
            assert conn.exec_driver_sql(f'SELECT count(*) FROM "{table}"').scalar_one() == 1
        assert _index_exists(
            conn,
            "sandbox_runs",
            ["task_id", "request_id"],
            unique=True,
            partial=False,
        )
        assert _index_exists(
            conn,
            "filter_intercepts",
            ["task_id", "request_id"],
            unique=True,
            partial=False,
        )
        task_row = conn.exec_driver_sql(
            "SELECT updated_at, failure_kind, failure_reason_redacted FROM review_tasks").one()
        run_row = conn.exec_driver_sql(
            "SELECT request_id, failure_kind, stdout, output_file_count FROM sandbox_runs").one()
        decision_row = conn.exec_driver_sql("SELECT request_id, error_kind, reason FROM filter_intercepts").one()
        assert task_row == ("2026-07-10T00:00:00+00:00", "", "")
        assert run_row == ("legacy:legacy-run", "", "legacy stdout", 1)
        assert decision_row == (
            "legacy:legacy-intercept",
            "policy_denied",
            "legacy policy denial",
        )
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").all() == []

    repeated = ReviewStorage(db_url)
    with repeated.engine.connect() as conn:
        versions = conn.exec_driver_sql("SELECT version, count(*) FROM schema_migrations "
                                        "GROUP BY version ORDER BY version").all()
        assert versions == [
            ("002_review_lifecycle", 1),
            ("003_request_identity", 1),
        ]
        assert conn.exec_driver_sql("SELECT count(*) FROM sandbox_runs").scalar_one() == 1
        assert conn.exec_driver_sql("SELECT count(*) FROM filter_intercepts").scalar_one() == 1


def test_request_identity_migration_backfills_only_empty_ids_and_preserves_audit_fields(tmp_path):
    db_url = _create_legacy_database(tmp_path)
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript((MIGRATIONS_DIR / "002_review_lifecycle.sql").read_text(encoding="utf-8"))
        conn.execute("INSERT INTO schema_migrations (version) VALUES ('002_review_lifecycle')")
        conn.execute("UPDATE sandbox_runs SET request_id = '', failure_kind = 'orchestration_error'")
        conn.execute("UPDATE filter_intercepts SET request_id = ''")
        conn.execute("""
            INSERT INTO sandbox_runs
            SELECT
                'kept-run', task_id, 'kept-request', runtime, command_json,
                decision, exit_code, timed_out, duration_ms, stdout, stderr,
                output_files_json, stdout_truncated, stderr_truncated,
                output_truncated, output_file_count, output_bytes,
                'execution_nonzero', failure_reason, warning, created_at
            FROM sandbox_runs
            WHERE run_id = 'legacy-run'
        """)
        conn.execute("""
            INSERT INTO filter_intercepts
            SELECT
                'kept-intercept', task_id, 'kept-filter-request', decision,
                error_kind, reason, command_json, runtime, metadata_json,
                created_at
            FROM filter_intercepts
            WHERE intercept_id = 'legacy-intercept'
        """)

    storage = ReviewStorage(db_url)
    with storage.engine.connect() as conn:
        runs = {
            row.run_id: (row.request_id, row.failure_kind)
            for row in conn.exec_driver_sql("SELECT run_id, request_id, failure_kind FROM sandbox_runs").all()
        }
        decisions = {
            row.intercept_id: (row.request_id, row.decision, row.error_kind)
            for row in conn.exec_driver_sql(
                "SELECT intercept_id, request_id, decision, error_kind FROM filter_intercepts").all()
        }
        versions = conn.exec_driver_sql(
            "SELECT version, count(*) FROM schema_migrations GROUP BY version ORDER BY version").all()

    assert runs == {
        "legacy-run": ("legacy:legacy-run", "orchestration_error"),
        "kept-run": ("kept-request", "execution_nonzero"),
    }
    assert decisions == {
        "legacy-intercept": ("legacy:legacy-intercept", "deny", "policy_denied"),
        "kept-intercept": ("kept-filter-request", "deny", "policy_denied"),
    }
    assert versions == [
        ("002_review_lifecycle", 1),
        ("003_request_identity", 1),
    ]


def test_legacy_migration_with_orphan_never_records_success_or_skips_retry(tmp_path):
    db_url = _create_legacy_database(tmp_path)
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO review_inputs "
            "(task_id, redacted_diff, changed_files_json, redaction_summary_json, input_metadata_json) "
            "VALUES (?, ?, ?, ?, ?)",
            ("missing-task", "orphan diff", "[]", "{}", "{}"),
        )

    with pytest.raises(RuntimeError, match="orphan task rows prevent migration"):
        ReviewStorage(db_url)

    with sqlite3.connect(db_path) as conn:
        migration_table_exists = conn.execute("SELECT count(*) FROM sqlite_master "
                                              "WHERE type='table' AND name='schema_migrations'").fetchone()[0]
        migration_count = (conn.execute("SELECT count(*) FROM schema_migrations "
                                        "WHERE version='002_review_lifecycle'").fetchone()[0]
                           if migration_table_exists else 0)
        task_columns = {row[1] for row in conn.execute("PRAGMA table_info(review_tasks)")}
        assert migration_count == 0
        assert "updated_at" not in task_columns
        assert conn.execute("SELECT count(*) FROM review_tasks").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM review_inputs").fetchone()[0] == 2
        assert conn.execute("SELECT count(*) FROM sandbox_runs").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM filter_intercepts").fetchone()[0] == 1

    with pytest.raises(RuntimeError, match="orphan task rows prevent migration"):
        ReviewStorage(db_url)


def test_ledger_write_failure_rolls_back_the_entire_legacy_migration(tmp_path):
    db_url = _create_legacy_database(tmp_path)
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript("""
            CREATE TABLE schema_migrations (
                version VARCHAR(128) PRIMARY KEY,
                applied_at VARCHAR(64) NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TRIGGER block_migration_ledger
            BEFORE INSERT ON schema_migrations
            BEGIN
                SELECT RAISE(FAIL, 'ledger write blocked');
            END;
        """)

    def assert_legacy_database_is_unchanged() -> None:
        with sqlite3.connect(db_path) as conn:
            task_columns = {row[1] for row in conn.execute("PRAGMA table_info(review_tasks)")}
            assert "updated_at" not in task_columns
            assert conn.execute("SELECT count(*) FROM schema_migrations "
                                "WHERE version='002_review_lifecycle'").fetchone()[0] == 0
            for table in (
                    "review_tasks",
                    "review_inputs",
                    "sandbox_runs",
                    "findings",
                    "filter_intercepts",
                    "telemetry_summaries",
                    "reports",
            ):
                assert conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0] == 1

    with pytest.raises(sqlite3.IntegrityError, match="ledger write blocked"):
        ReviewStorage(db_url)
    assert_legacy_database_is_unchanged()

    with pytest.raises(sqlite3.IntegrityError, match="ledger write blocked"):
        ReviewStorage(db_url)
    assert_legacy_database_is_unchanged()


def test_storage_roundtrip_by_task_id(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'review.db'}"
    storage = ReviewStorage(db_url)
    task = ReviewTask(
        task_id="task-storage",
        input_type="fixture",
        input_ref="fixture:clean",
        runtime="local",
        dry_run=True,
        status="completed",
        created_at="1970-01-01T00:00:00+00:00",
    )
    finding = Finding(
        severity="high",
        category="security",
        file="app.py",
        line=3,
        title="danger",
        evidence="redacted evidence",
        recommendation="fix it",
        confidence=0.9,
        source=["rule:test"],
    )

    storage.reset_task(task.task_id)
    storage.save_task(task)
    storage.save_input(
        task_id=task.task_id,
        redacted_diff="diff --git a/app.py b/app.py\n",
        changed_files=["app.py"],
        redaction_summary=RedactionSummary(),
        input_metadata={"fixture_names": ["clean"]},
    )
    storage.save_sandbox_runs([
        SandboxRun(
            run_id="sandbox-task-storage-1",
            task_id=task.task_id,
            request_id=f"{task.task_id}:skill-run:1",
            runtime="local",
            command=["python3", "scripts/run_static_review.py"],
            decision="allow",
            output_files={"out/findings.json": "{}"},
        )
    ])
    storage.save_findings(task.task_id, [finding])
    storage.save_telemetry(
        TelemetrySummary(
            task_id=task.task_id,
            task_status=ReviewTaskStatus.COMPLETED,
            findings_count=1,
        ))

    rows = storage.query_task(task.task_id)

    assert rows["review_tasks"][0]["task_id"] == task.task_id
    assert rows["findings"][0]["title"] == "danger"
    assert rows["sandbox_runs"][0]["output_file_count"] == 1
    assert rows["sandbox_runs"][0]["output_bytes"] == 2
    assert "redacted evidence" in storage.dump_task_text(task.task_id)


def test_latest_task_uses_task_id_as_deterministic_timestamp_tiebreaker(tmp_path):
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    assert storage.latest_task() is None
    for task_id in ("task-latest-a", "task-latest-b"):
        storage.save_task(
            ReviewTask(
                task_id=task_id,
                input_type="fixture",
                dry_run=True,
                created_at="1970-01-01T00:00:00+00:00",
                updated_at="1970-01-01T00:00:00+00:00",
            ))

    assert storage.latest_task().task_id == "task-latest-b"


def test_create_task_with_input_persists_both_rows_atomically(tmp_path):
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    task = ReviewTask(
        task_id="task-created-with-input",
        input_type="fixture",
        dry_run=True,
    )

    storage.create_task_with_input(
        task=task,
        redacted_diff="redacted diff",
        changed_files=["src/app.py"],
        redaction_summary=RedactionSummary(),
        input_metadata={"fixture_names": ["clean"]},
    )
    rows = storage.query_task(task.task_id)

    assert rows["task"]["status"] == ReviewTaskStatus.CREATED.value
    assert rows["input"]["redacted_diff"] == "redacted diff"


def test_create_task_with_input_rejects_non_created_status_without_partial_rows(tmp_path):
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    created = ReviewTask(
        task_id="task-running-with-input",
        input_type="fixture",
        dry_run=True,
    )
    running = transition_task(created, ReviewTaskStatus.RUNNING)

    with pytest.raises(ValueError, match="initial task must be created"):
        storage.create_task_with_input(
            task=running,
            redacted_diff="",
            changed_files=[],
            redaction_summary=RedactionSummary(),
            input_metadata={},
        )

    rows = storage.query_task(created.task_id)
    assert rows["review_tasks"] == []
    assert rows["review_inputs"] == []


def test_update_task_rejects_unknown_task(tmp_path):
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    task = ReviewTask(
        task_id="missing-task",
        input_type="fixture",
        dry_run=True,
    )

    with pytest.raises(KeyError, match="unknown review task missing-task"):
        storage.update_task(task)


def test_storage_rejects_secret_bearing_task_identities_without_partial_rows(tmp_path):
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    for raw_task_id in (
            "token:dummy-105690",
            "token:production-104491",
    ):
        created = ReviewTask(
            task_id=raw_task_id,
            input_type="fixture",
            dry_run=True,
        )
        with pytest.raises(ValueError, match="task_id must not contain secret material") as create_error:
            storage.create_task_with_input(
                task=created,
                redacted_diff="",
                changed_files=[],
                redaction_summary=RedactionSummary(),
                input_metadata={},
            )
        assert raw_task_id not in str(create_error.value)
        with pytest.raises(ValueError, match="task_id must not contain secret material"):
            storage.update_task(transition_task(created, ReviewTaskStatus.RUNNING))
        with pytest.raises(ValueError, match="task_id must not contain secret material"):
            storage.query_task(raw_task_id)
        with pytest.raises(ValueError, match="task_id must not contain secret material"):
            storage.reset_task(raw_task_id)

    with storage.engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT count(*) FROM review_tasks").scalar_one() == 0
        assert conn.exec_driver_sql("SELECT count(*) FROM review_inputs").scalar_one() == 0
