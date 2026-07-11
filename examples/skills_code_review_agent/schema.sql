CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(128) PRIMARY KEY,
    applied_at VARCHAR(64) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS review_tasks (
    task_id VARCHAR(128) PRIMARY KEY,
    input_type VARCHAR(64) NOT NULL,
    input_ref TEXT NOT NULL,
    runtime VARCHAR(64) NOT NULL,
    dry_run BOOLEAN NOT NULL,
    status VARCHAR(64) NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64) NOT NULL,
    failure_kind VARCHAR(64) NOT NULL DEFAULT '',
    failure_reason_redacted TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS review_inputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id VARCHAR(128) NOT NULL,
    redacted_diff TEXT NOT NULL,
    changed_files_json TEXT NOT NULL,
    redaction_summary_json TEXT NOT NULL,
    input_metadata_json TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES review_tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sandbox_runs (
    run_id VARCHAR(160) PRIMARY KEY,
    task_id VARCHAR(128) NOT NULL,
    request_id VARCHAR(160) NOT NULL DEFAULT '',
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
    failure_kind VARCHAR(64) NOT NULL DEFAULT '',
    failure_reason TEXT,
    warning TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    FOREIGN KEY (task_id) REFERENCES review_tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
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
    source_json TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES review_tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS filter_intercepts (
    intercept_id VARCHAR(160) PRIMARY KEY,
    task_id VARCHAR(128) NOT NULL,
    request_id VARCHAR(160) NOT NULL DEFAULT '',
    decision VARCHAR(64) NOT NULL,
    error_kind VARCHAR(64) NOT NULL DEFAULT '',
    reason TEXT NOT NULL,
    command_json TEXT NOT NULL,
    runtime VARCHAR(64) NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    FOREIGN KEY (task_id) REFERENCES review_tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS telemetry_summaries (
    task_id VARCHAR(128) PRIMARY KEY,
    metrics_json TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    FOREIGN KEY (task_id) REFERENCES review_tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
    task_id VARCHAR(128) PRIMARY KEY,
    json_report TEXT NOT NULL,
    markdown_report TEXT NOT NULL,
    json_path TEXT NOT NULL,
    markdown_path TEXT NOT NULL,
    summary_json TEXT NOT NULL DEFAULT '{}',
    created_at VARCHAR(64) NOT NULL,
    FOREIGN KEY (task_id) REFERENCES review_tasks(task_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_review_inputs_task_id ON review_inputs(task_id);
CREATE INDEX IF NOT EXISTS idx_sandbox_runs_task_id ON sandbox_runs(task_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_sandbox_runs_task_request_nonempty
    ON sandbox_runs(task_id, request_id) WHERE request_id <> '';
CREATE INDEX IF NOT EXISTS idx_findings_task_id ON findings(task_id);
CREATE INDEX IF NOT EXISTS idx_filter_intercepts_task_id ON filter_intercepts(task_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_filter_intercepts_task_request_nonempty
    ON filter_intercepts(task_id, request_id) WHERE request_id <> '';
CREATE INDEX IF NOT EXISTS idx_telemetry_summaries_task_id ON telemetry_summaries(task_id);
CREATE INDEX IF NOT EXISTS idx_reports_task_id ON reports(task_id);
