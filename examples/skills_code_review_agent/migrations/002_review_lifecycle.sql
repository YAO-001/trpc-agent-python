PRAGMA foreign_keys=OFF;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(128) PRIMARY KEY,
    applied_at VARCHAR(64) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE review_tasks_new (
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

INSERT INTO review_tasks_new (
    task_id,
    input_type,
    input_ref,
    runtime,
    dry_run,
    status,
    created_at,
    updated_at,
    failure_kind,
    failure_reason_redacted
)
SELECT
    task_id,
    input_type,
    input_ref,
    runtime,
    dry_run,
    status,
    created_at,
    created_at,
    '',
    ''
FROM review_tasks;

DROP TABLE review_tasks;
ALTER TABLE review_tasks_new RENAME TO review_tasks;

CREATE TABLE sandbox_runs_new (
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

INSERT INTO sandbox_runs_new (
    run_id,
    task_id,
    request_id,
    runtime,
    command_json,
    decision,
    exit_code,
    timed_out,
    duration_ms,
    stdout,
    stderr,
    output_files_json,
    stdout_truncated,
    stderr_truncated,
    output_truncated,
    output_file_count,
    output_bytes,
    failure_kind,
    failure_reason,
    warning,
    created_at
)
SELECT
    run_id,
    task_id,
    'legacy:' || run_id,
    runtime,
    command_json,
    decision,
    exit_code,
    timed_out,
    duration_ms,
    stdout,
    stderr,
    output_files_json,
    stdout_truncated,
    stderr_truncated,
    output_truncated,
    output_file_count,
    output_bytes,
    '',
    failure_reason,
    warning,
    created_at
FROM sandbox_runs;

DROP TABLE sandbox_runs;
ALTER TABLE sandbox_runs_new RENAME TO sandbox_runs;

CREATE TABLE filter_intercepts_new (
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

INSERT INTO filter_intercepts_new (
    intercept_id,
    task_id,
    request_id,
    decision,
    error_kind,
    reason,
    command_json,
    runtime,
    metadata_json,
    created_at
)
SELECT
    intercept_id,
    task_id,
    'legacy:' || intercept_id,
    decision,
    CASE decision
        WHEN 'deny' THEN 'policy_denied'
        WHEN 'needs_human_review' THEN 'approval_required'
        ELSE ''
    END,
    reason,
    command_json,
    runtime,
    metadata_json,
    created_at
FROM filter_intercepts;

DROP TABLE filter_intercepts;
ALTER TABLE filter_intercepts_new RENAME TO filter_intercepts;

CREATE TABLE review_inputs_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id VARCHAR(128) NOT NULL,
    redacted_diff TEXT NOT NULL,
    changed_files_json TEXT NOT NULL,
    redaction_summary_json TEXT NOT NULL,
    input_metadata_json TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES review_tasks(task_id) ON DELETE CASCADE
);

INSERT INTO review_inputs_new (
    id,
    task_id,
    redacted_diff,
    changed_files_json,
    redaction_summary_json,
    input_metadata_json
)
SELECT
    id,
    task_id,
    redacted_diff,
    changed_files_json,
    redaction_summary_json,
    input_metadata_json
FROM review_inputs;

DROP TABLE review_inputs;
ALTER TABLE review_inputs_new RENAME TO review_inputs;

CREATE TABLE findings_new (
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

INSERT INTO findings_new (
    id,
    task_id,
    dedupe_key,
    severity,
    category,
    file,
    line,
    title,
    evidence,
    recommendation,
    confidence,
    source_json
)
SELECT
    id,
    task_id,
    dedupe_key,
    severity,
    category,
    file,
    line,
    title,
    evidence,
    recommendation,
    confidence,
    source_json
FROM findings;

DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;

CREATE TABLE telemetry_summaries_new (
    task_id VARCHAR(128) PRIMARY KEY,
    metrics_json TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    FOREIGN KEY (task_id) REFERENCES review_tasks(task_id) ON DELETE CASCADE
);

INSERT INTO telemetry_summaries_new (task_id, metrics_json, created_at)
SELECT task_id, metrics_json, created_at
FROM telemetry_summaries;

DROP TABLE telemetry_summaries;
ALTER TABLE telemetry_summaries_new RENAME TO telemetry_summaries;

CREATE TABLE reports_new (
    task_id VARCHAR(128) PRIMARY KEY,
    json_report TEXT NOT NULL,
    markdown_report TEXT NOT NULL,
    json_path TEXT NOT NULL,
    markdown_path TEXT NOT NULL,
    summary_json TEXT NOT NULL DEFAULT '{}',
    created_at VARCHAR(64) NOT NULL,
    FOREIGN KEY (task_id) REFERENCES review_tasks(task_id) ON DELETE CASCADE
);

INSERT INTO reports_new (
    task_id,
    json_report,
    markdown_report,
    json_path,
    markdown_path,
    summary_json,
    created_at
)
SELECT
    task_id,
    json_report,
    markdown_report,
    json_path,
    markdown_path,
    summary_json,
    created_at
FROM reports;

DROP TABLE reports;
ALTER TABLE reports_new RENAME TO reports;

CREATE INDEX idx_review_inputs_task_id ON review_inputs(task_id);
CREATE INDEX idx_sandbox_runs_task_id ON sandbox_runs(task_id);
CREATE UNIQUE INDEX uq_sandbox_runs_task_request_nonempty
    ON sandbox_runs(task_id, request_id) WHERE request_id <> '';
CREATE INDEX idx_findings_task_id ON findings(task_id);
CREATE INDEX idx_filter_intercepts_task_id ON filter_intercepts(task_id);
CREATE UNIQUE INDEX uq_filter_intercepts_task_request_nonempty
    ON filter_intercepts(task_id, request_id) WHERE request_id <> '';
CREATE INDEX idx_telemetry_summaries_task_id ON telemetry_summaries(task_id);
CREATE INDEX idx_reports_task_id ON reports(task_id);
