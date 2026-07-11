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
    request_id VARCHAR(160) NOT NULL,
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
    termination_reason VARCHAR(64) NOT NULL DEFAULT '',
    termination_confirmed BOOLEAN NOT NULL DEFAULT 0,
    execution_started BOOLEAN NOT NULL DEFAULT 0,
    stdout_bytes_observed INTEGER NOT NULL DEFAULT 0,
    stderr_bytes_observed INTEGER NOT NULL DEFAULT 0,
    output_bytes_observed INTEGER NOT NULL DEFAULT 0,
    failure_kind VARCHAR(64) NOT NULL DEFAULT '',
    failure_reason TEXT,
    warning TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    CONSTRAINT ck_sandbox_runs_request_id_nonempty CHECK (request_id <> ''),
    CONSTRAINT uq_sandbox_runs_task_request UNIQUE (task_id, request_id),
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
    request_id VARCHAR(160) NOT NULL,
    decision VARCHAR(64) NOT NULL,
    error_kind VARCHAR(64) NOT NULL,
    reason TEXT NOT NULL,
    command_json TEXT NOT NULL,
    runtime VARCHAR(64) NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    CONSTRAINT ck_filter_intercepts_request_id_nonempty CHECK (request_id <> ''),
    CONSTRAINT ck_filter_intercepts_decision_error_kind CHECK (
        (decision = 'allow' AND error_kind = '')
        OR (decision = 'deny' AND error_kind = 'policy_denied')
        OR (
            decision = 'needs_human_review'
            AND error_kind = 'approval_required'
        )
    ),
    CONSTRAINT uq_filter_intercepts_task_request UNIQUE (task_id, request_id),
    FOREIGN KEY (task_id) REFERENCES review_tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS telemetry_summaries (
    task_id VARCHAR(128) PRIMARY KEY,
    task_failure_kind VARCHAR(64) NOT NULL DEFAULT '',
    orchestration_elapsed_ms INTEGER NOT NULL DEFAULT 0,
    sandbox_elapsed_ms INTEGER NOT NULL DEFAULT 0,
    tool_attempts_count INTEGER NOT NULL DEFAULT 0,
    tool_executed_count INTEGER NOT NULL DEFAULT 0,
    severity_distribution_json TEXT NOT NULL DEFAULT '{}',
    exception_kind_distribution_json TEXT NOT NULL DEFAULT '{}',
    output_limit_exceeded_count INTEGER NOT NULL DEFAULT 0,
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
CREATE INDEX IF NOT EXISTS idx_findings_task_id ON findings(task_id);
CREATE INDEX IF NOT EXISTS idx_filter_intercepts_task_id ON filter_intercepts(task_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_summaries_task_id ON telemetry_summaries(task_id);
CREATE INDEX IF NOT EXISTS idx_reports_task_id ON reports(task_id);
