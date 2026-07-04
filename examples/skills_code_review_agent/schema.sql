CREATE TABLE IF NOT EXISTS review_tasks (
    task_id VARCHAR(128) PRIMARY KEY,
    input_type VARCHAR(64) NOT NULL,
    input_ref TEXT NOT NULL,
    runtime VARCHAR(64) NOT NULL,
    dry_run BOOLEAN NOT NULL,
    status VARCHAR(64) NOT NULL,
    created_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS review_inputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id VARCHAR(128) NOT NULL,
    redacted_diff TEXT NOT NULL,
    changed_files_json TEXT NOT NULL,
    redaction_summary_json TEXT NOT NULL,
    input_metadata_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sandbox_runs (
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
    warning TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL
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
    source_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS filter_intercepts (
    intercept_id VARCHAR(160) PRIMARY KEY,
    task_id VARCHAR(128) NOT NULL,
    decision VARCHAR(64) NOT NULL,
    reason TEXT NOT NULL,
    command_json TEXT NOT NULL,
    runtime VARCHAR(64) NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS telemetry_summaries (
    task_id VARCHAR(128) PRIMARY KEY,
    metrics_json TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    task_id VARCHAR(128) PRIMARY KEY,
    json_report TEXT NOT NULL,
    markdown_report TEXT NOT NULL,
    json_path TEXT NOT NULL,
    markdown_path TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL
);

