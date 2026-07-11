PRAGMA foreign_keys=OFF;

BEGIN IMMEDIATE;

CREATE TABLE sandbox_runs_new (
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
    failure_kind VARCHAR(64) NOT NULL DEFAULT '',
    failure_reason TEXT,
    warning TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    CONSTRAINT ck_sandbox_runs_request_id_nonempty CHECK (request_id <> ''),
    CONSTRAINT uq_sandbox_runs_task_request UNIQUE (task_id, request_id),
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
    CASE WHEN request_id = '' THEN 'legacy:' || run_id ELSE request_id END,
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
FROM sandbox_runs;

DROP TABLE sandbox_runs;
ALTER TABLE sandbox_runs_new RENAME TO sandbox_runs;

CREATE TABLE filter_intercepts_new (
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
    CASE WHEN request_id = '' THEN 'legacy:' || intercept_id ELSE request_id END,
    decision,
    error_kind,
    reason,
    command_json,
    runtime,
    metadata_json,
    created_at
FROM filter_intercepts;

DROP TABLE filter_intercepts;
ALTER TABLE filter_intercepts_new RENAME TO filter_intercepts;

CREATE INDEX idx_sandbox_runs_task_id ON sandbox_runs(task_id);
CREATE INDEX idx_filter_intercepts_task_id ON filter_intercepts(task_id);
