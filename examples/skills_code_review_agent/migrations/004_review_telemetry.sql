BEGIN IMMEDIATE;

ALTER TABLE sandbox_runs
    ADD COLUMN termination_reason VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE sandbox_runs
    ADD COLUMN termination_confirmed BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE sandbox_runs
    ADD COLUMN execution_started BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE sandbox_runs
    ADD COLUMN stdout_bytes_observed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sandbox_runs
    ADD COLUMN stderr_bytes_observed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sandbox_runs
    ADD COLUMN output_bytes_observed INTEGER NOT NULL DEFAULT 0;

UPDATE sandbox_runs
SET execution_started = CASE
    WHEN failure_kind = 'runtime_unavailable' THEN 0
    ELSE 1
END;
