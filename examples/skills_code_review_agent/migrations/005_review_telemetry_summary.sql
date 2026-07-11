BEGIN IMMEDIATE;

ALTER TABLE telemetry_summaries ADD COLUMN task_failure_kind VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE telemetry_summaries ADD COLUMN orchestration_elapsed_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry_summaries ADD COLUMN sandbox_elapsed_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry_summaries ADD COLUMN tool_attempts_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry_summaries ADD COLUMN tool_executed_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry_summaries ADD COLUMN severity_distribution_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE telemetry_summaries ADD COLUMN exception_kind_distribution_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE telemetry_summaries ADD COLUMN output_limit_exceeded_count INTEGER NOT NULL DEFAULT 0;

UPDATE telemetry_summaries
SET metrics_json = CASE
    WHEN json_valid(metrics_json) THEN
        CASE WHEN json_type(metrics_json) = 'object' THEN metrics_json ELSE '{}' END
    ELSE '{}'
END;

UPDATE telemetry_summaries
SET task_failure_kind = CASE WHEN json_type(metrics_json, '$.task_failure_kind') = 'text' THEN json_extract(metrics_json, '$.task_failure_kind') ELSE '' END,
    orchestration_elapsed_ms = CASE
        WHEN json_type(metrics_json, '$.orchestration_elapsed_ms') = 'integer' AND json_extract(metrics_json, '$.orchestration_elapsed_ms') >= 0 THEN json_extract(metrics_json, '$.orchestration_elapsed_ms')
        WHEN json_type(metrics_json, '$.elapsed_ms') = 'integer' AND json_extract(metrics_json, '$.elapsed_ms') >= 0 THEN json_extract(metrics_json, '$.elapsed_ms')
        ELSE 0 END,
    sandbox_elapsed_ms = CASE WHEN json_type(metrics_json, '$.sandbox_elapsed_ms') = 'integer' AND json_extract(metrics_json, '$.sandbox_elapsed_ms') >= 0 THEN json_extract(metrics_json, '$.sandbox_elapsed_ms') ELSE 0 END,
    tool_attempts_count = CASE WHEN json_type(metrics_json, '$.tool_attempts_count') = 'integer' AND json_extract(metrics_json, '$.tool_attempts_count') >= 0 THEN json_extract(metrics_json, '$.tool_attempts_count') ELSE 0 END,
    tool_executed_count = CASE WHEN json_type(metrics_json, '$.tool_executed_count') = 'integer' AND json_extract(metrics_json, '$.tool_executed_count') >= 0 THEN json_extract(metrics_json, '$.tool_executed_count') ELSE 0 END,
    severity_distribution_json = CASE
        WHEN json_type(metrics_json, '$.severity_distribution') = 'object'
         AND NOT EXISTS (SELECT 1 FROM json_each(json_extract(metrics_json, '$.severity_distribution')) WHERE type != 'integer' OR value < 0)
        THEN json_extract(metrics_json, '$.severity_distribution') ELSE '{}' END,
    exception_kind_distribution_json = CASE
        WHEN json_type(metrics_json, '$.exception_kind_distribution') = 'object'
         AND NOT EXISTS (SELECT 1 FROM json_each(json_extract(metrics_json, '$.exception_kind_distribution')) WHERE type != 'integer' OR value < 0)
        THEN json_extract(metrics_json, '$.exception_kind_distribution') ELSE '{}' END,
    output_limit_exceeded_count = CASE WHEN json_type(metrics_json, '$.output_limit_exceeded_count') = 'integer' AND json_extract(metrics_json, '$.output_limit_exceeded_count') >= 0 THEN json_extract(metrics_json, '$.output_limit_exceeded_count') ELSE 0 END;

UPDATE telemetry_summaries
SET metrics_json = json_set(
    metrics_json,
    '$.task_failure_kind', task_failure_kind,
    '$.orchestration_elapsed_ms', orchestration_elapsed_ms,
    '$.elapsed_ms', orchestration_elapsed_ms,
    '$.sandbox_elapsed_ms', sandbox_elapsed_ms,
    '$.tool_attempts_count', tool_attempts_count,
    '$.tool_executed_count', tool_executed_count,
    '$.severity_distribution', json(severity_distribution_json),
    '$.exception_kind_distribution', json(exception_kind_distribution_json),
    '$.output_limit_exceeded_count', output_limit_exceeded_count
);
