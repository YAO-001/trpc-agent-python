# Output Schema

The host report is the source of truth. Skill scripts emit auxiliary JSON files
under `out/` using only Python standard library code. The host loader accepts
`findings`, `warnings`, and `needs_human_review` arrays from `out/findings.json`,
`out/secrets.json`, and `out/smoke.json`.

Required finding fields:

- `severity`
- `category`
- `file`
- `line`
- `title`
- `evidence`
- `recommendation`
- `confidence`
- `source`

Reports include conclusion, findings summary, severity distribution, warnings,
`needs_human_review`, Filter intercept summary, sandbox summary, telemetry,
redaction summary, executable recommendations, task id, and database query
command. Report JSON includes `schema_version: "1.0"`.

Sandbox run records include:

- `stdout_truncated`
- `stderr_truncated`
- `output_truncated`
