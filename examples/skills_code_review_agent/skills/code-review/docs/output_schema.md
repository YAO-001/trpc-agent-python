# Output Schema

The host report is the source of truth. Skill scripts emit auxiliary JSON files
under `out/` using only Python standard library code.

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
command.

