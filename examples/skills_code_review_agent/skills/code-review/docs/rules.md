# Deterministic Rules

The host review core parses unified diffs, redacts secrets, and evaluates added
lines only. Context lines are retained for lifecycle checks.

Rule categories:

- `security`: `subprocess(..., shell=True)`, `eval`/`exec` on request data, SQL interpolation with request data, unsafe `yaml.load`, and `pickle.loads` on request data.
- `secret`: AWS-style keys, GitHub tokens, OpenAI-like keys, JWT-like tokens, PEM private key blocks, and generic password/token/api_key/secret assignments.
- `async_resource`: unclosed `aiohttp.ClientSession`, unclosed `open`, untracked `asyncio.create_task`, and lock acquire without release.
- `database`: unclosed sqlite/engine/session handles and transaction begin without rollback in an obvious exception path.
- `test`: code files changed without test files changed. This is intentionally low confidence.
- `sandbox`: sandbox failures are warnings or human-review records, not findings.

Confidence routing:

- `confidence >= 0.80`: persisted as a finding.
- `0.50 <= confidence < 0.80`: warning or `needs_human_review`.
- `confidence < 0.50`: dropped and counted in debug telemetry.

