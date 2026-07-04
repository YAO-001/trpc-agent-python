# Code Review Report

- Task ID: `review_21a71a142ea4d1b0`
- Schema version: `1.0`
- Conclusion: High-confidence issues require changes before merge.
- Database query: `python examples/skills_code_review_agent/run_review.py query --db-url sqlite:///examples/skills_code_review_agent/review.db --task-id review_21a71a142ea4d1b0`

## Findings Summary

- Findings: 19
- Warnings: 1
- Needs human review: 3
- Severity distribution: `{"high": 13, "medium": 6}`

## Findings

### MEDIUM async_resource: aiohttp ClientSession is not closed

- Location: `app/async_worker.py:5`
- Evidence: `session = aiohttp.ClientSession()`
- Confidence: 0.86
- Source: `rule:async_resource, run_static_review.py, skill-rule:aiohttp_session_lifecycle, skill:run_static_review`
- Recommendation: Use async with aiohttp.ClientSession(...) or close the session in a finally block.

### MEDIUM async_resource: file handle opened without a context manager

- Location: `app/async_worker.py:8`
- Evidence: `f = open(path, "w")`
- Confidence: 0.84
- Source: `rule:async_resource`
- Recommendation: Use with open(...) as f so the descriptor is closed on every path.

### MEDIUM resource: file handle may not be closed

- Location: `app/async_worker.py:8`
- Evidence: `f = open(path, "w")`
- Confidence: 0.80
- Source: `run_static_review.py, skill-rule:open_without_context, skill:run_static_review`
- Recommendation: Use with open(...) as f or close the file in a finally block.

### HIGH security: subprocess invoked with shell=True

- Location: `app/handlers.py:7`
- Evidence: `subprocess.run(request.args["cmd"], shell=True)`
- Confidence: 0.96
- Source: `rule:security, run_static_review.py, skill-rule:subprocess_shell_true, skill:run_static_review`
- Recommendation: Pass an argv list with shell=False and validate the executable explicitly.

### HIGH security: dynamic code execution on request-controlled data

- Location: `app/handlers.py:8`
- Evidence: `result = eval(request.args["expr"])`
- Confidence: 0.92
- Source: `rule:security, run_static_review.py, skill-rule:eval_exec, skill:run_static_review`
- Recommendation: Replace eval/exec with a parser or an allowlisted command table.

### HIGH security: SQL query uses string interpolation with user data

- Location: `app/handlers.py:9`
- Evidence: `cursor.execute(f"SELECT * FROM users WHERE id = {request.args['user_id']}")`
- Confidence: 0.91
- Source: `rule:security`
- Recommendation: Use parameterized SQL placeholders and pass user values separately.

### HIGH security: yaml.load used without SafeLoader

- Location: `app/handlers.py:10`
- Evidence: `config = yaml.load(request.data)`
- Confidence: 0.90
- Source: `rule:security`
- Recommendation: Use yaml.safe_load or pass Loader=yaml.SafeLoader for untrusted YAML.

### HIGH security: pickle.loads called on request-controlled data

- Location: `app/handlers.py:11`
- Evidence: `profile = pickle.loads(request.body)`
- Confidence: 0.93
- Source: `rule:security`
- Recommendation: Do not unpickle untrusted input; use a safe serialization format such as JSON.

### MEDIUM database: database connection/session is not closed

- Location: `app/repository.py:5`
- Evidence: `conn = sqlite3.connect("app.db")`
- Confidence: 0.86
- Source: `rule:database, run_static_review.py, skill-rule:database_lifecycle, skill:run_static_review`
- Recommendation: Use a context manager or close the connection/session in a finally block.

### MEDIUM database: database connection/session is not closed

- Location: `app/repository.py:6`
- Evidence: `remote = engine.connect()`
- Confidence: 0.86
- Source: `rule:database, run_static_review.py, skill-rule:database_lifecycle, skill:run_static_review`
- Recommendation: Use a context manager or close the connection/session in a finally block.

### MEDIUM database: database connection/session is not closed

- Location: `app/repository.py:7`
- Evidence: `session = Session()`
- Confidence: 0.86
- Source: `rule:database, run_static_review.py, skill-rule:database_lifecycle, skill:run_static_review`
- Recommendation: Use a context manager or close the connection/session in a finally block.

### HIGH secret: aws_access_key secret added to source

- Location: `config/settings.py:2`
- Evidence: `AWS_ACCESS_KEY_ID = "[REDACTED:SECRET:aws_access_key:1a5d44a2]"`
- Confidence: 0.99
- Source: `redactor:aws_access_key, rule:secret`
- Recommendation: Remove the secret from source, rotate it, and load it from a managed secret store.

### HIGH secret: github_token secret added to source

- Location: `config/settings.py:3`
- Evidence: `GITHUB_TOKEN = "[REDACTED:SECRET:github_token:d73541f5]"`
- Confidence: 0.99
- Source: `redactor:github_token, rule:secret`
- Recommendation: Remove the secret from source, rotate it, and load it from a managed secret store.

### HIGH secret: openai_key secret added to source

- Location: `config/settings.py:4`
- Evidence: `OPENAI_API_KEY = "[REDACTED:SECRET:openai_key:2dfacb42]"`
- Confidence: 0.99
- Source: `redactor:openai_key, rule:secret`
- Recommendation: Remove the secret from source, rotate it, and load it from a managed secret store.

### HIGH secret: jwt secret added to source

- Location: `config/settings.py:5`
- Evidence: `JWT_SAMPLE = "[REDACTED:SECRET:jwt:3908a066]"`
- Confidence: 0.99
- Source: `redactor:jwt, rule:secret`
- Recommendation: Remove the secret from source, rotate it, and load it from a managed secret store.

### HIGH secret: generic_assignment secret added to source

- Location: `config/settings.py:6`
- Evidence: `password = "[REDACTED:SECRET:generic_assignment:87cbebfe]"`
- Confidence: 0.99
- Source: `redactor:generic_assignment, rule:secret`
- Recommendation: Remove the secret from source, rotate it, and load it from a managed secret store.

### HIGH secret: pem_private_key secret added to source

- Location: `config/settings.py:7`
- Evidence: `private_key = "[REDACTED:SECRET:pem_private_key:4b420350]"`
- Confidence: 0.99
- Source: `redactor:pem_private_key, rule:secret`
- Recommendation: Remove the secret from source, rotate it, and load it from a managed secret store.

### HIGH security: subprocess invoked with shell=True

- Location: `tools/runner.py:4`
- Evidence: `subprocess.run(request.args["cmd"], shell=True)`
- Confidence: 0.96
- Source: `rule:security, run_static_review.py, skill-rule:subprocess_shell_true, skill:run_static_review`
- Recommendation: Pass an argv list with shell=False and validate the executable explicitly.

### HIGH security: subprocess invoked with shell=True

- Location: `tools/runner.py:5`
- Evidence: `subprocess.run(request.args["cmd"], shell=True)`
- Confidence: 0.96
- Source: `rule:security, run_static_review.py, skill-rule:subprocess_shell_true, skill:run_static_review`
- Recommendation: Pass an argv list with shell=False and validate the executable explicitly.

## Warnings And Human Review

- warning: async_resource `app/async_worker.py:10` asyncio.create_task result is not tracked (confidence 0.72) - asyncio.create_task(send_metric(url)) Recommendation: Store the task and await, gather, or cancel it during shutdown.
- needs human review: sandbox `n/a` sandbox smoke test failed (confidence 1.00) - sandbox_failure fixture intentionally returns a non-zero smoke-test status.
- needs human review: async_resource `app/async_worker.py:11` lock acquired without an obvious release (confidence 0.74) - await lock.acquire() Recommendation: Use a with/async with lock guard or release the lock in a finally block.
- needs human review: database `app/repository.py:8` transaction begin lacks rollback on exception path (confidence 0.72) - tx = conn.begin() Recommendation: Rollback in except/finally or use a transaction context manager.

## Filter Intercepts

- Denied: 0
- Needs human review: 0


## Sandbox Execution

- Runs: 3
- Failures/timeouts: 1
- Stdout truncated: 0
- Stderr truncated: 0
- Output files truncated: 0
- `python3 scripts/run_static_review.py --input work/inputs/review_input.json --output out/findings.json` exit=0 timed_out=False stdout_truncated=False stderr_truncated=False output_truncated=False
- `python3 scripts/secret_scan.py --input work/inputs/review_input.json --output out/secrets.json` exit=0 timed_out=False stdout_truncated=False stderr_truncated=False output_truncated=False
- `python3 scripts/smoke_test.py --input work/inputs/review_input.json --output out/smoke.json` exit=2 timed_out=False stdout_truncated=False stderr_truncated=False output_truncated=False

## Telemetry

- Files changed: 9
- Added lines: 43
- Redactions: 6
- Debug dropped: 0

## Redaction Summary

- By type: `{"aws_access_key": 1, "generic_assignment": 1, "github_token": 1, "jwt": 1, "openai_key": 1, "pem_private_key": 1}`

## Executable Recommendations

- Use async with aiohttp.ClientSession(...) or close the session in a finally block.
- Use with open(...) as f so the descriptor is closed on every path.
- Use with open(...) as f or close the file in a finally block.
- Pass an argv list with shell=False and validate the executable explicitly.
- Replace eval/exec with a parser or an allowlisted command table.
- Use parameterized SQL placeholders and pass user values separately.
- Use yaml.safe_load or pass Loader=yaml.SafeLoader for untrusted YAML.
- Do not unpickle untrusted input; use a safe serialization format such as JSON.
- Use a context manager or close the connection/session in a finally block.
- Remove the secret from source, rotate it, and load it from a managed secret store.
- asyncio.create_task(send_metric(url)) Recommendation: Store the task and await, gather, or cancel it during shutdown.
- sandbox_failure fixture intentionally returns a non-zero smoke-test status.
