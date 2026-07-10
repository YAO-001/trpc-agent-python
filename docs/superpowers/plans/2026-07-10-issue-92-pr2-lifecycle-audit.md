# Issue #92 PR2 Lifecycle and Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make task status, PolicyGate decisions, SandboxRun rows, telemetry, and report conclusions describe the same execution outcome at every point in time.

**Architecture:** Define task status in the model layer, migrate schema in the same task, and persist created/input atomically. Every PolicyGate decision and every allowed request attempt is saved through immediate callbacks. Auto selects container once and never retries locally. Final findings, telemetry, report, and terminal status commit in one transaction.

**Tech Stack:** Python enums, Pydantic v2, SQLAlchemy transactions, versioned SQLite migrations, pytest.

---

### Task 1: Add the state machine and its schema migration together

**Files:**
- Modify: `examples/skills_code_review_agent/agent/models.py:25-163`
- Create: `examples/skills_code_review_agent/agent/task_state.py`
- Create: `examples/skills_code_review_agent/migrations/002_review_lifecycle.sql`
- Modify: `examples/skills_code_review_agent/schema.sql`
- Modify: `examples/skills_code_review_agent/agent/storage.py:18-160`
- Create: `tests/examples/test_skills_code_review_agent_lifecycle.py`
- Modify: `tests/examples/test_skills_code_review_agent_storage.py`

- [ ] **Step 1: Write exhaustive transition tests**

```python
from itertools import product

import pytest

from agent.models import ReviewTask
from agent.models import ReviewTaskStatus
from agent.task_state import transition_task


STATUSES = list(ReviewTaskStatus)
ALLOWED = {
    (ReviewTaskStatus.CREATED, ReviewTaskStatus.RUNNING),
    *{
        (ReviewTaskStatus.RUNNING, target)
        for target in (
            ReviewTaskStatus.COMPLETED,
            ReviewTaskStatus.COMPLETED_WITH_ERRORS,
            ReviewTaskStatus.BLOCKED,
            ReviewTaskStatus.FAILED,
        )
    },
}


@pytest.mark.parametrize(("source", "target"), product(STATUSES, STATUSES))
def test_every_task_transition_is_explicit(source, target):
    task = ReviewTask(
        task_id="task-1",
        input_type="fixture",
        runtime="container",
        status=source,
        dry_run=True,
    )
    if (source, target) in ALLOWED:
        changed = transition_task(task, target)
        assert changed.status == target
        assert changed.updated_at == "1970-01-01T00:00:00+00:00"
    else:
        with pytest.raises(ValueError, match="illegal task transition"):
            transition_task(task, target)
```

- [ ] **Step 2: Write a legacy-database migration test**

Create a SQLite database with the pre-PR2 `review_tasks`, `sandbox_runs`, and `filter_intercepts` definitions, insert one row in each, then instantiate `ReviewStorage`. Assert:

```python
def test_legacy_database_migrates_without_losing_audit_rows(tmp_path):
    db_url = _create_legacy_database(tmp_path)
    storage = ReviewStorage(db_url)
    with storage.engine.connect() as conn:
        task_columns = _column_names(conn, "review_tasks")
        run_columns = _column_names(conn, "sandbox_runs")
        decision_columns = _column_names(conn, "filter_intercepts")
        assert {
            "updated_at",
            "failure_kind",
            "failure_reason_redacted",
        } <= task_columns
        assert {"request_id", "failure_kind"} <= run_columns
        assert {"request_id", "error_kind"} <= decision_columns
        assert _foreign_key_target(conn, "sandbox_runs", "task_id") == "review_tasks"
        assert _foreign_key_target(conn, "filter_intercepts", "task_id") == "review_tasks"
        assert _index_exists(conn, "sandbox_runs", ["task_id"])
        assert _index_exists(conn, "filter_intercepts", ["task_id"])
        assert conn.exec_driver_sql("SELECT count(*) FROM sandbox_runs").scalar_one() == 1
        assert conn.exec_driver_sql("SELECT count(*) FROM filter_intercepts").scalar_one() == 1
        assert conn.exec_driver_sql(
            "SELECT error_kind FROM filter_intercepts"
        ).scalar_one() == "policy_denied"
    ReviewStorage(db_url)
    with storage.engine.connect() as conn:
        assert conn.exec_driver_sql(
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='002_review_lifecycle'"
        ).scalar_one() == 1
```

The test helper executes literal legacy CREATE TABLE statements in the test, inserts a legacy deny decision, and must not import the new metadata to create the database.

- [ ] **Step 3: Define status in models to avoid circular imports**

Add before `ReviewTask`:

```python
class ReviewTaskStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    BLOCKED = "blocked"
    FAILED = "failed"


TERMINAL_TASK_STATUSES = frozenset({
    ReviewTaskStatus.COMPLETED,
    ReviewTaskStatus.COMPLETED_WITH_ERRORS,
    ReviewTaskStatus.BLOCKED,
    ReviewTaskStatus.FAILED,
})
```

`ReviewTask.status` uses this enum and adds `updated_at=Field(default_factory=utc_now)`, `failure_kind: str = ""`, and `failure_reason_redacted: str = ""`. The latter two fields carry non-Sandbox terminal failures such as `storage_error`; they must be empty unless status is `FAILED`. `SandboxRun` adds temporary-compatible `request_id: str = ""` and `failure_kind: str = ""`; `FilterIntercept` adds temporary-compatible `request_id: str = ""` and `error_kind: str = ""`. Task 2 removes both Filter defaults after every decision constructor is migrated, and Task 3 removes the SandboxRun default after every run constructor is migrated. `task_state.py` imports all types from models; models never imports task_state:

```python
_ALLOWED = {
    ReviewTaskStatus.CREATED: {ReviewTaskStatus.RUNNING},
    ReviewTaskStatus.RUNNING: set(TERMINAL_TASK_STATUSES),
}


def transition_task(task: ReviewTask, target: ReviewTaskStatus) -> ReviewTask:
    current = ReviewTaskStatus(task.status)
    if target not in _ALLOWED.get(current, set()):
        raise ValueError(f"illegal task transition: {current.value} -> {target.value}")
    return task.model_copy(update={
        "status": target,
        "updated_at": utc_now(task.dry_run),
    })
```

- [ ] **Step 4: Apply a versioned migration**

The canonical schema adds:

- `review_tasks.updated_at NOT NULL`, `failure_kind NOT NULL DEFAULT ''`, and `failure_reason_redacted NOT NULL DEFAULT ''`;
- `sandbox_runs.request_id NOT NULL DEFAULT ''`, `failure_kind NOT NULL DEFAULT ''`, a partial unique index on `(task_id, request_id) WHERE request_id <> ''`, and task foreign key/index;
- `filter_intercepts.request_id NOT NULL DEFAULT ''`, `error_kind NOT NULL DEFAULT ''`, the same non-empty partial unique index, and task foreign key/index;
- task_id indexes and `ON DELETE CASCADE` foreign keys for review_inputs, findings, telemetry, and reports.

Migration 002 rebuilds `review_tasks` first so historical rows receive non-null `updated_at=created_at`. It then rebuilds `sandbox_runs` and `filter_intercepts` for request identity/uniqueness, and rebuilds `review_inputs`, `findings`, `telemetry_summaries`, and `reports` so every task-owned table gains its foreign key. Backfill legacy request IDs as `'legacy:' || run_id` and `'legacy:' || intercept_id`; backfill `filter_intercepts.error_kind` as empty for allow, `policy_denied` for deny, and `approval_required` for needs-human-review. It creates `schema_migrations(version PRIMARY KEY, applied_at)` and records `002_review_lifecycle`.

In `ReviewStorage.__init__`, create the engine and inspect table names. For a new database, create current metadata and atomically record every bundled migration version currently discovered as applied. For an existing database, run sorted unapplied migrations, then call `metadata.create_all` for any new tables. Migration 002 must toggle `PRAGMA foreign_keys=OFF` before opening its rebuild transaction, commit the rebuild, then re-enable and verify `PRAGMA foreign_key_check` returns no rows. Register a SQLAlchemy connect event that enables foreign keys for all normal storage transactions. Remove the ad-hoc per-column `_ensure_schema_compat` loop after its behavior is represented by versioned migrations.

- [ ] **Step 5: Run transition, migration, and existing storage tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_lifecycle.py -k "transition" -v
python -m pytest tests/examples/test_skills_code_review_agent_storage.py -v
python -m pytest tests/examples -k "storage or lifecycle" -o addopts= -q
```

Expected: all selected tests pass at the end of Task 1; no model/schema mismatch remains for a later task.

- [ ] **Step 6: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/models.py',
  'examples/skills_code_review_agent/agent/task_state.py',
  'examples/skills_code_review_agent/agent/storage.py',
  'examples/skills_code_review_agent/schema.sql',
  'examples/skills_code_review_agent/migrations/002_review_lifecycle.sql',
  'tests/examples/test_skills_code_review_agent_lifecycle.py',
  'tests/examples/test_skills_code_review_agent_storage.py'
)
git add @stage
git commit -m "feat(review): define and migrate task lifecycle"
```

### Task 2: Persist every PolicyGate decision with collision-free IDs

**Files:**
- Modify: `examples/skills_code_review_agent/agent/models.py`
- Modify: `examples/skills_code_review_agent/agent/filter_policy.py:39-180`
- Modify: `examples/skills_code_review_agent/agent/storage.py:160-360`
- Modify: `examples/skills_code_review_agent/agent/sandbox_runner.py:440-556`
- Test: `tests/examples/test_skills_code_review_agent_lifecycle.py`
- Test: `tests/examples/test_skills_code_review_agent_storage.py`

- [ ] **Step 1: Write tests through the real policy API**

```python
def _request(tmp_path, *, task_id="task-1", runtime="container"):
    path = tmp_path / f"{task_id}.json"
    path.write_text("{}", encoding="utf-8")
    return build_execution_requests(task_id, runtime, str(path))[0]


def _context(request):
    return PolicyContext(
        task_id=request.task_id,
        runtime=request.runtime,
        allowed_input_sources=frozenset({request.inputs[0].src}),
    )


def _runner(tmp_path, harness=None):
    runner = SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        boundary=RedactionBoundary(),
    )
    if harness is not None:
        runner._harness_for_runtime = lambda runtime: harness
    return runner


def _successful_run(request):
    return SandboxRun(
        run_id=f"sandbox-{request.request_id}",
        task_id=request.task_id,
        request_id=request.request_id,
        runtime=request.runtime,
        command=list(request.command_argv),
        exit_code=0,
        created_at=DRY_RUN_TIMESTAMP,
    )


def test_same_decision_is_unique_across_tasks(tmp_path):
    policy = ReviewExecutionPolicy(dry_run=True)
    first_request = _request(tmp_path, task_id="task-a")
    second_request = _request(tmp_path, task_id="task-b")
    first = policy.evaluate(first_request, _context(first_request)).intercept
    second = policy.evaluate(second_request, _context(second_request)).intercept
    assert first.decision == second.decision == "allow"
    assert first.intercept_id != second.intercept_id


def test_filter_error_taxonomy_is_persisted(tmp_path):
    storage, task, requests = _running_task_with_three_requests(tmp_path)
    policy = ReviewExecutionPolicy(dry_run=True)
    commands = (
        requests[0].command_argv,
        ("rm", "-rf", "/"),
        ("pip", "install", "unapproved-package"),
    )
    for request, command in zip(requests, commands):
        item = policy.evaluate(
            request.model_copy(update={"command_argv": command}),
            _context(request),
        ).intercept
        storage.save_filter_decision(item)
    rows = storage.query_task(task.task_id)["filter_intercepts"]
    assert {
        row["decision"]: row["error_kind"]
        for row in rows
    } == {
        "allow": "",
        "deny": "policy_denied",
        "needs_human_review": "approval_required",
    }


def test_allow_decision_is_saved_before_execution(tmp_path):
    events = []
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    task = ReviewTask(
        task_id="task-1",
        input_type="fixture",
        runtime="container",
        dry_run=True,
    )
    input_row = {
        "redacted_diff": "",
        "changed_files": [],
        "redaction_summary": RedactionSummary(),
        "input_metadata": {},
    }
    storage.create_task_with_input(task=task, **input_row)
    running = transition_task(task, ReviewTaskStatus.RUNNING)
    storage.update_task(running)

    class OrderingHarness:
        def execute_one(self, **kwargs):
            request = kwargs["request"]
            rows = storage.query_task(task.task_id)
            assert rows["filter_intercepts"][0]["request_id"] == request.request_id
            events.append("execute")
            return _successful_run(request)

    request = _request(tmp_path, task_id=task.task_id)
    runner = _runner(tmp_path, harness=OrderingHarness())
    runner.run(
        task_id=task.task_id,
        review_input={"task_id": task.task_id},
        runtime="container",
        dry_run=True,
        requests=[request],
        policy_context=_context(request),
        on_decision=storage.save_filter_decision,
        on_run=storage.save_sandbox_run,
    )
    assert events == ["execute"]
```

`_running_task_with_three_requests` creates one task/input transaction, transitions it to running, and returns three `_request` values with request IDs ending in 1, 2, and 3 against the same trusted input source.

- [ ] **Step 2: Run the tests and verify allow is not saved**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_lifecycle.py -k "decision" -v
```

Expected: FAIL because current code stores only deny/needs-human decisions, IDs omit request/task identity, and no explicit canonical error-kind column exists.

- [ ] **Step 3: Derive stable globally unique decision IDs**

In the sole `_decision` helper:

```python
payload = json.dumps({
    "task_id": request.task_id,
    "request_id": request.request_id,
    "decision": decision,
    "reason": reason,
    "command": list(request.command_argv),
    "runtime": request.runtime,
}, sort_keys=True)
intercept_id = "filter_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
```

Populate required `task_id`/`request_id` and explicit `error_kind=DECISION_ERROR_KIND[decision]` on the model. Keep raw input URIs and env values out of metadata.

After every policy construction site and test is migrated, remove the temporary defaults from `FilterIntercept.request_id` and `FilterIntercept.error_kind`. Validate the exact decision/error-kind pairs `allow/""`, `deny/policy_denied`, and `needs_human_review/approval_required`; constructing a new decision without either explicit field or with a mismatched pair must raise validation error.

- [ ] **Step 4: Add singular append APIs and immediate callbacks**

```python
def save_filter_decision(self, item: FilterIntercept) -> None:
    with self.engine.begin() as conn:
        conn.execute(filter_intercepts.insert().values(**self._filter_row(item)))


def save_sandbox_run(self, item: SandboxRun) -> None:
    with self.engine.begin() as conn:
        conn.execute(sandbox_runs.insert().values(**self._sandbox_row(item)))


def update_task(self, task: ReviewTask) -> None:
    with self.engine.begin() as conn:
        result = conn.execute(
            review_tasks.update()
            .where(review_tasks.c.task_id == task.task_id)
            .values(**self._task_row(task))
        )
        if result.rowcount != 1:
            raise KeyError(f"unknown review task {task.task_id}")


def create_task_with_input(self, *, task: ReviewTask, **input_row) -> None:
    if task.status != ReviewTaskStatus.CREATED:
        raise ValueError("initial task must be created")
    with self.engine.begin() as conn:
        conn.execute(review_tasks.insert().values(**self._task_row(task)))
        conn.execute(review_inputs.insert().values(**self._input_row(
            task.task_id,
            **input_row,
        )))
```

`_filter_row` persists the explicit canonical `error_kind` column as well as decision/reason. `SandboxRunner.run` invokes `on_decision` immediately for allow, deny, and needs_human_review before any harness lookup. Duplicate `(task_id, request_id)` is an error, not an upsert that hides repeated execution.

- [ ] **Step 5: Run decision/storage regressions**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_lifecycle.py -k "decision" -v
python -m pytest tests/examples/test_skills_code_review_agent_storage.py -v
```

Expected: all selected tests pass and the database contains allow decisions.

- [ ] **Step 6: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/models.py',
  'examples/skills_code_review_agent/agent/filter_policy.py',
  'examples/skills_code_review_agent/agent/storage.py',
  'examples/skills_code_review_agent/agent/sandbox_runner.py',
  'tests/examples/test_skills_code_review_agent_lifecycle.py',
  'tests/examples/test_skills_code_review_agent_storage.py'
)
git add @stage
git commit -m "fix(review): persist every policy decision"
```

### Task 3: Record one SandboxRun per allowed request and remove local fallback

**Files:**
- Modify: `examples/skills_code_review_agent/agent/models.py`
- Modify: `examples/skills_code_review_agent/agent/sandbox_runner.py:190-556`
- Modify: `examples/skills_code_review_agent/agent/agent_factory.py`
- Create: `examples/skills_code_review_agent/migrations/003_request_identity.sql`
- Modify: `examples/skills_code_review_agent/schema.sql`
- Test: `tests/examples/test_skills_code_review_agent_lifecycle.py`
- Modify: `tests/examples/test_skills_code_review_agent_e2e.py`

- [ ] **Step 1: Write direct runner tests with real request objects**

```python
def _three_valid_requests(tmp_path, *, task_id: str, runtime: str):
    path = tmp_path / f"{task_id}-review.json"
    path.write_text("{}", encoding="utf-8")
    return build_execution_requests(task_id, runtime, str(path))


def test_auto_runtime_records_each_request_when_container_start_fails(tmp_path):
    created = []

    def fail_factory(runtime):
        created.append(runtime)
        raise RuntimeError("docker unavailable")

    requests = _three_valid_requests(
        tmp_path,
        task_id="task-1",
        runtime="container",
    )
    saved = []
    runner = _runner(tmp_path)
    runner._harness_for_runtime = fail_factory
    result = runner.run(
        task_id="task-1",
        review_input={"task_id": "task-1"},
        runtime="auto",
        dry_run=True,
        requests=requests,
        policy_context=_context(requests[0]),
        on_run=saved.append,
    )

    assert created == ["container"]
    assert result.effective_runtime == "container"
    assert len(result.runs) == len(saved) == 3
    assert [item.request_id for item in result.runs] == [
        item.request_id for item in requests
    ]
    assert {item.failure_kind for item in result.runs} == {"runtime_unavailable"}


def test_successful_runs_keep_request_identity(tmp_path):
    requests = _three_valid_requests(
        tmp_path,
        task_id="task-1",
        runtime="local",
    )
    result = _runner(tmp_path).run(
        task_id="task-1",
        review_input={"task_id": "task-1"},
        runtime="local",
        dry_run=True,
        requests=requests,
        policy_context=_context(requests[0]),
    )
    assert [item.request_id for item in result.runs] == [
        item.request_id for item in requests
    ]
```

The shared test helper calls `build_execution_requests`; it does not fabricate loose command lists or reference an undefined `_runner`.

- [ ] **Step 2: Run focused tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_lifecycle.py -k "runtime or request_identity" -v
```

Expected: FAIL because auto invokes local, startup failure creates no runs, and success rows lack request IDs.

- [ ] **Step 3: Execute one validated request at a time**

Both harnesses expose:

```python
def execute_one(
    self,
    *,
    task_id: str,
    review_input: dict[str, Any],
    request: ExecutionRequest,
    dry_run: bool,
) -> SandboxRun:
```

Local execution derives argv, cwd, input mapping, output glob, env, timeout, and budget only from `request`. Its sole platform translation maps the already-validated logical executable `python3` to `sys.executable` on the host (required on Windows); `SandboxRun.command` still records the logical request argv. Container execution invokes `request.to_skill_run_args()` once and maps its output to a run with `request.request_id`. Delete list-based command reconstruction and every `commands=` API.

After local, container, startup-failure, timeout, and test constructors all supply identity, remove the temporary default from `SandboxRun.request_id`. Legacy database rows remain backfilled by migration rather than relying on the model default.

Migration `003_request_identity.sql` backfills any development-era empty IDs as `legacy:<primary-key>`, rebuilds `sandbox_runs` and `filter_intercepts` with `CHECK(request_id <> '')` plus full `UNIQUE(task_id, request_id)`, preserves `error_kind`, and adds a database check for the three exact decision/error-kind pairs. Update canonical schema. Add storage tests that a direct empty-request insert and a mismatched decision/error-kind insert each raise `sqlalchemy.exc.IntegrityError`; this closes the temporary compatibility window from Task 1.

- [ ] **Step 4: Fail closed without a second runtime**

For `runtime="auto"`, normalize request runtimes to container and construct the container harness once. If construction fails, create one failure run per allow request:

```python
def _failure_run(
    request,
    exc,
    *,
    failure_kind,
    dry_run,
    boundary,
):
    return SandboxRun(
        run_id="sandbox_" + hashlib.sha256(
            f"{request.task_id}:{request.request_id}".encode("utf-8")
        ).hexdigest()[:24],
        task_id=request.task_id,
        request_id=request.request_id,
        runtime=request.runtime,
        command=list(request.command_argv),
        decision="allow",
        exit_code=-1,
        failure_kind=failure_kind,
        failure_reason=boundary.text(exc).text,
        warning="sandbox runtime failed before command start",
        created_at=utc_now(dry_run),
    )
```

Use `failure_kind="runtime_unavailable"` only when harness construction fails. If `execute_one` raises unexpectedly for a specific request, use `failure_kind="orchestration_error"` and continue recording the remaining requests against the same runtime; never instantiate a local harness. For a returned run, verify task ID, request ID, runtime, and `decision="allow"` equal the request before invoking `on_run`; identity mismatch becomes an orchestration-error row. Map a normal returned timeout to `execution_timeout` and a non-zero exit to `execution_nonzero`. Explicit `runtime="local"` remains supported.

- [ ] **Step 5: Run lifecycle and e2e tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_lifecycle.py -v
python -m pytest tests/examples/test_skills_code_review_agent_e2e.py -v
```

Expected: all tests pass; auto has no local execution path and every allow request has exactly one run row.

- [ ] **Step 6: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/models.py',
  'examples/skills_code_review_agent/agent/sandbox_runner.py',
  'examples/skills_code_review_agent/agent/agent_factory.py',
  'examples/skills_code_review_agent/schema.sql',
  'examples/skills_code_review_agent/migrations/003_request_identity.sql',
  'tests/examples/test_skills_code_review_agent_lifecycle.py',
  'tests/examples/test_skills_code_review_agent_e2e.py'
)
git add @stage
git commit -m "fix(review): record and stop unavailable runtimes"
```

### Task 4: Persist lifecycle incrementally and commit truthful terminal reports

**Files:**
- Modify: `examples/skills_code_review_agent/agent/orchestrator.py:64-260`
- Modify: `examples/skills_code_review_agent/agent/report_builder.py:24-263`
- Modify: `examples/skills_code_review_agent/agent/telemetry.py:20-70`
- Modify: `examples/skills_code_review_agent/agent/storage.py:160-400`
- Modify: `examples/skills_code_review_agent/agent/models.py:165-220`
- Test: `tests/examples/test_skills_code_review_agent_lifecycle.py`

- [ ] **Step 1: Add report/status consistency tests with complete helpers**

```python
def test_filter_only_report_is_blocked_not_clean(tmp_path):
    orchestrator = _orchestrator(tmp_path)
    report = orchestrator.demo_filter(dry_run=True, runtime="container")
    rows = ReviewStorage(_db_url(tmp_path)).query_task(report.task_id)
    assert report.task_status == "blocked"
    assert rows["task"]["status"] == "blocked"
    assert report.telemetry.task_status == "blocked"
    assert report.conclusion.startswith("Review blocked")


def test_runtime_failure_is_failed_everywhere(tmp_path, monkeypatch, caplog):
    raw = "runtime-secret-987"
    monkeypatch.setattr(
        "agent.sandbox_runner.SandboxRunner._harness_for_runtime",
        lambda self, runtime: (_ for _ in ()).throw(
            RuntimeError(f"client_secret={raw}")
        ),
    )
    report = _orchestrator(tmp_path).review(
        fixture="clean",
        dry_run=True,
        runtime="container",
    )
    rows = ReviewStorage(_db_url(tmp_path)).query_task(report.task_id)
    assert report.task_status == "failed"
    assert rows["task"]["status"] == "failed"
    assert report.telemetry.task_status == "failed"
    assert len(rows["sandbox_runs"]) == 3
    assert report.section_summary["sandbox_summary"]["failures_or_timeouts"] == 3
    persisted = ReviewStorage(_db_url(tmp_path)).dump_task_text(report.task_id)
    assert raw not in persisted
    assert raw not in caplog.text


def test_partial_execution_plus_blocked_required_request_is_blocked(tmp_path):
    allow_request = _request(tmp_path, task_id="task-partial")
    denied_request = allow_request.model_copy(update={
        "request_id": "task-partial:skill-run:2",
        "command_argv": ("python3", "unapproved.py"),
    })
    policy = ReviewExecutionPolicy(dry_run=True)
    decisions = [
        policy.evaluate(allow_request, _context(allow_request)).intercept,
        policy.evaluate(denied_request, _context(denied_request)).intercept,
    ]
    status = terminal_status(
        task_id="task-partial",
        required_request_ids={
            allow_request.request_id,
            denied_request.request_id,
        },
        decisions=decisions,
        runs=[_successful_run(allow_request)],
    )
    assert status == ReviewTaskStatus.BLOCKED


@pytest.mark.parametrize(
    "case",
    ["missing_decision", "duplicate_decision", "extra_run", "run_after_deny"],
)
def test_audit_bijection_violation_is_failed(tmp_path, case):
    request = _request(tmp_path, task_id="task-audit")
    allow = ReviewExecutionPolicy(dry_run=True).evaluate(
        request,
        _context(request),
    ).intercept
    decisions = [allow]
    runs = [_successful_run(request)]
    if case == "missing_decision":
        decisions = []
    elif case == "duplicate_decision":
        decisions = [allow, allow]
    elif case == "extra_run":
        runs.append(runs[0].model_copy(update={"request_id": "unexpected"}))
    else:
        decisions = [allow.model_copy(update={"decision": "deny"})]
    assert terminal_status(
        task_id=request.task_id,
        required_request_ids={request.request_id},
        decisions=decisions,
        runs=runs,
    ) == ReviewTaskStatus.FAILED


@pytest.mark.parametrize(
    ("failure_kind", "exit_code", "timed_out", "expected"),
    [
        ("runtime_unavailable", -1, False, ReviewTaskStatus.FAILED),
        ("orchestration_error", -1, False, ReviewTaskStatus.FAILED),
        ("execution_timeout", -1, True, ReviewTaskStatus.COMPLETED_WITH_ERRORS),
        ("execution_nonzero", 2, False, ReviewTaskStatus.COMPLETED_WITH_ERRORS),
        ("artifact_invalid", 0, False, ReviewTaskStatus.COMPLETED_WITH_ERRORS),
    ],
)
def test_terminal_failure_classification(
    tmp_path,
    failure_kind,
    exit_code,
    timed_out,
    expected,
):
    request = _request(tmp_path, task_id="task-failure")
    decision = ReviewExecutionPolicy(dry_run=True).evaluate(
        request,
        _context(request),
    ).intercept
    run = _successful_run(request).model_copy(update={
        "failure_kind": failure_kind,
        "exit_code": exit_code,
        "timed_out": timed_out,
    })
    assert terminal_status(
        task_id=request.task_id,
        required_request_ids={request.request_id},
        decisions=[decision],
        runs=[run],
    ) == expected


def test_terminal_bundle_rejects_missing_persisted_run(tmp_path):
    storage = ReviewStorage(_db_url(tmp_path))
    task = ReviewTask(
        task_id="task-missing-run",
        input_type="fixture",
        runtime="container",
        dry_run=True,
    )
    storage.create_task_with_input(
        task=task,
        redacted_diff="",
        changed_files=[],
        redaction_summary=RedactionSummary(),
        input_metadata={},
    )
    running = transition_task(task, ReviewTaskStatus.RUNNING)
    storage.update_task(running)
    request = _request(tmp_path, task_id=task.task_id)
    decision = ReviewExecutionPolicy(dry_run=True).evaluate(
        request,
        _context(request),
    ).intercept
    storage.save_filter_decision(decision)
    terminal = transition_task(running, ReviewTaskStatus.COMPLETED)
    telemetry = TelemetrySummary(
        task_id=task.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
    )
    report = ReviewReport(
        task_id=task.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        conclusion="complete",
        telemetry=telemetry,
    )
    with pytest.raises(ValueError, match="persisted audit"):
        storage.save_terminal_bundle(
            task=terminal,
            required_request_ids={request.request_id},
            findings=[],
            telemetry=telemetry,
            report=report,
            json_report="{}",
            markdown_report="complete",
        )


def test_terminal_storage_failure_is_canonical_redacted_and_not_clean(
    tmp_path,
    monkeypatch,
    caplog,
):
    raw = "storage-password-987"
    orchestrator = _orchestrator(tmp_path)
    original = ReviewStorage.save_terminal_bundle

    def fail_terminal(self, **kwargs):
        raise RuntimeError(f"password={raw}")

    monkeypatch.setattr(ReviewStorage, "save_terminal_bundle", fail_terminal)
    with pytest.raises(ReviewStorageError) as caught:
        orchestrator.review(fixture="clean", dry_run=True, runtime="container")
    assert raw not in str(caught.value)

    monkeypatch.setattr(ReviewStorage, "save_terminal_bundle", original)
    task = ReviewStorage(_db_url(tmp_path)).latest_task()
    assert task.status == ReviewTaskStatus.FAILED
    assert task.failure_kind == "storage_error"
    assert raw not in task.failure_reason_redacted
    assert raw not in caplog.text
```

Define `_db_url(tmp_path)` as the SQLite URL and `_orchestrator(tmp_path)` as a `ReviewOrchestrator` using that URL and `tmp_path / "out"`. Reuse the concrete `_request`, `_context`, and `_successful_run` helpers introduced in Task 2.

- [ ] **Step 2: Use the atomic create API before running**

```python
storage.create_task_with_input(
    task=task,
    redacted_diff=redacted_diff,
    changed_files=parsed.changed_files,
    redaction_summary=boundary.summary,
    input_metadata=input_metadata,
)
task = transition_task(task, ReviewTaskStatus.RUNNING)
storage.update_task(task)
```

Only after this transaction succeeds, transition to running and call `update_task`. This gives created the exact meaning “task and input are durable.”

- [ ] **Step 3: Compute terminal status from required request IDs**

```python
from collections import Counter


def terminal_status(
    *,
    task_id: str,
    required_request_ids: set[str],
    decisions: list[FilterIntercept],
    runs: list[SandboxRun],
) -> ReviewTaskStatus:
    if not required_request_ids:
        return ReviewTaskStatus.FAILED
    if any(
        item.task_id != task_id
        or item.request_id not in required_request_ids
        or item.decision not in {"allow", "deny", "needs_human_review"}
        for item in decisions
    ):
        return ReviewTaskStatus.FAILED
    decision_counts = Counter(item.request_id for item in decisions)
    if (
        set(decision_counts) != required_request_ids
        or any(count != 1 for count in decision_counts.values())
    ):
        return ReviewTaskStatus.FAILED
    allow_ids = {
        item.request_id
        for item in decisions
        if item.decision == "allow"
    }
    non_allow_ids = {
        item.request_id
        for item in decisions
        if item.decision in {"deny", "needs_human_review"}
    }
    if any(
        item.task_id != task_id
        or item.request_id not in allow_ids
        or item.decision != "allow"
        for item in runs
    ):
        return ReviewTaskStatus.FAILED
    run_counts = Counter(item.request_id for item in runs)
    if (
        set(run_counts) != allow_ids
        or any(count != 1 for count in run_counts.values())
    ):
        return ReviewTaskStatus.FAILED
    if non_allow_ids:
        return ReviewTaskStatus.BLOCKED
    run_by_request = {item.request_id: item for item in runs}
    required_runs = [run_by_request[item] for item in sorted(allow_ids)]
    if any(
        item.failure_kind in {"runtime_unavailable", "orchestration_error"}
        for item in required_runs
    ):
        return ReviewTaskStatus.FAILED
    if any(
        item.failure_kind
        or item.exit_code != 0
        or item.timed_out
        for item in required_runs
    ):
        return ReviewTaskStatus.COMPLETED_WITH_ERRORS
    return ReviewTaskStatus.COMPLETED
```

An allow decision without exactly one run is failed, not completed. Missing/duplicate/extra decisions or runs, mismatched task identity, and any run after a non-allow decision are audit corruption and therefore failed. A legitimate mix of non-allow decisions plus exactly one run for each allow request is blocked.

- [ ] **Step 4: Make status first-class in telemetry and reports**

Add required `task_status` to `TelemetrySummary` and `ReviewReport`; set report `schema_version="2.0"`. `ReportBuilder._conclusion` checks status in this order: blocked, failed, completed_with_errors, then finding severity for completed.

Make `task_status` a required `build_telemetry` argument and count a Sandbox failure when `failure_kind` is non-empty as well as for timeout/non-zero exit. The orchestrator computes terminal status before telemetry/report construction and passes the same enum value to both.

Update both `review` and `demo_filter`. JSON, Markdown status heading, section summary, telemetry, and query output must all expose the same terminal value. Filter summaries/query rows also expose canonical `error_kind`, so `policy_denied` and `approval_required` remain distinct from Sandbox failures.

- [ ] **Step 5: Commit final state and report in one transaction**

```python
def save_terminal_bundle(
    self,
    *,
    task: ReviewTask,
    required_request_ids: set[str],
    findings: list[Finding],
    telemetry: TelemetrySummary,
    report: ReviewReport,
    json_report: str,
    markdown_report: str,
) -> None:
    if ReviewTaskStatus(task.status) not in TERMINAL_TASK_STATUSES:
        raise ValueError("terminal bundle requires a terminal task")
    with self.engine.begin() as conn:
        stored_decisions = self._load_decisions(conn, task.task_id)
        stored_runs = self._load_runs(conn, task.task_id)
        audited_status = terminal_status(
            task_id=task.task_id,
            required_request_ids=required_request_ids,
            decisions=stored_decisions,
            runs=stored_runs,
        )
        if audited_status != ReviewTaskStatus(task.status):
            raise ValueError(
                f"terminal status {task.status} disagrees with "
                f"persisted audit {audited_status.value}"
            )
        updated = conn.execute(
            review_tasks.update()
            .where(review_tasks.c.task_id == task.task_id)
            .values(**self._task_row(task))
        )
        if updated.rowcount != 1:
            raise KeyError(f"unknown review task {task.task_id}")
        if findings:
            conn.execute(findings_table.insert(), [
                self._finding_row(task.task_id, item) for item in findings
            ])
        conn.execute(telemetry_summaries.insert().values(self._telemetry_row(telemetry)))
        conn.execute(reports.insert().values(
            self._report_row(report, json_report, markdown_report)
        ))
```

`_task_row`, `_finding_row`, `_telemetry_row`, `_report_row`, `_load_decisions`, and `_load_runs` are production helpers implemented in the same task and reused by singular save/query APIs. The load helpers validate rows back into Pydantic models. Add `latest_task()` ordered by `created_at, task_id` for the failure-path test and CLI diagnostics. Remove the old separate final `save_findings/save_telemetry/save_report` orchestration calls.

If report construction fails, catch the redacted exception, transition running to failed, update the task, and re-raise; never leave a running row or write a clean conclusion.

Define `ReviewStorageError` with canonical `failure_kind="storage_error"`. Persistence methods catch SQLAlchemy/driver failures, clean them through their PR1 `RedactionBoundary`, and raise `ReviewStorageError(safe_reason) from None`; neither the raw message nor the original exception chain may reach logs. The orchestrator invokes create/update/callback/terminal persistence through one `_storage_call(operation, callable)` boundary, which passes an existing `ReviewStorageError` through and translates any other exception raised during that storage operation with the same clean-and-`from None` rule. This makes monkeypatched/adapter backends obey the same contract.

SandboxRunner must let `ReviewStorageError` from callbacks escape (it must not be relabeled `orchestration_error`). If the task row already exists, the orchestrator makes one separate best-effort update to `FAILED` with `failure_kind="storage_error"` and the already-redacted reason. A failed terminal transaction never returns or writes a clean report. If even the best-effort update fails, emit only the sanitized error and re-raise `ReviewStorageError`; do not claim a durable terminal row.

Before `create_task_with_input`, dry-run deletes an existing stable task ID through the task row and relies on tested `ON DELETE CASCADE`; non-dry runs always use a new UUID and never reset history. If non-storage terminal rendering fails, make one best-effort running-to-failed update with `failure_kind="orchestration_error"` and then re-raise the original redacted error.

- [ ] **Step 6: Run focused and full example tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_lifecycle.py -v
python -m pytest tests/examples/test_skills_code_review_agent_storage.py -v
python -m pytest tests/examples/test_skills_code_review_agent_e2e.py -v
python -m pytest tests/examples -o addopts= -q
```

Expected: task, decisions, request-specific runs, telemetry, database, JSON, Markdown, and conclusion agree.

- [ ] **Step 7: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/orchestrator.py',
  'examples/skills_code_review_agent/agent/report_builder.py',
  'examples/skills_code_review_agent/agent/telemetry.py',
  'examples/skills_code_review_agent/agent/storage.py',
  'examples/skills_code_review_agent/agent/models.py',
  'tests/examples/test_skills_code_review_agent_lifecycle.py',
  'tests/examples/test_skills_code_review_agent_storage.py',
  'tests/examples/test_skills_code_review_agent_e2e.py'
)
git add @stage
git commit -m "fix(review): commit truthful terminal reports"
```

## PR2 exit checklist

- [ ] Every legal and illegal state transition is tested; enum ownership creates no circular import.
- [ ] Legacy SQLite data migrates forward with request IDs, failure kinds, unique constraints, task indexes, and foreign keys.
- [ ] Every allow/deny/needs-human decision is saved before staging or execution.
- [ ] Every allow request has exactly one request-linked SandboxRun, including startup failure.
- [ ] Auto selects container once and never executes local after failure.
- [ ] Created task/input and terminal status/report each use one transaction.
- [ ] Partial blocked execution, missing runs, and startup failure cannot be reported as completed or clean.
- [ ] Database, telemetry, JSON, Markdown, and conclusion expose the same terminal status and failure count.
