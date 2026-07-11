# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Lifecycle state-machine tests for the skills code review agent example."""

from __future__ import annotations

import hashlib
import json
from itertools import product
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent.agent_factory import build_execution_requests
from agent.execution_request import PolicyContext
from agent.filter_policy import ReviewExecutionPolicy
from agent.input_resolver import EXAMPLE_DIR
from agent.models import DRY_RUN_TIMESTAMP
from agent.models import FilterIntercept
from agent.models import Finding
from agent.models import ParsedDiff
from agent.models import RedactionSummary
from agent.models import ReviewReport
from agent.models import ReviewTask
from agent.models import ReviewTaskStatus
from agent.models import SandboxRun
from agent.models import TelemetrySummary
from agent.models import TERMINAL_TASK_STATUSES
from agent.orchestrator import ReviewOrchestrator
from agent.orchestrator import terminal_status
from agent.redaction_boundary import RedactionBoundary
from agent.report_builder import ReportBuilder
from agent.sandbox_runner import SandboxRunner
from agent.storage import ReviewStorage
from agent.storage import ReviewStorageError
from agent.task_state import transition_task
from agent.telemetry import build_telemetry

STATUSES = list(ReviewTaskStatus)
ALLOWED = {
    (ReviewTaskStatus.CREATED, ReviewTaskStatus.RUNNING),
    (ReviewTaskStatus.RUNNING, ReviewTaskStatus.COMPLETED),
    (ReviewTaskStatus.RUNNING, ReviewTaskStatus.COMPLETED_WITH_ERRORS),
    (ReviewTaskStatus.RUNNING, ReviewTaskStatus.BLOCKED),
    (ReviewTaskStatus.RUNNING, ReviewTaskStatus.FAILED),
}


def test_telemetry_counts_attempts_execution_time_and_failure_kinds():
    finding = Finding(
        severity="high",
        category="security",
        file="app.py",
        line=1,
        title="unsafe call",
        evidence="unsafe()",
        recommendation="use safe call",
        confidence=0.9,
        source=["test"],
    )
    decisions = []
    for index, decision in enumerate(["allow", "deny", "allow", "allow", "needs_human_review"], 1):
        error_kind = {
            "allow": "",
            "deny": "policy_denied",
            "needs_human_review": "approval_required",
        }[decision]
        decisions.append(
            FilterIntercept(
                intercept_id=f"filter-{index}",
                task_id="task-1",
                request_id=f"task-1:skill-run:{index}",
                decision=decision,
                error_kind=error_kind,
                reason=decision,
                runtime="container",
                created_at=DRY_RUN_TIMESTAMP,
            ))
    runs = [
        SandboxRun(
            run_id="sandbox-1",
            task_id="task-1",
            request_id="task-1:skill-run:1",
            runtime="container",
            decision="allow",
            duration_ms=30,
            execution_started=True,
            created_at=DRY_RUN_TIMESTAMP,
        ),
        SandboxRun(
            run_id="sandbox-3",
            task_id="task-1",
            request_id="task-1:skill-run:3",
            runtime="container",
            decision="allow",
            duration_ms=20,
            failure_kind="output_limit_exceeded",
            execution_started=True,
            created_at=DRY_RUN_TIMESTAMP,
        ),
        SandboxRun(
            run_id="sandbox-4",
            task_id="task-1",
            request_id="task-1:skill-run:4",
            runtime="container",
            decision="allow",
            failure_kind="runtime_unavailable",
            execution_started=False,
            created_at=DRY_RUN_TIMESTAMP,
        ),
    ]

    telemetry = build_telemetry(
        task_id="task-1",
        task_status=ReviewTaskStatus.BLOCKED,
        task_failure_kind="",
        parsed_diff=ParsedDiff(changed_files=["a.py"], total_added_lines=2),
        findings=[finding],
        warnings=[],
        needs_human_review=[],
        filter_intercepts=decisions,
        sandbox_runs=runs,
        redaction_summary=RedactionSummary(total_redactions=2),
        debug_dropped_count=1,
        elapsed_ms=75,
        dry_run=False,
    )

    assert telemetry.orchestration_elapsed_ms == telemetry.elapsed_ms == 75
    assert telemetry.sandbox_elapsed_ms == 50
    assert telemetry.tool_attempts_count == 5
    assert telemetry.tool_executed_count == 2
    assert telemetry.exception_kind_distribution == {
        "approval_required": 1,
        "output_limit_exceeded": 1,
        "policy_denied": 1,
        "runtime_unavailable": 1,
    }
    assert telemetry.severity_distribution == {"high": 1}
    assert telemetry.output_limit_exceeded_count == 1


@pytest.mark.parametrize("field,value", [
    ("sandbox_elapsed_ms", -1),
    ("tool_attempts_count", True),
    ("severity_distribution", {"high": -1}),
    ("exception_kind_distribution", {"runtime_unavailable": False}),
])
def test_telemetry_rejects_non_integer_or_negative_counts(field, value):
    payload = {
        "task_id": "task-invalid-telemetry",
        "task_status": ReviewTaskStatus.FAILED,
        "task_failure_kind": "orchestration_error",
        field: value,
    }
    with pytest.raises(ValidationError):
        TelemetrySummary.model_validate(payload)


def test_telemetry_requires_task_failure_kind():
    with pytest.raises(ValidationError):
        TelemetrySummary.model_validate({
            "task_id": "task-missing-failure-kind",
            "task_status": ReviewTaskStatus.COMPLETED,
        })


def _request(tmp_path, *, task_id="task-1", runtime="container"):
    path = tmp_path / f"{task_id}.json"
    path.write_text("{}", encoding="utf-8")
    return build_execution_requests(task_id, runtime, str(path))[0]


def _three_valid_requests(tmp_path, *, task_id: str, runtime: str):
    path = tmp_path / f"{task_id}-review.json"
    path.write_text("{}", encoding="utf-8")
    return build_execution_requests(task_id, runtime, str(path))


def _context(request):
    return PolicyContext(
        task_id=request.task_id,
        runtime=request.runtime,
        allowed_input_sources=frozenset({request.inputs[0].src}),
    )


def _runner(harness=None):
    runner = SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        boundary=RedactionBoundary(),
    )
    if harness is not None:
        runner._harness_for_runtime = lambda runtime: harness
    return runner


def _db_url(tmp_path):
    return f"sqlite:///{tmp_path / 'review.db'}"


def _orchestrator(tmp_path):
    return ReviewOrchestrator(
        db_url=_db_url(tmp_path),
        output_dir=tmp_path / "out",
    )


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


def _running_task_with_three_requests(tmp_path):
    task = ReviewTask(
        task_id="task-three-decisions",
        input_type="fixture",
        runtime="container",
        dry_run=True,
    )
    input_path = tmp_path / "review_input.json"
    input_path.write_text("{}", encoding="utf-8")
    requests = build_execution_requests(task.task_id, task.runtime, str(input_path))
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    storage.create_task_with_input(
        task=task,
        redacted_diff="",
        changed_files=[],
        redaction_summary=RedactionSummary(),
        input_metadata={},
    )
    running = transition_task(task, ReviewTaskStatus.RUNNING)
    storage.update_task(running)
    return storage, running, requests


def _persisted_single_request_audit(tmp_path, *, task_id: str, run_updates=None):
    storage = ReviewStorage(_db_url(tmp_path))
    task = ReviewTask(
        task_id=task_id,
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
    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context(request)).intercept
    run = _successful_run(request)
    if run_updates:
        run = run.model_copy(update=run_updates)
    storage.save_filter_decision(decision)
    storage.save_sandbox_run(run)
    return storage, running, request, decision, run


def test_task_statuses_and_terminal_set_are_complete():
    actual = {status.value for status in ReviewTaskStatus}

    assert actual == {
        "created",
        "running",
        "completed",
        "completed_with_errors",
        "blocked",
        "failed",
    }
    assert TERMINAL_TASK_STATUSES == frozenset({
        ReviewTaskStatus.COMPLETED,
        ReviewTaskStatus.COMPLETED_WITH_ERRORS,
        ReviewTaskStatus.BLOCKED,
        ReviewTaskStatus.FAILED,
    })


@pytest.mark.parametrize(("source", "target"), list(product(STATUSES, STATUSES)))
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


@pytest.mark.parametrize(
    "status",
    [status for status in ReviewTaskStatus if status is not ReviewTaskStatus.FAILED],
)
def test_failure_details_are_rejected_outside_failed_status(status):
    with pytest.raises(ValueError, match="failure details require failed task status"):
        ReviewTask(
            task_id="task-1",
            input_type="fixture",
            status=status,
            failure_kind="storage_error",
            failure_reason_redacted="redacted persistence failure",
        )


def test_failed_status_accepts_redacted_failure_details():
    task = ReviewTask(
        task_id="task-1",
        input_type="fixture",
        status=ReviewTaskStatus.FAILED,
        failure_kind="storage_error",
        failure_reason_redacted="redacted persistence failure",
    )

    assert task.failure_kind == "storage_error"
    assert task.failure_reason_redacted == "redacted persistence failure"


def test_sandbox_request_identity_is_required():
    with pytest.raises(ValidationError):
        SandboxRun(run_id="run-1", task_id="task-1", runtime="container")


def test_build_execution_requests_normalizes_auto_to_container(tmp_path):
    requests = _three_valid_requests(
        tmp_path,
        task_id="task-auto-requests",
        runtime="auto",
    )

    assert len(requests) == 3
    assert {item.runtime for item in requests} == {"container"}


def test_auto_runtime_records_each_request_when_container_start_fails(tmp_path):
    created = []
    raw = "runtime-construction-secret-987"

    def fail_factory(runtime):
        created.append(runtime)
        raise RuntimeError(f"client_secret={raw}")

    requests = _three_valid_requests(
        tmp_path,
        task_id="task-auto-runtime",
        runtime="container",
    )
    saved = []
    runner = _runner()
    runner._harness_for_runtime = fail_factory

    result = runner.run(
        task_id="task-auto-runtime",
        review_input={"task_id": "task-auto-runtime"},
        runtime="auto",
        dry_run=True,
        requests=requests,
        policy_context=_context(requests[0]),
        on_run=saved.append,
    )

    assert created == ["container"]
    assert result.effective_runtime == "container"
    assert len(result.runs) == len(saved) == 3
    assert saved == result.runs
    assert [item.request_id for item in result.runs] == [item.request_id for item in requests]
    assert {item.failure_kind for item in result.runs} == {"runtime_unavailable"}
    assert all(item.runtime == "container" for item in result.runs)
    assert all(item.decision == "allow" and item.exit_code == -1 for item in result.runs)
    assert [item.command for item in result.runs] == [list(item.command_argv) for item in requests]
    assert [item.run_id for item in result.runs] == [
        "sandbox_" + hashlib.sha256(f"{item.task_id}:{item.request_id}".encode("utf-8")).hexdigest()[:24]
        for item in requests
    ]
    assert raw not in json.dumps([item.model_dump(mode="json") for item in result.runs], sort_keys=True)


def test_successful_local_runs_keep_request_identity(tmp_path):
    requests = _three_valid_requests(
        tmp_path,
        task_id="task-local-identity",
        runtime="local",
    )

    result = _runner().run(
        task_id="task-local-identity",
        review_input={"task_id": "task-local-identity"},
        runtime="local",
        dry_run=True,
        requests=requests,
        policy_context=_context(requests[0]),
    )

    assert [item.request_id for item in result.runs] == [item.request_id for item in requests]
    assert [item.command for item in result.runs] == [list(item.command_argv) for item in requests]
    assert {item.runtime for item in result.runs} == {"local"}


def test_filter_only_report_is_blocked_not_clean(tmp_path):
    orchestrator = _orchestrator(tmp_path)

    report = orchestrator.demo_filter(dry_run=True, runtime="container")
    rows = ReviewStorage(_db_url(tmp_path)).query_task(report.task_id)

    assert report.task_status == "blocked"
    assert rows["task"]["status"] == "blocked"
    assert report.telemetry.task_status == "blocked"
    assert report.section_summary["task_status"] == "blocked"
    assert report.conclusion.startswith("Review blocked")
    persisted_report = json.loads(rows["reports"][0]["json_report"])
    persisted_telemetry = json.loads(rows["telemetry_summaries"][0]["metrics_json"])
    persisted_summary = json.loads(rows["reports"][0]["summary_json"])
    markdown = (tmp_path / "out" / "filter_blocked_report.md").read_text(encoding="utf-8")
    assert persisted_report["task_status"] == "blocked"
    assert persisted_report["section_summary"]["task_status"] == "blocked"
    assert persisted_telemetry["task_status"] == "blocked"
    assert persisted_summary["task_status"] == "blocked"
    assert rows["filter_intercepts"][0]["error_kind"] == "policy_denied"
    assert report.section_summary["filter_summary"]["error_kinds"] == {"policy_denied": 1}
    assert "- Status: `blocked`" in markdown
    assert "deny (policy_denied)" in markdown


def test_runtime_failure_is_failed_everywhere(tmp_path, monkeypatch, caplog):
    raw = "runtime-secret-987"
    monkeypatch.setattr(
        "agent.sandbox_runner.SandboxRunner._harness_for_runtime",
        lambda self, runtime: (_ for _ in ()).throw(RuntimeError(f"client_secret={raw}")),
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
        required_request_ids={allow_request.request_id, denied_request.request_id},
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
    allow = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context(request)).intercept
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
def test_terminal_failure_classification(tmp_path, failure_kind, exit_code, timed_out, expected):
    request = _request(tmp_path, task_id="task-failure")
    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context(request)).intercept
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
    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context(request)).intercept
    storage.save_filter_decision(decision)
    terminal = transition_task(running, ReviewTaskStatus.COMPLETED)
    telemetry = TelemetrySummary(
        task_id=task.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        task_failure_kind="",
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


def test_terminal_bundle_rolls_back_when_final_report_insert_fails(tmp_path):
    raw = "terminal-report-storage-secret-987"
    storage = ReviewStorage(_db_url(tmp_path))
    task = ReviewTask(
        task_id="task-terminal-rollback",
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
    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context(request)).intercept
    run = _successful_run(request)
    storage.save_filter_decision(decision)
    storage.save_sandbox_run(run)
    terminal = transition_task(running, ReviewTaskStatus.COMPLETED)
    finding = Finding(
        severity="high",
        category="security",
        file="app.py",
        line=1,
        title="terminal rollback",
        evidence="safe evidence",
        recommendation="fix it",
        confidence=1.0,
    )
    telemetry = TelemetrySummary(
        task_id=task.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        task_failure_kind="",
        sandbox_runs_count=1,
        findings_count=1,
        tool_attempts_count=1,
        tool_executed_count=0,
        severity_distribution={"high": 1},
    )
    builder = ReportBuilder(tmp_path / "out", _db_url(tmp_path))
    report = builder.build(
        task_id=task.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        findings=[finding],
        warnings=[],
        needs_human_review=[],
        filter_intercepts=[decision],
        sandbox_runs=[run],
        telemetry=telemetry,
        redaction_summary=RedactionSummary(),
        input_summary={"input_type": "fixture"},
    )
    json_report, markdown_report, report = builder.render(report)
    with storage.engine.begin() as conn:
        conn.exec_driver_sql("CREATE TRIGGER fail_terminal_report BEFORE INSERT ON reports "
                             f"BEGIN SELECT RAISE(FAIL, 'password={raw}'); END")

    with pytest.raises(ReviewStorageError) as caught:
        storage.save_terminal_bundle(
            task=terminal,
            required_request_ids={request.request_id},
            findings=[finding],
            telemetry=report.telemetry,
            report=report,
            json_report=json_report,
            markdown_report=markdown_report,
        )

    rows = storage.query_task(task.task_id)
    assert rows["task"]["status"] == ReviewTaskStatus.RUNNING.value
    assert len(rows["filter_intercepts"]) == 1
    assert len(rows["sandbox_runs"]) == 1
    assert rows["findings"] == []
    assert rows["telemetry_summaries"] == []
    assert rows["reports"] == []
    assert caught.value.failure_kind == "storage_error"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert raw not in str(caught.value)


def test_terminal_bundle_rejects_cross_task_products_before_writing(tmp_path):
    storage = ReviewStorage(_db_url(tmp_path))
    task = ReviewTask(
        task_id="task-terminal-owner",
        input_type="fixture",
        runtime="container",
        dry_run=True,
    )
    other = task.model_copy(update={"task_id": "task-terminal-other"})
    for item in (task, other):
        storage.create_task_with_input(
            task=item,
            redacted_diff="",
            changed_files=[],
            redaction_summary=RedactionSummary(),
            input_metadata={},
        )
    running = transition_task(task, ReviewTaskStatus.RUNNING)
    storage.update_task(running)
    request = _request(tmp_path, task_id=task.task_id)
    decision = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context(request)).intercept
    storage.save_filter_decision(decision)
    storage.save_sandbox_run(_successful_run(request))
    terminal = transition_task(running, ReviewTaskStatus.COMPLETED)
    telemetry = TelemetrySummary(
        task_id=other.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        task_failure_kind="",
    )
    report = ReviewReport(
        task_id=other.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        conclusion="wrong owner",
        telemetry=telemetry,
    )

    with pytest.raises(ValueError, match="task identity"):
        storage.save_terminal_bundle(
            task=terminal,
            required_request_ids={request.request_id},
            findings=[],
            telemetry=telemetry,
            report=report,
            json_report="{}",
            markdown_report="wrong owner",
        )

    owner_rows = storage.query_task(task.task_id)
    other_rows = storage.query_task(other.task_id)
    assert owner_rows["task"]["status"] == ReviewTaskStatus.RUNNING.value
    assert owner_rows["telemetry_summaries"] == owner_rows["reports"] == []
    assert other_rows["telemetry_summaries"] == other_rows["reports"] == []


@pytest.mark.parametrize("mismatch", ["empty", "nested_cross_task"])
def test_terminal_bundle_rejects_report_audit_that_differs_from_persisted_rows(tmp_path, mismatch):
    storage, running, request, decision, run = _persisted_single_request_audit(
        tmp_path,
        task_id="task-report-audit",
    )
    terminal = transition_task(running, ReviewTaskStatus.COMPLETED)
    telemetry = TelemetrySummary(
        task_id=running.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        task_failure_kind="",
        sandbox_runs_count=1,
    )
    report_decisions = [decision]
    report_runs = [run]
    if mismatch == "empty":
        report_decisions = []
        report_runs = []
    else:
        report_decisions = [decision.model_copy(update={"task_id": "nested-other-task"})]
        report_runs = [run.model_copy(update={"task_id": "nested-other-task"})]
    report = ReviewReport(
        task_id=running.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        conclusion="mismatched audit",
        filter_intercepts=report_decisions,
        sandbox_runs=report_runs,
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
            markdown_report="mismatched audit",
        )

    rows = storage.query_task(running.task_id)
    assert rows["task"]["status"] == ReviewTaskStatus.RUNNING.value
    assert len(rows["filter_intercepts"]) == len(rows["sandbox_runs"]) == 1
    assert rows["telemetry_summaries"] == rows["reports"] == []


def test_terminal_bundle_rejects_wrong_audit_failure_count(tmp_path):
    storage, running, request, decision, run = _persisted_single_request_audit(
        tmp_path,
        task_id="task-wrong-failure-count",
        run_updates={"failure_kind": "artifact_invalid"},
    )
    terminal = transition_task(running, ReviewTaskStatus.COMPLETED_WITH_ERRORS)
    telemetry = TelemetrySummary(
        task_id=running.task_id,
        task_status=ReviewTaskStatus.COMPLETED_WITH_ERRORS,
        task_failure_kind="",
        sandbox_runs_count=1,
        sandbox_failures_count=0,
    )
    report = ReviewReport(
        task_id=running.task_id,
        task_status=ReviewTaskStatus.COMPLETED_WITH_ERRORS,
        conclusion="wrong failure count",
        filter_intercepts=[decision],
        sandbox_runs=[run],
        telemetry=telemetry,
    )

    with pytest.raises(ValueError, match="telemetry.*persisted audit"):
        storage.save_terminal_bundle(
            task=terminal,
            required_request_ids={request.request_id},
            findings=[],
            telemetry=telemetry,
            report=report,
            json_report="{}",
            markdown_report="wrong failure count",
        )

    rows = storage.query_task(running.task_id)
    assert rows["task"]["status"] == ReviewTaskStatus.RUNNING.value
    assert rows["telemetry_summaries"] == rows["reports"] == []


@pytest.mark.parametrize("field,value", [
    ("sandbox_elapsed_ms", 1),
    ("tool_attempts_count", 2),
    ("tool_executed_count", 1),
    ("severity_distribution", {"high": 1}),
    ("exception_kind_distribution", {"orchestration_error": 1}),
    ("output_limit_exceeded_count", 1),
    ("task_failure_kind", "orchestration_error"),
])
def test_terminal_bundle_rejects_tampered_derived_telemetry(tmp_path, field, value):
    storage, running, request, decision, run = _persisted_single_request_audit(
        tmp_path,
        task_id=f"task-tampered-telemetry-{field}",
    )
    terminal = transition_task(running, ReviewTaskStatus.COMPLETED)
    telemetry = TelemetrySummary(
        task_id=running.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        task_failure_kind="",
        sandbox_runs_count=1,
        tool_attempts_count=1,
    ).model_copy(update={field: value})
    report = ReviewReport(
        task_id=running.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        conclusion="tampered telemetry",
        filter_intercepts=[decision],
        sandbox_runs=[run],
        telemetry=telemetry,
    )

    with pytest.raises(ValueError, match="telemetry.*persisted audit|failure kind"):
        storage.save_terminal_bundle(
            task=terminal,
            required_request_ids={request.request_id},
            findings=[],
            telemetry=telemetry,
            report=report,
            json_report="{}",
            markdown_report="tampered telemetry",
        )


def test_terminal_bundle_rejects_report_telemetry_or_finding_count_mismatch(tmp_path):
    storage, running, request, decision, run = _persisted_single_request_audit(
        tmp_path,
        task_id="task-wrong-report-products",
    )
    terminal = transition_task(running, ReviewTaskStatus.COMPLETED)
    finding = Finding(
        severity="high",
        category="security",
        file="app.py",
        line=1,
        title="counted finding",
        evidence="safe evidence",
        recommendation="fix it",
        confidence=1.0,
    )
    telemetry = TelemetrySummary(
        task_id=running.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        task_failure_kind="",
        sandbox_runs_count=1,
        findings_count=0,
    )
    report = ReviewReport(
        task_id=running.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        conclusion="wrong products",
        findings=[finding],
        filter_intercepts=[decision],
        sandbox_runs=[run],
        telemetry=telemetry.model_copy(update={
            "elapsed_ms": 1,
            "orchestration_elapsed_ms": 1
        }),
    )

    with pytest.raises(ValueError, match="telemetry|finding"):
        storage.save_terminal_bundle(
            task=terminal,
            required_request_ids={request.request_id},
            findings=[finding],
            telemetry=telemetry,
            report=report,
            json_report="{}",
            markdown_report="wrong products",
        )

    rows = storage.query_task(running.task_id)
    assert rows["task"]["status"] == ReviewTaskStatus.RUNNING.value
    assert rows["findings"] == rows["telemetry_summaries"] == rows["reports"] == []


@pytest.mark.parametrize("tamper", ["json_status", "markdown_status", "markdown_conclusion"])
def test_terminal_bundle_rejects_tampered_persisted_report_text(tmp_path, tamper):
    storage, running, request, decision, run = _persisted_single_request_audit(
        tmp_path,
        task_id="task-tampered-report-text",
    )
    terminal = transition_task(running, ReviewTaskStatus.COMPLETED)
    telemetry = TelemetrySummary(
        task_id=running.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        task_failure_kind="",
        sandbox_runs_count=1,
        tool_attempts_count=1,
        tool_executed_count=0,
    )
    report = ReviewReport(
        task_id=running.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        conclusion="complete",
        filter_intercepts=[decision],
        sandbox_runs=[run],
        telemetry=telemetry,
    )
    json_text, markdown_text, canonical_report = ReportBuilder(
        tmp_path / "out",
        _db_url(tmp_path),
    ).render(report)
    if tamper == "json_status":
        payload = json.loads(json_text)
        payload["task_status"] = ReviewTaskStatus.FAILED.value
        json_text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    elif tamper == "markdown_status":
        markdown_text = markdown_text.replace("- Status: `completed`", "- Status: `failed`")
    else:
        markdown_text = markdown_text.replace("- Conclusion: complete", "- Conclusion: failed")

    with pytest.raises(ValueError, match="terminal .* report"):
        storage.save_terminal_bundle(
            task=terminal,
            required_request_ids={request.request_id},
            findings=[],
            telemetry=canonical_report.telemetry,
            report=canonical_report,
            json_report=json_text,
            markdown_report=markdown_text,
        )

    rows = storage.query_task(running.task_id)
    assert rows["task"]["status"] == ReviewTaskStatus.RUNNING.value
    assert len(rows["filter_intercepts"]) == len(rows["sandbox_runs"]) == 1
    assert rows["findings"] == rows["telemetry_summaries"] == rows["reports"] == []


@pytest.mark.parametrize("tamper", ["section_summary", "derived_review_fields"])
def test_terminal_bundle_rejects_self_consistent_report_with_tampered_derived_fields(tmp_path, tamper):
    storage, running, request, decision, run = _persisted_single_request_audit(
        tmp_path,
        task_id="task-tampered-derived-report",
    )
    terminal = transition_task(running, ReviewTaskStatus.COMPLETED)
    finding = Finding(
        severity="high",
        category="security",
        file="app.py",
        line=7,
        title="canonical issue",
        evidence="safe evidence",
        recommendation="apply canonical fix",
        confidence=1.0,
    )
    telemetry = TelemetrySummary(
        task_id=running.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        task_failure_kind="",
        sandbox_runs_count=1,
        findings_count=1,
        tool_attempts_count=1,
        tool_executed_count=0,
        severity_distribution={"high": 1},
    )
    builder = ReportBuilder(tmp_path / "out", _db_url(tmp_path))
    report = builder.build(
        task_id=running.task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        findings=[finding],
        warnings=[],
        needs_human_review=[],
        filter_intercepts=[decision],
        sandbox_runs=[run],
        telemetry=telemetry,
        redaction_summary=RedactionSummary(),
        input_summary={"input_type": "fixture"},
    )
    if tamper == "section_summary":
        section_summary = report.section_summary.copy()
        section_summary["task_status"] = ReviewTaskStatus.FAILED.value
        section_summary["sandbox_summary"] = {
            **section_summary["sandbox_summary"],
            "runs": 0,
            "failures_or_timeouts": 99,
        }
        report = report.model_copy(update={"section_summary": section_summary})
    else:
        report = report.model_copy(
            update={
                "conclusion": "Everything is clean.",
                "severity_distribution": {
                    "low": 99
                },
                "recommendations": ["Ship the tampered report."],
            })
    json_report, markdown_report, report = builder.render(report)

    with pytest.raises(ValueError, match="terminal report does not match canonical report"):
        storage.save_terminal_bundle(
            task=terminal,
            required_request_ids={request.request_id},
            findings=[finding],
            telemetry=report.telemetry,
            report=report,
            json_report=json_report,
            markdown_report=markdown_report,
        )

    rows = storage.query_task(running.task_id)
    assert rows["task"]["status"] == ReviewTaskStatus.RUNNING.value
    assert len(rows["filter_intercepts"]) == len(rows["sandbox_runs"]) == 1
    assert rows["findings"] == rows["telemetry_summaries"] == rows["reports"] == []


def test_terminal_storage_failure_is_canonical_redacted_and_not_clean(tmp_path, monkeypatch, caplog):
    raw = "storage-password-987"
    orchestrator = _orchestrator(tmp_path)
    original = ReviewStorage.save_terminal_bundle

    def fail_terminal(self, **kwargs):
        raise RuntimeError(f"password={raw}")

    monkeypatch.setattr(ReviewStorage, "save_terminal_bundle", fail_terminal)
    with pytest.raises(ReviewStorageError) as caught:
        orchestrator.review(fixture="clean", dry_run=True, runtime="container")
    assert raw not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None

    monkeypatch.setattr(ReviewStorage, "save_terminal_bundle", original)
    task = ReviewStorage(_db_url(tmp_path)).latest_task()
    assert task.status == ReviewTaskStatus.FAILED
    assert task.failure_kind == "storage_error"
    assert raw not in task.failure_reason_redacted
    assert raw not in caplog.text


def test_repeated_dry_run_storage_failure_removes_previous_clean_report(tmp_path, monkeypatch, caplog):
    raw = "repeated-storage-secret-987"
    orchestrator = _orchestrator(tmp_path)
    first = orchestrator.review(fixture="clean", dry_run=True, runtime="local")
    output_dir = tmp_path / "out"
    json_path = output_dir / "review_report.json"
    markdown_path = output_dir / "review_report.md"
    assert first.task_status == ReviewTaskStatus.COMPLETED
    assert json_path.is_file()
    assert markdown_path.is_file()

    monkeypatch.setattr(
        ReviewStorage,
        "save_terminal_bundle",
        lambda self, **kwargs: (_ for _ in ()).throw(RuntimeError(f"password={raw}")),
    )

    with pytest.raises(ReviewStorageError) as caught:
        orchestrator.review(fixture="clean", dry_run=True, runtime="local")

    storage = ReviewStorage(_db_url(tmp_path))
    task = storage.latest_task()
    rows = storage.query_task(task.task_id)
    assert task.task_id == first.task_id
    assert task.status == ReviewTaskStatus.FAILED
    assert task.failure_kind == "storage_error"
    assert rows["reports"] == []
    assert rows["telemetry_summaries"] == []
    assert not json_path.exists()
    assert not markdown_path.exists()
    assert raw not in str(caught.value)
    assert raw not in storage.dump_task_text(task.task_id)
    assert raw not in caplog.text


def test_repeated_demo_filter_failure_removes_only_its_previous_report(tmp_path, monkeypatch):
    orchestrator = _orchestrator(tmp_path)
    review = orchestrator.review(fixture="clean", dry_run=True, runtime="local")
    review_json = tmp_path / "out" / "review_report.json"
    review_markdown = tmp_path / "out" / "review_report.md"
    previous_review_json = review_json.read_text(encoding="utf-8")
    previous_review_markdown = review_markdown.read_text(encoding="utf-8")
    first = orchestrator.demo_filter(dry_run=True, runtime="local")
    filter_json = tmp_path / "out" / "filter_blocked_report.json"
    filter_markdown = tmp_path / "out" / "filter_blocked_report.md"
    assert review.task_id != first.task_id
    assert filter_json.is_file()
    assert filter_markdown.is_file()

    monkeypatch.setattr(
        ReviewStorage,
        "save_terminal_bundle",
        lambda self, **kwargs: (_ for _ in ()).throw(RuntimeError("demo terminal persistence unavailable")),
    )

    with pytest.raises(ReviewStorageError):
        orchestrator.demo_filter(dry_run=True, runtime="local")

    rows = ReviewStorage(_db_url(tmp_path)).query_task(first.task_id)
    assert rows["task"]["status"] == ReviewTaskStatus.FAILED.value
    assert rows["reports"] == rows["telemetry_summaries"] == []
    assert not filter_json.exists()
    assert not filter_markdown.exists()
    assert review_json.read_text(encoding="utf-8") == previous_review_json
    assert review_markdown.read_text(encoding="utf-8") == previous_review_markdown


def test_dry_run_report_cleanup_failure_is_redacted_and_marks_task_failed(tmp_path, monkeypatch, caplog):
    raw = "cleanup-password-secret-987"
    orchestrator = _orchestrator(tmp_path)
    first = orchestrator.review(fixture="clean", dry_run=True, runtime="local")
    json_path = tmp_path / "out" / "review_report.json"
    markdown_path = tmp_path / "out" / "review_report.md"
    unrelated = tmp_path / "out" / "filter_blocked_report.json"
    unrelated.write_text('{"task_id": "unrelated"}\n', encoding="utf-8")
    original_unlink = Path.unlink

    def fail_json_cleanup(self, *args, **kwargs):
        if self == json_path:
            raise OSError(f"password={raw}")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_json_cleanup)

    with pytest.raises(OSError) as caught:
        orchestrator.review(fixture="clean", dry_run=True, runtime="local")

    storage = ReviewStorage(_db_url(tmp_path))
    rows = storage.query_task(first.task_id)
    assert rows["task"]["status"] == ReviewTaskStatus.FAILED.value
    assert rows["task"]["failure_kind"] == "orchestration_error"
    assert rows["reports"] == rows["telemetry_summaries"] == []
    assert json_path.exists()
    assert not markdown_path.exists()
    assert unrelated.exists()
    assert raw not in str(caught.value)
    assert raw not in storage.dump_task_text(first.task_id)
    assert raw not in caplog.text


def test_dry_run_prepublication_failure_preserves_fixed_report_owned_by_different_task(tmp_path, monkeypatch):
    orchestrator = _orchestrator(tmp_path)
    first = orchestrator.review(fixture="clean", dry_run=False, runtime="local")
    output_dir = tmp_path / "out"
    json_path = output_dir / "review_report.json"
    markdown_path = output_dir / "review_report.md"
    previous_json = (output_dir / f"review_report_{first.task_id}.json").read_text(encoding="utf-8")
    previous_markdown = (output_dir / f"review_report_{first.task_id}.md").read_text(encoding="utf-8")
    json_path.write_text(previous_json, encoding="utf-8")
    markdown_path.write_text(previous_markdown, encoding="utf-8")
    monkeypatch.setattr(
        "agent.orchestrator.prepare_execution_plan",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("execution plan unavailable")),
    )

    with pytest.raises(RuntimeError, match="execution plan unavailable"):
        orchestrator.review(fixture="clean", dry_run=True, runtime="local")

    assert json_path.read_text(encoding="utf-8") == previous_json
    assert markdown_path.read_text(encoding="utf-8") == previous_markdown


def test_report_build_failure_marks_task_failed_and_writes_no_clean_output(tmp_path, monkeypatch, caplog):
    raw = "report-build-secret-987"

    def fail_build(self, **kwargs):
        raise RuntimeError(f"client_secret={raw}")

    monkeypatch.setattr("agent.report_builder.ReportBuilder.build", fail_build)

    with pytest.raises(RuntimeError) as caught:
        _orchestrator(tmp_path).review(fixture="clean", dry_run=True, runtime="container")

    storage = ReviewStorage(_db_url(tmp_path))
    task = storage.latest_task()
    rows = storage.query_task(task.task_id)
    assert task.status == ReviewTaskStatus.FAILED
    assert task.failure_kind == "orchestration_error"
    assert rows["reports"] == []
    assert rows["telemetry_summaries"] == []
    assert not (tmp_path / "out" / "review_report.json").exists()
    assert not (tmp_path / "out" / "review_report.md").exists()
    assert raw not in str(caught.value)
    assert raw not in storage.dump_task_text(task.task_id)
    assert raw not in caplog.text


def test_execution_plan_failure_marks_running_task_failed(tmp_path, monkeypatch, caplog):
    raw = "execution-plan-secret-987"
    monkeypatch.setattr(
        "agent.orchestrator.prepare_execution_plan",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError(f"client_secret={raw}")),
    )

    with pytest.raises(RuntimeError) as caught:
        _orchestrator(tmp_path).review(fixture="clean", dry_run=True, runtime="container")

    storage = ReviewStorage(_db_url(tmp_path))
    task = storage.latest_task()
    rows = storage.query_task(task.task_id)
    assert task.status == ReviewTaskStatus.FAILED
    assert task.failure_kind == "orchestration_error"
    assert rows["filter_intercepts"] == []
    assert rows["sandbox_runs"] == []
    assert rows["telemetry_summaries"] == []
    assert rows["reports"] == []
    assert raw not in str(caught.value)
    assert raw not in storage.dump_task_text(task.task_id)
    assert raw not in caplog.text


def test_second_report_promotion_failure_restores_files_and_compensates_database(tmp_path, monkeypatch, caplog):
    raw = "second-promote-secret-987"
    orchestrator = _orchestrator(tmp_path)
    output_dir = tmp_path / "out"
    json_path = output_dir / "review_report.json"
    markdown_path = output_dir / "review_report.md"
    first = orchestrator.review(fixture="clean", dry_run=True, runtime="local")
    assert first.task_status == ReviewTaskStatus.COMPLETED
    assert json_path.is_file()
    assert markdown_path.is_file()
    original_replace = Path.replace

    def fail_second_promotion(self, target):
        target = Path(target)
        if self.name.startswith(".review_report.md.") and self.name.endswith(".tmp"):
            raise OSError(f"password={raw}")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_second_promotion)

    with pytest.raises(OSError) as caught:
        orchestrator.review(fixture="clean", dry_run=True, runtime="local")

    storage = ReviewStorage(_db_url(tmp_path))
    task = storage.latest_task()
    rows = storage.query_task(task.task_id)
    assert task.status == ReviewTaskStatus.FAILED
    assert task.failure_kind == "orchestration_error"
    assert rows["reports"] == []
    assert rows["telemetry_summaries"] == []
    assert rows["findings"] == []
    assert task.task_id == first.task_id
    assert not json_path.exists()
    assert not markdown_path.exists()
    assert raw not in str(caught.value)
    assert raw not in storage.dump_task_text(task.task_id)
    assert raw not in caplog.text


def test_report_commit_restores_prior_files_when_second_backup_fails(tmp_path, monkeypatch):
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    json_path = output_dir / "review_report.json"
    markdown_path = output_dir / "review_report.md"
    json_path.write_text("previous-json\n", encoding="utf-8")
    markdown_path.write_text("previous-markdown\n", encoding="utf-8")
    original_replace = Path.replace

    def fail_markdown_backup(self, target):
        target = Path(target)
        if self == markdown_path and target.name.endswith(".bak"):
            raise OSError("backup promotion failed")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_markdown_backup)

    with pytest.raises(OSError, match="backup promotion failed"):
        ReportBuilder(output_dir, _db_url(tmp_path)).commit("new-json", "new-markdown")

    assert json_path.read_text(encoding="utf-8") == "previous-json\n"
    assert markdown_path.read_text(encoding="utf-8") == "previous-markdown\n"


def test_report_commit_keeps_new_files_when_backup_cleanup_fails(tmp_path, monkeypatch):
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    json_path = output_dir / "review_report.json"
    markdown_path = output_dir / "review_report.md"
    json_path.write_text("previous-json\n", encoding="utf-8")
    markdown_path.write_text("previous-markdown\n", encoding="utf-8")
    original_unlink = Path.unlink

    def fail_backup_cleanup(self, *args, **kwargs):
        if self.name.endswith(".bak"):
            raise OSError("backup cleanup failed")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_backup_cleanup)

    ReportBuilder(output_dir, _db_url(tmp_path)).commit("new-json", "new-markdown")

    assert json_path.read_text(encoding="utf-8") == "new-json\n"
    assert markdown_path.read_text(encoding="utf-8") == "new-markdown"


def test_report_commit_surfaces_incomplete_rollback_with_fixed_safe_error(tmp_path, monkeypatch):
    raw_promotion = "promotion-password-secret-987"
    raw_rollback = "rollback-token-secret-987"
    output_dir = tmp_path / "out"
    json_path = output_dir / "review_report.json"
    original_replace = Path.replace
    original_unlink = Path.unlink

    def fail_markdown_promotion(self, target):
        if self.name.startswith(".review_report.md.") and self.name.endswith(".tmp"):
            raise OSError(f"password={raw_promotion}")
        return original_replace(self, target)

    def fail_published_json_unlink(self, *args, **kwargs):
        if self == json_path:
            raise OSError(f"token={raw_rollback}")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "replace", fail_markdown_promotion)
    monkeypatch.setattr(Path, "unlink", fail_published_json_unlink)

    with pytest.raises(RuntimeError, match="report publication rollback was incomplete") as caught:
        ReportBuilder(output_dir, _db_url(tmp_path)).commit("new-json", "new-markdown")

    assert raw_promotion not in str(caught.value)
    assert raw_rollback not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert json_path.exists()


@pytest.mark.parametrize("cleanup_method", ["discard", "quarantine"])
def test_report_cleanup_validates_json_and_markdown_ownership_independently(tmp_path, cleanup_method):
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    json_path = output_dir / "review_report.json"
    markdown_path = output_dir / "review_report.md"
    json_path.write_text('{"task_id": "task-current"}\n', encoding="utf-8")
    markdown_path.write_text("# Report\n\n- Task ID: `task-other`\n", encoding="utf-8")
    builder = ReportBuilder(output_dir, _db_url(tmp_path))

    getattr(builder, cleanup_method)(task_id="task-current")

    assert not json_path.exists()
    assert markdown_path.read_text(encoding="utf-8") == "# Report\n\n- Task ID: `task-other`\n"


def test_publication_rollback_cleanup_uses_quarantine_before_marking_failed(tmp_path, monkeypatch, caplog):
    raw_promotion = "publication-password-secret-987"
    raw_unlink = "publication-unlink-secret-987"
    output_dir = tmp_path / "out"
    json_path = output_dir / "review_report.json"
    markdown_path = output_dir / "review_report.md"
    original_replace = Path.replace
    original_unlink = Path.unlink

    def fail_markdown_promotion(self, target):
        if self.name.startswith(".review_report.md.") and self.name.endswith(".tmp"):
            raise OSError(f"password={raw_promotion}")
        return original_replace(self, target)

    def fail_public_json_unlink(self, *args, **kwargs):
        if self == json_path:
            raise OSError(f"token={raw_unlink}")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "replace", fail_markdown_promotion)
    monkeypatch.setattr(Path, "unlink", fail_public_json_unlink)

    with pytest.raises(RuntimeError, match="report publication rollback was incomplete") as caught:
        _orchestrator(tmp_path).review(fixture="clean", dry_run=True, runtime="local")

    storage = ReviewStorage(_db_url(tmp_path))
    task = storage.latest_task()
    rows = storage.query_task(task.task_id)
    assert task.status == ReviewTaskStatus.FAILED
    assert task.failure_kind == "orchestration_error"
    assert rows["reports"] == rows["telemetry_summaries"] == []
    assert not json_path.exists()
    assert not markdown_path.exists()
    assert raw_promotion not in str(caught.value)
    assert raw_unlink not in str(caught.value)
    assert raw_promotion not in caplog.text
    assert raw_unlink not in caplog.text


def test_publication_and_all_cleanup_failures_leave_task_running(tmp_path, monkeypatch, caplog):
    raw_promotion = "all-publication-password-secret-987"
    raw_unlink = "all-publication-unlink-secret-987"
    raw_quarantine = "all-publication-quarantine-secret-987"
    output_dir = tmp_path / "out"
    json_path = output_dir / "review_report.json"
    markdown_path = output_dir / "review_report.md"
    original_replace = Path.replace
    original_unlink = Path.unlink

    def fail_publication_and_quarantine(self, target):
        target = Path(target)
        if self.name.startswith(".review_report.md.") and self.name.endswith(".tmp"):
            raise OSError(f"password={raw_promotion}")
        if self == json_path and target.name.endswith(".failed"):
            raise OSError(f"client_secret={raw_quarantine}")
        return original_replace(self, target)

    def fail_public_json_unlink(self, *args, **kwargs):
        if self == json_path:
            raise OSError(f"token={raw_unlink}")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "replace", fail_publication_and_quarantine)
    monkeypatch.setattr(Path, "unlink", fail_public_json_unlink)

    with pytest.raises(ReviewStorageError) as caught:
        _orchestrator(tmp_path).review(fixture="clean", dry_run=True, runtime="local")

    storage = ReviewStorage(_db_url(tmp_path))
    task = storage.latest_task()
    rows = storage.query_task(task.task_id)
    assert task.status == ReviewTaskStatus.RUNNING
    assert task.failure_kind == ""
    assert rows["reports"] == rows["telemetry_summaries"] == []
    assert json_path.exists()
    assert not markdown_path.exists()
    assert caught.value.failure_kind == "storage_error"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    for raw in (raw_promotion, raw_unlink, raw_quarantine):
        assert raw not in str(caught.value)
        assert raw not in caplog.text


def test_failed_compensation_raises_sanitized_storage_error(tmp_path, monkeypatch, caplog):
    raw_file = "file-commit-secret-987"
    raw_storage = "compensation-storage-secret-987"

    monkeypatch.setattr(
        "agent.report_builder.ReportBuilder.commit",
        lambda self, *args, **kwargs: (_ for _ in ()).throw(OSError(f"token={raw_file}")),
    )
    monkeypatch.setattr(
        ReviewStorage,
        "mark_task_failed",
        lambda self, task: (_ for _ in ()).throw(RuntimeError(f"password={raw_storage}")),
    )

    with pytest.raises(ReviewStorageError) as caught:
        _orchestrator(tmp_path).review(fixture="clean", dry_run=True, runtime="container")

    assert caught.value.failure_kind == "storage_error"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert raw_file not in str(caught.value)
    assert raw_storage not in str(caught.value)
    assert raw_file not in caplog.text
    assert raw_storage not in caplog.text
    storage = ReviewStorage(_db_url(tmp_path))
    task = storage.latest_task()
    rows = storage.query_task(task.task_id)
    assert task.status == ReviewTaskStatus.RUNNING
    assert rows["findings"] == []
    assert rows["telemetry_summaries"] == []
    assert rows["reports"] == []
    assert not (tmp_path / "out" / "review_report.json").exists()
    assert not (tmp_path / "out" / "review_report.md").exists()


def test_terminal_storage_and_primary_cleanup_failure_uses_fallback_quarantine(tmp_path, monkeypatch, caplog):
    raw_storage = "terminal-storage-secret-654"
    raw_cleanup = "cleanup-secret-654"
    task_ids = []

    def fail_terminal(self, **kwargs):
        task_ids.append(kwargs["task"].task_id)
        raise RuntimeError(f"password={raw_storage}")

    monkeypatch.setattr(ReviewStorage, "save_terminal_bundle", fail_terminal)
    monkeypatch.setattr(
        ReportBuilder,
        "discard",
        lambda self, **kwargs: (_ for _ in ()).throw(OSError(f"token={raw_cleanup}")),
    )

    with pytest.raises(ReviewStorageError) as caught:
        _orchestrator(tmp_path).review(fixture="clean", dry_run=False, runtime="local")

    assert len(task_ids) == 1
    task_id = task_ids[0]
    storage = ReviewStorage(_db_url(tmp_path))
    rows = storage.query_task(task_id)
    assert rows["task"]["status"] == ReviewTaskStatus.FAILED.value
    assert rows["task"]["failure_kind"] == "storage_error"
    assert rows["reports"] == rows["telemetry_summaries"] == []
    assert not (tmp_path / "out" / f"review_report_{task_id}.json").exists()
    assert not (tmp_path / "out" / f"review_report_{task_id}.md").exists()
    assert raw_storage not in str(caught.value)
    assert raw_cleanup not in str(caught.value)
    assert raw_storage not in caplog.text
    assert raw_cleanup not in caplog.text


def test_terminal_storage_and_all_cleanup_failures_leave_task_running(tmp_path, monkeypatch, caplog):
    raw_primary = "primary-cleanup-secret-321"
    raw_fallback = "fallback-cleanup-secret-321"
    task_ids = []

    def fail_terminal(self, **kwargs):
        task_ids.append(kwargs["task"].task_id)
        raise RuntimeError("terminal persistence unavailable")

    monkeypatch.setattr(ReviewStorage, "save_terminal_bundle", fail_terminal)
    monkeypatch.setattr(
        ReportBuilder,
        "discard",
        lambda self, **kwargs: (_ for _ in ()).throw(OSError(f"password={raw_primary}")),
    )
    monkeypatch.setattr(
        ReportBuilder,
        "quarantine",
        lambda self, **kwargs: (_ for _ in ()).throw(OSError(f"token={raw_fallback}")),
        raising=False,
    )

    with pytest.raises(ReviewStorageError) as caught:
        _orchestrator(tmp_path).review(fixture="clean", dry_run=False, runtime="local")

    assert len(task_ids) == 1
    task_id = task_ids[0]
    rows = ReviewStorage(_db_url(tmp_path)).query_task(task_id)
    assert rows["task"]["status"] == ReviewTaskStatus.RUNNING.value
    assert rows["task"]["failure_kind"] == ""
    assert rows["reports"] == rows["telemetry_summaries"] == []
    assert (tmp_path / "out" / f"review_report_{task_id}.json").exists()
    assert (tmp_path / "out" / f"review_report_{task_id}.md").exists()
    assert caught.value.failure_kind == "storage_error"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert raw_primary not in str(caught.value)
    assert raw_fallback not in str(caught.value)
    assert raw_primary not in caplog.text
    assert raw_fallback not in caplog.text


def test_task_and_input_are_running_and_durable_before_sandbox(tmp_path, monkeypatch):
    original = SandboxRunner.run

    def inspect_before_run(self, **kwargs):
        rows = ReviewStorage(_db_url(tmp_path)).query_task(kwargs["task_id"])
        assert rows["task"]["status"] == ReviewTaskStatus.RUNNING.value
        assert len(rows["review_inputs"]) == 1
        assert rows["filter_intercepts"] == []
        assert rows["sandbox_runs"] == []
        return original(self, **kwargs)

    monkeypatch.setattr(SandboxRunner, "run", inspect_before_run)

    report = _orchestrator(tmp_path).review(fixture="clean", dry_run=True, runtime="local")

    assert report.task_status == ReviewTaskStatus.COMPLETED


def test_orchestrator_persists_decisions_and_prior_runs_incrementally(tmp_path, monkeypatch):
    observed = []

    class InspectingHarness:

        def execute_one(self, **kwargs):
            request = kwargs["request"]
            rows = ReviewStorage(_db_url(tmp_path)).query_task(request.task_id)
            observed.append((request.request_id, rows))
            assert rows["task"]["status"] == ReviewTaskStatus.RUNNING.value
            assert len(rows["review_inputs"]) == 1
            assert len(rows["filter_intercepts"]) == 3
            assert len(rows["sandbox_runs"]) == len(observed) - 1
            return _successful_run(request)

    monkeypatch.setattr(
        SandboxRunner,
        "_harness_for_runtime",
        lambda self, runtime: InspectingHarness(),
    )

    report = _orchestrator(tmp_path).review(fixture="clean", dry_run=True, runtime="container")

    assert len(observed) == 3
    assert report.task_status == ReviewTaskStatus.COMPLETED


def test_artifact_invalid_run_is_persisted_before_the_next_execution(tmp_path, monkeypatch):
    observed = []

    class InspectingHarness:

        def execute_one(self, **kwargs):
            request = kwargs["request"]
            rows = ReviewStorage(_db_url(tmp_path)).query_task(request.task_id)
            if observed:
                assert len(rows["sandbox_runs"]) == len(observed)
                assert rows["sandbox_runs"][0]["failure_kind"] == "artifact_invalid"
            content = "{not-json" if not observed else "{}"
            observed.append(request.request_id)
            return _successful_run(request).model_copy(update={"output_files": {request.output_spec.globs[0]: content}})

    monkeypatch.setattr(
        SandboxRunner,
        "_harness_for_runtime",
        lambda self, runtime: InspectingHarness(),
    )

    report = _orchestrator(tmp_path).review(fixture="clean", dry_run=True, runtime="container")
    rows = ReviewStorage(_db_url(tmp_path)).query_task(report.task_id)

    assert len(observed) == 3
    assert len(rows["sandbox_runs"]) == 3
    assert rows["sandbox_runs"][0]["failure_kind"] == "artifact_invalid"
    assert all(item["failure_kind"] == "" for item in rows["sandbox_runs"][1:])
    assert report.task_status == ReviewTaskStatus.COMPLETED_WITH_ERRORS


@pytest.mark.parametrize("method_name", ["save_filter_decision", "save_sandbox_run"])
def test_orchestrator_callback_storage_error_escapes_without_reclassification(tmp_path, monkeypatch, method_name):

    def fail_callback(self, item):
        raise ReviewStorageError(f"{method_name} callback failed")

    monkeypatch.setattr(ReviewStorage, method_name, fail_callback)

    with pytest.raises(ReviewStorageError) as caught:
        _orchestrator(tmp_path).review(fixture="clean", dry_run=True, runtime="container")

    storage = ReviewStorage(_db_url(tmp_path))
    task = storage.latest_task()
    rows = storage.query_task(task.task_id)
    assert caught.value.failure_kind == "storage_error"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert task.status == ReviewTaskStatus.FAILED
    assert task.failure_kind == "storage_error"
    assert all(item["failure_kind"] != "orchestration_error" for item in rows["sandbox_runs"])
    assert rows["telemetry_summaries"] == []
    assert rows["reports"] == []


def test_non_dry_reviews_keep_history_and_never_reset(tmp_path, monkeypatch):

    def forbidden_reset(self, task_id):
        raise AssertionError(f"non-dry task unexpectedly reset: {task_id}")

    monkeypatch.setattr(ReviewStorage, "reset_task", forbidden_reset)
    orchestrator = _orchestrator(tmp_path)

    first = orchestrator.review(fixture="clean", dry_run=False, runtime="local")
    second = orchestrator.review(fixture="clean", dry_run=False, runtime="local")

    assert first.task_id != second.task_id
    assert ReviewStorage(_db_url(tmp_path)).query_task(first.task_id)["task"]
    assert ReviewStorage(_db_url(tmp_path)).query_task(second.task_id)["task"]


@pytest.mark.parametrize(
    ("workflow", "prefix"),
    [("review", "review_report"), ("demo_filter", "filter_blocked_report")],
)
def test_non_dry_runs_use_task_specific_report_files_and_keep_both_histories(tmp_path, workflow, prefix):
    orchestrator = _orchestrator(tmp_path)

    def invoke():
        if workflow == "review":
            return orchestrator.review(fixture="clean", dry_run=False, runtime="local")
        return orchestrator.demo_filter(dry_run=False, runtime="local")

    first = invoke()
    second = invoke()

    assert first.task_id != second.task_id
    storage = ReviewStorage(_db_url(tmp_path))
    for report in (first, second):
        json_name = f"{prefix}_{report.task_id}.json"
        markdown_name = f"{prefix}_{report.task_id}.md"
        json_path = tmp_path / "out" / json_name
        markdown_path = tmp_path / "out" / markdown_name
        rows = storage.query_task(report.task_id)
        assert json_path.is_file()
        assert markdown_path.is_file()
        assert json.loads(json_path.read_text(encoding="utf-8"))["task_id"] == report.task_id
        assert report.report_paths["json"].endswith(json_name)
        assert report.report_paths["markdown"].endswith(markdown_name)
        assert rows["reports"][0]["json_path"].endswith(json_name)
        assert rows["reports"][0]["markdown_path"].endswith(markdown_name)
    assert first.report_paths != second.report_paths


def test_request_execution_exception_records_failure_and_continues(tmp_path):
    requests = _three_valid_requests(
        tmp_path,
        task_id="task-execution-error",
        runtime="container",
    )
    calls = []
    saved = []
    raw = "orchestration-secret-987"

    class PerRequestHarness:

        def execute_one(self, **kwargs):
            request = kwargs["request"]
            calls.append(request.request_id)
            if request.request_id == requests[1].request_id:
                raise RuntimeError(f"client_secret={raw}")
            return _successful_run(request)

    runner = _runner(harness=PerRequestHarness())
    result = runner.run(
        task_id="task-execution-error",
        review_input={"task_id": "task-execution-error"},
        runtime="container",
        dry_run=True,
        requests=requests,
        policy_context=_context(requests[0]),
        on_run=saved.append,
    )

    assert calls == [item.request_id for item in requests]
    assert saved == result.runs
    assert [item.request_id for item in result.runs] == [item.request_id for item in requests]
    assert [item.failure_kind for item in result.runs] == ["", "orchestration_error", ""]
    assert raw not in json.dumps([item.model_dump(mode="json") for item in result.runs], sort_keys=True)


@pytest.mark.parametrize(
    "changes",
    (
        pytest.param({"task_id": "other-task"}, id="task-id"),
        pytest.param({"request_id": "task-returned-identity:other"}, id="request-id"),
        pytest.param({"runtime": "local"}, id="runtime"),
        pytest.param({"decision": "deny"}, id="decision"),
    ),
)
def test_returned_run_identity_mismatch_becomes_orchestration_error(tmp_path, changes):
    request = _three_valid_requests(
        tmp_path,
        task_id="task-returned-identity",
        runtime="container",
    )[0]

    class MismatchedHarness:

        def execute_one(self, **kwargs):
            return _successful_run(kwargs["request"]).model_copy(update=changes)

    saved = []
    result = _runner(harness=MismatchedHarness()).run(
        task_id=request.task_id,
        review_input={"task_id": request.task_id},
        runtime="container",
        dry_run=True,
        requests=[request],
        policy_context=_context(request),
        on_run=saved.append,
    )

    assert saved == result.runs
    assert len(result.runs) == 1
    assert result.runs[0].task_id == request.task_id
    assert result.runs[0].request_id == request.request_id
    assert result.runs[0].runtime == request.runtime
    assert result.runs[0].decision == "allow"
    assert result.runs[0].failure_kind == "orchestration_error"


def test_returned_run_with_non_utf8_identity_fails_before_callback(tmp_path):
    request = _three_valid_requests(
        tmp_path,
        task_id="task-returned-surrogate",
        runtime="container",
    )[0]

    class SurrogateHarness:

        def execute_one(self, **kwargs):
            return _successful_run(kwargs["request"]).model_copy(update={"run_id": "\ud800"})

    saved = []
    result = _runner(harness=SurrogateHarness()).run(
        task_id=request.task_id,
        review_input={"task_id": request.task_id},
        runtime="container",
        dry_run=True,
        requests=[request],
        policy_context=_context(request),
        on_run=saved.append,
    )

    assert saved == result.runs
    assert len(result.runs) == 1
    assert result.runs[0].failure_kind == "orchestration_error"
    result.runs[0].model_dump_json().encode("utf-8")


def test_successful_returned_run_discards_stale_failure_fields(tmp_path):
    request = _three_valid_requests(
        tmp_path,
        task_id="task-success-audit",
        runtime="container",
    )[0]
    raw = "returned-success-secret-987"

    class StaleFailureHarness:

        def execute_one(self, **kwargs):
            return _successful_run(kwargs["request"]).model_copy(
                update={
                    "failure_kind": "execution_nonzero",
                    "failure_reason": f"stale failure client_secret={raw}",
                    "warning": f"advisory client_secret={raw}",
                })

    saved = []
    result = _runner(harness=StaleFailureHarness()).run(
        task_id=request.task_id,
        review_input={"task_id": request.task_id},
        runtime="container",
        dry_run=True,
        requests=[request],
        policy_context=_context(request),
        on_run=saved.append,
    )

    assert saved == result.runs
    assert len(result.runs) == 1
    assert result.runs[0].failure_kind == ""
    assert result.runs[0].failure_reason == ""
    assert result.runs[0].warning.startswith("advisory ")
    assert raw not in json.dumps(result.runs[0].model_dump(mode="json"), sort_keys=True)


@pytest.mark.parametrize(
    ("changes", "failure_kind", "reason_field", "raw"),
    (
        pytest.param(
            {
                "timed_out": True,
                "exit_code": -1,
                "failure_kind": "runtime_unavailable",
                "failure_reason": "stale failure client_secret=returned-timeout-secret-987",
                "warning": "timeout warning client_secret=returned-timeout-secret-987",
                "stderr": "timeout stderr client_secret=returned-timeout-secret-987",
            },
            "execution_timeout",
            "warning",
            "returned-timeout-secret-987",
            id="timeout"),
        pytest.param(
            {
                "timed_out": False,
                "exit_code": 7,
                "failure_kind": "runtime_unavailable",
                "failure_reason": "stale failure client_secret=returned-nonzero-secret-987",
                "warning": "",
                "stderr": "nonzero stderr client_secret=returned-nonzero-secret-987",
            },
            "execution_nonzero",
            "stderr",
            "returned-nonzero-secret-987",
            id="nonzero"),
    ),
)
def test_returned_run_failure_is_classified(tmp_path, changes, failure_kind, reason_field, raw):
    request = _three_valid_requests(
        tmp_path,
        task_id="task-run-classification",
        runtime="container",
    )[0]

    class ClassifiedHarness:

        def execute_one(self, **kwargs):
            return _successful_run(kwargs["request"]).model_copy(update=changes)

    result = _runner(harness=ClassifiedHarness()).run(
        task_id=request.task_id,
        review_input={"task_id": request.task_id},
        runtime="container",
        dry_run=True,
        requests=[request],
        policy_context=_context(request),
    )

    assert len(result.runs) == 1
    assert result.runs[0].request_id == request.request_id
    assert result.runs[0].failure_kind == failure_kind
    assert result.runs[0].failure_reason == getattr(result.runs[0], reason_field)
    assert result.runs[0].failure_reason
    assert "stale failure" not in result.runs[0].failure_reason
    assert raw not in json.dumps(result.runs[0].model_dump(mode="json"), sort_keys=True)


def test_same_decision_is_unique_across_tasks(tmp_path):
    policy = ReviewExecutionPolicy(dry_run=True)
    first_request = _request(tmp_path, task_id="task-a")
    second_request = _request(tmp_path, task_id="task-b")

    first = policy.evaluate(first_request, _context(first_request)).intercept
    second = policy.evaluate(second_request, _context(second_request)).intercept

    assert first.decision == second.decision == "allow"
    assert first.intercept_id != second.intercept_id
    assert len(first.intercept_id.removeprefix("filter_")) == 24
    assert len(second.intercept_id.removeprefix("filter_")) == 24
    assert first.task_id == "task-a"
    assert second.task_id == "task-b"
    assert first.request_id == first_request.request_id
    assert second.request_id == second_request.request_id


@pytest.mark.parametrize(
    ("decision", "error_kind"),
    (
        ("allow", ""),
        ("deny", "policy_denied"),
        ("needs_human_review", "approval_required"),
    ),
)
def test_filter_decision_model_accepts_only_exact_taxonomy_pairs(decision, error_kind):
    item = FilterIntercept(
        intercept_id=f"decision-{decision}",
        task_id="task-1",
        request_id="task-1:skill-run:1",
        decision=decision,
        error_kind=error_kind,
        reason="canonical decision",
    )

    assert item.error_kind == error_kind


@pytest.mark.parametrize(
    ("missing", "decision", "error_kind"),
    (
        ("task_id", "allow", ""),
        ("request_id", "allow", ""),
        ("error_kind", "allow", ""),
        (None, "allow", "policy_denied"),
        (None, "deny", ""),
        (None, "needs_human_review", "policy_denied"),
        (None, "unknown", ""),
    ),
)
def test_filter_decision_model_rejects_missing_or_mismatched_taxonomy(missing, decision, error_kind):
    payload = {
        "intercept_id": "decision-1",
        "task_id": "task-1",
        "request_id": "task-1:skill-run:1",
        "decision": decision,
        "error_kind": error_kind,
        "reason": "canonical decision",
    }
    if missing is not None:
        del payload[missing]

    with pytest.raises(ValidationError):
        FilterIntercept.model_validate(payload)


def test_filter_decision_error_taxonomy_is_persisted(tmp_path):
    storage, task, requests = _running_task_with_three_requests(tmp_path)
    policy = ReviewExecutionPolicy(dry_run=True)
    commands = (
        requests[0].command_argv,
        ("rm", "-rf", "/"),
        ("pip", "install", "unapproved-package"),
    )
    for request, command in zip(requests, commands):
        evaluated = request.model_copy(update={"command_argv": command})
        item = policy.evaluate(evaluated, _context(request)).intercept
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


def test_filter_decision_metadata_excludes_raw_input_and_environment(tmp_path):
    request = _request(tmp_path)

    item = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context(request)).intercept

    assert request.inputs[0].src not in item.metadata.values()
    assert all(env.name not in item.metadata for env in request.env)
    assert all(env.value not in item.metadata.values() for env in request.env)


def test_duplicate_task_request_decision_is_a_storage_error(tmp_path):
    storage, _, requests = _running_task_with_three_requests(tmp_path)
    request = requests[0]
    item = ReviewExecutionPolicy(dry_run=True).evaluate(request, _context(request)).intercept
    duplicate = item.model_copy(update={"intercept_id": item.intercept_id + "-duplicate"})
    storage.save_filter_decision(item)

    with pytest.raises(ReviewStorageError):
        storage.save_filter_decision(duplicate)


@pytest.mark.parametrize("field", ("intercept_id", "task_id", "request_id"))
@pytest.mark.parametrize("empty_value", ("", "   "))
def test_filter_decision_model_rejects_empty_identity_fields(field, empty_value):
    payload = {
        "intercept_id": "decision-1",
        "task_id": "task-1",
        "request_id": "task-1:skill-run:1",
        "decision": "allow",
        "error_kind": "",
        "reason": "canonical decision",
    }
    payload[field] = empty_value

    with pytest.raises(ValidationError):
        FilterIntercept.model_validate(payload)


def test_filter_decision_storage_revalidates_model_copy_identity(tmp_path):
    storage, task, requests = _running_task_with_three_requests(tmp_path)
    item = ReviewExecutionPolicy(dry_run=True).evaluate(requests[0], _context(requests[0])).intercept
    invalid_singular = item.model_copy(update={
        "intercept_id": "invalid-singular",
        "request_id": "",
    })
    invalid_bulk = item.model_copy(update={
        "intercept_id": "invalid-bulk",
        "request_id": "",
    })

    with pytest.raises(ValidationError):
        storage.save_filter_decision(invalid_singular)
    with pytest.raises(ValidationError):
        storage.save_filter_intercepts([invalid_bulk])

    assert storage.query_task(task.task_id)["filter_intercepts"] == []


def test_distinct_invalid_request_decisions_are_audited_without_raw_identity(tmp_path):
    storage, task, requests = _running_task_with_three_requests(tmp_path)
    base = requests[0]
    first_raw = "bad id one"
    second_raw = "bad id two"
    policy = ReviewExecutionPolicy(dry_run=True)
    first = policy.evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    second = policy.evaluate(
        base.model_copy(update={"request_id": second_raw}),
        _context(base),
    ).intercept

    storage.save_filter_decision(first)
    storage.save_filter_decision(second)
    repeated = ReviewExecutionPolicy(dry_run=True).evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    rows = storage.query_task(task.task_id)["filter_intercepts"]
    serialized = json.dumps(rows, ensure_ascii=False, sort_keys=True)

    assert first.decision == second.decision == "deny"
    assert first.reason == second.reason == "request id is invalid"
    assert first.request_id != second.request_id
    assert first.intercept_id != second.intercept_id
    assert first.request_id.startswith("invalid-")
    assert second.request_id.startswith("invalid-")
    assert len(first.request_id.removeprefix("invalid-")) == 24
    assert len(second.request_id.removeprefix("invalid-")) == 24
    assert int(first.request_id.removeprefix("invalid-"), 16) >= 0
    assert int(second.request_id.removeprefix("invalid-"), 16) >= 0
    assert repeated.request_id == first.request_id
    assert repeated.intercept_id == first.intercept_id
    assert len(rows) == 2
    assert first_raw not in serialized
    assert second_raw not in serialized
    with pytest.raises(ReviewStorageError):
        storage.save_filter_decision(repeated)


def test_distinct_invalid_container_request_decisions_are_audited_without_raw_identity(tmp_path):
    storage, task, requests = _running_task_with_three_requests(tmp_path)
    base = requests[0]
    first_raw = [1]
    second_raw = [2]
    policy = ReviewExecutionPolicy(dry_run=True)
    first = policy.evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    second = policy.evaluate(
        base.model_copy(update={"request_id": second_raw}),
        _context(base),
    ).intercept

    storage.save_filter_decision(first)
    storage.save_filter_decision(second)
    repeated = ReviewExecutionPolicy(dry_run=True).evaluate(
        base.model_copy(update={"request_id": [1]}),
        _context(base),
    ).intercept
    rows = storage.query_task(task.task_id)["filter_intercepts"]
    serialized = json.dumps(
        {
            "first": first.model_dump(mode="json"),
            "second": second.model_dump(mode="json"),
            "rows": rows,
        },
        ensure_ascii=False,
        sort_keys=True,
    )

    assert first.decision == second.decision == "deny"
    assert first.reason == second.reason == "request id is invalid"
    assert first.request_id != second.request_id
    assert first.intercept_id != second.intercept_id
    for item in (first, second):
        request_digest = item.request_id.removeprefix("invalid-")
        intercept_digest = item.intercept_id.removeprefix("filter_")
        assert item.request_id.startswith("invalid-")
        assert item.intercept_id.startswith("filter_")
        assert len(request_digest) == len(intercept_digest) == 24
        assert int(request_digest, 16) >= 0
        assert int(intercept_digest, 16) >= 0
    assert repeated.request_id == first.request_id
    assert repeated.intercept_id == first.intercept_id
    assert len(rows) == 2
    assert str(first_raw) not in serialized
    assert str(second_raw) not in serialized
    with pytest.raises(ReviewStorageError):
        storage.save_filter_decision(repeated)


@pytest.mark.parametrize(
    ("first_raw", "second_raw", "secret"),
    (
        pytest.param(
            {"1": "typed-key-secret"},
            {1: "typed-key-secret"},
            "typed-key-secret",
            id="dict-string-int-key",
        ),
        pytest.param(
            {"null": "typed-null-secret"},
            {None: "typed-null-secret"},
            "typed-null-secret",
            id="dict-string-none-key",
        ),
        pytest.param(
            {"true": "typed-bool-secret"},
            {True: "typed-bool-secret"},
            "typed-bool-secret",
            id="dict-string-bool-key",
        ),
        pytest.param(
            [("typed-sequence-secret", )],
            [["typed-sequence-secret"]],
            "typed-sequence-secret",
            id="nested-tuple-list",
        ),
        pytest.param(
            {"value": ("typed-value-secret", )},
            {"value": ["typed-value-secret"]},
            "typed-value-secret",
            id="dict-value-tuple-list",
        ),
    ),
)
def test_typed_invalid_container_request_decisions_are_distinct_and_replay_stable(tmp_path, first_raw, second_raw,
                                                                                  secret):
    storage, task, requests = _running_task_with_three_requests(tmp_path)
    base = requests[0]
    policy = ReviewExecutionPolicy(dry_run=True)
    first = policy.evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    second = policy.evaluate(
        base.model_copy(update={"request_id": second_raw}),
        _context(base),
    ).intercept

    storage.save_filter_decision(first)
    storage.save_filter_decision(second)
    repeated = ReviewExecutionPolicy(dry_run=True).evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    rows = storage.query_task(task.task_id)["filter_intercepts"]
    serialized = json.dumps(
        {
            "first": first.model_dump(mode="json"),
            "second": second.model_dump(mode="json"),
            "rows": rows,
        },
        ensure_ascii=False,
        sort_keys=True,
    )

    assert first.decision == second.decision == "deny"
    assert first.reason == second.reason == "request id is invalid"
    assert first.request_id != second.request_id
    assert first.intercept_id != second.intercept_id
    for item in (first, second):
        request_digest = item.request_id.removeprefix("invalid-")
        intercept_digest = item.intercept_id.removeprefix("filter_")
        assert item.request_id.startswith("invalid-")
        assert item.intercept_id.startswith("filter_")
        assert len(request_digest) == len(intercept_digest) == 24
        assert int(request_digest, 16) >= 0
        assert int(intercept_digest, 16) >= 0
    assert repeated.request_id == first.request_id
    assert repeated.intercept_id == first.intercept_id
    assert len(rows) == 2
    assert secret not in serialized
    assert repr(first_raw) not in serialized
    assert repr(second_raw) not in serialized
    with pytest.raises(ReviewStorageError):
        storage.save_filter_decision(repeated)


def test_typed_invalid_container_dict_order_is_replay_stable(tmp_path):
    storage, _, requests = _running_task_with_three_requests(tmp_path)
    base = requests[0]
    first_raw = {
        "z": ("typed-order-secret", ),
        "a": [1],
    }
    reordered_raw = {
        "a": [1],
        "z": ("typed-order-secret", ),
    }
    policy = ReviewExecutionPolicy(dry_run=True)
    first = policy.evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    reordered = policy.evaluate(
        base.model_copy(update={"request_id": reordered_raw}),
        _context(base),
    ).intercept

    storage.save_filter_decision(first)

    assert reordered.request_id == first.request_id
    assert reordered.intercept_id == first.intercept_id
    assert "typed-order-secret" not in json.dumps(first.model_dump(mode="json"), sort_keys=True)
    with pytest.raises(ReviewStorageError):
        storage.save_filter_decision(reordered)


def test_typed_invalid_cyclic_container_identity_is_replay_stable(tmp_path):
    storage, _, requests = _running_task_with_three_requests(tmp_path)
    base = requests[0]
    first_raw = ["typed-cycle-secret"]
    first_raw.append(first_raw)
    replay_raw = ["typed-cycle-secret"]
    replay_raw.append(replay_raw)
    policy = ReviewExecutionPolicy(dry_run=True)
    first = policy.evaluate(
        base.model_copy(update={"request_id": first_raw}),
        _context(base),
    ).intercept
    replay = policy.evaluate(
        base.model_copy(update={"request_id": replay_raw}),
        _context(base),
    ).intercept

    storage.save_filter_decision(first)

    assert replay.request_id == first.request_id
    assert replay.intercept_id == first.intercept_id
    assert "typed-cycle-secret" not in json.dumps(first.model_dump(mode="json"), sort_keys=True)
    with pytest.raises(ReviewStorageError):
        storage.save_filter_decision(replay)


def test_allow_decision_is_saved_before_execution(tmp_path):
    events = []
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    task = ReviewTask(
        task_id="task-1",
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
    storage.update_task(transition_task(task, ReviewTaskStatus.RUNNING))

    class OrderingHarness:

        def execute_one(self, **kwargs):
            request = kwargs["request"]
            rows = storage.query_task(task.task_id)
            assert rows["filter_intercepts"][0]["request_id"] == request.request_id
            events.append("execute")
            return _successful_run(request)

    request = _request(tmp_path, task_id=task.task_id)
    runner = _runner(harness=OrderingHarness())
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
