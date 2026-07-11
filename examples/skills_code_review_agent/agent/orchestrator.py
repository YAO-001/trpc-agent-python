# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""End-to-end orchestration for the code review example."""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from .agent_factory import prepare_execution_plan
from .dedupe import dedupe_findings
from .dedupe import dedupe_warnings
from .diff_parser import parse_unified_diff
from .filter_policy import ReviewExecutionPolicy
from .input_resolver import EXAMPLE_DIR
from .input_resolver import FIXTURE_ORDER
from .input_resolver import resolve_review_input
from .models import FilterIntercept
from .models import Finding
from .models import ReviewReport
from .models import ReviewTask
from .models import ReviewTaskStatus
from .models import ReviewWarning
from .models import SandboxRun
from .models import TelemetrySummary
from .models import terminal_status
from .models import utc_now
from .report_builder import ReportBuilder
from .redaction_boundary import RedactionBoundary
from .rule_engine import RuleEngine
from .sandbox_runner import SandboxRunner
from .storage import DEFAULT_DB_URL
from .storage import ReviewStorage
from .storage import ReviewStorageError
from .task_state import transition_task
from .telemetry import build_telemetry

LOGGER = logging.getLogger(__name__)


def _stable_task_id(*, input_type: str, input_ref: str, redacted_diff: str, runtime: str, dry_run: bool) -> str:
    if not dry_run:
        return "review_" + uuid.uuid4().hex[:16]
    payload = json.dumps(
        {
            "input_type": input_type,
            "input_ref": input_ref,
            "redacted_diff": redacted_diff,
            "runtime": runtime
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return "review_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _warning_sort_key(warning: ReviewWarning) -> tuple[str, int, str]:
    return warning.file, warning.line, warning.title


def _finalize_persistence_bundle(
    *,
    boundary: RedactionBoundary,
    task: ReviewTask,
    redacted_input: dict[str, Any],
    decisions: list[FilterIntercept],
    runs: list[SandboxRun],
    findings: list[Finding],
    warnings: list[ReviewWarning],
    needs_human_review: list[ReviewWarning],
    telemetry: TelemetrySummary,
    report: ReviewReport,
) -> dict[str, Any]:
    bundle = boundary.clean({
        "task": task.model_dump(mode="json"),
        "input": redacted_input,
        "decisions": [item.model_dump(mode="json") for item in decisions],
        "runs": [item.model_dump(mode="json") for item in runs],
        "findings": [item.model_dump(mode="json") for item in findings],
        "warnings": [item.model_dump(mode="json") for item in warnings],
        "needs_human_review": [item.model_dump(mode="json") for item in needs_human_review],
        "telemetry": telemetry.model_dump(mode="json"),
        "report": report.model_dump(mode="json"),
    })
    bundle = boundary.clean(bundle)
    if not isinstance(bundle, dict):  # pragma: no cover - caller contract
        raise ValueError("redacted persistence bundle must remain a mapping")
    summary = boundary.summary.model_dump(mode="json")
    bundle["input"]["redaction_summary"] = summary
    bundle["telemetry"]["redaction_count"] = summary["total_redactions"]
    bundle["report"]["redaction_summary"] = summary
    bundle["report"]["telemetry"] = bundle["telemetry"]
    metrics = bundle["report"].get("section_summary", {}).get("metrics")
    if isinstance(metrics, dict):
        metrics["redaction_count"] = summary["total_redactions"]
    return {
        "task": ReviewTask.model_validate(bundle["task"]),
        "input": bundle["input"],
        "decisions": [FilterIntercept.model_validate(item) for item in bundle["decisions"]],
        "runs": [SandboxRun.model_validate(item) for item in bundle["runs"]],
        "findings": [Finding.model_validate(item) for item in bundle["findings"]],
        "warnings": [ReviewWarning.model_validate(item) for item in bundle["warnings"]],
        "needs_human_review": [ReviewWarning.model_validate(item) for item in bundle["needs_human_review"]],
        "telemetry": TelemetrySummary.model_validate(bundle["telemetry"]),
        "report": ReviewReport.model_validate(bundle["report"]),
    }


class ReviewOrchestrator:

    def __init__(
        self,
        *,
        example_dir: Path = EXAMPLE_DIR,
        db_url: str = DEFAULT_DB_URL,
        output_dir: str | Path | None = None,
    ) -> None:
        self.example_dir = Path(example_dir)
        self.db_url = db_url
        self.output_dir = Path(output_dir) if output_dir else self.example_dir / "outputs"

    @staticmethod
    def _report_names(*, prefix: str, task_id: str, dry_run: bool) -> tuple[str, str]:
        stem = prefix if dry_run else f"{prefix}_{task_id}"
        return f"{stem}.json", f"{stem}.md"

    @staticmethod
    def _storage_call(operation: str, callback, boundary: RedactionBoundary):
        failure = None
        try:
            return callback()
        except ReviewStorageError as exc:
            failure = exc
        except Exception as exc:  # pylint: disable=broad-except
            failure = ReviewStorageError(f"{operation} failed: {boundary.text(exc).text}")
        raise failure from None

    def _best_effort_failure(
        self,
        *,
        storage: ReviewStorage,
        task: ReviewTask,
        failure_kind: str,
        safe_reason: str,
        boundary: RedactionBoundary,
    ) -> ReviewTask:
        safe_reason = boundary.text(safe_reason).text
        if task.status == ReviewTaskStatus.RUNNING:
            failed = transition_task(task, ReviewTaskStatus.FAILED)
        else:
            failed = task.model_copy(update={
                "status": ReviewTaskStatus.FAILED,
                "updated_at": utc_now(task.dry_run),
            })
        failed = failed.model_copy(update={
            "failure_kind": failure_kind,
            "failure_reason_redacted": safe_reason,
        })
        try:
            self._storage_call(
                "record failed task",
                lambda: storage.mark_task_failed(failed),
                boundary,
            )
        except ReviewStorageError as exc:
            LOGGER.error("Could not durably record failed review task: %s", boundary.text(exc).text)
            raise exc from None
        return failed

    def _persist_audit(
        self,
        *,
        storage: ReviewStorage,
        task: ReviewTask,
        operation: str,
        callback,
        boundary: RedactionBoundary,
    ) -> None:
        failure = None
        try:
            self._storage_call(operation, callback, boundary)
        except ReviewStorageError as exc:
            failure = exc
        if failure is not None:
            self._best_effort_failure(
                storage=storage,
                task=task,
                failure_kind=failure.failure_kind,
                safe_reason=str(failure),
                boundary=boundary,
            )
            raise failure from None

    def _durable_storage_call(
        self,
        *,
        storage: ReviewStorage,
        task: ReviewTask,
        operation: str,
        callback,
        boundary: RedactionBoundary,
    ):
        failure = None
        try:
            return self._storage_call(operation, callback, boundary)
        except ReviewStorageError as exc:
            failure = exc
        self._best_effort_failure(
            storage=storage,
            task=task,
            failure_kind=failure.failure_kind,
            safe_reason=str(failure),
            boundary=boundary,
        )
        raise failure from None

    def _terminal_storage_call(
        self,
        *,
        storage: ReviewStorage,
        task: ReviewTask,
        operation: str,
        callback,
        cleanup,
        cleanup_fallback,
        boundary: RedactionBoundary,
    ):
        failure = None
        try:
            return self._storage_call(operation, callback, boundary)
        except ReviewStorageError as exc:
            failure = exc
        cleanup_failure = None
        try:
            cleanup()
        except Exception as exc:  # pylint: disable=broad-except
            cleanup_failure = self._redacted_error(exc, boundary)
        if cleanup_failure is not None:
            LOGGER.error("Could not remove unpublished review report: %s", boundary.text(cleanup_failure).text)
            fallback_failure = None
            try:
                cleanup_fallback()
            except Exception as exc:  # pylint: disable=broad-except
                fallback_failure = self._redacted_error(exc, boundary)
            if fallback_failure is not None:
                LOGGER.error("Could not quarantine unpublished review report: %s", boundary.text(fallback_failure).text)
                terminal_failure = ReviewStorageError(
                    f"terminal report cleanup failed: {boundary.text(fallback_failure).text}")
                raise terminal_failure from None
        self._best_effort_failure(
            storage=storage,
            task=task,
            failure_kind=failure.failure_kind,
            safe_reason=str(failure),
            boundary=boundary,
        )
        raise failure from None

    def _orchestration_call(
        self,
        *,
        storage: ReviewStorage,
        task: ReviewTask,
        callback,
        boundary: RedactionBoundary,
    ):
        failure = None
        try:
            return callback()
        except Exception as exc:  # pylint: disable=broad-except
            failure = self._redacted_error(exc, boundary)
        self._best_effort_failure(
            storage=storage,
            task=task,
            failure_kind="orchestration_error",
            safe_reason=str(failure),
            boundary=boundary,
        )
        raise failure from None

    def _publication_call(
        self,
        *,
        storage: ReviewStorage,
        task: ReviewTask,
        callback,
        cleanup,
        cleanup_fallback,
        boundary: RedactionBoundary,
    ):
        failure = None
        try:
            return callback()
        except Exception as exc:  # pylint: disable=broad-except
            failure = self._redacted_error(exc, boundary)
        cleanup_failure = None
        try:
            cleanup()
        except Exception as exc:  # pylint: disable=broad-except
            cleanup_failure = self._redacted_error(exc, boundary)
        if cleanup_failure is not None:
            LOGGER.error("Could not remove partially published review report: %s", boundary.text(cleanup_failure).text)
            fallback_failure = None
            try:
                cleanup_fallback()
            except Exception as exc:  # pylint: disable=broad-except
                fallback_failure = self._redacted_error(exc, boundary)
            if fallback_failure is not None:
                LOGGER.error("Could not quarantine partially published review report: %s",
                             boundary.text(fallback_failure).text)
                publication_failure = ReviewStorageError(
                    f"report publication cleanup failed: {boundary.text(fallback_failure).text}")
                raise publication_failure from None
        self._best_effort_failure(
            storage=storage,
            task=task,
            failure_kind="orchestration_error",
            safe_reason=str(failure),
            boundary=boundary,
        )
        raise failure from None

    def _execution_call(
        self,
        *,
        storage: ReviewStorage,
        task: ReviewTask,
        callback,
        boundary: RedactionBoundary,
    ):
        storage_failure = None
        orchestration_failure = None
        try:
            return callback()
        except ReviewStorageError as exc:
            storage_failure = exc
        except Exception as exc:  # pylint: disable=broad-except
            orchestration_failure = self._redacted_error(exc, boundary)
        if storage_failure is not None:
            raise storage_failure from None
        self._best_effort_failure(
            storage=storage,
            task=task,
            failure_kind="orchestration_error",
            safe_reason=str(orchestration_failure),
            boundary=boundary,
        )
        raise orchestration_failure from None

    @staticmethod
    def _redacted_error(exc: Exception, boundary: RedactionBoundary) -> Exception:
        safe_reason = boundary.text(exc).text
        try:
            return exc.__class__(safe_reason)
        except Exception:  # pragma: no cover - defensive constructor fallback
            return RuntimeError(safe_reason)

    def _build_terminal_products(
        self,
        *,
        started: float,
        boundary: RedactionBoundary,
        task: ReviewTask,
        parsed,
        finding_candidates: list[Finding],
        warning_candidates: list[ReviewWarning],
        review_candidates: list[ReviewWarning],
        decisions: list[FilterIntercept],
        runs: list[SandboxRun],
        debug_dropped_count: int,
        input_summary: dict[str, Any],
        redacted_input: dict[str, Any],
        dry_run: bool,
        json_name: str = "review_report.json",
        markdown_name: str = "review_report.md",
    ):
        findings = dedupe_findings(
            [Finding.model_validate(boundary.clean(item.model_dump(mode="json"))) for item in finding_candidates])
        warnings = sorted(
            dedupe_warnings([
                ReviewWarning.model_validate(boundary.clean(item.model_dump(mode="json")))
                for item in warning_candidates
            ]),
            key=_warning_sort_key,
        )
        needs_human_review = sorted(
            dedupe_warnings([
                ReviewWarning.model_validate(boundary.clean(item.model_dump(mode="json"))) for item in review_candidates
            ]),
            key=_warning_sort_key,
        )
        status = ReviewTaskStatus(task.status)
        telemetry = build_telemetry(
            task_id=task.task_id,
            task_status=status,
            parsed_diff=parsed,
            findings=findings,
            warnings=warnings,
            needs_human_review=needs_human_review,
            filter_intercepts=decisions,
            sandbox_runs=runs,
            redaction_summary=boundary.summary,
            debug_dropped_count=debug_dropped_count,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            dry_run=dry_run,
        )
        builder = ReportBuilder(self.output_dir, self.db_url, boundary=boundary)
        draft_report = builder.build(
            task_id=task.task_id,
            task_status=status,
            findings=findings,
            warnings=warnings,
            needs_human_review=needs_human_review,
            filter_intercepts=decisions,
            sandbox_runs=runs,
            telemetry=telemetry,
            redaction_summary=boundary.summary,
            input_summary=input_summary,
        )
        safe_bundle = _finalize_persistence_bundle(
            boundary=boundary,
            task=task,
            redacted_input=redacted_input,
            decisions=decisions,
            runs=runs,
            findings=findings,
            warnings=warnings,
            needs_human_review=needs_human_review,
            telemetry=telemetry,
            report=draft_report,
        )
        json_text, markdown_text, report = builder.render(
            safe_bundle["report"],
            json_name=json_name,
            markdown_name=markdown_name,
        )
        safe_bundle.update({
            "decisions": report.filter_intercepts,
            "runs": report.sandbox_runs,
            "findings": report.findings,
            "warnings": report.warnings,
            "needs_human_review": report.needs_human_review,
            "telemetry": report.telemetry,
            "report": report,
        })
        safe_bundle["input"]["redaction_summary"] = report.redaction_summary.model_dump(mode="json")
        return builder, safe_bundle, json_text, markdown_text, report

    def _execute_sandbox(
        self,
        *,
        storage: ReviewStorage,
        task: ReviewTask,
        review_input: dict[str, Any],
        runtime: str,
        dry_run: bool,
        boundary: RedactionBoundary,
        request_transform=None,
    ):
        sandbox = SandboxRunner(
            example_dir=self.example_dir,
            policy=ReviewExecutionPolicy(dry_run=dry_run),
            boundary=boundary,
        )
        with prepare_execution_plan(
                task_id=task.task_id,
                runtime=runtime,
                review_input=review_input,
                boundary=boundary,
        ) as plan:
            requests = list(plan.requests)
            if request_transform is not None:
                requests = request_transform(requests)
            sandbox_result = sandbox.run(
                task_id=task.task_id,
                review_input=review_input,
                runtime=runtime,
                dry_run=dry_run,
                requests=requests,
                policy_context=plan.policy_context,
                on_decision=lambda item: self._persist_audit(
                    storage=storage,
                    task=task,
                    operation="save filter decision",
                    callback=lambda: storage.save_filter_decision(item),
                    boundary=boundary,
                ),
                on_run=lambda item: self._persist_audit(
                    storage=storage,
                    task=task,
                    operation="save sandbox run",
                    callback=lambda: storage.save_sandbox_run(item),
                    boundary=boundary,
                ),
            )
        return sandbox_result, {item.request_id for item in requests}

    def review(
        self,
        *,
        diff_file: str | None = None,
        repo_path: str | None = None,
        fixture: str | None = None,
        file_list: str | None = None,
        dry_run: bool = False,
        runtime: str = "container",
    ) -> ReviewReport:
        started = time.perf_counter()
        boundary = RedactionBoundary()
        resolved = resolve_review_input(diff_file=diff_file, repo_path=repo_path, fixture=fixture, file_list=file_list)
        resolved_metadata = boundary.clean({
            "input_type": resolved.input_type,
            "input_ref": resolved.input_ref,
            "fixture_names": resolved.fixture_names,
            "file_list": resolved.file_list,
        })
        redaction = boundary.text(resolved.diff_text)
        parsed = parse_unified_diff(redaction.text)
        if resolved_metadata["file_list"]:
            parsed = parsed.model_copy(
                update={"changed_files": sorted({*parsed.changed_files, *resolved_metadata["file_list"]})})

        task_id = _stable_task_id(
            input_type=resolved_metadata["input_type"],
            input_ref=resolved_metadata["input_ref"],
            redacted_diff=redaction.text,
            runtime=runtime,
            dry_run=dry_run,
        )
        json_name, markdown_name = self._report_names(
            prefix="review_report",
            task_id=task_id,
            dry_run=dry_run,
        )
        rule_result = RuleEngine().run(parsed, boundary.summary)
        rule_result.findings = [
            item.__class__.model_validate(boundary.clean(item.model_dump(mode="json"))) for item in rule_result.findings
        ]
        rule_result.warnings = [
            item.__class__.model_validate(boundary.clean(item.model_dump(mode="json"))) for item in rule_result.warnings
        ]
        rule_result.needs_human_review = [
            item.__class__.model_validate(boundary.clean(item.model_dump(mode="json")))
            for item in rule_result.needs_human_review
        ]
        review_input = boundary.clean({
            "task_id":
            task_id,
            "input_type":
            resolved_metadata["input_type"],
            "input_ref":
            resolved_metadata["input_ref"],
            "fixture_names":
            resolved_metadata["fixture_names"],
            "file_list":
            resolved_metadata["file_list"],
            "changed_files":
            parsed.changed_files,
            "added_lines": [line.model_dump(mode="json") for line in parsed.added_lines],
            "rule_warnings": [item.model_dump(mode="json") for item in rule_result.warnings],
            "rule_needs_human_review": [item.model_dump(mode="json") for item in rule_result.needs_human_review],
        })
        review_input["redaction_summary"] = boundary.summary.model_dump(mode="json")
        task = ReviewTask.model_validate(
            boundary.clean({
                "task_id": task_id,
                "input_type": review_input["input_type"],
                "input_ref": review_input["input_ref"],
                "runtime": runtime,
                "dry_run": dry_run,
                "status": "created",
                "created_at": utc_now(dry_run),
                "updated_at": utc_now(dry_run),
            }))
        storage = self._storage_call(
            "initialize storage",
            lambda: ReviewStorage(self.db_url, boundary=boundary),
            boundary,
        )
        if dry_run:
            self._storage_call(
                "reset dry-run task",
                lambda: storage.reset_task(task.task_id),
                boundary,
            )
        self._storage_call(
            "create task with input",
            lambda: storage.create_task_with_input(
                task=task,
                redacted_diff=redaction.text,
                changed_files=list(review_input["changed_files"]),
                redaction_summary=boundary.summary,
                input_metadata={
                    "fixture_names": review_input["fixture_names"],
                    "file_list": review_input["file_list"],
                },
            ),
            boundary,
        )
        task = transition_task(task, ReviewTaskStatus.RUNNING)
        self._durable_storage_call(
            storage=storage,
            task=task,
            operation="start task",
            callback=lambda: storage.update_task(task),
            boundary=boundary,
        )
        if dry_run:
            self._orchestration_call(
                storage=storage,
                task=task,
                callback=lambda: ReportBuilder(self.output_dir, self.db_url, boundary=boundary).discard(
                    task_id=task.task_id,
                    json_name=json_name,
                    markdown_name=markdown_name,
                ),
                boundary=boundary,
            )
        sandbox_result, required_request_ids = self._execution_call(
            storage=storage,
            task=task,
            callback=lambda: self._execute_sandbox(
                storage=storage,
                task=task,
                review_input=review_input,
                runtime=runtime,
                dry_run=dry_run,
                boundary=boundary,
            ),
            boundary=boundary,
        )

        task = self._orchestration_call(
            storage=storage,
            task=task,
            callback=lambda: transition_task(
                task,
                terminal_status(
                    task_id=task_id,
                    required_request_ids=required_request_ids,
                    decisions=sandbox_result.decisions,
                    runs=sandbox_result.runs,
                ),
            ),
            boundary=boundary,
        )

        builder, safe_bundle, json_text, markdown_text, report = self._orchestration_call(
            storage=storage,
            task=task,
            boundary=boundary,
            callback=lambda: self._build_terminal_products(
                started=started,
                boundary=boundary,
                task=task,
                parsed=parsed,
                finding_candidates=[*rule_result.findings, *sandbox_result.findings],
                warning_candidates=[*rule_result.warnings, *sandbox_result.warnings],
                review_candidates=[*rule_result.needs_human_review, *sandbox_result.needs_human_review],
                decisions=sandbox_result.decisions,
                runs=sandbox_result.runs,
                debug_dropped_count=rule_result.debug_dropped_count,
                input_summary={
                    "input_type": review_input["input_type"],
                    "input_ref": review_input["input_ref"],
                    "fixtures": review_input["fixture_names"],
                    "changed_files": review_input["changed_files"],
                    "effective_runtime": sandbox_result.effective_runtime,
                },
                redacted_input={
                    "redacted_diff": redaction.text,
                    "changed_files": list(review_input["changed_files"]),
                    "redaction_summary": boundary.summary.model_dump(mode="json"),
                    "input_metadata": {
                        "fixture_names": review_input["fixture_names"],
                        "file_list": review_input["file_list"],
                        "effective_runtime": sandbox_result.effective_runtime,
                    },
                    "review_input": review_input,
                },
                dry_run=dry_run,
                json_name=json_name,
                markdown_name=markdown_name,
            ),
        )

        self._publication_call(
            storage=storage,
            task=task,
            callback=lambda: builder.commit(
                json_text,
                markdown_text,
                json_name=json_name,
                markdown_name=markdown_name,
            ),
            cleanup=lambda: builder.discard(
                task_id=task.task_id,
                json_name=json_name,
                markdown_name=markdown_name,
            ),
            cleanup_fallback=lambda: builder.quarantine(
                task_id=task.task_id,
                json_name=json_name,
                markdown_name=markdown_name,
            ),
            boundary=boundary,
        )
        self._terminal_storage_call(
            storage=storage,
            task=task,
            operation="save terminal bundle",
            callback=lambda: storage.save_terminal_bundle(
                task=safe_bundle["task"],
                required_request_ids=required_request_ids,
                findings=safe_bundle["findings"],
                telemetry=report.telemetry,
                report=report,
                json_report=json_text,
                markdown_report=markdown_text,
            ),
            cleanup=lambda: builder.discard(
                task_id=task.task_id,
                json_name=json_name,
                markdown_name=markdown_name,
            ),
            cleanup_fallback=lambda: builder.quarantine(
                task_id=task.task_id,
                json_name=json_name,
                markdown_name=markdown_name,
            ),
            boundary=boundary,
        )
        return report

    def demo_filter(self, *, dry_run: bool = False, runtime: str = "container") -> ReviewReport:
        started = time.perf_counter()
        boundary = RedactionBoundary()
        redaction = boundary.text("")
        parsed = parse_unified_diff(redaction.text)
        task_id = _stable_task_id(
            input_type="demo_filter",
            input_ref="filter:rm-rf-root",
            redacted_diff=redaction.text,
            runtime=runtime,
            dry_run=dry_run,
        )
        json_name, markdown_name = self._report_names(
            prefix="filter_blocked_report",
            task_id=task_id,
            dry_run=dry_run,
        )
        task = ReviewTask.model_validate(
            boundary.clean({
                "task_id": task_id,
                "input_type": "demo_filter",
                "input_ref": "filter:rm-rf-root",
                "runtime": runtime,
                "dry_run": dry_run,
                "status": "created",
                "created_at": utc_now(dry_run),
                "updated_at": utc_now(dry_run),
            }))
        review_input = boundary.clean({
            "task_id": task_id,
            "input_type": "demo_filter",
            "input_ref": "filter:rm-rf-root",
            "fixture_names": [],
            "file_list": [],
            "changed_files": [],
            "added_lines": [],
            "rule_warnings": [],
            "rule_needs_human_review": [],
        })
        review_input["redaction_summary"] = boundary.summary.model_dump(mode="json")
        storage = self._storage_call(
            "initialize storage",
            lambda: ReviewStorage(self.db_url, boundary=boundary),
            boundary,
        )
        if dry_run:
            self._storage_call(
                "reset dry-run task",
                lambda: storage.reset_task(task.task_id),
                boundary,
            )
        self._storage_call(
            "create task with input",
            lambda: storage.create_task_with_input(
                task=task,
                redacted_diff=redaction.text,
                changed_files=[],
                redaction_summary=boundary.summary,
                input_metadata={
                    "demo": "filter",
                    "dangerous_command": "rm -rf /"
                },
            ),
            boundary,
        )
        task = transition_task(task, ReviewTaskStatus.RUNNING)
        self._durable_storage_call(
            storage=storage,
            task=task,
            operation="start task",
            callback=lambda: storage.update_task(task),
            boundary=boundary,
        )
        if dry_run:
            self._orchestration_call(
                storage=storage,
                task=task,
                callback=lambda: ReportBuilder(self.output_dir, self.db_url, boundary=boundary).discard(
                    task_id=task.task_id,
                    json_name=json_name,
                    markdown_name=markdown_name,
                ),
                boundary=boundary,
            )
        sandbox_result, required_request_ids = self._execution_call(
            storage=storage,
            task=task,
            callback=lambda: self._execute_sandbox(
                storage=storage,
                task=task,
                review_input=review_input,
                runtime=runtime,
                dry_run=dry_run,
                boundary=boundary,
                request_transform=lambda requests: [
                    requests[0].model_copy(update={
                        "request_id": f"{task_id}:demo-filter",
                        "command_argv": ("rm", "-rf", "/"),
                    })
                ],
            ),
            boundary=boundary,
        )
        task = self._orchestration_call(
            storage=storage,
            task=task,
            callback=lambda: transition_task(
                task,
                terminal_status(
                    task_id=task_id,
                    required_request_ids=required_request_ids,
                    decisions=sandbox_result.decisions,
                    runs=sandbox_result.runs,
                ),
            ),
            boundary=boundary,
        )
        builder, safe_bundle, json_text, markdown_text, report = self._orchestration_call(
            storage=storage,
            task=task,
            boundary=boundary,
            callback=lambda: self._build_terminal_products(
                started=started,
                boundary=boundary,
                task=task,
                parsed=parsed,
                finding_candidates=[],
                warning_candidates=sandbox_result.warnings,
                review_candidates=sandbox_result.needs_human_review,
                decisions=sandbox_result.decisions,
                runs=sandbox_result.runs,
                debug_dropped_count=0,
                input_summary={
                    "input_type": "demo_filter",
                    "input_ref": "filter:rm-rf-root",
                    "effective_runtime": sandbox_result.effective_runtime,
                },
                redacted_input={
                    "redacted_diff": redaction.text,
                    "changed_files": [],
                    "redaction_summary": boundary.summary.model_dump(mode="json"),
                    "input_metadata": {
                        "demo": "filter",
                        "dangerous_command": "rm -rf /",
                        "effective_runtime": sandbox_result.effective_runtime,
                    },
                    "review_input": review_input,
                },
                dry_run=dry_run,
                json_name=json_name,
                markdown_name=markdown_name,
            ),
        )

        self._publication_call(
            storage=storage,
            task=task,
            callback=lambda: builder.commit(
                json_text,
                markdown_text,
                json_name=json_name,
                markdown_name=markdown_name,
            ),
            cleanup=lambda: builder.discard(
                task_id=task.task_id,
                json_name=json_name,
                markdown_name=markdown_name,
            ),
            cleanup_fallback=lambda: builder.quarantine(
                task_id=task.task_id,
                json_name=json_name,
                markdown_name=markdown_name,
            ),
            boundary=boundary,
        )
        self._terminal_storage_call(
            storage=storage,
            task=task,
            operation="save terminal bundle",
            callback=lambda: storage.save_terminal_bundle(
                task=safe_bundle["task"],
                required_request_ids=required_request_ids,
                findings=safe_bundle["findings"],
                telemetry=report.telemetry,
                report=report,
                json_report=json_text,
                markdown_report=markdown_text,
            ),
            cleanup=lambda: builder.discard(
                task_id=task.task_id,
                json_name=json_name,
                markdown_name=markdown_name,
            ),
            cleanup_fallback=lambda: builder.quarantine(
                task_id=task.task_id,
                json_name=json_name,
                markdown_name=markdown_name,
            ),
            boundary=boundary,
        )
        return report

    def eval_fixtures(self, *, dry_run: bool = False, runtime: str = "container") -> dict[str, Any]:
        boundary = RedactionBoundary()
        rows = []
        for fixture in FIXTURE_ORDER:
            fixture_runner = ReviewOrchestrator(
                example_dir=self.example_dir,
                db_url=self.db_url,
                output_dir=self.output_dir / "fixtures" / fixture,
            )
            report = fixture_runner.review(fixture=fixture, dry_run=dry_run, runtime=runtime)
            rows.append(
                boundary.clean({
                    "fixture": fixture,
                    "task_id": report.task_id,
                    "findings": len(report.findings),
                    "warnings": len(report.warnings),
                    "needs_human_review": len(report.needs_human_review),
                    "sandbox_failures": report.telemetry.sandbox_failures_count,
                    "redactions": report.telemetry.redaction_count,
                    "conclusion": report.conclusion,
                }))
        summary = boundary.clean({
            "fixtures": rows,
            "total_fixtures": len(rows),
            "total_findings": sum(row["findings"] for row in rows),
            "total_needs_human_review": sum(row["needs_human_review"] for row in rows),
        })
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "eval_summary.json").write_text(
            boundary.text(json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2)).text + "\n",
            encoding="utf-8",
        )
        return summary

    def query(self, *, task_id: str) -> dict[str, Any]:
        return ReviewStorage(self.db_url).query_task(task_id)
