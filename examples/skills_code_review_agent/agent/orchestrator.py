# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""End-to-end orchestration for the code review example."""

from __future__ import annotations

import hashlib
import json
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
from .models import ReviewWarning
from .models import SandboxRun
from .models import TelemetrySummary
from .models import utc_now
from .report_builder import ReportBuilder
from .redaction_boundary import RedactionBoundary
from .rule_engine import RuleEngine
from .sandbox_runner import SandboxRunner
from .storage import DEFAULT_DB_URL
from .storage import ReviewStorage
from .telemetry import build_telemetry


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
                "status": "completed",
                "created_at": utc_now(dry_run),
            }))
        sandbox = SandboxRunner(
            example_dir=self.example_dir,
            policy=ReviewExecutionPolicy(dry_run=dry_run),
            boundary=boundary,
        )
        with prepare_execution_plan(
                task_id=task_id,
                runtime=runtime,
                review_input=review_input,
                boundary=boundary,
        ) as plan:
            sandbox_result = sandbox.run(
                task_id=task_id,
                review_input=review_input,
                runtime=runtime,
                dry_run=dry_run,
                requests=list(plan.requests),
                policy_context=plan.policy_context,
            )

        finding_candidates = [
            Finding.model_validate(boundary.clean(item.model_dump(mode="json")))
            for item in [*rule_result.findings, *sandbox_result.findings]
        ]
        warning_candidates = [
            ReviewWarning.model_validate(boundary.clean(item.model_dump(mode="json")))
            for item in [*rule_result.warnings, *sandbox_result.warnings]
        ]
        review_candidates = [
            ReviewWarning.model_validate(boundary.clean(item.model_dump(mode="json")))
            for item in [*rule_result.needs_human_review, *sandbox_result.needs_human_review]
        ]
        merged_findings = dedupe_findings(finding_candidates)
        warnings = sorted(dedupe_warnings(warning_candidates), key=_warning_sort_key)
        needs_human_review = sorted(
            dedupe_warnings(review_candidates),
            key=_warning_sort_key,
        )
        telemetry = build_telemetry(
            task_id=task_id,
            parsed_diff=parsed,
            findings=merged_findings,
            warnings=warnings,
            needs_human_review=needs_human_review,
            filter_intercepts=sandbox_result.decisions,
            sandbox_runs=sandbox_result.runs,
            redaction_summary=boundary.summary,
            debug_dropped_count=rule_result.debug_dropped_count,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            dry_run=dry_run,
        )

        builder = ReportBuilder(self.output_dir, self.db_url, boundary=boundary)
        draft_report = builder.build(
            task_id=task_id,
            findings=merged_findings,
            warnings=warnings,
            needs_human_review=needs_human_review,
            filter_intercepts=sandbox_result.decisions,
            sandbox_runs=sandbox_result.runs,
            telemetry=telemetry,
            redaction_summary=boundary.summary,
            input_summary={
                "input_type": review_input["input_type"],
                "input_ref": review_input["input_ref"],
                "fixtures": review_input["fixture_names"],
                "changed_files": review_input["changed_files"],
                "effective_runtime": sandbox_result.effective_runtime,
            },
        )
        safe_bundle = _finalize_persistence_bundle(
            boundary=boundary,
            task=task,
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
            decisions=sandbox_result.decisions,
            runs=sandbox_result.runs,
            findings=merged_findings,
            warnings=warnings,
            needs_human_review=needs_human_review,
            telemetry=telemetry,
            report=draft_report,
        )
        json_text, markdown_text, report = builder.write(safe_bundle["report"])
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

        storage = ReviewStorage(self.db_url, boundary=boundary)
        storage.reset_task(safe_bundle["task"].task_id)
        storage.save_task(safe_bundle["task"])
        storage.save_input(
            task_id=safe_bundle["task"].task_id,
            redacted_diff=safe_bundle["input"]["redacted_diff"],
            changed_files=safe_bundle["input"]["changed_files"],
            redaction_summary=report.redaction_summary,
            input_metadata=safe_bundle["input"]["input_metadata"],
        )
        storage.save_sandbox_runs(safe_bundle["runs"])
        storage.save_findings(safe_bundle["task"].task_id, safe_bundle["findings"])
        storage.save_filter_intercepts(safe_bundle["decisions"])
        storage.save_telemetry(safe_bundle["telemetry"])
        storage.save_report(
            report=report,
            json_report=json_text,
            markdown_report=markdown_text,
            json_path=report.report_paths["json"],
            markdown_path=report.report_paths["markdown"],
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
        task = ReviewTask.model_validate(
            boundary.clean({
                "task_id": task_id,
                "input_type": "demo_filter",
                "input_ref": "filter:rm-rf-root",
                "runtime": runtime,
                "dry_run": dry_run,
                "status": "completed",
                "created_at": utc_now(dry_run),
            }))
        sandbox = SandboxRunner(
            example_dir=self.example_dir,
            policy=ReviewExecutionPolicy(dry_run=dry_run),
            boundary=boundary,
        )
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
        with prepare_execution_plan(
                task_id=task_id,
                runtime=runtime,
                review_input=review_input,
                boundary=boundary,
        ) as plan:
            denied_request = plan.requests[0].model_copy(update={
                "request_id": f"{task_id}:demo-filter",
                "command_argv": ("rm", "-rf", "/"),
            })
            sandbox_result = sandbox.run(
                task_id=task_id,
                review_input=review_input,
                runtime=runtime,
                dry_run=dry_run,
                requests=[denied_request],
                policy_context=plan.policy_context,
            )
        warnings = sorted(
            dedupe_warnings([
                ReviewWarning.model_validate(boundary.clean(item.model_dump(mode="json")))
                for item in sandbox_result.warnings
            ]),
            key=_warning_sort_key,
        )
        needs_human_review = sorted(
            dedupe_warnings([
                ReviewWarning.model_validate(boundary.clean(item.model_dump(mode="json")))
                for item in sandbox_result.needs_human_review
            ]),
            key=_warning_sort_key,
        )
        telemetry = build_telemetry(
            task_id=task_id,
            parsed_diff=parsed,
            findings=[],
            warnings=warnings,
            needs_human_review=needs_human_review,
            filter_intercepts=sandbox_result.decisions,
            sandbox_runs=sandbox_result.runs,
            redaction_summary=boundary.summary,
            debug_dropped_count=0,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            dry_run=dry_run,
        )

        builder = ReportBuilder(self.output_dir, self.db_url, boundary=boundary)
        draft_report = builder.build(
            task_id=task_id,
            findings=[],
            warnings=warnings,
            needs_human_review=needs_human_review,
            filter_intercepts=sandbox_result.decisions,
            sandbox_runs=sandbox_result.runs,
            telemetry=telemetry,
            redaction_summary=boundary.summary,
            input_summary={
                "input_type": "demo_filter",
                "input_ref": "filter:rm-rf-root",
                "effective_runtime": sandbox_result.effective_runtime,
            },
        )
        safe_bundle = _finalize_persistence_bundle(
            boundary=boundary,
            task=task,
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
            decisions=sandbox_result.decisions,
            runs=sandbox_result.runs,
            findings=[],
            warnings=warnings,
            needs_human_review=needs_human_review,
            telemetry=telemetry,
            report=draft_report,
        )
        json_text, markdown_text, report = builder.write(
            safe_bundle["report"],
            json_name="filter_blocked_report.json",
            markdown_name="filter_blocked_report.md",
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

        storage = ReviewStorage(self.db_url, boundary=boundary)
        storage.reset_task(safe_bundle["task"].task_id)
        storage.save_task(safe_bundle["task"])
        storage.save_input(
            task_id=safe_bundle["task"].task_id,
            redacted_diff=safe_bundle["input"]["redacted_diff"],
            changed_files=safe_bundle["input"]["changed_files"],
            redaction_summary=report.redaction_summary,
            input_metadata=safe_bundle["input"]["input_metadata"],
        )
        storage.save_sandbox_runs(safe_bundle["runs"])
        storage.save_findings(safe_bundle["task"].task_id, safe_bundle["findings"])
        storage.save_filter_intercepts(safe_bundle["decisions"])
        storage.save_telemetry(safe_bundle["telemetry"])
        storage.save_report(
            report=report,
            json_report=json_text,
            markdown_report=markdown_text,
            json_path=report.report_paths["json"],
            markdown_path=report.report_paths["markdown"],
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
