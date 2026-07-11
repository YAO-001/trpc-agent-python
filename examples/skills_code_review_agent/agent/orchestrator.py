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
from .models import ReviewReport
from .models import ReviewTask
from .models import ReviewWarning
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
        resolved = resolve_review_input(diff_file=diff_file, repo_path=repo_path, fixture=fixture, file_list=file_list)
        boundary = RedactionBoundary()
        redaction = boundary.text(resolved.diff_text)
        parsed = parse_unified_diff(redaction.text)
        if resolved.file_list:
            parsed = parsed.model_copy(update={"changed_files": sorted({*parsed.changed_files, *resolved.file_list})})

        task_id = _stable_task_id(
            input_type=resolved.input_type,
            input_ref=resolved.input_ref,
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
            resolved.input_type,
            "input_ref":
            resolved.input_ref,
            "fixture_names":
            resolved.fixture_names,
            "file_list":
            resolved.file_list,
            "changed_files":
            parsed.changed_files,
            "added_lines": [line.model_dump(mode="json") for line in parsed.added_lines],
            "rule_warnings": [item.model_dump(mode="json") for item in rule_result.warnings],
            "rule_needs_human_review": [item.model_dump(mode="json") for item in rule_result.needs_human_review],
        })
        review_input["redaction_summary"] = boundary.summary.model_dump(mode="json")
        task = ReviewTask(
            task_id=task_id,
            input_type=str(review_input["input_type"]),
            input_ref=str(review_input["input_ref"]),
            runtime=runtime,
            dry_run=dry_run,
            status="completed",
            created_at=utc_now(dry_run),
        )
        sandbox = SandboxRunner(
            example_dir=self.example_dir,
            policy=ReviewExecutionPolicy(dry_run=dry_run),
            redactor=boundary.redactor,
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

        merged_findings = dedupe_findings([*rule_result.findings, *sandbox_result.findings])
        warnings = sorted(dedupe_warnings([*rule_result.warnings, *sandbox_result.warnings]), key=_warning_sort_key)
        needs_human_review = sorted(
            dedupe_warnings([*rule_result.needs_human_review, *sandbox_result.needs_human_review]),
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

        storage = ReviewStorage(self.db_url)
        storage.reset_task(task_id)
        storage.save_task(task)
        storage.save_input(
            task_id=task_id,
            redacted_diff=redaction.text,
            changed_files=list(review_input["changed_files"]),
            redaction_summary=boundary.summary,
            input_metadata={
                "fixture_names": review_input["fixture_names"],
                "file_list": review_input["file_list"],
                "effective_runtime": sandbox_result.effective_runtime,
            },
        )
        storage.save_sandbox_runs(sandbox_result.runs)
        storage.save_findings(task_id, merged_findings)
        storage.save_filter_intercepts(sandbox_result.decisions)
        storage.save_telemetry(telemetry)

        builder = ReportBuilder(self.output_dir, self.db_url)
        report = builder.build(
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
        json_text, markdown_text, report = builder.write(report)
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
        task = ReviewTask(
            task_id=task_id,
            input_type="demo_filter",
            input_ref="filter:rm-rf-root",
            runtime=runtime,
            dry_run=dry_run,
            status="completed",
            created_at=utc_now(dry_run),
        )
        sandbox = SandboxRunner(
            example_dir=self.example_dir,
            policy=ReviewExecutionPolicy(dry_run=dry_run),
            redactor=boundary.redactor,
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
        warnings = sorted(dedupe_warnings(sandbox_result.warnings), key=_warning_sort_key)
        needs_human_review = sorted(dedupe_warnings(sandbox_result.needs_human_review), key=_warning_sort_key)
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

        storage = ReviewStorage(self.db_url)
        storage.reset_task(task_id)
        storage.save_task(task)
        storage.save_input(
            task_id=task_id,
            redacted_diff=redaction.text,
            changed_files=[],
            redaction_summary=boundary.summary,
            input_metadata={
                "demo": "filter",
                "dangerous_command": "rm -rf /",
                "effective_runtime": sandbox_result.effective_runtime,
            },
        )
        storage.save_sandbox_runs(sandbox_result.runs)
        storage.save_filter_intercepts(sandbox_result.decisions)
        storage.save_telemetry(telemetry)

        builder = ReportBuilder(self.output_dir, self.db_url)
        report = builder.build(
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
        json_text, markdown_text, report = builder.write(
            report,
            json_name="filter_blocked_report.json",
            markdown_name="filter_blocked_report.md",
        )
        storage.save_report(
            report=report,
            json_report=json_text,
            markdown_report=markdown_text,
            json_path=report.report_paths["json"],
            markdown_path=report.report_paths["markdown"],
        )
        return report

    def eval_fixtures(self, *, dry_run: bool = False, runtime: str = "container") -> dict[str, Any]:
        rows = []
        for fixture in FIXTURE_ORDER:
            fixture_runner = ReviewOrchestrator(
                example_dir=self.example_dir,
                db_url=self.db_url,
                output_dir=self.output_dir / "fixtures" / fixture,
            )
            report = fixture_runner.review(fixture=fixture, dry_run=dry_run, runtime=runtime)
            rows.append({
                "fixture": fixture,
                "task_id": report.task_id,
                "findings": len(report.findings),
                "warnings": len(report.warnings),
                "needs_human_review": len(report.needs_human_review),
                "sandbox_failures": report.telemetry.sandbox_failures_count,
                "redactions": report.telemetry.redaction_count,
                "conclusion": report.conclusion,
            })
        summary = {
            "fixtures": rows,
            "total_fixtures": len(rows),
            "total_findings": sum(row["findings"] for row in rows),
            "total_needs_human_review": sum(row["needs_human_review"] for row in rows),
        }
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "eval_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return summary

    def query(self, *, task_id: str) -> dict[str, Any]:
        return ReviewStorage(self.db_url).query_task(task_id)
