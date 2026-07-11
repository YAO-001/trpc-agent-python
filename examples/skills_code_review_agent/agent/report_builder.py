# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""JSON and Markdown report generation."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from .models import FilterIntercept
from .models import Finding
from .models import RedactionSummary
from .models import ReviewReport
from .models import ReviewTaskStatus
from .models import ReviewWarning
from .models import SandboxRun
from .models import TelemetrySummary
from .redaction_boundary import RedactionBoundary


def _severity_distribution(findings: list[Finding]) -> dict[str, int]:
    distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        distribution[finding.severity] = distribution.get(finding.severity, 0) + 1
    return {key: value for key, value in distribution.items() if value}


def _conclusion(
    task_status: ReviewTaskStatus,
    findings: list[Finding],
    needs_human_review: list[ReviewWarning],
) -> str:
    if task_status == ReviewTaskStatus.BLOCKED:
        return "Review blocked by execution policy or required human approval."
    if task_status == ReviewTaskStatus.FAILED:
        return "Review failed before all required execution completed."
    if task_status == ReviewTaskStatus.COMPLETED_WITH_ERRORS:
        return "Review completed with execution errors; inspect sandbox results."
    if any(item.severity in {"critical", "high"} for item in findings):
        return "High-confidence issues require changes before merge."
    if findings:
        return "Review found deterministic issues to address."
    if needs_human_review:
        return "No high-confidence findings, but human review is needed for warnings or sandbox state."
    return "No deterministic findings."


def _recommendations(findings: list[Finding], warnings: list[ReviewWarning]) -> list[str]:
    values = []
    seen = set()
    for item in findings:
        if item.recommendation not in seen:
            values.append(item.recommendation)
            seen.add(item.recommendation)
    for warning in warnings:
        if warning.message not in seen:
            values.append(warning.message)
            seen.add(warning.message)
    return values[:12]


def _section_summary(
    *,
    findings: list[Finding],
    warnings: list[ReviewWarning],
    needs_human_review: list[ReviewWarning],
    filter_intercepts: list[FilterIntercept],
    sandbox_runs: list[SandboxRun],
    telemetry: TelemetrySummary,
    severity_distribution: dict[str, int],
    recommendations: list[str],
) -> dict[str, Any]:
    byte_totals = {
        "stdout_observed": sum(item.stdout_bytes_observed for item in sandbox_runs),
        "stdout_retained": sum(len(item.stdout.encode("utf-8")) for item in sandbox_runs),
        "stderr_observed": sum(item.stderr_bytes_observed for item in sandbox_runs),
        "stderr_retained": sum(len(item.stderr.encode("utf-8")) for item in sandbox_runs),
        "output_observed": sum(item.output_bytes_observed for item in sandbox_runs),
        "output_retained": sum(item.output_bytes for item in sandbox_runs),
    }
    return {
        "task_status": telemetry.task_status.value,
        "findings_summary": {
            "findings": len(findings),
            "warnings": len(warnings),
            "needs_human_review": len(needs_human_review),
        },
        "severity_stats": severity_distribution,
        "human_review": {
            "warnings": len(warnings),
            "needs_human_review": len(needs_human_review),
        },
        "filter_summary": {
            "denied": telemetry.filter_denied_count,
            "needs_human_review": telemetry.filter_needs_review_count,
            "persisted_intercepts": len(filter_intercepts),
            "error_kinds": {
                error_kind: sum(1 for item in filter_intercepts if item.error_kind == error_kind)
                for error_kind in ("policy_denied", "approval_required")
                if any(item.error_kind == error_kind for item in filter_intercepts)
            },
        },
        "metrics": telemetry.model_dump(mode="json"),
        "sandbox_summary": {
            "runs":
            len(sandbox_runs),
            "attempts":
            telemetry.tool_attempts_count,
            "executions":
            telemetry.tool_executed_count,
            "failures_or_timeouts":
            telemetry.sandbox_failures_count,
            "stdout_truncated":
            telemetry.stdout_truncated_count,
            "stderr_truncated":
            telemetry.stderr_truncated_count,
            "output_truncated":
            telemetry.output_truncated_count,
            "bytes":
            byte_totals,
            "termination_reasons":
            dict(
                sorted((reason, sum(1 for item in sandbox_runs if item.termination_reason == reason))
                       for reason in {item.termination_reason
                                      for item in sandbox_runs if item.termination_reason})),
        },
        "recommendations": recommendations,
    }


def _posix_path(path: Path) -> str:
    return PurePosixPath(*path.parts).as_posix()


class ReportBuilder:

    def __init__(
        self,
        output_dir: Path,
        db_url: str,
        boundary: RedactionBoundary | None = None,
    ) -> None:
        self.output_dir = output_dir
        self.db_url = db_url
        self.boundary = boundary or RedactionBoundary()

    def _display_path(self, path: Path) -> str:
        resolved = path.resolve()
        for base in [Path.cwd().resolve(), self.output_dir.resolve().parent]:
            try:
                return _posix_path(resolved.relative_to(base))
            except ValueError:
                continue
        return path.name

    def _display_db_url(self) -> str:
        if not self.db_url.lower().startswith("sqlite:"):
            self.boundary.text(self.db_url)
        safe_url = self.boundary.display_db_url(self.db_url)
        prefix = "sqlite:///"
        if not safe_url.startswith(prefix) or safe_url == "sqlite:///:memory:":
            return safe_url
        db_path = Path(safe_url.removeprefix(prefix))
        if not db_path.is_absolute():
            return prefix + _posix_path(db_path)
        return prefix + self._display_path(db_path)

    def _refresh_redaction_fields(self, payload: dict[str, Any]) -> None:
        summary = self.boundary.summary.model_dump(mode="json")
        payload["redaction_summary"] = summary
        telemetry = payload.get("telemetry")
        if isinstance(telemetry, dict):
            telemetry["redaction_count"] = summary["total_redactions"]
        section_summary = payload.get("section_summary")
        if isinstance(section_summary, dict):
            metrics = section_summary.get("metrics")
            if isinstance(metrics, dict):
                metrics["redaction_count"] = summary["total_redactions"]

    def _safe_report(self, report: ReviewReport) -> ReviewReport:
        payload = self.boundary.clean(report.model_dump(mode="json"))
        self._refresh_redaction_fields(payload)
        payload = self.boundary.clean(payload)
        self._refresh_redaction_fields(payload)
        safe_report = ReviewReport.model_validate(payload)
        normalized = safe_report.model_dump(mode="json")
        self._refresh_redaction_fields(normalized)
        return ReviewReport.model_validate(normalized)

    def build(
        self,
        *,
        task_id: str,
        task_status: ReviewTaskStatus,
        findings: list[Finding],
        warnings: list[ReviewWarning],
        needs_human_review: list[ReviewWarning],
        filter_intercepts: list[FilterIntercept],
        sandbox_runs: list[SandboxRun],
        telemetry: TelemetrySummary,
        redaction_summary: RedactionSummary,
        input_summary: dict,
    ) -> ReviewReport:
        return self.canonical_report(
            task_id=task_id,
            task_status=task_status,
            findings=findings,
            warnings=warnings,
            needs_human_review=needs_human_review,
            filter_intercepts=filter_intercepts,
            sandbox_runs=sandbox_runs,
            telemetry=telemetry,
            redaction_summary=redaction_summary,
            input_summary=input_summary,
        )

    def canonical_report(
        self,
        *,
        task_id: str,
        task_status: ReviewTaskStatus,
        findings: list[Finding],
        warnings: list[ReviewWarning],
        needs_human_review: list[ReviewWarning],
        filter_intercepts: list[FilterIntercept],
        sandbox_runs: list[SandboxRun],
        telemetry: TelemetrySummary,
        redaction_summary: RedactionSummary,
        input_summary: dict,
        report_paths: dict[str, str] | None = None,
        database_query: str | None = None,
    ) -> ReviewReport:
        """Derive every persisted report field from canonical review inputs."""
        filter_intercepts = sorted(filter_intercepts, key=lambda item: item.request_id)
        sandbox_runs = sorted(sandbox_runs, key=lambda item: item.request_id)
        query_cmd = database_query
        if query_cmd is None:
            query_cmd = ("python examples/skills_code_review_agent/run_review.py query "
                         f"--db-url {self._display_db_url()} --task-id {task_id}")
        severity_distribution = _severity_distribution(findings)
        recommendations = _recommendations(findings, warnings + needs_human_review)
        section_summary = _section_summary(
            findings=findings,
            warnings=warnings,
            needs_human_review=needs_human_review,
            filter_intercepts=filter_intercepts,
            sandbox_runs=sandbox_runs,
            telemetry=telemetry,
            severity_distribution=severity_distribution,
            recommendations=recommendations,
        )
        draft = ReviewReport(
            task_id=task_id,
            task_status=task_status,
            conclusion=_conclusion(task_status, findings, needs_human_review),
            findings=findings,
            warnings=warnings,
            needs_human_review=needs_human_review,
            filter_intercepts=filter_intercepts,
            sandbox_runs=sandbox_runs,
            telemetry=telemetry,
            severity_distribution=severity_distribution,
            section_summary=section_summary,
            redaction_summary=redaction_summary,
            recommendations=recommendations,
            database_query=query_cmd,
            report_paths=report_paths or {},
            input_summary=input_summary,
        )
        return self._safe_report(draft)

    def write(
        self,
        report: ReviewReport,
        *,
        json_name: str = "review_report.json",
        markdown_name: str = "review_report.md",
    ) -> tuple[str, str, ReviewReport]:
        json_text, markdown, safe_report = self.render(
            report,
            json_name=json_name,
            markdown_name=markdown_name,
        )
        self.commit(
            json_text,
            markdown,
            json_name=json_name,
            markdown_name=markdown_name,
        )
        return json_text, markdown, safe_report

    def render(
        self,
        report: ReviewReport,
        *,
        json_name: str = "review_report.json",
        markdown_name: str = "review_report.md",
    ) -> tuple[str, str, ReviewReport]:
        """Render a final report without mutating the filesystem."""
        json_path = self.output_dir / json_name
        md_path = self.output_dir / markdown_name
        report = report.model_copy(
            update={"report_paths": {
                "json": self._display_path(json_path),
                "markdown": self._display_path(md_path),
            }})
        safe_report = self._safe_report(report)
        json_text = json.dumps(safe_report.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, indent=2)
        markdown = self._render_markdown(safe_report)
        return json_text, markdown, safe_report

    def commit(
        self,
        json_text: str,
        markdown: str,
        *,
        json_name: str = "review_report.json",
        markdown_name: str = "review_report.md",
    ) -> None:
        """Stage and promote both files, restoring prior output if promotion fails."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        json_path = self.output_dir / json_name
        md_path = self.output_dir / markdown_name
        nonce = uuid.uuid4().hex
        json_tmp = self.output_dir / f".{json_name}.{nonce}.tmp"
        md_tmp = self.output_dir / f".{markdown_name}.{nonce}.tmp"
        json_backup = self.output_dir / f".{json_name}.{nonce}.bak"
        md_backup = self.output_dir / f".{markdown_name}.{nonce}.bak"
        json_backed_up = False
        markdown_backed_up = False
        json_promoted = False
        markdown_promoted = False
        publication_failure = None
        rollback_incomplete = False
        try:
            json_tmp.write_text(json_text + "\n", encoding="utf-8")
            md_tmp.write_text(markdown, encoding="utf-8")
            if json_path.exists():
                json_path.replace(json_backup)
                json_backed_up = True
            if md_path.exists():
                md_path.replace(md_backup)
                markdown_backed_up = True
            json_tmp.replace(json_path)
            json_promoted = True
            md_tmp.replace(md_path)
            markdown_promoted = True
        except BaseException as exc:
            publication_failure = exc
            for path in (json_tmp, md_tmp):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    rollback_incomplete = True
            for promoted, final in ((json_promoted, json_path), (markdown_promoted, md_path)):
                if not promoted:
                    continue
                try:
                    final.unlink(missing_ok=True)
                except OSError:
                    rollback_incomplete = True
            for backed_up, backup, final in (
                (json_backed_up, json_backup, json_path),
                (markdown_backed_up, md_backup, md_path),
            ):
                if not backed_up:
                    continue
                try:
                    backup.replace(final)
                except OSError:
                    rollback_incomplete = True
        if publication_failure is not None:
            if rollback_incomplete:
                raise RuntimeError("report publication rollback was incomplete") from None
            raise publication_failure from None
        for backup in (json_backup, md_backup):
            try:
                backup.unlink(missing_ok=True)
            except OSError:
                pass

    def _owned_report_paths(
        self,
        *,
        task_id: str,
        json_name: str,
        markdown_name: str,
    ) -> tuple[Path, ...]:
        json_path = self.output_dir / json_name
        markdown_path = self.output_dir / markdown_name
        owned_paths = []
        if json_path.exists():
            try:
                payload = json.loads(json_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict) and payload.get("task_id") == task_id:
                owned_paths.append(json_path)
        if markdown_path.exists():
            prefix = "- Task ID: `"
            for line in markdown_path.read_text(encoding="utf-8").splitlines():
                if line.startswith(prefix) and line.endswith("`"):
                    if line[len(prefix):-1] == task_id:
                        owned_paths.append(markdown_path)
                    break
        return tuple(owned_paths)

    def discard(
        self,
        *,
        task_id: str,
        json_name: str = "review_report.json",
        markdown_name: str = "review_report.md",
    ) -> None:
        """Remove report output only when it belongs to the given task."""
        failure = None
        for path in self._owned_report_paths(
                task_id=task_id,
                json_name=json_name,
                markdown_name=markdown_name,
        ):
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                if failure is None:
                    failure = exc
        public_paths_remain = self._owned_report_paths(
            task_id=task_id,
            json_name=json_name,
            markdown_name=markdown_name,
        )
        if failure is not None:
            raise failure
        if public_paths_remain:
            raise OSError("task-owned report discard did not clear public paths")

    def quarantine(
        self,
        *,
        task_id: str,
        json_name: str = "review_report.json",
        markdown_name: str = "review_report.md",
    ) -> None:
        """Hide task-owned output from public paths without reusing discard."""
        paths = self._owned_report_paths(
            task_id=task_id,
            json_name=json_name,
            markdown_name=markdown_name,
        )
        quarantined = []
        failure = None
        nonce = uuid.uuid4().hex
        for path in paths:
            if not path.exists():
                continue
            hidden = self.output_dir / f".{path.name}.{nonce}.failed"
            try:
                path.replace(hidden)
                quarantined.append(hidden)
            except OSError as exc:
                if failure is None:
                    failure = exc
        public_paths_remain = any(path.exists() for path in paths)
        for path in quarantined:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        if public_paths_remain:
            if failure is not None:
                raise failure
            raise OSError("task-owned report quarantine did not clear public paths")

    def to_markdown(self, report: ReviewReport) -> str:
        return self._render_markdown(self._safe_report(report))

    @staticmethod
    def _render_markdown(report: ReviewReport) -> str:
        lines = [
            "# Code Review Report",
            "",
            f"- Task ID: `{report.task_id}`",
            f"- Status: `{report.task_status.value}`",
            f"- Schema version: `{report.schema_version}`",
            f"- Conclusion: {report.conclusion}",
            f"- Database query: `{report.database_query}`",
            "",
            "## Findings Summary",
            "",
            f"- Findings: {len(report.findings)}",
            f"- Warnings: {len(report.warnings)}",
            f"- Needs human review: {len(report.needs_human_review)}",
            "",
            "## Severity Stats",
            "",
            f"- Distribution: `{json.dumps(report.severity_distribution, sort_keys=True)}`",
            "",
        ]
        if report.findings:
            lines.extend(["## Findings", ""])
            for finding in report.findings:
                lines.extend([
                    f"### {finding.severity.upper()} {finding.category}: {finding.title}",
                    "",
                    f"- Location: `{finding.file}:{finding.line}`",
                    f"- Evidence: `{finding.evidence}`",
                    f"- Confidence: {finding.confidence:.2f}",
                    f"- Source: `{', '.join(finding.source)}`",
                    f"- Recommendation: {finding.recommendation}",
                    "",
                ])
        lines.extend([
            "## Human Review",
            "",
            f"- Warnings: {len(report.warnings)}",
            f"- Needs human review: {len(report.needs_human_review)}",
        ])
        for warning in [*report.warnings, *report.needs_human_review]:
            marker = "needs human review" if warning.needs_human_review else "warning"
            location = f"{warning.file}:{warning.line}" if warning.file else "n/a"
            lines.append(f"- {marker}: {warning.category} `{location}` {warning.title} "
                         f"(confidence {warning.confidence:.2f}) - {warning.message}")
        lines.append("")
        lines.extend([
            "## Filter Summary",
            "",
            f"- Denied: {report.telemetry.filter_denied_count}",
            f"- Needs human review: {report.telemetry.filter_needs_review_count}",
            "",
        ])
        for intercept in report.filter_intercepts:
            lines.append(f"- {intercept.decision} ({intercept.error_kind or 'none'}): "
                         f"`{' '.join(intercept.command)}` - {intercept.reason}")
        lines.extend([
            "",
            "## Sandbox Summary",
            "",
            f"- Runs: {len(report.sandbox_runs)}",
            f"- Attempts: {report.telemetry.tool_attempts_count}",
            f"- Executions: {report.telemetry.tool_executed_count}",
            f"- Failures/timeouts: {report.telemetry.sandbox_failures_count}",
            f"- Stdout truncated: {report.telemetry.stdout_truncated_count}",
            f"- Stderr truncated: {report.telemetry.stderr_truncated_count}",
            f"- Output files truncated: {report.telemetry.output_truncated_count}",
        ])
        for run in report.sandbox_runs:
            lines.append(f"- `{' '.join(run.command)}` exit={run.exit_code} timed_out={run.timed_out} "
                         f"stdout_truncated={run.stdout_truncated} stderr_truncated={run.stderr_truncated} "
                         f"output_truncated={run.output_truncated} "
                         f"execution_started={run.execution_started} "
                         f"termination_reason={run.termination_reason or 'none'} "
                         f"termination_confirmed={run.termination_confirmed} "
                         f"stdout_bytes={len(run.stdout.encode('utf-8'))}/{run.stdout_bytes_observed} "
                         f"stderr_bytes={len(run.stderr.encode('utf-8'))}/{run.stderr_bytes_observed} "
                         f"output_bytes={run.output_bytes}/{run.output_bytes_observed}")
        lines.extend([
            "",
            "## Metrics",
            "",
            f"- Orchestration elapsed ms: {report.telemetry.orchestration_elapsed_ms}",
            f"- Sandbox elapsed ms: {report.telemetry.sandbox_elapsed_ms}",
            f"- Severity distribution: `{json.dumps(report.telemetry.severity_distribution, sort_keys=True)}`",
            f"- Exception distribution: `{json.dumps(report.telemetry.exception_kind_distribution, sort_keys=True)}`",
            f"- Output limit exceeded: {report.telemetry.output_limit_exceeded_count}",
            f"- Files changed: {report.telemetry.files_changed}",
            f"- Added lines: {report.telemetry.lines_added}",
            f"- Redactions: {report.telemetry.redaction_count}",
            f"- Debug dropped: {report.telemetry.debug_dropped_count}",
            "",
            "## Redaction Summary",
            "",
            f"- By type: `{json.dumps(report.redaction_summary.by_type, sort_keys=True)}`",
            "",
            "## Recommendations",
            "",
        ])
        lines.extend([f"- {item}" for item in report.recommendations] or ["- No executable recommendations."])
        lines.append("")
        return "\n".join(lines)
