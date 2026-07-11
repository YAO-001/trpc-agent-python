# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""JSON and Markdown report generation."""

from __future__ import annotations

import json
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from .models import FilterIntercept
from .models import Finding
from .models import RedactionSummary
from .models import ReviewReport
from .models import ReviewWarning
from .models import SandboxRun
from .models import TelemetrySummary
from .redaction_boundary import RedactionBoundary


def _severity_distribution(findings: list[Finding]) -> dict[str, int]:
    distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        distribution[finding.severity] = distribution.get(finding.severity, 0) + 1
    return {key: value for key, value in distribution.items() if value}


def _conclusion(findings: list[Finding], needs_human_review: list[ReviewWarning]) -> str:
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
    return {
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
        },
        "metrics": telemetry.model_dump(mode="json"),
        "sandbox_summary": {
            "runs": len(sandbox_runs),
            "failures_or_timeouts": telemetry.sandbox_failures_count,
            "stdout_truncated": telemetry.stdout_truncated_count,
            "stderr_truncated": telemetry.stderr_truncated_count,
            "output_truncated": telemetry.output_truncated_count,
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
        findings: list[Finding],
        warnings: list[ReviewWarning],
        needs_human_review: list[ReviewWarning],
        filter_intercepts: list[FilterIntercept],
        sandbox_runs: list[SandboxRun],
        telemetry: TelemetrySummary,
        redaction_summary: RedactionSummary,
        input_summary: dict,
    ) -> ReviewReport:
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
            conclusion=_conclusion(findings, needs_human_review),
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
        self.output_dir.mkdir(parents=True, exist_ok=True)
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
        json_path.write_text(json_text + "\n", encoding="utf-8")
        md_path.write_text(markdown, encoding="utf-8")
        return json_text, markdown, safe_report

    def to_markdown(self, report: ReviewReport) -> str:
        return self._render_markdown(self._safe_report(report))

    @staticmethod
    def _render_markdown(report: ReviewReport) -> str:
        lines = [
            "# Code Review Report",
            "",
            f"- Task ID: `{report.task_id}`",
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
            lines.append(f"- {intercept.decision}: `{' '.join(intercept.command)}` - {intercept.reason}")
        lines.extend([
            "",
            "## Sandbox Summary",
            "",
            f"- Runs: {len(report.sandbox_runs)}",
            f"- Failures/timeouts: {report.telemetry.sandbox_failures_count}",
            f"- Stdout truncated: {report.telemetry.stdout_truncated_count}",
            f"- Stderr truncated: {report.telemetry.stderr_truncated_count}",
            f"- Output files truncated: {report.telemetry.output_truncated_count}",
        ])
        for run in report.sandbox_runs:
            lines.append(f"- `{' '.join(run.command)}` exit={run.exit_code} timed_out={run.timed_out} "
                         f"stdout_truncated={run.stdout_truncated} stderr_truncated={run.stderr_truncated} "
                         f"output_truncated={run.output_truncated}")
        lines.extend([
            "",
            "## Metrics",
            "",
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
