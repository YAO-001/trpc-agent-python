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

from .models import FilterIntercept
from .models import Finding
from .models import RedactionSummary
from .models import ReviewReport
from .models import ReviewWarning
from .models import SandboxRun
from .models import TelemetrySummary


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


def _posix_path(path: Path) -> str:
    return PurePosixPath(*path.parts).as_posix()


class ReportBuilder:
    def __init__(self, output_dir: Path, db_url: str) -> None:
        self.output_dir = output_dir
        self.db_url = db_url

    def _display_path(self, path: Path) -> str:
        resolved = path.resolve()
        for base in [Path.cwd().resolve(), self.output_dir.resolve().parent]:
            try:
                return _posix_path(resolved.relative_to(base))
            except ValueError:
                continue
        return path.name

    def _display_db_url(self) -> str:
        prefix = "sqlite:///"
        if not self.db_url.startswith(prefix) or self.db_url == "sqlite:///:memory:":
            return self.db_url
        db_path = Path(self.db_url.removeprefix(prefix))
        if not db_path.is_absolute():
            return prefix + _posix_path(db_path)
        return prefix + self._display_path(db_path)

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
        query_cmd = (
            "python examples/skills_code_review_agent/run_review.py query "
            f"--db-url {self._display_db_url()} --task-id {task_id}"
        )
        return ReviewReport(
            task_id=task_id,
            conclusion=_conclusion(findings, needs_human_review),
            findings=findings,
            warnings=warnings,
            needs_human_review=needs_human_review,
            filter_intercepts=[item for item in filter_intercepts if item.decision in {"deny", "needs_human_review"}],
            sandbox_runs=sandbox_runs,
            telemetry=telemetry,
            severity_distribution=_severity_distribution(findings),
            redaction_summary=redaction_summary,
            recommendations=_recommendations(findings, warnings + needs_human_review),
            database_query=query_cmd,
            input_summary=input_summary,
        )

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
            update={
                "report_paths": {
                    "json": self._display_path(json_path),
                    "markdown": self._display_path(md_path),
                }
            }
        )
        json_text = json.dumps(report.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, indent=2)
        markdown = self.to_markdown(report)
        json_path.write_text(json_text + "\n", encoding="utf-8")
        md_path.write_text(markdown, encoding="utf-8")
        return json_text, markdown, report

    def to_markdown(self, report: ReviewReport) -> str:
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
            f"- Severity distribution: `{json.dumps(report.severity_distribution, sort_keys=True)}`",
            "",
        ]
        if report.findings:
            lines.extend(["## Findings", ""])
            for finding in report.findings:
                lines.extend(
                    [
                        f"### {finding.severity.upper()} {finding.category}: {finding.title}",
                        "",
                        f"- Location: `{finding.file}:{finding.line}`",
                        f"- Evidence: `{finding.evidence}`",
                        f"- Confidence: {finding.confidence:.2f}",
                        f"- Source: `{', '.join(finding.source)}`",
                        f"- Recommendation: {finding.recommendation}",
                        "",
                    ]
                )
        if report.warnings or report.needs_human_review:
            lines.extend(["## Warnings And Human Review", ""])
            for warning in [*report.warnings, *report.needs_human_review]:
                marker = "needs human review" if warning.needs_human_review else "warning"
                location = f"{warning.file}:{warning.line}" if warning.file else "n/a"
                lines.append(
                    f"- {marker}: {warning.category} `{location}` {warning.title} "
                    f"(confidence {warning.confidence:.2f}) - {warning.message}"
                )
            lines.append("")
        lines.extend(
            [
                "## Filter Intercepts",
                "",
                f"- Denied: {report.telemetry.filter_denied_count}",
                f"- Needs human review: {report.telemetry.filter_needs_review_count}",
                "",
            ]
        )
        for intercept in report.filter_intercepts:
            lines.append(f"- {intercept.decision}: `{' '.join(intercept.command)}` - {intercept.reason}")
        lines.extend(
            [
                "",
                "## Sandbox Execution",
                "",
                f"- Runs: {len(report.sandbox_runs)}",
                f"- Failures/timeouts: {report.telemetry.sandbox_failures_count}",
                f"- Stdout truncated: {report.telemetry.stdout_truncated_count}",
                f"- Stderr truncated: {report.telemetry.stderr_truncated_count}",
                f"- Output files truncated: {report.telemetry.output_truncated_count}",
            ]
        )
        for run in report.sandbox_runs:
            lines.append(
                f"- `{' '.join(run.command)}` exit={run.exit_code} timed_out={run.timed_out} "
                f"stdout_truncated={run.stdout_truncated} stderr_truncated={run.stderr_truncated} "
                f"output_truncated={run.output_truncated}"
            )
        lines.extend(
            [
                "",
                "## Telemetry",
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
                "## Executable Recommendations",
                "",
            ]
        )
        lines.extend([f"- {item}" for item in report.recommendations] or ["- No executable recommendations."])
        lines.append("")
        return "\n".join(lines)
