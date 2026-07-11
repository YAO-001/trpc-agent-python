# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Deterministic rule engine and confidence routing."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .dedupe import dedupe_findings
from .diff_parser import is_test_file
from .models import ChangedLine
from .models import Finding
from .models import ParsedDiff
from .models import RedactionEvent
from .models import RedactionSummary
from .models import ReviewWarning
from .rules_async_resource import run_async_resource_rules
from .rules_database import run_database_rules
from .rules_security import run_security_rules
from .rules_tests import run_test_rules
from .secret_redactor import SecretRedactor

_PLACEHOLDER_RE = SecretRedactor.PLACEHOLDER_RE


def _is_fixture_file(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return (normalized.startswith("fixtures/") or "/fixtures/" in normalized
            or "fixture" in normalized.rsplit("/", 1)[-1])


@dataclass
class RuleEngineResult:
    findings: list[Finding]
    warnings: list[ReviewWarning]
    needs_human_review: list[ReviewWarning]
    debug_dropped_count: int = 0


def _secret_findings(
    lines: list[ChangedLine],
    redaction_summary: RedactionSummary,
) -> list[Finding]:
    events: dict[tuple[str, str], list[RedactionEvent]] = {}
    for event in redaction_summary.events:
        events.setdefault((event.secret_type, event.sha256[:8]), []).append(event)
    findings: list[Finding] = []
    for line in lines:
        matches = list(_PLACEHOLDER_RE.finditer(line.content))
        if not matches:
            continue
        if is_test_file(line.file) or _is_fixture_file(line.file):
            continue

        def is_likely_placeholder(match: re.Match[str]) -> bool:
            matching_events = events.get((match.group("type"), match.group("hash")), [])
            return len(matching_events) == 1 and matching_events[0].likely_placeholder

        confidence = 0.58 if all(is_likely_placeholder(match) for match in matches) else 0.99
        selected = next((match for match in matches if not is_likely_placeholder(match)), matches[0])
        secret_type = selected.group("type")
        findings.append(
            Finding(
                severity="high",
                category="secret",
                file=line.file,
                line=line.line,
                title=f"{secret_type} secret added to source",
                evidence=line.content.strip(),
                recommendation="Remove the secret from source, rotate it, and load it from a managed secret store.",
                confidence=confidence,
                source=["rule:secret", f"redactor:{secret_type}"],
            ))
    return findings


def _warning_from_finding(finding: Finding, needs_human_review: bool) -> ReviewWarning:
    return ReviewWarning(
        category=finding.category,
        title=finding.title,
        message=f"{finding.evidence} Recommendation: {finding.recommendation}",
        file=finding.file,
        line=finding.line,
        confidence=finding.confidence,
        source=finding.source,
        needs_human_review=needs_human_review,
    )


class RuleEngine:
    high_confidence_threshold = 0.80
    low_confidence_threshold = 0.50

    def run(
        self,
        parsed_diff: ParsedDiff,
        redaction_summary: RedactionSummary,
    ) -> RuleEngineResult:
        raw_findings: list[Finding] = []
        raw_findings.extend(run_security_rules(parsed_diff.added_lines))
        raw_findings.extend(_secret_findings(parsed_diff.added_lines, redaction_summary))
        raw_findings.extend(run_async_resource_rules(parsed_diff.added_lines))
        raw_findings.extend(run_database_rules(parsed_diff.added_lines))
        raw_findings.extend(run_test_rules(parsed_diff))

        findings: list[Finding] = []
        warnings: list[ReviewWarning] = []
        needs_human_review: list[ReviewWarning] = []
        dropped = 0
        for finding in dedupe_findings(raw_findings):
            if finding.confidence >= self.high_confidence_threshold:
                findings.append(finding)
            elif finding.confidence >= self.low_confidence_threshold:
                needs_review = finding.severity in {"medium", "high", "critical"} and finding.confidence < 0.80
                warning = _warning_from_finding(finding, needs_review)
                if needs_review:
                    needs_human_review.append(warning)
                else:
                    warnings.append(warning)
            else:
                dropped += 1
        return RuleEngineResult(
            findings=findings,
            warnings=sorted(warnings, key=lambda item: (item.file, item.line, item.category, item.title)),
            needs_human_review=sorted(
                needs_human_review,
                key=lambda item: (item.file, item.line, item.category, item.title),
            ),
            debug_dropped_count=dropped,
        )
