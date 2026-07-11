# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Deterministic production of raw host review candidates."""

from __future__ import annotations

import re

from .diff_parser import is_test_file
from .models import ChangedLine
from .models import Finding
from .models import ParsedDiff
from .models import RedactionEvent
from .models import RedactionSummary
from .result_normalizer import ReviewCandidates
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


class RuleEngine:

    def run(
        self,
        parsed_diff: ParsedDiff,
        redaction_summary: RedactionSummary,
    ) -> ReviewCandidates:
        return ReviewCandidates(findings=[
            *run_security_rules(parsed_diff.added_lines),
            *_secret_findings(parsed_diff.added_lines, redaction_summary),
            *run_async_resource_rules(parsed_diff.added_lines),
            *run_database_rules(parsed_diff.added_lines),
            *run_test_rules(parsed_diff),
        ])
