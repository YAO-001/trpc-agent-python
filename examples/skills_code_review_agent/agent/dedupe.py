# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Finding deduplication helpers."""

from __future__ import annotations

from .models import Finding
from .models import ReviewWarning
from .models import normalize_title


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity.lower(), 0)


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    grouped: dict[tuple[str, int, str], Finding] = {}
    merged_sources: dict[tuple[str, int, str], set[str]] = {}
    for finding in findings:
        key = (finding.file, finding.line, finding.category)
        merged_sources.setdefault(key, set()).update(finding.source)
        current = grouped.get(key)
        if current is None:
            grouped[key] = finding
            continue
        if (
            severity_rank(finding.severity),
            finding.confidence,
        ) > (severity_rank(current.severity), current.confidence):
            grouped[key] = finding
    return sorted(
        [
            finding.model_copy(update={"source": sorted(merged_sources.get(key, set()))})
            for key, finding in grouped.items()
        ],
        key=lambda item: (item.file, item.line, item.category, item.title),
    )


def _warning_message_prefix(message: str) -> str:
    return normalize_title(message)[:160]


def dedupe_warnings(warnings: list[ReviewWarning]) -> list[ReviewWarning]:
    grouped: dict[tuple[str, str, int, str, str], ReviewWarning] = {}
    merged_sources: dict[tuple[str, str, int, str, str], set[str]] = {}
    for warning in warnings:
        key = (
            warning.category,
            warning.file,
            warning.line,
            normalize_title(warning.title),
            _warning_message_prefix(warning.message),
        )
        merged_sources.setdefault(key, set()).update(warning.source)
        current = grouped.get(key)
        if current is None:
            grouped[key] = warning
            continue
        if warning.confidence > current.confidence:
            grouped[key] = warning
        if warning.needs_human_review and not grouped[key].needs_human_review:
            grouped[key] = grouped[key].model_copy(update={"needs_human_review": True})
    return sorted(
        [
            warning.model_copy(update={"source": sorted(merged_sources.get(key, set()))})
            for key, warning in grouped.items()
        ],
        key=lambda item: (item.file, item.line, item.category, item.title, item.message),
    )
