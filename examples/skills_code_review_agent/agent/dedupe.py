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
    grouped: dict[tuple[str, int, str], list[Finding]] = {}
    for finding in findings:
        key = (finding.file, finding.line, finding.category)
        grouped.setdefault(key, []).append(finding)

    merged: list[Finding] = []
    for values in grouped.values():
        representative = max(
            values,
            key=lambda item: (
                item.confidence,
                severity_rank(item.severity),
                item.title,
                item.evidence,
                item.recommendation,
                tuple(item.source),
            ),
        )
        severity = max(values, key=lambda item: severity_rank(item.severity)).severity
        confidence = max(item.confidence for item in values)
        sources = sorted({source for item in values for source in item.source})
        payload = representative.model_dump(mode="json")
        payload.update({"severity": severity, "confidence": confidence, "source": sources})
        merged.append(Finding.model_validate(payload))
    return sorted(
        merged,
        key=lambda item: (item.file, item.line, item.category, item.title, item.evidence, item.recommendation),
    )


def _warning_message_prefix(message: str) -> str:
    return normalize_title(message)[:160]


def dedupe_warnings(warnings: list[ReviewWarning]) -> list[ReviewWarning]:
    grouped: dict[tuple[str, str, int, str, str], list[ReviewWarning]] = {}
    for warning in warnings:
        key = (
            warning.category,
            warning.file,
            warning.line,
            normalize_title(warning.title),
            _warning_message_prefix(warning.message),
        )
        grouped.setdefault(key, []).append(warning)

    merged: list[ReviewWarning] = []
    for values in grouped.values():
        representative = max(
            values,
            key=lambda item: (
                item.confidence,
                item.title,
                item.message,
                item.file,
                item.line,
                item.category,
                tuple(item.source),
            ),
        )
        payload = representative.model_dump(mode="json")
        payload.update({
            "confidence": max(item.confidence for item in values),
            "source": sorted({source
                              for item in values
                              for source in item.source}),
            "needs_human_review": any(item.needs_human_review for item in values),
        })
        merged.append(ReviewWarning.model_validate(payload))
    return sorted(
        merged,
        key=lambda item: (item.file, item.line, item.category, item.title, item.message),
    )
