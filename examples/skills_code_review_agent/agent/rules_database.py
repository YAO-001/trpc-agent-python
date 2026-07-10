# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Database lifecycle rules."""

from __future__ import annotations

import re

from .models import ChangedLine
from .models import Finding


def _nearby_text(line: ChangedLine) -> str:
    return "\n".join(line.context_before + [line.content] + line.context_after).lower()


def _finding(
    line: ChangedLine,
    title: str,
    evidence: str,
    recommendation: str,
    confidence: float,
    severity: str = "medium",
) -> Finding:
    return Finding(
        severity=severity,
        category="database",
        file=line.file,
        line=line.line,
        title=title,
        evidence=evidence.strip(),
        recommendation=recommendation,
        confidence=confidence,
        source=["rule:database"],
    )


def run_database_rules(lines: list[ChangedLine]) -> list[Finding]:
    findings: list[Finding] = []
    for line in lines:
        text = line.content.strip()
        lower = text.lower()
        nearby = _nearby_text(line)
        starts_with_context = lower.startswith("with ") or lower.startswith("async with ")
        opens_connection = ("sqlite3.connect(" in lower
                            or (".connect(" in lower and ("engine" in lower or "db" in lower))
                            or re.search(r"\bsession\s*=\s*session\(", lower) is not None)
        if opens_connection and not starts_with_context and ".close(" not in nearby:
            findings.append(
                _finding(
                    line,
                    "database connection/session is not closed",
                    text,
                    "Use a context manager or close the connection/session in a finally block.",
                    0.86,
                ))
        if ".begin(" in lower or lower.endswith(".begin()"):
            if "rollback" not in nearby and "except" in nearby:
                findings.append(
                    _finding(
                        line,
                        "transaction begin lacks rollback on exception path",
                        text,
                        "Rollback in except/finally or use a transaction context manager.",
                        0.72,
                    ))
    return findings
