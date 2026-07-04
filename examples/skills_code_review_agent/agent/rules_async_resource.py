# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Async and resource lifecycle rules."""

from __future__ import annotations

import re

from .models import ChangedLine
from .models import Finding


def _nearby_text(line: ChangedLine) -> str:
    return "\n".join(line.context_before + [line.content] + line.context_after).lower()


def _finding(line: ChangedLine, title: str, evidence: str, recommendation: str, confidence: float, severity: str = "medium") -> Finding:
    return Finding(
        severity=severity,
        category="async_resource",
        file=line.file,
        line=line.line,
        title=title,
        evidence=evidence.strip(),
        recommendation=recommendation,
        confidence=confidence,
        source=["rule:async_resource"],
    )


def run_async_resource_rules(lines: list[ChangedLine]) -> list[Finding]:
    findings: list[Finding] = []
    for line in lines:
        text = line.content.strip()
        lower = text.lower()
        nearby = _nearby_text(line)
        if "aiohttp.clientsession(" in lower and "async with" not in lower and ".close(" not in nearby:
            findings.append(
                _finding(
                    line,
                    "aiohttp ClientSession is not closed",
                    text,
                    "Use async with aiohttp.ClientSession(...) or close the session in a finally block.",
                    0.86,
                )
            )
        if re.search(r"(?<![\w.])open\(", text) and not lower.startswith("with ") and ".close(" not in nearby:
            findings.append(
                _finding(
                    line,
                    "file handle opened without a context manager",
                    text,
                    "Use with open(...) as f so the descriptor is closed on every path.",
                    0.84,
                )
            )
        if "asyncio.create_task(" in lower:
            assigned = "=" in text.split("asyncio.create_task(", 1)[0]
            awaited = lower.startswith("await ") or "gather(" in lower
            if not assigned and not awaited:
                findings.append(
                    _finding(
                        line,
                        "asyncio.create_task result is not tracked",
                        text,
                        "Store the task and await, gather, or cancel it during shutdown.",
                        0.72,
                        "low",
                    )
                )
        if ".acquire(" in lower and "with " not in lower and ".release(" not in nearby:
            findings.append(
                _finding(
                    line,
                    "lock acquired without an obvious release",
                    text,
                    "Use a with/async with lock guard or release the lock in a finally block.",
                    0.74,
                )
            )
    return findings

