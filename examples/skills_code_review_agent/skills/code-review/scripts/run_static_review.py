#!/usr/bin/env python3
# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Stdlib-only sandbox helper for deterministic static review findings."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


_SUBPROCESS_SHELL_RE = re.compile(
    r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\(.*\bshell\s*=\s*True\b"
)
_EVAL_EXEC_RE = re.compile(r"\b(?:eval|exec)\s*\(")
_OPEN_RE = re.compile(r"(?<![\w.])open\s*\(")
_BUSINESS_PREFIXES = ("src/", "app/", "lib/", "package/")


def _line_text(line: dict[str, Any]) -> str:
    return str(line.get("content") or "").strip()


def _line_file(line: dict[str, Any]) -> str:
    return str(line.get("file") or "")


def _line_number(line: dict[str, Any]) -> int:
    try:
        return int(line.get("line") or 0)
    except (TypeError, ValueError):
        return 0


def _finding(
    line: dict[str, Any],
    *,
    severity: str,
    category: str,
    title: str,
    recommendation: str,
    confidence: float,
    rule_name: str,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "category": category,
        "file": _line_file(line),
        "line": _line_number(line),
        "title": title,
        "evidence": _line_text(line),
        "recommendation": recommendation,
        "confidence": confidence,
        "source": ["run_static_review.py", f"skill-rule:{rule_name}"],
    }


def _same_file_nearby(lines: list[dict[str, Any]], target: dict[str, Any], *, radius: int = 6) -> list[str]:
    target_file = _line_file(target)
    target_line = _line_number(target)
    nearby: list[str] = []
    for line in lines:
        if _line_file(line) != target_file:
            continue
        line_number = _line_number(line)
        if abs(line_number - target_line) <= radius:
            nearby.append(_line_text(line).lower())
    return nearby


def _has_lifecycle_signal(lines: list[dict[str, Any]], target: dict[str, Any]) -> bool:
    nearby = _same_file_nearby(lines, target)
    return any(
        ".close(" in text
        or "finally:" in text
        or text.startswith("with ")
        or text.startswith("async with ")
        for text in nearby
    )


def _is_test_file(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    return (
        normalized.startswith("tests/")
        or "/tests/" in normalized
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def _is_business_python_file(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return normalized.endswith(".py") and normalized.startswith(_BUSINESS_PREFIXES) and not _is_test_file(normalized)


def _run_rules(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    lines = [line for line in payload.get("added_lines", []) if isinstance(line, dict)]
    changed_files = [str(path) for path in payload.get("changed_files", [])]
    findings: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    for line in lines:
        text = _line_text(line)
        lower = text.lower()
        if _SUBPROCESS_SHELL_RE.search(text):
            findings.append(
                _finding(
                    line,
                    severity="high",
                    category="security",
                    title="subprocess invoked with shell=True",
                    recommendation=(
                        "Pass an argv list with shell=False and validate the executable explicitly."
                    ),
                    confidence=0.92,
                    rule_name="subprocess_shell_true",
                )
            )
        if _EVAL_EXEC_RE.search(text):
            findings.append(
                _finding(
                    line,
                    severity="high",
                    category="security",
                    title="dynamic code execution in changed code",
                    recommendation="Avoid eval/exec; use explicit parsing or a safe dispatch table.",
                    confidence=0.90,
                    rule_name="eval_exec",
                )
            )
        if (
            ("sqlite3.connect(" in lower or "engine.connect(" in lower or "session(" in lower)
            and not lower.startswith(("with ", "async with "))
            and not _has_lifecycle_signal(lines, line)
        ):
            findings.append(
                _finding(
                    line,
                    severity="medium",
                    category="database",
                    title="database connection/session may not be closed",
                    recommendation=(
                        "Use a context manager or close the connection/session in a finally block."
                    ),
                    confidence=0.82,
                    rule_name="database_lifecycle",
                )
            )
        if _OPEN_RE.search(text) and "with open(" not in lower and not _has_lifecycle_signal(lines, line):
            findings.append(
                _finding(
                    line,
                    severity="medium",
                    category="resource",
                    title="file handle may not be closed",
                    recommendation="Use with open(...) as f or close the file in a finally block.",
                    confidence=0.80,
                    rule_name="open_without_context",
                )
            )
        if "aiohttp.clientsession(" in lower and "async with" not in lower and not _has_lifecycle_signal(lines, line):
            findings.append(
                _finding(
                    line,
                    severity="medium",
                    category="async_resource",
                    title="aiohttp ClientSession may not be closed",
                    recommendation=(
                        "Use async with aiohttp.ClientSession(...) or close the session in a finally block."
                    ),
                    confidence=0.82,
                    rule_name="aiohttp_session_lifecycle",
                )
            )

    if any(_is_business_python_file(path) for path in changed_files) and not any(
        _is_test_file(path) for path in changed_files
    ):
        warnings.append(
            {
                "category": "test",
                "title": "code changed without an accompanying test change",
                "message": "Business code changed, but the diff does not include a test file.",
                "confidence": 0.72,
                "needs_human_review": False,
                "source": ["run_static_review.py", "skill-rule:missing_tests"],
            }
        )

    return findings, warnings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    findings, warnings = _run_rules(payload)
    output = {
        "task_id": payload.get("task_id", ""),
        "status": "ok",
        "changed_files": len(payload.get("changed_files", [])),
        "added_lines": len(payload.get("added_lines", [])),
        "fixtures": payload.get("fixture_names", []),
        "findings": findings,
        "warnings": warnings,
        "needs_human_review": [],
    }
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
