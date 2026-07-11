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
    r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\(.*\bshell\s*=\s*True\b",
    re.IGNORECASE,
)
_POPEN_SHELL_RE = re.compile(r"(?<![\w.])popen\s*\(.*\bshell\s*=\s*True\b", re.IGNORECASE)
_EVAL_EXEC_RE = re.compile(r"\b(?:eval|exec)\s*\(")
_OS_SYSTEM_RE = re.compile(r"\bos\.system\s*\(")
_OPEN_RE = re.compile(r"(?<![\w.])open\s*\(")
_SQLALCHEMY_SESSION_RE = re.compile(r"(?<![A-Za-z0-9_])Session\s*\(")
_SECRET_TYPES = (
    "pem_private_key",
    "aws_access_key",
    "github_token",
    "openai_key",
    "jwt",
    "bearer_token",
    "credential_url",
    "generic_assignment",
)
_SECRET_TYPE_PATTERN = "|".join(map(re.escape, _SECRET_TYPES))
_SECRET_PLACEHOLDER_RE = re.compile(rf"\[REDACTED:SECRET:(?P<type>{_SECRET_TYPE_PATTERN}):(?P<hash>[a-f0-9]{{8}})\]", )
_GENERIC_SECRET_ASSIGNMENT_RE = re.compile(
    r"\b(?:password|passwd|token|api_key|apikey|secret)\b\s*=\s*['\"]([^'\"]{8,})['\"]",
    re.IGNORECASE,
)
_SQL_TOKEN_RE = re.compile(r"\b(select|insert|update|delete|where)\b", re.IGNORECASE)
_SQL_NAMED_BIND_RE = re.compile(r":[A-Za-z_][A-Za-z0-9_]*")
_PRODUCTION_PREFIXES = ("src/", "app/", "service/", "package/")
_DUMMY_SECRET_MARKER_RE = re.compile(
    r"(?:^|[^a-z0-9])(?:change-me|changeme|dummy|example|fixture|placeholder|sample|sk-test|tests?)"
    r"(?:$|[^a-z0-9])",
    re.IGNORECASE,
)


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


def _context_values(line: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("context_before", "context_after"):
        context = line.get(key) or []
        if isinstance(context, list):
            values.extend(str(item) for item in context)
    return values


def _same_file_nearby(lines: list[dict[str, Any]], target: dict[str, Any], *, radius: int = 8) -> list[str]:
    target_file = _line_file(target)
    target_line = _line_number(target)
    nearby: list[str] = [item.strip().lower() for item in _context_values(target)]
    for line in lines:
        if _line_file(line) != target_file:
            continue
        line_number = _line_number(line)
        if abs(line_number - target_line) <= radius:
            nearby.append(_line_text(line).lower())
    return nearby


def _has_lifecycle_signal(lines: list[dict[str, Any]], target: dict[str, Any]) -> bool:
    nearby = _same_file_nearby(lines, target)
    return any(".close(" in text or "close()" in text or "finally:" in text or "contextlib.closing" in text
               or "closing(" in text or text.startswith("with ") or text.startswith("async with ") for text in nearby)


def _is_test_file(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    return (normalized.startswith("tests/") or "/tests/" in normalized or name.startswith("test_")
            or name.endswith("_test.py"))


def _is_fixture_file(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return (normalized.startswith("fixtures/") or "/fixtures/" in normalized
            or "fixture" in normalized.rsplit("/", 1)[-1])


def _is_business_python_file(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return normalized.endswith(".py") and normalized.startswith(_PRODUCTION_PREFIXES) and not _is_test_file(normalized)


def _is_database_lifecycle_candidate(text: str) -> bool:
    lower = text.lower()
    return ("sqlite3.connect(" in lower or "engine.connect(" in lower or bool(_SQLALCHEMY_SESSION_RE.search(text)))


def _has_user_controlled_data(lower: str) -> bool:
    return any(marker in lower for marker in ("request", "user", "input", "args", "body", "data"))


def _execute_args_text(text: str) -> str:
    match = re.search(r"\bexecute\s*\((?P<args>.*)\)\s*$", text, re.IGNORECASE)
    return match.group("args") if match else ""


def _is_parameterized_execute(text: str, lower: str) -> bool:
    if "execute(" not in lower:
        return False
    args_text = _execute_args_text(text)
    if not args_text or "," not in args_text:
        return False
    if re.search(r"\bexecute\s*\([^,]+,\s*(?:\(|\[|\{)", text, re.IGNORECASE):
        return True
    if "?" in args_text and re.search(r",\s*(?:\(|\[)", args_text):
        return True
    if _SQL_NAMED_BIND_RE.search(args_text) and (re.search(r",\s*(?:\{|\w)", args_text) or "bindparam(" in lower
                                                 or ".bindparams(" in lower):
        return True
    return False


def _is_sql_interpolation_candidate(text: str, lower: str) -> bool:
    if "execute(" not in lower or not _SQL_TOKEN_RE.search(text):
        return False
    if _is_parameterized_execute(text, lower):
        return False
    if not _has_user_controlled_data(lower):
        return False
    args_text = _execute_args_text(text)
    return ('execute(f"' in lower or "execute(f'" in lower or ".format(" in lower or " % " in text or "%" in args_text
            or bool(re.search(r"\+.*\b(request|user|input|args|body|data)\b", args_text, re.IGNORECASE)))


def _is_yaml_load_without_safe_loader(lower: str) -> bool:
    return "yaml.load(" in lower and "safeloader" not in lower and "safe_load(" not in lower


def _is_pickle_loads_on_untrusted_data(lower: str) -> bool:
    return "pickle.loads(" in lower and _has_user_controlled_data(lower)


def _placeholder_signal(
    text: str,
    event_flags: dict[tuple[str, str], list[bool]],
) -> tuple[float, bool] | None:
    matches = list(_SECRET_PLACEHOLDER_RE.finditer(text))
    if not matches:
        return None
    all_likely_placeholders = all(
        len(flags) == 1 and flags[0] for match in matches
        for flags in [event_flags.get((match.group("type"), match.group("hash")), [])])
    return (0.58, True) if all_likely_placeholders else (0.99, False)


def _redaction_event_flags(payload: dict[str, Any]) -> dict[tuple[str, str], list[bool]]:
    summary = payload.get("redaction_summary") or {}
    if not isinstance(summary, dict):
        return {}
    flags: dict[tuple[str, str], list[bool]] = {}
    for event in summary.get("events") or []:
        if not isinstance(event, dict):
            continue
        secret_type = str(event.get("secret_type") or "")
        digest = str(event.get("sha256") or "")
        if secret_type and len(digest) >= 8:
            flags.setdefault((secret_type, digest[:8]), []).append(bool(event.get("likely_placeholder")))
    return flags


def _secret_assignment_value(text: str) -> str | None:
    match = _GENERIC_SECRET_ASSIGNMENT_RE.search(text)
    if not match:
        return None
    return match.group(1)


def _is_dummy_secret_value(value: str) -> bool:
    normalized = value.strip().lower()
    return _DUMMY_SECRET_MARKER_RE.search(normalized) is not None


def _looks_like_raw_secret_assignment(text: str) -> bool:
    value = _secret_assignment_value(text)
    return value is not None and not _is_dummy_secret_value(value)


def _looks_like_low_confidence_secret_assignment(text: str) -> bool:
    value = _secret_assignment_value(text)
    return value is not None and _is_dummy_secret_value(value)


def _secret_candidate(line: dict[str, Any], *, confidence: float = 0.58) -> dict[str, Any]:
    return _finding(
        line,
        severity="high",
        category="secret",
        title="placeholder secret-like value added to production code",
        recommendation="Confirm the value is non-production test data or remove it from source.",
        confidence=confidence,
        rule_name="low_confidence_secret",
    )


def _run_rules(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    lines = [line for line in payload.get("added_lines", []) if isinstance(line, dict)]
    changed_files = [str(path) for path in payload.get("changed_files", [])]
    findings: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    redaction_event_flags = _redaction_event_flags(payload)

    for line in lines:
        text = _line_text(line)
        lower = text.lower()
        file_path = _line_file(line)
        if _SUBPROCESS_SHELL_RE.search(text) or _POPEN_SHELL_RE.search(text):
            findings.append(
                _finding(
                    line,
                    severity="high",
                    category="security",
                    title="subprocess invoked with shell=True",
                    recommendation=("Pass an argv list with shell=False and validate the executable explicitly."),
                    confidence=0.92,
                    rule_name="subprocess_shell_true",
                ))
        if _OS_SYSTEM_RE.search(text):
            findings.append(
                _finding(
                    line,
                    severity="high",
                    category="security",
                    title="os.system executes a shell command",
                    recommendation="Pass an argv list to subprocess.run(..., shell=False) and validate the executable.",
                    confidence=0.90,
                    rule_name="os_system_shell",
                ))
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
                ))
        if _is_sql_interpolation_candidate(text, lower):
            findings.append(
                _finding(
                    line,
                    severity="high",
                    category="security",
                    title="SQL query uses string interpolation with user data",
                    recommendation="Use parameterized SQL placeholders and pass user values separately.",
                    confidence=0.90,
                    rule_name="sql_interpolation",
                ))
        if _is_yaml_load_without_safe_loader(lower):
            findings.append(
                _finding(
                    line,
                    severity="high",
                    category="security",
                    title="yaml.load used without SafeLoader",
                    recommendation="Use yaml.safe_load or pass Loader=yaml.SafeLoader for untrusted YAML.",
                    confidence=0.88,
                    rule_name="yaml_load",
                ))
        if _is_pickle_loads_on_untrusted_data(lower):
            findings.append(
                _finding(
                    line,
                    severity="high",
                    category="security",
                    title="pickle.loads called on request-controlled data",
                    recommendation="Do not unpickle untrusted input; use a safe serialization format such as JSON.",
                    confidence=0.88,
                    rule_name="pickle_loads",
                ))
        is_secret_test_context = _is_test_file(file_path) or _is_fixture_file(file_path)
        placeholder_signal = _placeholder_signal(text, redaction_event_flags)
        if not is_secret_test_context and placeholder_signal is not None:
            placeholder_confidence, likely_placeholder = placeholder_signal
            if not likely_placeholder:
                findings.append(
                    _finding(
                        line,
                        severity="high",
                        category="secret",
                        title="secret material added to source",
                        recommendation=(
                            "Remove the secret from source, rotate it, and load it from a managed secret store."),
                        confidence=placeholder_confidence,
                        rule_name="hardcoded_secret",
                    ))
            else:
                findings.append(_secret_candidate(line, confidence=placeholder_confidence))
        elif not is_secret_test_context and _looks_like_raw_secret_assignment(text):
            findings.append(
                _finding(
                    line,
                    severity="high",
                    category="secret",
                    title="secret material added to source",
                    recommendation="Remove the secret from source, rotate it, and load it from a managed secret store.",
                    confidence=0.99,
                    rule_name="hardcoded_secret",
                ))
        elif not is_secret_test_context and _looks_like_low_confidence_secret_assignment(text):
            findings.append(_secret_candidate(line))
        if (_is_database_lifecycle_candidate(text) and not lower.startswith(("with ", "async with "))
                and not _has_lifecycle_signal(lines, line)):
            findings.append(
                _finding(
                    line,
                    severity="medium",
                    category="database",
                    title="database connection/session may not be closed",
                    recommendation=("Use a context manager or close the connection/session in a finally block."),
                    confidence=0.82,
                    rule_name="database_lifecycle",
                ))
        if _OPEN_RE.search(text) and "with open(" not in lower and not _has_lifecycle_signal(lines, line):
            findings.append(
                _finding(
                    line,
                    severity="medium",
                    category="async_resource",
                    title="file handle may not be closed",
                    recommendation="Use with open(...) as f or close the file in a finally block.",
                    confidence=0.80,
                    rule_name="open_without_context",
                ))
        if "aiohttp.clientsession(" in lower and "async with" not in lower and not _has_lifecycle_signal(lines, line):
            findings.append(
                _finding(
                    line,
                    severity="medium",
                    category="async_resource",
                    title="aiohttp ClientSession may not be closed",
                    recommendation=(
                        "Use async with aiohttp.ClientSession(...) or close the session in a finally block."),
                    confidence=0.82,
                    rule_name="aiohttp_session_lifecycle",
                ))

    business_files = sorted(path for path in changed_files if _is_business_python_file(path))
    if business_files and not any(_is_test_file(path) for path in changed_files):
        first_file = business_files[0]
        candidate_line = next(
            (line for line in lines if _line_file(line) == first_file),
            {
                "file": first_file,
                "line": 1,
                "content": first_file,
            },
        )
        findings.append(
            _finding(
                candidate_line,
                severity="low",
                category="test",
                title="code changed without nearby test changes",
                recommendation="Add or update focused tests for the changed behavior.",
                confidence=0.66,
                rule_name="missing_tests",
            ))

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
