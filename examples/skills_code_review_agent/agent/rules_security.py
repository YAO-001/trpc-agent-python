# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Security rules for the deterministic review core."""

from __future__ import annotations

import re

from .models import ChangedLine
from .models import Finding


_USER_DATA_RE = re.compile(r"\b(user|request|input|body|payload|params|query|args)\b", re.IGNORECASE)
_SQL_RE = re.compile(r"\b(select|insert|update|delete|where)\b", re.IGNORECASE)


def _finding(line: ChangedLine, title: str, evidence: str, recommendation: str, confidence: float = 0.9) -> Finding:
    return Finding(
        severity="high",
        category="security",
        file=line.file,
        line=line.line,
        title=title,
        evidence=evidence.strip(),
        recommendation=recommendation,
        confidence=confidence,
        source=["rule:security"],
    )


def run_security_rules(lines: list[ChangedLine]) -> list[Finding]:
    findings: list[Finding] = []
    for line in lines:
        text = line.content.strip()
        compact = re.sub(r"\s+", "", text).lower()
        lower = text.lower()
        if "shell=true" in compact and "subprocess" in lower:
            findings.append(
                _finding(
                    line,
                    "subprocess invoked with shell=True",
                    text,
                    "Pass an argv list with shell=False and validate the executable explicitly.",
                    0.96,
                )
            )
        if re.search(r"\b(eval|exec)\s*\(", text) and _USER_DATA_RE.search(text):
            findings.append(
                _finding(
                    line,
                    "dynamic code execution on request-controlled data",
                    text,
                    "Replace eval/exec with a parser or an allowlisted command table.",
                    0.92,
                )
            )
        if _SQL_RE.search(text) and _USER_DATA_RE.search(text):
            has_interpolation = "f\"" in text or "f'" in text or ".format(" in text or "%" in text
            if "execute" in lower and has_interpolation:
                findings.append(
                    _finding(
                        line,
                        "SQL query uses string interpolation with user data",
                        text,
                        "Use parameterized SQL placeholders and pass user values separately.",
                        0.91,
                    )
                )
        if "yaml.load(" in lower and "safeloader" not in lower and "safe_load(" not in lower:
            findings.append(
                _finding(
                    line,
                    "yaml.load used without SafeLoader",
                    text,
                    "Use yaml.safe_load or pass Loader=yaml.SafeLoader for untrusted YAML.",
                    0.9,
                )
            )
        if "pickle.loads(" in lower and _USER_DATA_RE.search(text):
            findings.append(
                _finding(
                    line,
                    "pickle.loads called on request-controlled data",
                    text,
                    "Do not unpickle untrusted input; use a safe serialization format such as JSON.",
                    0.93,
                )
            )
    return findings
