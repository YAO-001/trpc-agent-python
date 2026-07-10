# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Test coverage heuristic rules."""

from __future__ import annotations

from .diff_parser import code_files
from .diff_parser import is_test_file
from .models import Finding
from .models import ParsedDiff


def run_test_rules(parsed_diff: ParsedDiff) -> list[Finding]:
    changed_code = code_files(parsed_diff.changed_files)
    changed_tests = [path for path in parsed_diff.changed_files if is_test_file(path)]
    if not changed_code or changed_tests:
        return []
    first_file = sorted(changed_code)[0]
    first_line = 1
    for line in parsed_diff.added_lines:
        if line.file == first_file:
            first_line = line.line
            break
    return [
        Finding(
            severity="low",
            category="test",
            file=first_file,
            line=first_line,
            title="code changed without nearby test changes",
            evidence=", ".join(sorted(changed_code)),
            recommendation=("Add or update focused tests for the changed behavior, "
                            "or document why existing coverage is sufficient."),
            confidence=0.66,
            source=["rule:test"],
        )
    ]
