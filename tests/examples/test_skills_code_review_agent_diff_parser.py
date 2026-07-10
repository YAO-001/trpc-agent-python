# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Tests for the skills code review diff parser."""

from __future__ import annotations

from agent.diff_parser import parse_unified_diff


def test_parse_multiple_hunks_line_mapping():
    diff = """diff --git a/pkg/app.py b/pkg/app.py
index 1111111..2222222 100644
--- a/pkg/app.py
+++ b/pkg/app.py
@@ -7,6 +7,7 @@ def first():
     before()
+    added_one()
     after()
@@ -20,6 +21,8 @@ def second():
     before_two()
+    added_two()
+    added_three()
     after_two()
"""
    parsed = parse_unified_diff(diff)

    assert parsed.changed_files == ["pkg/app.py"]
    assert [(line.file, line.line, line.content) for line in parsed.added_lines] == [
        ("pkg/app.py", 8, "    added_one()"),
        ("pkg/app.py", 22, "    added_two()"),
        ("pkg/app.py", 23, "    added_three()"),
    ]
    assert parsed.added_lines[1].context_before[-1] == "    before_two()"
    assert parsed.added_lines[1].context_after[0] == "    added_three()"


def test_parse_fixture_added_lines_only():
    diff = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,4 +1,5 @@
-old_value = 1
+new_value = 2
 context = True
"""
    parsed = parse_unified_diff(diff)

    assert len(parsed.added_lines) == 1
    assert parsed.added_lines[0].line == 1
    assert parsed.added_lines[0].content == "new_value = 2"
