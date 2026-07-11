# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Tests for the skills code review diff parser."""

from __future__ import annotations

import pytest

from agent.diff_parser import parse_unified_diff


def test_parse_multiple_hunks_line_mapping():
    diff = """diff --git a/pkg/app.py b/pkg/app.py
index 1111111..2222222 100644
--- a/pkg/app.py
+++ b/pkg/app.py
@@ -7,2 +7,3 @@ def first():
     before()
+    added_one()
     after()
@@ -20,2 +21,4 @@ def second():
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
@@ -1,2 +1,2 @@
-old_value = 1
+new_value = 2
 context = True
"""
    parsed = parse_unified_diff(diff)

    assert len(parsed.added_lines) == 1
    assert parsed.added_lines[0].line == 1
    assert parsed.added_lines[0].content == "new_value = 2"


def test_parse_standard_unified_diff_without_git_header():
    diff = """--- a/pkg/app.py
+++ b/pkg/app.py
@@ -1 +1,2 @@
 value = 1
+added = 2
"""
    parsed = parse_unified_diff(diff)

    assert parsed.changed_files == ["pkg/app.py"]
    assert [(line.file, line.line, line.content) for line in parsed.added_lines] == [
        ("pkg/app.py", 2, "added = 2"),
    ]


def test_parse_quoted_git_paths_with_spaces():
    diff = """diff --git "a/pkg/path with spaces.py" "b/pkg/path with spaces.py"
--- "a/pkg/path with spaces.py"\t2026-07-10 10:00:00 +0000
+++ "b/pkg/path with spaces.py"\t2026-07-10 10:00:01 +0000
@@ -0,0 +1 @@
+answer = 42
"""
    parsed = parse_unified_diff(diff)

    assert parsed.changed_files == ["pkg/path with spaces.py"]
    assert parsed.added_lines[0].file == "pkg/path with spaces.py"


@pytest.mark.parametrize(
    ("encoded", "expected"),
    [
        (r'a/pkg/a\"b.py', 'pkg/a"b.py'),
        (r'a/pkg/\346\226\207.py', "pkg/文.py"),
        (r'a/pkg/dir\\name.py', r"pkg/dir\name.py"),
    ],
)
def test_parse_git_c_quoted_path_escapes(encoded, expected):
    new_path = encoded.replace("a/", "b/", 1)
    diff = (f'diff --git "{encoded}" "{new_path}"\n'
            f'--- "{encoded}"\n'
            f'+++ "{new_path}"\n'
            "@@ -0,0 +1 @@\n"
            "+answer = 42\n")

    assert parse_unified_diff(diff).changed_files == [expected]


@pytest.mark.parametrize(
    "header",
    [
        'diff --git "a/pkg/app.py b/pkg/app.py',
        "diff --git a/pkg/app.py b/pkg/app.py unexpected",
        'diff --git "a/pkg/app.py""b/pkg/app.py"',
        'diff --git "a/pkg/app.py"b/pkg/app.py',
    ],
)
def test_parse_rejects_malformed_git_headers(header):
    with pytest.raises(ValueError):
        parse_unified_diff(f"{header}\n")


def test_parse_preserves_trailing_space_in_c_quoted_path():
    diff = '''diff --git "a/pkg/name " "b/pkg/name "
--- "a/pkg/name "
+++ "b/pkg/name "
@@ -0,0 +1 @@
+answer = 42
'''

    parsed = parse_unified_diff(diff)

    assert parsed.changed_files == ["pkg/name "]
    assert parsed.added_lines[0].file == "pkg/name "


def test_hunk_content_that_looks_like_file_headers_is_not_reparsed():
    diff = """--- a/pkg/app.py
+++ b/pkg/app.py
@@ -1 +1 @@
--- old marker
+++ new marker
"""
    parsed = parse_unified_diff(diff)

    assert parsed.changed_files == ["pkg/app.py"]
    assert parsed.added_lines[0].content == "++ new marker"


def test_parse_rejects_truncated_hunk_counts():
    diff = """--- a/pkg/app.py
+++ b/pkg/app.py
@@ -1,2 +1,2 @@
 only_one_of_two_lines
"""

    with pytest.raises(ValueError, match="truncated"):
        parse_unified_diff(diff)


def test_parse_rejects_malformed_hunk_header_delimiter():
    diff = """--- a/pkg/app.py
+++ b/pkg/app.py
@@ -1 +1 @@@
-old
+new
"""

    with pytest.raises(ValueError, match="hunk header"):
        parse_unified_diff(diff)


@pytest.mark.parametrize(
    "diff",
    [
        """--- a/pkg/app.py
+++ b/pkg/app.py
@@ -0,0 +1 @@
+first
+unexpected
""",
        """--- a/pkg/app.py
+++ b/pkg/app.py
@@ -1 +0,0 @@
-first
-unexpected
""",
        """--- a/pkg/app.py
+++ b/pkg/app.py
@@ -1 +1 @@
 expected
 unexpected
""",
    ],
)
def test_parse_rejects_hunks_with_too_many_lines(diff):
    with pytest.raises(ValueError, match="too many"):
        parse_unified_diff(diff)


@pytest.mark.parametrize("newline", ["\r\n", "\r"])
def test_parse_normalizes_line_endings_and_standard_header_timestamps(newline):
    diff = newline.join([
        "--- a/pkg/app.py\t2026-07-10 10:00:00 +0000",
        "+++ b/pkg/app.py\t2026-07-10 10:00:01 +0000",
        "@@ -0,0 +1 @@",
        "+answer = 42",
        "",
    ])

    parsed = parse_unified_diff(diff)

    assert parsed.changed_files == ["pkg/app.py"]
    assert parsed.added_lines[0].content == "answer = 42"


def test_parse_quoted_standard_paths_with_tab_timestamps():
    diff = """--- "a/pkg/path with spaces.py"\t2026-07-10 10:00:00 +0000
+++ "b/pkg/path with spaces.py"\t2026-07-10 10:00:01 +0000
@@ -0,0 +1 @@
+answer = 42
"""

    parsed = parse_unified_diff(diff)

    assert parsed.changed_files == ["pkg/path with spaces.py"]


def test_parse_preserves_trailing_space_in_unquoted_standard_path():
    diff = """--- a/pkg/name \t2026-07-10 10:00:00 +0000
+++ b/pkg/name \t2026-07-10 10:00:01 +0000
@@ -0,0 +1 @@
+answer = 42
"""

    parsed = parse_unified_diff(diff)

    assert parsed.changed_files == ["pkg/name "]
    assert parsed.added_lines[0].file == "pkg/name "


def test_parse_rejects_orphan_standard_file_header():
    with pytest.raises(ValueError, match="orphan"):
        parse_unified_diff("--- a/pkg/app.py\n")


def test_parse_multiple_standard_files_and_zero_count_hunk():
    diff = """--- a/pkg/empty.py
+++ b/pkg/empty.py
@@ -0,0 +0,0 @@
--- a/pkg/app.py
+++ b/pkg/app.py
@@ -0,0 +1 @@
+answer = 42
"""

    parsed = parse_unified_diff(diff)

    assert [(item.old_file, item.new_file) for item in parsed.files] == [
        ("pkg/empty.py", "pkg/empty.py"),
        ("pkg/app.py", "pkg/app.py"),
    ]
    assert parsed.changed_files == ["pkg/empty.py", "pkg/app.py"]
    assert [(line.file, line.line) for line in parsed.added_lines] == [("pkg/app.py", 1)]


def test_parse_preserves_new_deleted_and_renamed_file_semantics():
    diff = """diff --git a/pkg/new.py b/pkg/new.py
new file mode 100644
--- /dev/null
+++ b/pkg/new.py
@@ -0,0 +1 @@
+new_value = 1
diff --git a/pkg/deleted.py b/pkg/deleted.py
deleted file mode 100644
--- a/pkg/deleted.py
+++ /dev/null
@@ -1 +0,0 @@
-deleted_value = 1
diff --git a/pkg/old_name.py b/pkg/new_name.py
similarity index 90%
rename from pkg/old_name.py
rename to pkg/new_name.py
--- a/pkg/old_name.py
+++ b/pkg/new_name.py
@@ -1 +1 @@
-old_value = 1
+new_value = 2
"""

    parsed = parse_unified_diff(diff)

    assert [(item.old_file, item.new_file, item.is_new, item.is_deleted) for item in parsed.files] == [
        ("/dev/null", "pkg/new.py", True, False),
        ("pkg/deleted.py", "/dev/null", False, True),
        ("pkg/old_name.py", "pkg/new_name.py", False, False),
    ]
    assert parsed.changed_files == ["pkg/new.py", "pkg/new_name.py"]
    assert [(line.file, line.old_file) for line in parsed.added_lines] == [
        ("pkg/new.py", "/dev/null"),
        ("pkg/new_name.py", "pkg/old_name.py"),
    ]


def test_parse_pure_git_rename_without_hunks():
    diff = """diff --git a/pkg/old.py b/pkg/new.py
similarity index 100%
rename from pkg/old.py
rename to pkg/new.py
"""

    parsed = parse_unified_diff(diff)

    assert [(item.old_file, item.new_file, item.added_lines) for item in parsed.files] == [
        ("pkg/old.py", "pkg/new.py", []),
    ]
    assert parsed.changed_files == ["pkg/new.py"]
