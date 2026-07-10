# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Unified diff parser for deterministic review rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .models import ChangedLine
from .models import FileChange
from .models import ParsedDiff

_DIFF_RE = re.compile(r"^diff --git a/(.*?) b/(.*)$")
_HUNK_RE = re.compile(r"^@@ -(?P<old>\d+)(?:,(?P<old_count>\d+))? \+(?P<new>\d+)(?:,(?P<new_count>\d+))? @@")


@dataclass
class _LineEvent:
    kind: str
    content: str
    new_line: int
    old_line: int
    hunk_header: str


def _normalize_path(path: str) -> str:
    path = path.strip()
    if path == "/dev/null":
        return path
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def _context(events: list[_LineEvent], idx: int, direction: int, limit: int = 4) -> list[str]:
    values: list[str] = []
    cursor = idx + direction
    while 0 <= cursor < len(events) and len(values) < limit:
        event = events[cursor]
        if event.kind in {"context", "add"}:
            values.append(event.content)
        cursor += direction
    if direction < 0:
        values.reverse()
    return values


def _finalize_file(file_change: FileChange | None, events: list[_LineEvent]) -> None:
    if file_change is None:
        return
    file_change.added_lines = [
        ChangedLine(
            file=file_change.new_file,
            old_file=file_change.old_file,
            line=event.new_line,
            content=event.content,
            hunk_header=event.hunk_header,
            context_before=_context(events, idx, -1),
            context_after=_context(events, idx, 1),
        ) for idx, event in enumerate(events) if event.kind == "add"
    ]


def parse_unified_diff(diff_text: str) -> ParsedDiff:
    files: list[FileChange] = []
    events: list[_LineEvent] = []
    current: FileChange | None = None
    old_line = 0
    new_line = 0
    hunk_header = ""

    for raw in diff_text.replace("\r\n", "\n").splitlines():
        diff_match = _DIFF_RE.match(raw)
        if diff_match:
            _finalize_file(current, events)
            old_path, new_path = diff_match.groups()
            current = FileChange(old_file=old_path, new_file=new_path)
            files.append(current)
            events = []
            hunk_header = ""
            continue
        if current is None:
            continue
        if raw.startswith("--- "):
            current.old_file = _normalize_path(raw[4:].split("\t", 1)[0])
            continue
        if raw.startswith("+++ "):
            current.new_file = _normalize_path(raw[4:].split("\t", 1)[0])
            current.is_new = current.old_file == "/dev/null"
            current.is_deleted = current.new_file == "/dev/null"
            continue
        hunk_match = _HUNK_RE.match(raw)
        if hunk_match:
            old_line = int(hunk_match.group("old"))
            new_line = int(hunk_match.group("new"))
            hunk_header = raw
            continue
        if not hunk_header:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            events.append(_LineEvent("add", raw[1:], new_line, old_line, hunk_header))
            new_line += 1
            continue
        if raw.startswith("-") and not raw.startswith("---"):
            events.append(_LineEvent("delete", raw[1:], new_line, old_line, hunk_header))
            old_line += 1
            continue
        if raw.startswith(" "):
            events.append(_LineEvent("context", raw[1:], new_line, old_line, hunk_header))
            old_line += 1
            new_line += 1

    _finalize_file(current, events)
    added_lines = [line for file_change in files for line in file_change.added_lines]
    changed_files = [file_change.new_file for file_change in files if file_change.new_file != "/dev/null"]
    return ParsedDiff(
        files=files,
        added_lines=added_lines,
        changed_files=changed_files,
        total_added_lines=len(added_lines),
    )


def is_test_file(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    return (normalized.startswith("tests/") or "/tests/" in normalized or name.startswith("test_")
            or name.endswith("_test.py") or name.endswith(".test.ts") or name.endswith(".spec.ts")
            or name.endswith(".test.js") or name.endswith(".spec.js"))


def code_files(paths: Iterable[str]) -> list[str]:
    suffixes = (".py", ".js", ".ts", ".tsx", ".go", ".java", ".rs", ".rb")
    return [path for path in paths if path.lower().endswith(suffixes) and not is_test_file(path)]
