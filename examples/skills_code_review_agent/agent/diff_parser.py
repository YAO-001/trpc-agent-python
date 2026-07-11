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

_HUNK_RE = re.compile(r"^@@ -(?P<old>\d+)(?:,(?P<old_count>\d+))? "
                      r"\+(?P<new>\d+)(?:,(?P<new_count>\d+))? @@(?:[ \t].*)?$")

_C_ESCAPES = {
    "a": b"\a",
    "b": b"\b",
    "f": b"\f",
    "n": b"\n",
    "r": b"\r",
    "t": b"\t",
    "v": b"\v",
    "\\": b"\\",
    '"': b'"',
}


@dataclass
class _LineEvent:
    kind: str
    content: str
    new_line: int
    old_line: int
    hunk_header: str


def _normalize_path(path: str) -> str:
    if path == "/dev/null":
        return path
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def _split_git_path_tokens(value: str) -> list[str]:
    """Split the two path tokens in a ``diff --git`` header."""
    tokens: list[str] = []
    cursor = 0
    while cursor < len(value):
        while cursor < len(value) and value[cursor].isspace():
            cursor += 1
        if cursor >= len(value):
            break
        start = cursor
        if value[cursor] != '"':
            while cursor < len(value) and not value[cursor].isspace():
                cursor += 1
        else:
            cursor += 1
            escaped = False
            while cursor < len(value):
                char = value[cursor]
                cursor += 1
                if char == '"' and not escaped:
                    break
                if char == "\\" and not escaped:
                    escaped = True
                else:
                    escaped = False
            else:
                raise ValueError(f"unterminated quoted diff path: {value!r}")
            if cursor < len(value) and not value[cursor].isspace():
                raise ValueError(f"quoted diff paths must be whitespace separated: {value!r}")
        tokens.append(value[start:cursor])
    return tokens


def _decode_git_path(value: str) -> str:
    """Decode Git's C-style quoted path representation."""
    if not value.startswith('"'):
        return value
    if len(value) < 2 or not value.endswith('"'):
        raise ValueError(f"invalid quoted diff path: {value!r}")
    raw = value[1:-1]
    decoded = bytearray()
    cursor = 0
    while cursor < len(raw):
        char = raw[cursor]
        if char != "\\":
            decoded.extend(char.encode("utf-8"))
            cursor += 1
            continue
        cursor += 1
        if cursor >= len(raw):
            raise ValueError(f"invalid trailing escape in diff path: {value!r}")
        if (cursor + 3 <= len(raw) and all(item in "01234567" for item in raw[cursor:cursor + 3])):
            decoded.append(int(raw[cursor:cursor + 3], 8))
            cursor += 3
            continue
        escaped = raw[cursor]
        decoded.extend(_C_ESCAPES.get(escaped, escaped.encode("utf-8")))
        cursor += 1
    return bytes(decoded).decode("utf-8")


def _git_header_paths(raw: str) -> tuple[str, str] | None:
    if not raw.startswith("diff --git "):
        return None
    values = _split_git_path_tokens(raw[len("diff --git "):])
    if len(values) != 2:
        raise ValueError(f"invalid git diff header: {raw!r}")
    return (
        _normalize_path(_decode_git_path(values[0])),
        _normalize_path(_decode_git_path(values[1])),
    )


def _file_header_path(raw: str, prefix: str) -> str:
    value = raw[len(prefix):].split("\t", 1)[0]
    return _normalize_path(_decode_git_path(value))


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
    expecting_git_file_pair = False
    in_hunk = False
    completed_hunk = False
    remaining_old = 0
    remaining_new = 0

    lines = diff_text.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    index = 0
    while index < len(lines):
        raw = lines[index]

        if in_hunk:
            if raw.startswith("\\ No newline at end of file"):
                index += 1
                continue
            if raw.startswith("+"):
                if remaining_new <= 0:
                    raise ValueError(f"hunk has too many new lines at {raw!r}")
                events.append(_LineEvent("add", raw[1:], new_line, old_line, hunk_header))
                new_line += 1
                remaining_new -= 1
            elif raw.startswith("-"):
                if remaining_old <= 0:
                    raise ValueError(f"hunk has too many old lines at {raw!r}")
                events.append(_LineEvent("delete", raw[1:], new_line, old_line, hunk_header))
                old_line += 1
                remaining_old -= 1
            elif raw.startswith(" "):
                if remaining_old <= 0 or remaining_new <= 0:
                    raise ValueError(f"hunk has too many context lines at {raw!r}")
                events.append(_LineEvent("context", raw[1:], new_line, old_line, hunk_header))
                old_line += 1
                new_line += 1
                remaining_old -= 1
                remaining_new -= 1
            elif raw.startswith("diff --git ") or raw.startswith("@@"):
                raise ValueError(f"truncated unified-diff hunk before {raw!r}")
            else:
                raise ValueError(f"invalid unified-diff hunk line: {raw!r}")
            in_hunk = remaining_old > 0 or remaining_new > 0
            completed_hunk = not in_hunk
            index += 1
            continue

        if raw.startswith("\\ No newline at end of file"):
            index += 1
            continue

        git_paths = _git_header_paths(raw)
        if git_paths is not None:
            _finalize_file(current, events)
            current = FileChange(old_file=git_paths[0], new_file=git_paths[1])
            files.append(current)
            events = []
            hunk_header = ""
            expecting_git_file_pair = True
            completed_hunk = False
            index += 1
            continue

        is_header_pair = (raw.startswith("--- ") and index + 1 < len(lines) and lines[index + 1].startswith("+++ "))
        if is_header_pair:
            old_path = _file_header_path(raw, "--- ")
            new_path = _file_header_path(lines[index + 1], "+++ ")
            if current is not None and not expecting_git_file_pair:
                _finalize_file(current, events)
                current = None
                events = []
            if current is None:
                current = FileChange(old_file=old_path, new_file=new_path)
                files.append(current)
            else:
                current.old_file = old_path
                current.new_file = new_path
            current.is_new = old_path == "/dev/null"
            current.is_deleted = new_path == "/dev/null"
            expecting_git_file_pair = False
            hunk_header = ""
            completed_hunk = False
            index += 2
            continue

        if raw.startswith("--- ") or raw.startswith("+++ "):
            raise ValueError(f"orphan unified-diff file header: {raw!r}")

        hunk_match = _HUNK_RE.match(raw)
        if hunk_match:
            if current is None:
                raise ValueError(f"unified-diff hunk has no file header: {raw!r}")
            old_line = int(hunk_match.group("old"))
            new_line = int(hunk_match.group("new"))
            remaining_old = int(hunk_match.group("old_count") or 1)
            remaining_new = int(hunk_match.group("new_count") or 1)
            hunk_header = raw
            in_hunk = remaining_old > 0 or remaining_new > 0
            completed_hunk = not in_hunk
            index += 1
            continue

        if raw.startswith("@@"):
            raise ValueError(f"invalid unified-diff hunk header: {raw!r}")

        if completed_hunk and raw.startswith(("+", "-", " ")):
            raise ValueError(f"hunk has too many lines at {raw!r}")

        index += 1

    if in_hunk or remaining_old > 0 or remaining_new > 0:
        raise ValueError("truncated unified-diff hunk: "
                         f"missing old={remaining_old} new={remaining_new} lines")

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
