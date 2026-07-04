# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Resolve review input from files, repositories, or bundled fixtures."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


EXAMPLE_DIR = Path(__file__).resolve().parents[1]
FIXTURE_DIR = EXAMPLE_DIR / "fixtures"
FIXTURE_ORDER = [
    "clean",
    "security",
    "async_resource_leak",
    "db_lifecycle",
    "missing_tests",
    "duplicate_finding",
    "sandbox_failure",
    "secret_redaction",
]


@dataclass(frozen=True)
class ResolvedInput:
    input_type: str
    input_ref: str
    diff_text: str
    fixture_names: list[str]
    file_list: list[str]


def _read_file_list(path: str | None) -> list[str]:
    if not path:
        return []
    return [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def _resolve_fixture(name: str) -> ResolvedInput:
    if name == "all":
        chunks = [(FIXTURE_DIR / f"{fixture}.diff").read_text(encoding="utf-8") for fixture in FIXTURE_ORDER]
        return ResolvedInput("fixture", "fixture:all", "\n".join(chunks) + "\n", list(FIXTURE_ORDER), [])
    if name not in FIXTURE_ORDER:
        raise ValueError(f"unknown fixture {name!r}; expected one of {', '.join(FIXTURE_ORDER)} or all")
    return ResolvedInput(
        "fixture",
        f"fixture:{name}",
        (FIXTURE_DIR / f"{name}.diff").read_text(encoding="utf-8"),
        [name],
        [],
    )


def _resolve_repo(repo_path: str) -> ResolvedInput:
    path = Path(repo_path).resolve()
    result = subprocess.run(
        ["git", "-C", str(path), "diff", "--no-ext-diff", "--unified=3"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git diff failed for {path}: {result.stderr.strip()}")
    return ResolvedInput("repo", str(path), result.stdout, [], [])


def resolve_review_input(
    *,
    diff_file: str | None = None,
    repo_path: str | None = None,
    fixture: str | None = None,
    file_list: str | None = None,
) -> ResolvedInput:
    selected = [bool(diff_file), bool(repo_path), bool(fixture)]
    if sum(selected) > 1:
        raise ValueError("choose exactly one of --diff-file, --repo-path, or --fixture")
    if fixture:
        resolved = _resolve_fixture(fixture)
    elif repo_path:
        resolved = _resolve_repo(repo_path)
    elif diff_file:
        path = Path(diff_file).resolve()
        resolved = ResolvedInput("diff_file", str(path), path.read_text(encoding="utf-8"), [], [])
    else:
        resolved = _resolve_fixture("all")
    extra_files = _read_file_list(file_list)
    if not extra_files:
        return resolved
    return ResolvedInput(
        resolved.input_type,
        resolved.input_ref,
        resolved.diff_text,
        resolved.fixture_names,
        extra_files,
    )
