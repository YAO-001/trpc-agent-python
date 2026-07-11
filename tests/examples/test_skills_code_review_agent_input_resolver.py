# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Tests for complete and repository-scoped review input resolution."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import agent.input_resolver as resolver_module
from agent.cli import build_parser
from agent.diff_parser import parse_unified_diff
from agent.input_resolver import resolve_review_input
from agent.orchestrator import _stable_task_id


def _git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )
    return result.stdout


def _init_repo(path: Path, *, commit: bool = False) -> Path:
    path.mkdir()
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "review@example.invalid")
    _git(path, "config", "user.name", "Review Test")
    _git(path, "config", "core.autocrlf", "false")
    if commit:
        (path / "base.py").write_text("base = 1\n", encoding="utf-8")
        (path / "tracked.py").write_text("value = 1\n", encoding="utf-8")
        _git(path, "add", ".")
        _git(path, "commit", "-q", "-m", "base")
    return path


def _repo_with_changes(tmp_path: Path) -> Path:
    repo = _init_repo(tmp_path / "repo", commit=True)
    (repo / "staged.py").write_text("staged = 1\n", encoding="utf-8")
    _git(repo, "add", "staged.py")
    (repo / "tracked.py").write_text("value = 2\n", encoding="utf-8")
    (repo / "untracked.py").write_text("untracked = 1\n", encoding="utf-8")
    return repo


def test_repo_input_contains_staged_unstaged_and_untracked(tmp_path):
    repo = _repo_with_changes(tmp_path)

    resolved = resolve_review_input(repo_path=str(repo))
    parsed = parse_unified_diff(resolved.diff_text)

    assert set(parsed.changed_files) == {"staged.py", "tracked.py", "untracked.py"}


def test_unborn_repo_uses_final_worktree_version_once(tmp_path):
    repo = _init_repo(tmp_path / "repo")
    target = repo / "staged.py"
    target.write_text("value = 1\n", encoding="utf-8")
    _git(repo, "add", "staged.py")
    target.write_text("value = 2\n", encoding="utf-8")
    (repo / "untracked.py").write_text("untracked = 1\n", encoding="utf-8")

    parsed = parse_unified_diff(resolve_review_input(repo_path=str(repo)).diff_text)
    staged_lines = [line.content for line in parsed.added_lines if line.file == "staged.py"]

    assert set(parsed.changed_files) == {"staged.py", "untracked.py"}
    assert staged_lines == ["value = 2"]


def test_clean_unborn_repo_returns_empty_diff(tmp_path):
    repo = _init_repo(tmp_path / "repo")

    resolved = resolve_review_input(repo_path=str(repo))

    assert resolved.diff_text == ""
    assert parse_unified_diff(resolved.diff_text).changed_files == []


def test_file_list_is_literal_repo_scoped_selector(tmp_path):
    repo = _repo_with_changes(tmp_path)
    selected = tmp_path / "files.txt"
    selected.write_text("staged.py\nuntracked.py\n", encoding="utf-8")

    resolved = resolve_review_input(repo_path=str(repo), file_list=str(selected))

    assert resolved.input_type == "repo_file_list"
    assert resolved.file_list == ["staged.py", "untracked.py"]
    assert set(parse_unified_diff(resolved.diff_text).changed_files) == {"staged.py", "untracked.py"}


def test_file_list_preserves_leading_space_dash_and_unicode(tmp_path):
    repo = _init_repo(tmp_path / "repo", commit=True)
    names = [" leading.py", "-dash.py", "文.py"]
    for name in names:
        (repo / name).write_text(f"name = {name!r}\n", encoding="utf-8")
    selected = tmp_path / "files.txt"
    selected.write_text("\n".join(names) + "\n", encoding="utf-8")

    resolved = resolve_review_input(repo_path=str(repo), file_list=str(selected))

    assert resolved.file_list == sorted(names)
    assert set(parse_unified_diff(resolved.diff_text).changed_files) == set(names)


@pytest.mark.parametrize("literal", ["*.py", ":(glob)*.py"])
def test_file_list_disables_git_pathspec_magic(tmp_path, literal):
    repo = _repo_with_changes(tmp_path)
    selected = tmp_path / "files.txt"
    selected.write_text(literal + "\n", encoding="utf-8")

    resolved = resolve_review_input(repo_path=str(repo), file_list=str(selected))

    assert resolved.file_list == [literal]
    assert resolved.diff_text == ""


def test_file_list_requires_repo_path_before_default_fixture(tmp_path):
    selected = tmp_path / "files.txt"
    selected.write_text("app.py\n", encoding="utf-8")

    with pytest.raises(ValueError, match="--file-list requires --repo-path"):
        resolve_review_input(file_list=str(selected))


def test_empty_file_list_does_not_expand_to_full_repo(tmp_path):
    repo = _repo_with_changes(tmp_path)
    selected = tmp_path / "files.txt"
    selected.write_text("\n", encoding="utf-8")

    with pytest.raises(ValueError, match="file-list must select at least one path"):
        resolve_review_input(repo_path=str(repo), file_list=str(selected))


def test_empty_file_list_argument_does_not_expand_to_full_repo(tmp_path):
    repo = _repo_with_changes(tmp_path)

    with pytest.raises(ValueError, match="file-list"):
        resolve_review_input(repo_path=str(repo), file_list="")


@pytest.mark.parametrize(
    "selector",
    [
        "../outside.py",
        "sub/../../outside.py",
        "/absolute.py",
        "C:/absolute.py",
        r"\\server\share\file.py",
        ".",
    ],
)
def test_file_list_rejects_non_relative_or_root_selectors(tmp_path, selector):
    repo = _repo_with_changes(tmp_path)
    selected = tmp_path / "files.txt"
    selected.write_text(selector + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="repository-relative|escapes repository root|repository root"):
        resolve_review_input(repo_path=str(repo), file_list=str(selected))


def test_file_list_rejects_absolute_path_even_when_inside_repo(tmp_path):
    repo = _repo_with_changes(tmp_path)
    selected = tmp_path / "files.txt"
    selected.write_text(str(repo / "tracked.py") + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="repository-relative"):
        resolve_review_input(repo_path=str(repo), file_list=str(selected))


def test_file_list_rejects_directory_symlink_escape(tmp_path):
    repo = _repo_with_changes(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, repo / "link", target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")
    selected = tmp_path / "files.txt"
    selected.write_text("link/secret.py\n", encoding="utf-8")

    with pytest.raises(ValueError, match="escapes repository root"):
        resolve_review_input(repo_path=str(repo), file_list=str(selected))


def test_selected_unchanged_and_missing_paths_are_not_fabricated(tmp_path):
    repo = _repo_with_changes(tmp_path)
    selected = tmp_path / "files.txt"
    selected.write_text("base.py\nmissing.py\n", encoding="utf-8")

    resolved = resolve_review_input(repo_path=str(repo), file_list=str(selected))

    assert resolved.file_list == ["base.py", "missing.py"]
    assert parse_unified_diff(resolved.diff_text).changed_files == []


def test_different_empty_file_lists_have_distinct_dry_run_identity(tmp_path):
    repo = _init_repo(tmp_path / "repo", commit=True)
    first_list = tmp_path / "first.txt"
    second_list = tmp_path / "second.txt"
    first_list.write_text("base.py\n", encoding="utf-8")
    second_list.write_text("missing.py\n", encoding="utf-8")
    first = resolve_review_input(repo_path=str(repo), file_list=str(first_list))
    second = resolve_review_input(repo_path=str(repo), file_list=str(second_list))

    first_id = _stable_task_id(
        input_type=first.input_type,
        input_ref=first.input_ref,
        redacted_diff=first.diff_text,
        runtime="local",
        dry_run=True,
    )
    second_id = _stable_task_id(
        input_type=second.input_type,
        input_ref=second.input_ref,
        redacted_diff=second.diff_text,
        runtime="local",
        dry_run=True,
    )

    assert first.diff_text == second.diff_text == ""
    assert first.input_ref != second.input_ref
    assert first_id != second_id


def test_empty_binary_and_non_utf8_untracked_files_do_not_crash(tmp_path):
    repo = _init_repo(tmp_path / "repo", commit=True)
    (repo / "empty.bin").write_bytes(b"")
    (repo / "binary.bin").write_bytes(b"\x00\xff")
    (repo / "invalid.py").write_bytes(b"value = '\xff'\n")

    parsed = parse_unified_diff(resolve_review_input(repo_path=str(repo)).diff_text)

    assert set(parsed.changed_files) == {"empty.bin", "binary.bin", "invalid.py"}


def test_staged_delete_and_pure_rename_are_preserved(tmp_path):
    repo = _init_repo(tmp_path / "repo", commit=True)
    (repo / "deleted.py").write_text("deleted = 1\n", encoding="utf-8")
    (repo / "old.py").write_text("renamed = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add rename inputs")
    _git(repo, "rm", "-q", "deleted.py")
    _git(repo, "mv", "old.py", "new.py")

    parsed = parse_unified_diff(resolve_review_input(repo_path=str(repo)).diff_text)

    assert any(item.old_file == "deleted.py" and item.is_deleted for item in parsed.files)
    assert any(item.old_file == "old.py" and item.new_file == "new.py" for item in parsed.files)
    assert "deleted.py" not in parsed.changed_files
    assert "new.py" in parsed.changed_files


def test_user_diff_prefix_and_color_config_cannot_corrupt_paths(tmp_path):
    repo = _init_repo(tmp_path / "repo", commit=True)
    nested = repo / "a"
    nested.mkdir()
    (nested / "file.py").write_text("value = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "nested")
    _git(repo, "config", "diff.noprefix", "true")
    _git(repo, "config", "diff.mnemonicPrefix", "true")
    _git(repo, "config", "color.ui", "always")
    (nested / "file.py").write_text("value = 2\n", encoding="utf-8")

    resolved = resolve_review_input(repo_path=str(repo))

    assert "\x1b" not in resolved.diff_text
    assert parse_unified_diff(resolved.diff_text).changed_files == ["a/file.py"]


def test_user_suppress_blank_empty_config_cannot_break_hunks(tmp_path):
    repo = _init_repo(tmp_path / "repo", commit=True)
    target = repo / "blank.py"
    target.write_text("one\n\nthree\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "blank context")
    _git(repo, "config", "diff.suppressBlankEmpty", "true")
    target.write_text("ONE\n\nthree\n", encoding="utf-8")

    parsed = parse_unified_diff(resolve_review_input(repo_path=str(repo)).diff_text)

    assert parsed.changed_files == ["blank.py"]


def test_missing_file_non_git_and_bare_repo_fail_actionably(tmp_path):
    missing = tmp_path / "missing"
    file_path = tmp_path / "file.txt"
    file_path.write_text("not a repo", encoding="utf-8")
    plain = tmp_path / "plain"
    plain.mkdir()
    bare = tmp_path / "bare.git"
    subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True)

    with pytest.raises(ValueError, match="does not exist"):
        resolve_review_input(repo_path=str(missing))
    with pytest.raises(ValueError, match="directory"):
        resolve_review_input(repo_path=str(file_path))
    with pytest.raises(ValueError, match="Git worktree"):
        resolve_review_input(repo_path=str(plain))
    with pytest.raises(ValueError, match="Git worktree"):
        resolve_review_input(repo_path=str(bare))


def test_git_timeout_is_wrapped(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path / "repo")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], timeout=30)

    monkeypatch.setattr(resolver_module.subprocess, "run", timeout)

    with pytest.raises(RuntimeError, match="timed out"):
        resolve_review_input(repo_path=str(repo))


def test_git_subprocess_uses_deterministic_locale(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path / "repo")
    real_run = subprocess.run
    locales: list[dict[str, str]] = []

    def capture(*args, **kwargs):
        locales.append(kwargs.get("env", {}))
        return real_run(*args, **kwargs)

    monkeypatch.setattr(resolver_module.subprocess, "run", capture)

    resolve_review_input(repo_path=str(repo))

    assert locales
    assert all(item.get("LC_ALL") == "C" and item.get("LANG") == "C" for item in locales)


def test_cli_documents_literal_file_list_contract():
    review_action = next(action for action in build_parser()._subparsers._group_actions if action.dest == "command")
    review_parser = review_action.choices["review"]
    file_list_action = next(action for action in review_parser._actions if action.dest == "file_list")

    assert file_list_action.help is not None
    assert "literal" in file_list_action.help.lower()
    assert "repository-relative" in file_list_action.help.lower()
    assert "--repo-path" in file_list_action.help
