# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Resolve review input from files, repositories, or bundled fixtures."""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from pathlib import PureWindowsPath

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

_GIT_TIMEOUT_SECONDS = 30
_DIFF_OPTIONS = [
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--no-relative",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--find-renames",
    "--unified=3",
]
_DIFF_CONFIG = ["-c", "diff.suppressBlankEmpty=false"]


@dataclass(frozen=True)
class ResolvedInput:
    input_type: str
    input_ref: str
    diff_text: str
    fixture_names: list[str]
    file_list: list[str]


def _decode_git_text(value: bytes) -> str:
    """Decode Git's textual patch output independently from the host locale."""
    return value.decode("utf-8", errors="replace")


def _run_git(
        path: Path,
        args: list[str],
        *,
        accepted_codes: tuple[int, ...] = (0, ),
) -> bytes:
    command = ["git", "-C", str(path), *args]
    environment = os.environ.copy()
    environment.update({"LC_ALL": "C", "LANG": "C", "LANGUAGE": "C"})
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            env=environment,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("git executable was not found while resolving review input") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"git command timed out after {_GIT_TIMEOUT_SECONDS} seconds while resolving review input") from exc
    if result.returncode not in accepted_codes:
        operation = args[0] if args else "command"
        stderr = _decode_git_text(result.stderr).strip()
        detail = f": {stderr}" if stderr else ""
        raise RuntimeError(f"git {operation} failed while resolving repository input "
                           f"(exit {result.returncode}){detail}")
    return result.stdout


def _repository_root(repo_path: str) -> Path:
    requested = Path(repo_path).expanduser()
    try:
        requested = requested.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError(f"repository path does not exist: {repo_path}") from exc
    if not requested.is_dir():
        raise ValueError(f"repository path must be a directory: {repo_path}")
    top_level = _run_git(
        requested,
        ["rev-parse", "--show-toplevel"],
        accepted_codes=(0, 1, 128),
    )
    top_level_text = _decode_git_text(top_level).rstrip("\r\n")
    if not top_level_text:
        raise ValueError("--repo-path must point to a Git worktree")
    try:
        return Path(top_level_text).resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - corrupt Git metadata
        raise ValueError("--repo-path Git worktree root is unavailable") from exc


def _is_absolute_selector(value: str) -> bool:
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return posix.is_absolute() or windows.is_absolute() or bool(windows.drive) or bool(windows.root)


def _normalize_selector(repo_root: Path, value: str) -> str:
    if "\0" in value:
        raise ValueError("file-list path must not contain NUL bytes")
    if _is_absolute_selector(value):
        raise ValueError(f"file-list path must be repository-relative: {value}")
    relative = Path(value)
    if not relative.parts or relative == Path("."):
        raise ValueError("file-list path must not select the repository root")
    if ".." in relative.parts:
        raise ValueError(f"file-list path escapes repository root: {value}")

    parent = repo_root
    for part in relative.parts[:-1]:
        parent /= part
        try:
            resolved_parent = parent.resolve(strict=False)
            resolved_parent.relative_to(repo_root)
        except (OSError, ValueError) as exc:
            raise ValueError(f"file-list path escapes repository root: {value}") from exc

    return relative.as_posix()


def _read_file_list(path: str | None, *, repo_root: Path | None) -> list[str]:
    if path is None:
        return []
    if path == "":
        raise ValueError("file-list path must not be empty")
    if repo_root is None:
        raise ValueError("--file-list requires --repo-path")
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError("file-list must be a readable UTF-8 text file") from exc
    selected = sorted({_normalize_selector(repo_root, raw) for raw in lines if raw != ""})
    if not selected:
        raise ValueError("file-list must select at least one path")
    return selected


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


def _literal_prefix(selected_paths: list[str]) -> list[str]:
    return ["--literal-pathspecs"] if selected_paths else []


def _pathspec(selected_paths: list[str]) -> list[str]:
    return ["--", *selected_paths]


def _decode_nul_paths(value: bytes) -> list[str]:
    return [os.fsdecode(item) for item in value.split(b"\0") if item]


def _listed_paths(root: Path, selected_paths: list[str], *, include_cached: bool) -> list[str]:
    modes = ["--cached"] if include_cached else []
    raw = _run_git(
        root,
        [
            *_literal_prefix(selected_paths),
            "ls-files",
            *modes,
            "--others",
            "--exclude-standard",
            "--full-name",
            "-z",
            *_pathspec(selected_paths),
        ],
    )
    return sorted(set(_decode_nul_paths(raw)))


def _untracked_patch(root: Path, relative: str) -> bytes:
    candidate = root / Path(relative)
    if not candidate.exists() and not candidate.is_symlink():
        return b""
    return _run_git(
        root,
        [
            *_DIFF_CONFIG,
            "--literal-pathspecs",
            "diff",
            "--no-index",
            *_DIFF_OPTIONS,
            "--",
            "/dev/null",
            relative,
        ],
        accepted_codes=(0, 1),
    )


def _has_head(root: Path) -> bool:
    output = _run_git(
        root,
        ["rev-parse", "--verify", "--quiet", "HEAD"],
        accepted_codes=(0, 1, 128),
    )
    return bool(output.strip())


def _complete_patch(root: Path, selected_paths: list[str]) -> str:
    patches: list[bytes] = []
    if _has_head(root):
        tracked = _run_git(
            root,
            [
                *_DIFF_CONFIG,
                *_literal_prefix(selected_paths),
                "diff",
                *_DIFF_OPTIONS,
                "HEAD",
                *_pathspec(selected_paths),
            ],
        )
        if tracked:
            patches.append(tracked)
        untracked = _listed_paths(root, selected_paths, include_cached=False)
    else:
        # With no HEAD, compare the final worktree directly to the empty tree.
        # This avoids reporting both staged and unstaged versions of one file.
        untracked = _listed_paths(root, selected_paths, include_cached=True)

    for relative in untracked:
        patch = _untracked_patch(root, relative)
        if patch:
            patches.append(patch)

    chunks = [_decode_git_text(item).rstrip("\n") for item in patches if item]
    return "\n".join(chunks) + ("\n" if chunks else "")


def _repo_input_ref(root: Path, selected_paths: list[str]) -> str:
    if not selected_paths:
        return str(root)
    payload = "\0".join(selected_paths).encode("utf-8", errors="surrogatepass")
    digest = hashlib.sha256(payload).hexdigest()[:16]
    return f"{root}#file-list:{digest}"


def _resolve_repo(root: Path, selected_paths: list[str]) -> ResolvedInput:
    input_type = "repo_file_list" if selected_paths else "repo"
    return ResolvedInput(
        input_type,
        _repo_input_ref(root, selected_paths),
        _complete_patch(root, selected_paths),
        [],
        selected_paths,
    )


def resolve_review_input(
    *,
    diff_file: str | None = None,
    repo_path: str | None = None,
    fixture: str | None = None,
    file_list: str | None = None,
) -> ResolvedInput:
    if file_list is not None and not repo_path:
        raise ValueError("--file-list requires --repo-path")
    selected_modes = [bool(diff_file), bool(repo_path), bool(fixture)]
    if sum(selected_modes) > 1:
        raise ValueError("choose exactly one of --diff-file, --repo-path, or --fixture")
    if repo_path:
        root = _repository_root(repo_path)
        selected_paths = _read_file_list(file_list, repo_root=root)
        return _resolve_repo(root, selected_paths)
    if fixture:
        return _resolve_fixture(fixture)
    if diff_file:
        path = Path(diff_file).resolve()
        return ResolvedInput("diff_file", str(path), path.read_text(encoding="utf-8"), [], [])
    return _resolve_fixture("all")
