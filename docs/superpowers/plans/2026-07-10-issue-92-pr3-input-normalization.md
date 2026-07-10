# Issue #92 PR3 Input and Result Normalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve every supported review input completely and route host and sandbox candidates through one schema, confidence, redaction, and deduplication boundary.

**Architecture:** InputResolver emits one `ResolvedInput` for standard patches, complete repository changes, or repository-scoped file lists. RuleEngine and SandboxArtifactLoader produce unclassified `Finding` candidates; ResultNormalizer validates, redacts, routes, deduplicates, and emits the only final findings/warnings collections consumed by storage and reports.

**Tech Stack:** Python pathlib/subprocess, Pydantic v2, pytest, git.

---

### Task 1: Parse standard and git-style unified diffs

**Files:**
- Modify: `examples/skills_code_review_agent/agent/diff_parser.py:19-124`
- Test: `tests/examples/test_skills_code_review_agent_diff_parser.py`

- [ ] **Step 1: Add failing standard-header and quoted-path tests**

Append:

```python
def test_parse_standard_unified_diff_without_git_header():
    diff = """--- a/pkg/app.py
+++ b/pkg/app.py
@@ -1,2 +1,3 @@
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
--- "a/pkg/path with spaces.py"
+++ "b/pkg/path with spaces.py"
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
    ],
)
def test_parse_git_c_quoted_path_escapes(encoded, expected):
    new_path = encoded.replace("a/", "b/", 1)
    diff = (
        f'diff --git "{encoded}" "{new_path}"\n'
        f'--- "{encoded}"\n'
        f'+++ "{new_path}"\n'
        "@@ -0,0 +1 @@\n"
        "+answer = 42\n"
    )
    assert parse_unified_diff(diff).changed_files == [expected]


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
```

- [ ] **Step 2: Run the focused tests and confirm the first one fails**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_diff_parser.py -v
```

Expected: the existing tests pass; the standard-header and header-like hunk-content regressions fail against the prefix-only parser.

- [ ] **Step 3: Replace header parsing with look-ahead state**

Replace `_DIFF_RE` with a two-token Git C-quote lexer/decoder, then iterate over an indexed `lines` list. Do not use `shlex` or `ast.literal_eval`: they mishandle escaped quotes and UTF-8 octal bytes.

```python
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


def _split_git_path_tokens(value: str) -> list[str]:
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
        tokens.append(value[start:cursor])
    return tokens


def _decode_git_path(value: str) -> str:
    value = value.strip()
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
        if (
            cursor + 3 <= len(raw)
            and all(item in "01234567" for item in raw[cursor:cursor + 3])
        ):
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
```

At the start of `parse_unified_diff`, track the exact hunk line counts. Hunk content is consumed before looking for file headers, so deleted content beginning with `-- ` followed by added content beginning with `++ ` cannot be reinterpreted as a `---/+++` pair:

```python
lines = diff_text.replace("\r\n", "\n").replace("\r", "\n").splitlines()
pending_old_path: str | None = None
expecting_git_file_pair = False
in_hunk = False
remaining_old = 0
remaining_new = 0

for index, raw in enumerate(lines):
    if in_hunk:
        if raw.startswith("\\ No newline at end of file"):
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
        else:
            raise ValueError(f"invalid unified-diff hunk line: {raw!r}")
        in_hunk = remaining_old > 0 or remaining_new > 0
        continue

    git_paths = _git_header_paths(raw)
    if git_paths:
        _finalize_file(current, events)
        current = FileChange(old_file=git_paths[0], new_file=git_paths[1])
        files.append(current)
        events = []
        hunk_header = ""
        pending_old_path = None
        expecting_git_file_pair = True
        continue

    is_header_pair = (
        raw.startswith("--- ")
        and index + 1 < len(lines)
        and lines[index + 1].startswith("+++ ")
    )
    if is_header_pair:
        old_path = _file_header_path(raw, "--- ")
        if current is not None and not expecting_git_file_pair:
            _finalize_file(current, events)
            current = None
            events = []
            hunk_header = ""
        pending_old_path = old_path
        continue

    if raw.startswith("+++ ") and pending_old_path is not None:
        new_path = _file_header_path(raw, "+++ ")
        if current is None:
            current = FileChange(old_file=pending_old_path, new_file=new_path)
            files.append(current)
        else:
            current.old_file = pending_old_path
            current.new_file = new_path
        current.is_new = pending_old_path == "/dev/null"
        current.is_deleted = new_path == "/dev/null"
        pending_old_path = None
        expecting_git_file_pair = False
        continue

    hunk_match = _HUNK_RE.match(raw)
    if hunk_match and current is not None:
        old_line = int(hunk_match.group("old"))
        new_line = int(hunk_match.group("new"))
        remaining_old = int(hunk_match.group("old_count") or 1)
        remaining_new = int(hunk_match.group("new_count") or 1)
        hunk_header = raw
        in_hunk = remaining_old > 0 or remaining_new > 0
        continue
```

Remove the old prefix-only hunk loop. At EOF, reject a nonzero remaining count as a truncated/malformed diff, then finalize the current file. Keep `_LineEvent` context construction unchanged.

- [ ] **Step 4: Run parser regressions**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_diff_parser.py -v
```

Expected: all parser tests pass.

- [ ] **Step 5: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/diff_parser.py',
  'tests/examples/test_skills_code_review_agent_diff_parser.py'
)
git add @stage
git commit -m "fix(review): parse standard unified diffs"
```

### Task 2: Resolve staged, unstaged, untracked, and file-list inputs

**Files:**
- Modify: `examples/skills_code_review_agent/agent/input_resolver.py:25-103`
- Create: `tests/examples/test_skills_code_review_agent_input_resolver.py`
- Modify: `examples/skills_code_review_agent/agent/cli.py:36-92`
- Modify: `examples/skills_code_review_agent/agent/orchestrator.py:73-82`

- [ ] **Step 1: Write repository fixtures and failing tests**

Create:

```python
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from agent.diff_parser import parse_unified_diff
from agent.input_resolver import resolve_review_input


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _repo_with_changes(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "review@example.invalid")
    _git(repo, "config", "user.name", "Review Test")
    _git(repo, "config", "core.autocrlf", "false")
    (repo / "base.py").write_text("base = 1\n", encoding="utf-8")
    (repo / "tracked.py").write_text("value = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")

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


def test_file_list_is_repo_scoped_path_selector(tmp_path):
    repo = _repo_with_changes(tmp_path)
    selected = tmp_path / "files.txt"
    selected.write_text("staged.py\nuntracked.py\n", encoding="utf-8")
    resolved = resolve_review_input(repo_path=str(repo), file_list=str(selected))
    assert set(parse_unified_diff(resolved.diff_text).changed_files) == {
        "staged.py",
        "untracked.py",
    }


def test_file_list_requires_repo_path(tmp_path):
    selected = tmp_path / "files.txt"
    selected.write_text("app.py\n", encoding="utf-8")
    with pytest.raises(ValueError, match="--file-list requires --repo-path"):
        resolve_review_input(file_list=str(selected))


def test_file_list_rejects_path_escape(tmp_path):
    repo = _repo_with_changes(tmp_path)
    selected = tmp_path / "files.txt"
    selected.write_text("../outside.py\n", encoding="utf-8")
    with pytest.raises(ValueError, match="escapes repository root"):
        resolve_review_input(repo_path=str(repo), file_list=str(selected))


def test_empty_file_list_does_not_expand_to_full_repo(tmp_path):
    repo = _repo_with_changes(tmp_path)
    selected = tmp_path / "files.txt"
    selected.write_text("\n", encoding="utf-8")
    with pytest.raises(ValueError, match="file-list must select at least one path"):
        resolve_review_input(repo_path=str(repo), file_list=str(selected))
```

- [ ] **Step 2: Run the new tests and verify missing inputs**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_input_resolver.py -v
```

Expected: all five tests fail against the old resolver.

- [ ] **Step 3: Validate file-list paths against the repository root**

Replace `_read_file_list` with:

```python
def _read_file_list(path: str | None, *, repo_root: Path | None) -> list[str]:
    if not path:
        return []
    if repo_root is None:
        raise ValueError("--file-list requires --repo-path")
    values: list[str] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        value = raw.strip().replace("\\", "/")
        if not value:
            continue
        candidate = (repo_root / value).resolve(strict=False)
        try:
            relative = candidate.relative_to(repo_root)
        except ValueError as exc:
            raise ValueError(f"file-list path escapes repository root: {value}") from exc
        values.append(relative.as_posix())
    selected = sorted(set(values))
    if not selected:
        raise ValueError("file-list must select at least one path")
    return selected
```

Perform the `file_list and repo_path` validation before selecting the default `fixture=all`. A bare `--file-list` must never cause fixture data to be loaded.

- [ ] **Step 4: Build a complete repository patch**

Add a Git runner that accepts the documented `git diff --no-index` return code and preserves NUL-delimited filenames:

```python
def _run_git(
    path: Path,
    args: list[str],
    *,
    accepted_codes: tuple[int, ...] = (0,),
) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode not in accepted_codes:
        raise RuntimeError(f"git {' '.join(args)} failed for {path}: {result.stderr.strip()}")
    return result.stdout


def _untracked_patch(root: Path, relative: str) -> str:
    absolute = (root / relative).resolve(strict=True)
    absolute.relative_to(root)
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "diff",
            "--no-index",
            "--no-ext-diff",
            "--unified=3",
            "--",
            "/dev/null",
            relative,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"git diff --no-index failed for {relative}: {result.stderr.strip()}")
    return result.stdout


def _resolve_repo(repo_path: str, selected_paths: list[str]) -> ResolvedInput:
    root = Path(repo_path).resolve(strict=True)
    pathspec = ["--", *selected_paths]
    tracked = _run_git(
        root,
        [
            "--literal-pathspecs",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--unified=3",
            "HEAD",
            *pathspec,
        ] if selected_paths else [
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--unified=3",
            "HEAD",
        ],
    )
    untracked_raw = _run_git(
        root,
        [
            "--literal-pathspecs",
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            *pathspec,
        ] if selected_paths else [
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
        ],
    )
    untracked = [item for item in untracked_raw.split("\0") if item]
    patches = [tracked.rstrip("\n")]
    patches.extend(_untracked_patch(root, item) for item in sorted(untracked))
    diff_text = "\n".join(item for item in patches if item) + ("\n" if any(patches) else "")
    input_type = "repo_file_list" if selected_paths else "repo"
    return ResolvedInput(input_type, str(root), diff_text, [], selected_paths)
```

In `resolve_review_input`, resolve `repo_root`, read the selected paths, then call `_resolve_repo(repo_path, selected_paths)`. Remove the orchestrator's old union of `resolved.file_list` into `parsed.changed_files`; selected paths must be backed by real diff content. Update CLI help to state that `--file-list` is a non-empty, literal, repository-relative path selector and requires `--repo-path`.

- [ ] **Step 5: Run input and parser tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_input_resolver.py -v
python -m pytest tests/examples/test_skills_code_review_agent_diff_parser.py -v
```

Expected: staged, unstaged, untracked, selected, and traversal cases all pass.

- [ ] **Step 6: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/input_resolver.py',
  'examples/skills_code_review_agent/agent/cli.py',
  'examples/skills_code_review_agent/agent/orchestrator.py',
  'tests/examples/test_skills_code_review_agent_input_resolver.py'
)
git add @stage
git commit -m "fix(review): resolve complete repository inputs"
```

### Task 3: Introduce the single confidence and dedupe boundary

**Files:**
- Create: `examples/skills_code_review_agent/agent/result_normalizer.py`
- Modify: `examples/skills_code_review_agent/agent/models.py:75-126`
- Modify: `examples/skills_code_review_agent/agent/dedupe.py:22-46`
- Modify: `examples/skills_code_review_agent/skills/code-review/scripts/run_static_review.py`
- Create: `tests/examples/test_skills_code_review_agent_result_normalizer.py`
- Modify: `tests/examples/test_skills_code_review_agent_e2e.py`

- [ ] **Step 1: Write failing boundary-value and dedupe tests**

Create:

```python
import pytest

from agent.models import Finding
from agent.redaction_boundary import RedactionBoundary
from agent.result_normalizer import ReviewCandidates
from agent.result_normalizer import ResultNormalizer


def _candidate(confidence: float, *, severity: str = "low", title: str = "candidate", source=None):
    return Finding(
        severity=severity,
        category="security",
        file="app.py",
        line=10,
        title=title,
        evidence="unsafe call",
        recommendation="use safe API",
        confidence=confidence,
        source=source or ["host"],
    )


@pytest.mark.parametrize(
    ("confidence", "severity", "bucket"),
    [
        (0.0, "low", "dropped"),
        (0.49, "critical", "dropped"),
        (0.50, "low", "warnings"),
        (0.79, "high", "needs_human_review"),
        (0.80, "low", "findings"),
        (1.0, "critical", "findings"),
    ],
)
def test_confidence_boundaries(confidence, severity, bucket):
    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(findings=[_candidate(confidence, severity=severity)])
    )
    if bucket == "dropped":
        assert result.dropped_count == 1
        assert result.findings == result.warnings == result.needs_human_review == []
    else:
        assert len(getattr(result, bucket)) == 1


def test_dedupe_key_ignores_title_and_merges_sources():
    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(findings=[
            _candidate(0.91, title="host title", source=["host"]),
            _candidate(0.95, title="sandbox title", source=["sandbox"]),
        ])
    )
    assert len(result.findings) == 1
    assert result.findings[0].title == "sandbox title"
    assert result.findings[0].source == ["host", "sandbox"]
    assert result.findings[0].dedupe_key == Finding(
        **_candidate(0.95, title="third title").model_dump(exclude={"dedupe_key"}),
    ).dedupe_key


def test_dedupe_keeps_maximum_severity_and_confidence_independently():
    high_low_confidence = _candidate(
        0.60,
        severity="high",
        title="high severity",
        source=["host"],
    )
    low_high_confidence = _candidate(
        0.95,
        severity="low",
        title="high confidence",
        source=["sandbox"],
    )
    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(findings=[
            high_low_confidence,
            low_high_confidence,
        ])
    )
    assert len(result.findings) == 1
    assert result.findings[0].severity == "high"
    assert result.findings[0].confidence == 0.95
    assert result.findings[0].source == ["host", "sandbox"]
    reversed_result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(findings=[
            low_high_confidence,
            high_low_confidence,
        ])
    )
    assert reversed_result.findings[0] == result.findings[0]


def test_normalizer_redacts_raw_mapping_fields():
    raw = _candidate(0.9).model_dump(mode="json")
    raw["evidence"] = 'client_secret="normalizer-secret-987"'
    raw["dedupe_key"] = "attacker-controlled"
    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(findings=[raw])
    )
    assert "normalizer-secret-987" not in result.findings[0].evidence
    assert result.findings[0].dedupe_key != "attacker-controlled"


def test_invalid_candidate_becomes_validation_error_and_human_review():
    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(findings=[{
            "severity": "impossible",
            "category": "security",
            "file": "app.py",
            "line": -1,
            "confidence": 2,
        }])
    )
    assert len(result.validation_errors) == 1
    assert len(result.needs_human_review) == 1


def test_invalid_warning_becomes_validation_error_instead_of_raising():
    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(warnings=[{
            "category": "sandbox",
            "title": "bad warning",
            "message": "bad",
            "confidence": 2,
        }])
    )
    assert len(result.validation_errors) == 1
    assert len(result.needs_human_review) == 1
```

- [ ] **Step 2: Run the new tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_result_normalizer.py -v
```

Expected: collection fails because `result_normalizer.py` does not exist.

- [ ] **Step 3: Make the persisted key match the approved dedupe key**

Change `finding_dedupe_key` to accept only `file, line, category`; update `Finding._set_dedupe_key` and every caller:

```python
def finding_dedupe_key(file: str, line: int, category: str) -> str:
    payload = f"{file}:{line}:{category}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
```

Constrain `Finding.confidence` and `ReviewWarning.confidence` with `Field(ge=0.0, le=1.0)`; constrain finding line to `ge=0`, severity to `info/low/medium/high/critical`, and category to `security/secret/async_resource/database/test/sandbox`. In the same step, change the static script's file-handle rule from legacy `category="resource"` to `category="async_resource"`; do not create a checkpoint where the producer emits a value the new model rejects.

Add this regression beside the existing `_run_static_review_script` tests:

```python
def test_static_review_file_handle_uses_canonical_category(tmp_path):
    output = _run_static_review_script(
        tmp_path,
        {
            "task_id": "task-category",
            "changed_files": ["src/files.py"],
            "added_lines": [{
                "file": "src/files.py",
                "line": 8,
                "content": "handle = open(user_path)",
                "context_before": [],
                "context_after": [],
            }],
        },
    )
    item = next(
        finding
        for finding in output["findings"]
        if finding["title"] == "file handle may not be closed"
    )
    assert item["category"] == "async_resource"
    assert Finding.model_validate(item).category == "async_resource"
```

Keep `dedupe_findings` keyed by `(file, line, category)`. For each group, choose the representative by the stable maximum tuple `(confidence, severity_rank, title, evidence, recommendation, tuple(source))`, then model-copy the independently highest severity and highest confidence onto it and merge every source. This prevents a high-severity/low-confidence candidate from erasing a lower-severity/high-confidence duplicate and makes reversed input order identical.

- [ ] **Step 4: Implement ResultNormalizer**

Create:

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from typing import Mapping
from typing import Sequence

from pydantic import BaseModel
from pydantic import Field
from pydantic import ValidationError

from .dedupe import dedupe_findings
from .dedupe import dedupe_warnings
from .models import Finding
from .models import ReviewWarning
from .redaction_boundary import RedactionBoundary


CandidateValue = Finding | Mapping[str, Any]
WarningValue = ReviewWarning | Mapping[str, Any]


@dataclass(frozen=True)
class ReviewCandidates:
    findings: Sequence[CandidateValue] = ()
    warnings: Sequence[WarningValue] = ()
    needs_human_review: Sequence[WarningValue] = ()
    validation_errors: Sequence[ReviewWarning] = ()


class NormalizedReviewResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    warnings: list[ReviewWarning] = Field(default_factory=list)
    needs_human_review: list[ReviewWarning] = Field(default_factory=list)
    dropped_count: int = 0
    validation_errors: list[ReviewWarning] = Field(default_factory=list)


def _warning_from_candidate(candidate: Finding, *, needs_review: bool) -> ReviewWarning:
    return ReviewWarning(
        category=candidate.category,
        title=candidate.title,
        message=f"{candidate.evidence} Recommendation: {candidate.recommendation}",
        file=candidate.file,
        line=candidate.line,
        confidence=candidate.confidence,
        source=candidate.source,
        needs_human_review=needs_review,
    )


class ResultNormalizer:
    high_confidence_threshold = 0.80
    low_confidence_threshold = 0.50

    def __init__(self, boundary: RedactionBoundary) -> None:
        self.boundary = boundary

    def _finding(
        self,
        value: CandidateValue,
        index: int,
    ) -> tuple[Finding | None, ReviewWarning | None]:
        payload = value.model_dump(mode="json") if isinstance(value, Finding) else dict(value)
        payload.pop("dedupe_key", None)
        try:
            return Finding.model_validate(self.boundary.clean(payload)), None
        except ValidationError as exc:
            message = self.boundary.text(
                f"candidate {index} failed schema validation: {exc}"
            ).text
            warning = ReviewWarning(
                category="sandbox",
                title="review candidate has invalid schema",
                message=message,
                confidence=1.0,
                source=["result_normalizer"],
                needs_human_review=True,
            )
            return None, warning

    def _warning(
        self,
        value: WarningValue,
        *,
        needs_review: bool,
    ) -> tuple[ReviewWarning | None, ReviewWarning | None]:
        payload = value.model_dump(mode="json") if isinstance(value, ReviewWarning) else dict(value)
        payload["needs_human_review"] = needs_review
        try:
            return ReviewWarning.model_validate(self.boundary.clean(payload)), None
        except ValidationError as exc:
            error = ReviewWarning(
                category="sandbox",
                title="review warning has invalid schema",
                message=self.boundary.text(
                    f"warning failed schema validation: {exc}"
                ).text,
                confidence=1.0,
                source=["result_normalizer"],
                needs_human_review=True,
            )
            return None, error

    def normalize(
        self,
        *batches: ReviewCandidates,
    ) -> NormalizedReviewResult:
        candidates: list[Finding] = []
        findings: list[Finding] = []
        routed_warnings: list[ReviewWarning] = []
        routed_review: list[ReviewWarning] = []
        validation_errors: list[ReviewWarning] = []
        candidate_index = 0
        for batch in batches:
            for value in batch.findings:
                candidate_index += 1
                candidate, error = self._finding(value, candidate_index)
                if error is not None:
                    validation_errors.append(error)
                    routed_review.append(error)
                elif candidate is not None:
                    candidates.append(candidate)
            for values, needs_review, is_validation_error in (
                (batch.warnings, False, False),
                (batch.needs_human_review, True, False),
                (batch.validation_errors, True, True),
            ):
                for value in values:
                    warning, error = self._warning(
                        value,
                        needs_review=needs_review,
                    )
                    if error is not None:
                        validation_errors.append(error)
                        routed_review.append(error)
                    elif warning is not None:
                        if is_validation_error:
                            validation_errors.append(warning)
                        (routed_review if needs_review else routed_warnings).append(
                            warning
                        )
        dropped = 0
        for candidate in dedupe_findings(candidates):
            if candidate.confidence >= self.high_confidence_threshold:
                findings.append(candidate)
            elif candidate.confidence >= self.low_confidence_threshold:
                needs_review = candidate.severity in {"medium", "high", "critical"}
                warning = _warning_from_candidate(candidate, needs_review=needs_review)
                (routed_review if needs_review else routed_warnings).append(warning)
            else:
                dropped += 1
        return NormalizedReviewResult(
            findings=findings,
            warnings=dedupe_warnings(routed_warnings),
            needs_human_review=dedupe_warnings(routed_review),
            dropped_count=dropped,
            validation_errors=dedupe_warnings(validation_errors),
        )
```

- [ ] **Step 5: Run normalizer and existing rule tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_result_normalizer.py -v
python -m pytest tests/examples/test_skills_code_review_agent_rules.py -v
python -m pytest tests/examples/test_skills_code_review_agent_e2e.py -k "file_handle_uses_canonical_category" -v
```

Expected: all normalizer and existing rule tests pass at this checkpoint.

- [ ] **Step 6: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/result_normalizer.py',
  'examples/skills_code_review_agent/agent/models.py',
  'examples/skills_code_review_agent/agent/dedupe.py',
  'examples/skills_code_review_agent/skills/code-review/scripts/run_static_review.py',
  'tests/examples/test_skills_code_review_agent_result_normalizer.py',
  'tests/examples/test_skills_code_review_agent_rules.py',
  'tests/examples/test_skills_code_review_agent_e2e.py'
)
git add @stage
git commit -m "feat(review): normalize confidence and dedupe once"
```

### Task 4: Route host and sandbox candidates through ResultNormalizer

**Files:**
- Modify: `examples/skills_code_review_agent/agent/rule_engine.py:37-119`
- Modify: `examples/skills_code_review_agent/agent/sandbox_artifact_loader.py:86-234`
- Modify: `examples/skills_code_review_agent/agent/sandbox_runner.py:65-77,440-556`
- Modify: `examples/skills_code_review_agent/agent/orchestrator.py:64-181`
- Modify: `examples/skills_code_review_agent/agent/telemetry.py:20-70`
- Modify: `tests/examples/test_skills_code_review_agent_e2e.py`
- Modify: `tests/examples/test_skills_code_review_agent_rules.py`
- Modify: `examples/skills_code_review_agent/README.md`

- [ ] **Step 1: Add a failing sandbox routing regression**

Add a fake harness result whose `out/findings.json` contains three otherwise-valid sandbox findings with confidences `0`, `0.79`, and `0.80`:

```python
def test_sandbox_findings_use_the_same_confidence_boundary(tmp_path, monkeypatch):
    payload = {
        "findings": [
            _sandbox_finding(line=1, confidence=0),
            _sandbox_finding(line=2, confidence=0.79, severity="high"),
            _sandbox_finding(line=3, confidence=0.80),
        ],
        "warnings": [],
        "needs_human_review": [],
    }
    monkeypatch.setattr(
        "agent.sandbox_runner.TrpcSkillToolSetHarness",
        _harness_with_artifact(payload),
    )
    report = ReviewOrchestrator(
        db_url=f"sqlite:///{tmp_path / 'review.db'}",
        output_dir=tmp_path / "out",
    ).review(fixture="clean", runtime="container", dry_run=True)

    sandbox_findings = [item for item in report.findings if "sandbox" in item.source]
    assert [item.line for item in sandbox_findings] == [3]
    assert any(item.line == 2 for item in report.needs_human_review)
    assert report.telemetry.debug_dropped_count >= 1


def test_invalid_artifact_marks_run_and_terminal_status(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "agent.sandbox_runner.TrpcSkillToolSetHarness",
        _harness_with_raw_artifact("{not-json"),
    )
    report = ReviewOrchestrator(
        db_url=f"sqlite:///{tmp_path / 'review.db'}",
        output_dir=tmp_path / "out-invalid",
    ).review(fixture="clean", runtime="container", dry_run=True)
    rows = ReviewStorage(
        f"sqlite:///{tmp_path / 'review.db'}"
    ).query_task(report.task_id)
    assert report.task_status == "completed_with_errors"
    assert any(
        item["failure_kind"] == "artifact_invalid"
        for item in rows["sandbox_runs"]
    )
    assert report.telemetry.sandbox_failures_count >= 1
```

Define `_sandbox_finding` next to the existing factories. `_harness_with_artifact(payload)` returns a harness class whose `execute_one` constructs a real `SandboxRun` using `request.request_id` and `output_files={request.output_spec.globs[0]: json.dumps(payload)}`; it must not return already-normalized findings or bypass SandboxArtifactLoader.

- [ ] **Step 2: Run the regression and confirm the confidence-zero bug**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_e2e.py -k "same_confidence_boundary" -v
```

Expected: FAIL because `float(payload.get("confidence") or 1.0)` turns zero into one and sandbox findings bypass host routing.

- [ ] **Step 3: Make producers return candidates, not final routing**

Replace `RuleEngineResult` with `ReviewCandidates`. Keep the PR1 redaction-summary argument: `RuleEngine.run(parsed_diff, redaction_summary)` returns concatenated raw rule candidates without dedupe or confidence routing:

```python
def run(
    self,
    parsed_diff: ParsedDiff,
    redaction_summary: RedactionSummary,
) -> ReviewCandidates:
    candidates = [
        *run_security_rules(parsed_diff.added_lines),
        *_secret_findings(parsed_diff.added_lines, redaction_summary),
        *run_async_resource_rules(parsed_diff.added_lines),
        *run_database_rules(parsed_diff.added_lines),
        *run_test_rules(parsed_diff),
    ]
    return ReviewCandidates(findings=candidates)
```

Change `SandboxArtifactLoader.load` to return `ReviewCandidates` plus `invalid_run_ids: frozenset[str]`. After JSON envelope parsing, keep finding payloads as cleaned mappings, add the artifact/run source, and let ResultNormalizer perform field validation. This removes the confidence coercion entirely, so numeric zero remains zero. Malformed JSON/non-object envelopes and invalid finding/warning payloads become redacted `ReviewWarning` values in `validation_errors` and add the producing run ID to `invalid_run_ids`.

Change `SandboxResult` to expose one `candidates: ReviewCandidates` field instead of final findings/warnings lists. Runtime/policy warnings are added to that batch's `warnings` or `needs_human_review`.

In `SandboxRunner.run`, load and validate each completed run's artifacts before invoking `on_run`. If its ID is invalid, model-copy `failure_kind="artifact_invalid"` and a redacted failure reason, then persist that updated run exactly once. This preserves PR2's immediate-after-completion audit rule and lets `terminal_status` return completed_with_errors.

- [ ] **Step 4: Normalize exactly once in both orchestration paths**

After SandboxRunner returns, replace the separate host/sandbox merges with:

```python
rule_candidates = RuleEngine().run(parsed, boundary.summary)
normalized = ResultNormalizer(boundary).normalize(
    rule_candidates,
    sandbox_result.candidates,
)
findings = normalized.findings
warnings = sorted(normalized.warnings, key=_warning_sort_key)
needs_human_review = sorted(normalized.needs_human_review, key=_warning_sort_key)
```

Pass `normalized.dropped_count` to telemetry. In `demo_filter`, call `ResultNormalizer(boundary).normalize(ReviewCandidates(), sandbox_result.candidates)` so policy/runtime warnings are preserved even though host candidates are empty. Remove direct orchestrator imports of `dedupe_findings`/`dedupe_warnings`.

The sandbox static script, already migrated to canonical `async_resource` in Task 3, must emit candidate records with confidence and source, but it must not independently apply the 0.50/0.80 routing thresholds. Its JSON schema remains `findings/warnings/needs_human_review` for compatibility; the host treats items in `findings` as candidates. Keep the Task 3 category regression green and add an end-to-end assertion that the sandbox async-resource candidate appears under `async_resource`, not `validation_errors`.

- [ ] **Step 5: Update behavior tests and input documentation**

Update RuleEngine unit tests to call `ResultNormalizer(boundary).normalize(RuleEngine().run(parsed, boundary.summary))`. Document:

- standard unified diff support;
- repository inputs include staged, unstaged, and untracked files;
- `--file-list` requires `--repo-path` and selects repository-relative paths;
- all source findings use one 0.50/0.80 confidence boundary and `(file, line, category)` dedupe key.

- [ ] **Step 6: Run PR3 regressions**

```powershell
$tests = @(
  'tests/examples/test_skills_code_review_agent_diff_parser.py',
  'tests/examples/test_skills_code_review_agent_input_resolver.py',
  'tests/examples/test_skills_code_review_agent_result_normalizer.py',
  'tests/examples/test_skills_code_review_agent_rules.py',
  'tests/examples/test_skills_code_review_agent_e2e.py'
)
python -m pytest @tests -v
python -m pytest tests/examples -o addopts= -q
```

Expected: all tests pass; sandbox confidence zero is dropped, 0.79 is routed, and 0.80 is a finding.

- [ ] **Step 7: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/rule_engine.py',
  'examples/skills_code_review_agent/agent/sandbox_artifact_loader.py',
  'examples/skills_code_review_agent/agent/sandbox_runner.py',
  'examples/skills_code_review_agent/agent/orchestrator.py',
  'examples/skills_code_review_agent/agent/telemetry.py',
  'examples/skills_code_review_agent/skills/code-review/scripts/run_static_review.py',
  'examples/skills_code_review_agent/README.md',
  'tests/examples/test_skills_code_review_agent_e2e.py',
  'tests/examples/test_skills_code_review_agent_rules.py'
)
git add @stage
git commit -m "fix(review): normalize host and sandbox results together"
```

## PR3 exit checklist

- [ ] Standard unified diffs work without a `diff --git` header, including quoted paths.
- [ ] Repository mode includes staged, unstaged, and untracked text changes.
- [ ] File-list mode cannot run without a repository and cannot escape its root.
- [ ] Confidence 0, 0.49, 0.50, 0.79, 0.80, and 1.0 follow the approved buckets for every source.
- [ ] Finding identity is exactly `(file, line, category)`; selected severity/confidence is deterministic and sources are merged.
- [ ] Orchestrator, storage, telemetry, JSON, and Markdown consume only `NormalizedReviewResult`.
