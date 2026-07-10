# Issue #92 PR0 Branch Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the Issue #92 work on current upstream main without unrelated Claude, OpenClaw, dependency-resolution, or tooling changes.

**Architecture:** Construct a fresh isolated branch from origin/main and copy only an explicit path allowlist from the source branch. Normalize formatting before the baseline commit so later PRs start from a deterministic, reviewable tree.

**Tech Stack:** Git worktrees, PowerShell, pytest, YAPF, flake8.

---

### Task 1: Create the clean worktree

**Files:**
- Read: `docs/superpowers/specs/2026-07-10-issue-92-code-review-agent-refactor-design.md`
- Read: `docs/superpowers/plans/2026-07-10-issue-92-refactor-roadmap.md`

- [ ] **Step 1: Record the source branch and commit**

Run:

```powershell
$sourceBranch = 'codex/issue-92-code-review-agent'
git rev-parse $sourceBranch
git status --short
```

Expected: the source branch resolves and the source worktree is clean.

- [ ] **Step 2: Fetch the current base**

Run:

```powershell
git fetch origin main
git rev-parse origin/main
```

Expected: both commands exit 0.

- [ ] **Step 3: Create an isolated clean branch**

Use the using-git-worktrees skill. If native worktree setup is required, run:

```powershell
$sourceRoot = [System.IO.Path]::GetFullPath((git rev-parse --show-toplevel))
$workspaceParent = [System.IO.Path]::GetFullPath((Split-Path $sourceRoot -Parent))
$target = [System.IO.Path]::GetFullPath((Join-Path $workspaceParent 'trpc-agent-issue-92-clean'))
if ([System.IO.Path]::GetFullPath((Split-Path $target -Parent)) -ne $workspaceParent) {
  throw 'unexpected worktree parent'
}
git worktree add -b codex/issue-92-pr0-clean $target origin/main
git -C $target status --short --branch
```

Expected: the new branch points at origin/main and the new worktree is clean.

### Task 2: Copy only the Issue #92 scope

**Files:**
- Restore: `examples/skills_code_review_agent/**`
- Restore: `tests/examples/**`
- Restore: `tests/code_executors/container/test_container_ws_runtime_paths.py`
- Restore: `trpc_agent_sdk/code_executors/container/_container_ws_runtime.py`
- Restore: `.gitignore`
- Restore: `docs/superpowers/specs/**`
- Restore: `docs/superpowers/plans/**`

- [ ] **Step 1: Restore the explicit allowlist**

Run inside the clean worktree:

```powershell
$source = 'codex/issue-92-code-review-agent'
$paths = @(
  '.gitignore',
  'examples/skills_code_review_agent',
  'tests/examples',
  'tests/code_executors/container/test_container_ws_runtime_paths.py',
  'trpc_agent_sdk/code_executors/container/_container_ws_runtime.py',
  'docs/superpowers/specs',
  'docs/superpowers/plans'
)
git restore --source $source -- @paths
git status --short
```

Expected: only the listed paths appear.

- [ ] **Step 2: Prove unrelated paths are absent**

Run:

```powershell
$allowed = @(
  '^\.gitignore$',
  '^examples/skills_code_review_agent/',
  '^tests/examples/',
  '^tests/code_executors/container/test_container_ws_runtime_paths\.py$',
  '^trpc_agent_sdk/code_executors/container/_container_ws_runtime\.py$',
  '^docs/superpowers/(specs|plans)/'
)
$changed = @(
  git diff --name-only --diff-filter=ACM origin/main
  git ls-files --others --exclude-standard
) | ForEach-Object { $_.Replace('\', '/') } | Sort-Object -Unique
$unexpected = @($changed | Where-Object {
  $path = $_
  -not ($allowed | Where-Object { $path -match $_ })
})
if ($unexpected) { throw "unexpected paths: $($unexpected -join ', ')" }
```

Expected: exit 0 with no exception.

- [ ] **Step 3: Verify the known unrelated files match upstream**

Run:

```powershell
$unrelated = @(
  'pyproject.toml',
  'requirements-test.txt',
  'lint_flake8.sh',
  'trpc_agent_sdk/server/agents/claude/_claude_agent.py',
  'trpc_agent_sdk/server/openclaw/service/_heart_service.py'
)
foreach ($path in $unrelated) {
  git diff --quiet origin/main -- $path
  if ($LASTEXITCODE -ne 0) { throw "$path differs from origin/main" }
}
```

Expected: every file matches origin/main.

### Task 3: Normalize and verify the baseline

**Files:**
- Modify mechanically: copied Python files under `examples/skills_code_review_agent` and `tests/examples`
- Modify mechanically: `tests/code_executors/container/test_container_ws_runtime_paths.py`

- [ ] **Step 1: Run the formatter check and observe the existing failure**

Run:

```powershell
$files = @(
  git diff --name-only --diff-filter=ACM origin/main -- '*.py'
  git ls-files --others --exclude-standard -- '*.py'
) | Sort-Object -Unique
if (-not $files) {
  throw 'expected copied Python files but found none'
}
python -m yapf --diff @files
```

Expected before formatting: YAPF prints diffs for the copied example/test files.

- [ ] **Step 2: Apply mechanical formatting**

Run:

```powershell
$files = @(
  git diff --name-only --diff-filter=ACM origin/main -- '*.py'
  git ls-files --others --exclude-standard -- '*.py'
) | Sort-Object -Unique
if (-not $files) {
  throw 'expected copied Python files but found none'
}
python -m yapf -i @files
python -m yapf --diff @files
```

Expected: the second command prints nothing.

- [ ] **Step 3: Run lint and focused tests**

Run:

```powershell
$files = @(
  git diff --name-only --diff-filter=ACM origin/main -- '*.py'
  git ls-files --others --exclude-standard -- '*.py'
) | Sort-Object -Unique
if (-not $files) {
  throw 'expected copied Python files but found none'
}
python -m flake8 @files
python -m pytest tests/examples -o addopts= -q
python -m pytest tests/code_executors/container -o addopts= -q
```

Expected: lint and both test commands exit 0. A real Docker integration skip is acceptable at PR0.

- [ ] **Step 4: Check whitespace and scope**

Run:

```powershell
$stage = @(
  '.gitignore',
  'examples/skills_code_review_agent',
  'tests/examples',
  'tests/code_executors/container/test_container_ws_runtime_paths.py',
  'trpc_agent_sdk/code_executors/container/_container_ws_runtime.py',
  'docs/superpowers/specs',
  'docs/superpowers/plans'
)
git add @stage
git diff --cached --check
git status --short
```

Expected: the cached whitespace check prints nothing; status contains only staged, allowlisted Issue #92 paths. Staging is intentional so new files are included in the check.

- [ ] **Step 5: Commit the clean baseline**

Run:

```powershell
git diff --cached --check
git commit -m "chore: rebuild issue 92 branch on current main"
```

Expected: one baseline commit containing no unrelated paths.

- [ ] **Step 6: Prove the rebuilt branch merges cleanly**

```powershell
$mergeTree = git merge-tree --write-tree origin/main HEAD 2>&1
if ($LASTEXITCODE -ne 0) {
  throw "merge-tree reported conflicts: $mergeTree"
}
$mergeTree
git status --short
```

Expected: `git merge-tree` prints a tree object ID, exits 0, and status remains clean.

## PR0 exit checklist

- [ ] `git diff --name-only origin/main...HEAD` contains only the explicit allowlist.
- [ ] Example tests pass.
- [ ] Container executor tests pass.
- [ ] All copied Python files pass flake8 and YAPF.
- [ ] `git merge-tree --write-tree origin/main HEAD` reports no conflict.
- [ ] No upstream PR is opened yet; PR1 is the first upstream review branch.
