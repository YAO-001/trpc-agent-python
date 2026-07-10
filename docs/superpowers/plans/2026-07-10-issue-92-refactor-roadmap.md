# Issue #92 Refactor Roadmap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the Issue #92 refactor as one cleanup prerequisite and four independently reviewable implementation PRs.

**Architecture:** The series follows the approved pipeline InputResolver → RedactionBoundary → PolicyGate → SandboxExecutor → ResultNormalizer → ReviewStorage → ReportBuilder. Each plan owns one boundary, introduces tests before behavior changes, and finishes with a clean verification checkpoint.

**Tech Stack:** Python 3.10+, Pydantic v2, SQLAlchemy, SQLite, pytest, Docker SDK, YAPF, flake8, PowerShell/git.

---

## Source documents

- Design: `docs/superpowers/specs/2026-07-10-issue-92-code-review-agent-refactor-design.md`
- Issue: https://github.com/trpc-group/trpc-agent-python/issues/92
- Starting branch: `codex/issue-92-code-review-agent`
- Starting design commit: `8bdf726`

## Plan sequence

| Order | Plan | Exit condition |
| --- | --- | --- |
| PR0 | `2026-07-10-issue-92-pr0-branch-cleanup.md` | Clean Issue #92-only baseline on current upstream main |
| PR1 | `2026-07-10-issue-92-pr1-security-boundary.md` | Full SkillRun request validation and sink-wide redaction |
| PR2 | `2026-07-10-issue-92-pr2-lifecycle-audit.md` | Truthful task state, failure records, audit-safe storage |
| PR3 | `2026-07-10-issue-92-pr3-input-normalization.md` | Complete inputs and one confidence/dedupe pipeline |
| PR4 | `2026-07-10-issue-92-pr4-resource-acceptance.md` | Enforced resource limits and automated Issue #92 acceptance |

PR0 is a branch-construction prerequisite rather than an upstream feature PR. PR1 is the first branch that should be proposed for upstream review. PR2–PR4 are stacked during development; each must be rebased onto the previously accepted stage and must leave the repository testable.

## Issue #92 traceability

| Issue capability or deliverable | Owning stage | Reproducible evidence |
| --- | --- | --- |
| code-review Skill and at least four rule classes | PR0, PR3 | Skill files plus rule/hidden-like regressions |
| Container Sandbox with local-only development fallback | PR1, PR2, PR4 | exact request gate, no auto fallback, required real-Docker job |
| unified diff, repo changes, and file-list inputs | PR3 | parser and temporary-repository tests |
| structured findings with all required fields | PR3 | Pydantic validation and ResultNormalizer tests |
| task/input/run/finding/report persistence | PR2 | migrations, audit-bijection tests, task query |
| dedupe and low-confidence routing | PR3 | boundary-value, order-invariance, and malicious-key tests |
| timeout, byte limits, env allowlist, redaction, failure records | PR1, PR2, PR4 | policy matrix, leak corpus, process-tree termination tests |
| Filter preflight and durable reasons | PR1, PR2 | deny/approval no-execution tests and decision rows |
| elapsed time, tool attempts/executions, intercepts, severity and exception distributions | PR2, PR4 | stored/JSON/Markdown telemetry agreement |
| JSON, Markdown, dry-run, eight fixtures, README and 300–500-character design | PR4 | full acceptance CLI, fixture audit, docs tests |

## Branch layout

```text
origin/main
  └── codex/issue-92-pr0-clean
        └── codex/issue-92-pr1-security
              └── codex/issue-92-pr2-lifecycle
                    └── codex/issue-92-pr3-inputs
                          └── codex/issue-92-pr4-acceptance
```

## Shared execution rules

- [ ] Use an isolated worktree when executing each plan.
- [ ] Run the named failing test before changing production code.
- [ ] Implement only enough behavior to satisfy the current task.
- [ ] Run the task-specific test, then the plan-level regression suite.
- [ ] Commit after each task with the exact commit message in that task.
- [ ] Do not carry unrelated Claude, OpenClaw, dependency-resolution, or formatting changes into the series.
- [ ] Do not push or open a PR until the current plan's exit checklist is green.

## Shared verification commands

Run from the repository root at the end of every implementation PR:

```powershell
python -m pytest tests/examples -o addopts= -q
python -m pytest tests/code_executors/container -o addopts= -q
$files = @(git diff --name-only --diff-filter=ACM origin/main...HEAD -- '*.py')
if ($files) {
  python -m flake8 @files
  python -m yapf --diff @files
}
git diff --check origin/main...HEAD
git status --short
```

Expected:

- pytest exits 0; a Docker integration skip is allowed only before PR4.
- flake8 exits 0.
- YAPF prints no diff.
- git diff --check prints nothing.
- git status prints nothing after the plan commit.

## Series completion checklist

- [ ] Public eight-fixture workflow writes JSON, Markdown, task, input, sandbox runs, findings, intercepts, telemetry, and report records.
- [ ] High-risk labeled corpus recall is at least 0.80.
- [ ] Safe labeled corpus false-positive rate is at most 0.15.
- [ ] Secret corpus redaction recall is at least 0.95 and no raw secret reaches report or database text.
- [ ] Container timeout and output-limit tests prove the execution is terminated rather than merely truncated after collection.
- [ ] Live Docker inspection proves CPU, memory, PID, network, read-only-root, and temporary-disk limits.
- [ ] deny and needs_human_review never stage inputs or execute a command.
- [ ] allow, deny, and needs_human_review decisions are all persisted with unique task/request identity.
- [ ] Telemetry records total and Sandbox time, attempts/executions, severity distribution, failure-kind distribution, truncations, and redactions.
- [ ] dry-run wall-clock acceptance is below 120 seconds.
- [ ] The Chinese design note contains 300-500 Han characters under the checked regex.
- [ ] Database, JSON, Markdown, and telemetry agree on terminal status and failure counts.
