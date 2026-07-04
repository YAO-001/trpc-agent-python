# Skills Code Review Agent

This example is a deterministic automatic code review agent built around
tRPC-Agent Skills, sandbox execution, Filter-style governance, SQL persistence,
telemetry, and dry-run fixtures.

## Architecture

- Deterministic review core: resolves diffs, redacts secrets, parses unified
  diffs, runs rules, deduplicates findings, stores SQL records, and writes JSON
  and Markdown reports.
- tRPC-Agent integration layer: provides a `code-review` Skill with docs and
  stdlib-only scripts. The production path uses `SkillToolSet` and `skill_run`
  with `output_files`; the test path uses an explicit local dry-run fallback.

## Quick Start

No API key is required for dry-run mode:

```bash
python examples/skills_code_review_agent/run_review.py review --fixture all --dry-run --runtime local
```

Evaluate fixtures independently:

```bash
python examples/skills_code_review_agent/run_review.py eval-fixtures --dry-run --runtime local
```

Query persisted records:

```bash
python examples/skills_code_review_agent/run_review.py query --db-url sqlite:///examples/skills_code_review_agent/review.db --task-id <task_id>
```

Running `run_review.py` without a subcommand defaults to
`review --fixture all --dry-run --runtime local`.

## Runtime Paths

Container runtime is the default design target. `agent/agent_factory.py` shows
how to create a `SkillToolSet` with a container workspace runtime and guarded
`skill_run` calls.

Local runtime is an explicit development and CI fallback. It stages the Skill
into a temporary workspace, writes `work/inputs/review_input.json`, executes the
same allowlisted commands, and collects `out/*.json` without shell redirection.

## Fixture Matrix

| Fixture | Purpose |
| --- | --- |
| `clean` | benign code and matching test change |
| `security` | shell, eval, SQL interpolation, yaml, pickle |
| `async_resource_leak` | unclosed sessions/files and async lifecycle warnings |
| `db_lifecycle` | unclosed database handles and transaction warning |
| `missing_tests` | code change without test change |
| `duplicate_finding` | duplicate-style security input for dedupe tests |
| `sandbox_failure` | deterministic sandbox command failure warning |
| `secret_redaction` | fake pattern-matching secrets that must be redacted |

## Expected Outputs

- `examples/skills_code_review_agent/outputs/review_report.json`
- `examples/skills_code_review_agent/outputs/review_report.md`
- `examples/skills_code_review_agent/outputs/eval_summary.json`
- `examples/skills_code_review_agent/review.db`

## Troubleshooting

- If Docker is unavailable, use `--runtime local --dry-run`.
- If a command is not executed, inspect `filter_intercepts` in the report or DB.
- Raw secret values must not appear in reports or storage; placeholders such as
  `[REDACTED:SECRET:...]` are expected.
- If `git diff` returns no content for `--repo-path`, confirm the repo has
  working tree changes.

