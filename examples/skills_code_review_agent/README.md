# Skills Code Review Agent

This example is a deterministic automatic code review agent built around
tRPC-Agent Skills, sandbox execution, Filter-style governance, SQL persistence,
telemetry, and dry-run fixtures.

## Architecture

- Deterministic review core: resolves diffs, redacts secrets, parses unified
  diffs, runs rules, deduplicates findings, stores SQL records, and writes JSON
  and Markdown reports.
- tRPC-Agent integration layer: provides a `code-review` Skill with docs and
  stdlib-only scripts. The main execution path uses `SkillToolSet` and
  `skill_run` with `output_files`, then merges sandbox artifacts back into the
  final findings. The local harness is an explicit development fallback.

## Quick Start

No API key is required for dry-run mode:

```bash
python examples/skills_code_review_agent/run_review.py review --fixture all --dry-run --runtime local
```

Evaluate fixtures independently:

```bash
python examples/skills_code_review_agent/run_review.py eval-fixtures --dry-run --runtime local
```

Show a public Filter deny report without executing a dangerous command:

```bash
python examples/skills_code_review_agent/run_review.py demo-filter --dry-run --runtime local
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
`skill_run` calls. `--runtime container` goes through the `SkillToolSet` harness;
Docker availability is only required for an optional integration run.

Local runtime is an explicit development and CI fallback. It stages the Skill
into a temporary workspace, writes `work/inputs/review_input.json`, executes the
same allowlisted commands, and collects `out/*.json` without shell redirection.
It uses a minimal `SAFE_ENV`, truncates stdout/stderr/output files, and redacts
all collected sandbox content before persistence.

`--runtime auto` prefers container execution. If container execution fails, it
falls back to local only with a persisted Filter intercept, human-review warning,
and telemetry record.

## Acceptance Matrix

| Requirement | Implementation |
| --- | --- |
| 8 fixtures | `fixtures/*.diff` plus `eval-fixtures` writes `outputs/eval_summary.json` |
| Default sandbox runtime | CLI defaults to `--runtime container`; `auto` prefers container |
| Local fallback behavior | `LocalSkillHarness` is only selected by `--runtime local` or recorded `auto` fallback |
| DB tables | `schema.sql` and `agent/storage.py` persist tasks, inputs, sandbox runs, findings, filter intercepts, telemetry, and reports |
| Filter-before-execution | `ReviewExecutionPolicy` gates every sandbox command before local/container harness execution |
| Timeout/output cap | sandbox stdout/stderr/output files are capped and record truncation plus output byte/file counts |
| Secret redaction | diffs, sandbox streams, output artifacts, reports, and DB records are redacted before persistence |
| Fake model/dry-run | no model API is required; dry-run uses deterministic timestamps and fixture task ids |
| Report fields | JSON/Markdown include schema version, findings, warnings, filter intercepts, sandbox summary, telemetry, redaction summary, recommendations, and query command |

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
- `examples/skills_code_review_agent/outputs/filter_blocked_report.json`
- `examples/skills_code_review_agent/outputs/filter_blocked_report.md`
- `examples/skills_code_review_agent/outputs/eval_summary.json`
- `examples/skills_code_review_agent/review.db`

## Troubleshooting

- If Docker is unavailable, use `--runtime local --dry-run`.
- If a command is not executed, inspect `filter_intercepts` in the report or DB.
- Use `demo-filter` to verify deny decisions are visible in JSON/Markdown output.
- Raw secret values must not appear in reports or storage; placeholders such as
  `[REDACTED:SECRET:...]` are expected.
- If `git diff` returns no content for `--repo-path`, confirm the repo has
  working tree changes.
