# Skills Code Review Agent

This example is a deterministic automatic code review agent built around
tRPC-Agent Skills, sandbox execution, Filter-style governance, SQL persistence,
telemetry, and dry-run fixtures.

## Architecture

- Deterministic review core: resolves diffs, redacts secrets, parses unified
  diffs, runs rules, validates all host and sandbox candidates at one schema
  boundary, stores SQL records, and writes JSON and Markdown reports.
- tRPC-Agent integration layer: provides a `code-review` Skill with docs and
  stdlib-only scripts. The main execution path uses `SkillToolSet` and
  `skill_run` with `output_files`, then merges sandbox artifacts back into the
  final findings. The local harness is available only through explicit
  `--runtime local` development runs.

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

## Input Modes

`--diff-file` accepts standard unified diffs, with or without `diff --git`
headers, including quoted paths and multi-file patches:

```bash
python examples/skills_code_review_agent/run_review.py review --diff-file change.diff --dry-run --runtime local
```

`--repo-path` reviews the final working-tree state across staged, unstaged, and
untracked text files. `--file-list` is only valid with `--repo-path`; every
selected path must be a non-empty repository-relative path that remains inside
that repository:

```bash
python examples/skills_code_review_agent/run_review.py review --repo-path . --file-list src/app.py,tests/test_app.py --dry-run --runtime local
```

All host rules and sandbox analysis scripts emit raw finding candidates. One
global normalizer validates them, deduplicates by exactly
`(file, line, category)`, merges provenance, drops confidence below `0.50`,
routes `0.50 <= confidence < 0.80` to warnings or human review according to
severity, and keeps confidence `>= 0.80` as findings. Runtime, policy, and
artifact audit warnings remain warnings and are not confidence-routed.

## Validation Commands

```bash
python -m pytest tests/examples -q
```

```bash
python examples/skills_code_review_agent/run_review.py review --fixture all --dry-run --runtime local
```

```bash
python examples/skills_code_review_agent/run_review.py eval-fixtures --dry-run --runtime local
```

Required container integration check:

```bash
python examples/skills_code_review_agent/run_review.py review --fixture security --dry-run --runtime container
```

## Runtime Paths

Container runtime is the default design target. `agent/agent_factory.py` shows
how to create a `SkillToolSet` with a container workspace runtime and guarded
`skill_run` calls. `--runtime container` goes through the `SkillToolSet` harness;
Docker availability is required by the dedicated container integration job.
Repository maintainers must require both the normal `test` job and
`code-review-docker` in branch protection; workflow YAML cannot set that
repository policy.

Local runtime is an explicit development and deterministic acceptance mode. It stages the Skill
into a temporary workspace, writes `work/inputs/review_input.json`, executes the
same allowlisted commands, and collects `out/*.json` without shell redirection.
It uses a minimal `SAFE_ENV`, truncates stdout/stderr/output files, and redacts
all collected sandbox content before persistence.

`--runtime auto` selects container execution. If container startup or execution
is unavailable, the task fails closed and records the failure; it never silently
reruns untrusted work on the host.

Run the complete dry-run acceptance evidence (frozen corpora plus all eight
fixtures) with:

```bash
python examples/skills_code_review_agent/run_review.py eval-acceptance --dry-run --runtime local --include-fixtures --output-dir /tmp/issue-92-acceptance --db-url sqlite:////tmp/issue-92-acceptance/acceptance.db
```

## Acceptance Matrix

| Requirement | Implementation | Test / Evidence |
| --- | --- | --- |
| 8 fixtures | `fixtures/*.diff` plus `eval-fixtures` writes `outputs/eval_summary.json` | `test_eval_fixtures_writes_summary`; `python examples/skills_code_review_agent/run_review.py eval-fixtures --dry-run --runtime local` |
| Default sandbox runtime | CLI defaults to `--runtime container`; `auto` selects the same fail-closed path | `test_real_container_review_stages_executes_collects_and_persists` |
| Local development behavior | `LocalSkillHarness` is selected only by explicit `--runtime local` | `test_labeled_acceptance_thresholds` |
| DB tables | `schema.sql` and `agent/storage.py` persist tasks, inputs, sandbox runs, findings, filter intercepts, telemetry, and reports | `test_query_task_returns_full_audit_chain`; `test_storage_roundtrip_by_task_id` |
| Filter-before-execution | `ReviewExecutionPolicy` gates every sandbox command before local/container harness execution | `test_filter_deny_before_sandbox_execution`; `test_filter_deny_before_container_execution_is_persisted` |
| Timeout/output cap | sandbox stdout/stderr/output files are capped and record truncation plus output byte/file counts | `test_local_sandbox_truncates_large_output_and_scrubs_env` |
| Secret redaction | diffs, sandbox streams, output artifacts, reports, and DB records are redacted before persistence | `test_e2e_all_8_fixtures_and_secret_redaction`; `test_report_outputs_do_not_include_user_home_path` |
| Unified input modes | standard unified diffs plus staged, unstaged, untracked, and repository-relative file-list selections | `test_parse_standard_unified_diff_without_git_header`; `test_repo_input_contains_staged_unstaged_and_untracked`; `test_file_list_requires_repo_path_before_default_fixture` |
| Global result normalization | host and sandbox candidates share the 0.50/0.80 thresholds and exact `(file, line, category)` identity | `test_sandbox_findings_use_the_same_confidence_boundary`; `test_host_and_sandbox_duplicate_is_finalized_once_with_all_provenance` |
| Fake model/dry-run | no model API is required; dry-run uses deterministic timestamps and fixture task ids | `test_eval_fixtures_writes_summary`; `python examples/skills_code_review_agent/run_review.py review --fixture all --dry-run --runtime local` |
| Report fields | JSON/Markdown include schema version, findings summary, severity stats, human review, filter summary, metrics, sandbox summary, redaction summary, recommendations, and query command | `test_review_report_contains_required_sections` |
| Hidden-like precision | static Skill script catches high-risk patterns while suppressing high findings on safe patterns | `test_hidden_like_precision_recall`; `test_hidden_like_safe_cases_do_not_emit_high_or_critical_findings` |
| Independent acceptance | frozen 10/15/20 corpora measure recall, false positives, redaction, and persisted leaks | `test_labeled_acceptance_thresholds`; `eval-acceptance --include-fixtures` |
| Required Docker isolation | live inspection proves resource limits, network isolation, bounded output, timeout, and descendant cleanup | `test_live_container_limits_and_termination` |

The smoke artifact's `network_probe_blocked` field records only that its fixed
external socket probe failed. The live Docker assertion of
`HostConfig.NetworkMode=none`, together with that probe, is the isolation
evidence; the probe field alone is not a general network diagnosis.

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

- Docker is mandatory for the required integration gate. Use explicit
  `--runtime local --dry-run` only for deterministic development checks.
- If a command is not executed, inspect `filter_intercepts` in the report or DB.
- Use `demo-filter` to verify deny decisions are visible in JSON/Markdown output.
- Raw secret values must not appear in reports or storage; placeholders such as
  `[REDACTED:SECRET:...]` are expected.
- If repository mode returns no content, confirm the repository has staged,
  unstaged, or untracked text changes and that any `--file-list` paths select
  them.
