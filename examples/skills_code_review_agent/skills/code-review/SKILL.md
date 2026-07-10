---
name: code-review
description: Deterministic static code review over redacted unified diffs.
---

# Code Review Skill

Use this Skill only for the deterministic review workflow. The caller stages a
redacted `review_input.json` at `work/inputs/review_input.json`; scripts write
JSON files under `out/`. Always call `skill_run` with `output_files` instead of
shell redirection.

The host merges `findings`, `warnings`, and `needs_human_review` emitted by
these JSON files into the final report after redaction and deduplication.

Allowed commands:

- `python3 scripts/run_static_review.py --input work/inputs/review_input.json --output out/findings.json`
- `python3 scripts/secret_scan.py --input work/inputs/review_input.json --output out/secrets.json`
- `python3 scripts/smoke_test.py --input work/inputs/review_input.json --output out/smoke.json`

Do not install packages, request network access, read host secrets, or write
outside `out/`.
