# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""End-to-end tests for the skills code review agent example."""

from __future__ import annotations

import json

from agent.filter_policy import ReviewExecutionPolicy
from agent.input_resolver import EXAMPLE_DIR
from agent.orchestrator import ReviewOrchestrator
from agent.sandbox_runner import SandboxRunner
from agent.secret_redactor import SecretRedactor
from agent.storage import ReviewStorage


RAW_SAMPLE_SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEF",
    "sk-1234567890abcdef1234567890abcdef",
    "correct-horse-battery-staple",
    "FAKEKEYDATA",
]


def test_filter_deny_before_sandbox_execution():
    runner = SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        redactor=SecretRedactor(),
    )

    result = runner.run(
        task_id="task-filter",
        review_input={"task_id": "task-filter", "fixture_names": []},
        runtime="local",
        dry_run=True,
        commands=[["rm", "-rf", "/"]],
    )

    assert result.runs == []
    assert len(result.intercepts) == 1
    assert result.intercepts[0].decision == "deny"


def test_e2e_all_8_fixtures_and_secret_redaction(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'review.db'}"
    output_dir = tmp_path / "out"
    report = ReviewOrchestrator(db_url=db_url, output_dir=output_dir).review(
        fixture="all",
        dry_run=True,
        runtime="local",
    )

    assert (output_dir / "review_report.json").is_file()
    assert (output_dir / "review_report.md").is_file()
    assert report.input_summary["fixtures"] == [
        "clean",
        "security",
        "async_resource_leak",
        "db_lifecycle",
        "missing_tests",
        "duplicate_finding",
        "sandbox_failure",
        "secret_redaction",
    ]
    categories = {finding.category for finding in report.findings}
    assert {"security", "secret", "async_resource", "database"}.issubset(categories)
    assert any(warning.category == "sandbox" for warning in report.needs_human_review)
    assert report.telemetry.sandbox_failures_count == 1

    json_text = (output_dir / "review_report.json").read_text(encoding="utf-8")
    md_text = (output_dir / "review_report.md").read_text(encoding="utf-8")
    db_text = ReviewStorage(db_url).dump_task_text(report.task_id)
    for raw in RAW_SAMPLE_SECRETS:
        assert raw not in json_text
        assert raw not in md_text
        assert raw not in db_text


def test_eval_fixtures_writes_summary(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'review.db'}"
    output_dir = tmp_path / "out"
    summary = ReviewOrchestrator(db_url=db_url, output_dir=output_dir).eval_fixtures(
        dry_run=True,
        runtime="local",
    )

    saved = json.loads((output_dir / "eval_summary.json").read_text(encoding="utf-8"))
    assert saved["total_fixtures"] == 8
    assert summary["total_fixtures"] == 8
