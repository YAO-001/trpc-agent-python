# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""End-to-end tests for the skills code review agent example."""

from __future__ import annotations

import json
from pathlib import Path

from agent import sandbox_runner as sandbox_module
from agent.filter_policy import ReviewExecutionPolicy
from agent.input_resolver import EXAMPLE_DIR
from agent.orchestrator import ReviewOrchestrator
from agent.sandbox_runner import HarnessExecutionResult
from agent.sandbox_runner import SandboxRunner
from agent.secret_redactor import SecretRedactor
from agent.models import SandboxRun
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


def test_skill_only_finding_is_persisted_to_report_and_db(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'review.db'}"
    output_dir = tmp_path / "out"
    report = ReviewOrchestrator(db_url=db_url, output_dir=output_dir).review(
        fixture="sandbox_failure",
        dry_run=True,
        runtime="local",
    )

    assert any(
        finding.title == "skill-only static review marker" and "skill:run_static_review" in finding.source
        for finding in report.findings
    )
    json_text = (output_dir / "review_report.json").read_text(encoding="utf-8")
    assert "skill-only static review marker" in json_text
    rows = ReviewStorage(db_url).query_task(report.task_id)
    assert any(row["title"] == "skill-only static review marker" for row in rows["findings"])
    static_run = next(run for run in report.sandbox_runs if "run_static_review.py" in " ".join(run.command))
    assert static_run.exit_code == 0


def test_container_runtime_uses_trpc_skill_tool_set_harness(tmp_path, monkeypatch):
    calls = {}

    class FakeTrpcSkillToolSetHarness:
        def __init__(self, *, runtime, redactor):
            calls["runtime"] = runtime
            self.runtime = runtime

        def execute(self, *, task_id, review_input, commands, dry_run):
            calls["commands"] = commands
            payload = {
                "findings": [
                    {
                        "severity": "medium",
                        "category": "sandbox",
                        "file": "src/container_only.py",
                        "line": 7,
                        "title": "container skill finding",
                        "evidence": "mocked SkillToolSet output",
                        "recommendation": "Keep container SkillToolSet artifacts in the final review.",
                        "confidence": 0.91,
                        "source": ["mock"],
                    }
                ]
            }
            return HarnessExecutionResult(
                runs=[
                    SandboxRun(
                        run_id=f"sandbox_{task_id}_1",
                        task_id=task_id,
                        runtime=self.runtime,
                        command=commands[0],
                        decision="allow",
                        output_files={"out/findings.json": json.dumps(payload)},
                        created_at="1970-01-01T00:00:00+00:00",
                    )
                ]
            )

    monkeypatch.setattr(sandbox_module, "TrpcSkillToolSetHarness", FakeTrpcSkillToolSetHarness)

    report = ReviewOrchestrator(db_url=f"sqlite:///{tmp_path / 'review.db'}", output_dir=tmp_path / "out").review(
        fixture="clean",
        dry_run=True,
        runtime="container",
    )

    assert calls["runtime"] == "container"
    assert calls["commands"]
    assert any(
        finding.title == "container skill finding" and "skill:run_static_review" in finding.source
        for finding in report.findings
    )


def test_auto_runtime_prefers_container_then_records_local_fallback(tmp_path, monkeypatch):
    class FailingTrpcSkillToolSetHarness:
        def __init__(self, *, runtime, redactor):
            self.runtime = runtime

        def execute(self, *, task_id, review_input, commands, dry_run):
            raise RuntimeError("docker unavailable")

    monkeypatch.setattr(sandbox_module, "TrpcSkillToolSetHarness", FailingTrpcSkillToolSetHarness)

    report = ReviewOrchestrator(db_url=f"sqlite:///{tmp_path / 'review.db'}", output_dir=tmp_path / "out").review(
        fixture="clean",
        dry_run=True,
        runtime="auto",
    )

    assert report.input_summary["effective_runtime"] == "local"
    assert any(item.decision == "needs_human_review" for item in report.filter_intercepts)
    assert report.telemetry.filter_needs_review_count == 1
    assert any(warning.title == "container runtime fell back to local" for warning in report.needs_human_review)
    assert len(report.sandbox_runs) == 3


def test_local_sandbox_truncates_large_output_and_scrubs_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "raw-secret-value")
    runner = SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        redactor=SecretRedactor(),
    )
    command = ["python3", "scripts/smoke_test.py", "--input", "work/inputs/review_input.json", "--output", "out/smoke.json"]

    env_result = runner.run(
        task_id="task-safe-env",
        review_input={"task_id": "task-safe-env", "fixture_names": []},
        runtime="local",
        dry_run=True,
        commands=[command],
    )
    smoke = json.loads(env_result.runs[0].output_files["out/smoke.json"])
    assert smoke["secret_token_in_env"] is False

    monkeypatch.setattr(sandbox_module, "MAX_STDOUT_CHARS", 24)
    monkeypatch.setattr(sandbox_module, "MAX_OUTPUT_FILE_BYTES", 96)
    large_result = runner.run(
        task_id="task-large-output",
        review_input={"task_id": "task-large-output", "fixture_names": [], "emit_large_output": 512},
        runtime="local",
        dry_run=True,
        commands=[command],
    )
    run = large_result.runs[0]
    assert run.stdout_truncated is True
    assert run.output_truncated is True
    assert "raw-secret-value" not in run.stdout
    assert "raw-secret-value" not in json.dumps(run.output_files, sort_keys=True)


def test_demo_filter_writes_public_deny_report_without_sandbox_run(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'review.db'}"
    output_dir = tmp_path / "out"
    report = ReviewOrchestrator(db_url=db_url, output_dir=output_dir).demo_filter(dry_run=True, runtime="local")

    assert (output_dir / "filter_blocked_report.json").is_file()
    assert (output_dir / "filter_blocked_report.md").is_file()
    assert report.sandbox_runs == []
    assert report.filter_intercepts
    assert report.filter_intercepts[0].decision == "deny"
    rows = ReviewStorage(db_url).query_task(report.task_id)
    assert rows["sandbox_runs"] == []
    assert rows["filter_intercepts"][0]["decision"] == "deny"


def test_report_outputs_do_not_include_user_home_path(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'review.db'}"
    output_dir = tmp_path / "out"
    ReviewOrchestrator(db_url=db_url, output_dir=output_dir).review(
        fixture="clean",
        dry_run=True,
        runtime="local",
    )

    json_text = (output_dir / "review_report.json").read_text(encoding="utf-8")
    md_text = (output_dir / "review_report.md").read_text(encoding="utf-8")
    combined = json_text + md_text
    home = str(Path.home())
    assert home not in combined
    assert home.replace("\\", "\\\\") not in combined
    assert Path.home().as_posix() not in combined
