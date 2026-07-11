from __future__ import annotations

import inspect
import json
import time
from pathlib import Path

from agent.evaluator import FIXTURE_ORDER
from agent.evaluator import detection_recall
from agent.evaluator import evaluate_acceptance
from agent.evaluator import evaluate_corpora
from agent.evaluator import evaluate_public_fixtures
from agent.evaluator import false_positive_rate
from agent import evaluator


def test_labeled_acceptance_thresholds(tmp_path):
    summary = evaluate_corpora(output_dir=tmp_path, db_url=f"sqlite:///{tmp_path / 'acceptance.db'}")
    assert summary.high_risk_recall >= 0.80
    assert summary.safe_false_positive_rate <= 0.15
    assert summary.secret_redaction_recall >= 0.95
    assert summary.raw_secret_leaks == []


def test_expected_labels_are_not_derived_from_predictions():
    expected = {("app.py", 7, "security")}
    predictions = {("app.py", 7, "database")}
    assert detection_recall(expected, predictions) == 0.0


def test_safe_false_positive_rate_counts_every_wrong_finding():
    assert false_positive_rate(10, {("a.py", 1, "security"), ("b.py", 2, "database")}) == 0.2


def test_evaluator_does_not_import_test_modules():
    source = inspect.getsource(__import__("agent.evaluator", fromlist=["*"]))
    assert "tests." not in source
    assert "test_skills_code_review_agent_hidden_like" not in source


def test_frozen_corpus_schema_invariants():
    high = evaluator._load("high_risk_cases.json")
    safe = evaluator._load("safe_cases.json")
    secrets = evaluator._load("secret_cases.json")
    assert (len(high), len(safe), len(secrets)) == (10, 15, 20)
    assert len({item["id"] for item in [*high, *safe, *secrets]}) == 45
    assert len({(item["expected"]["file"], item["expected"]["line"], item["expected"]["category"])
                for item in high}) == 10
    assert len({item["raw_value"] for item in secrets}) == 20


def test_corpus_loader_rejects_unsafe_case_id_and_path(tmp_path, monkeypatch):
    rows = evaluator._load("safe_cases.json")
    rows[0]["id"] = "../escape"
    rows[0]["changed_files"][0] = "../outside.py"
    (tmp_path / "safe_cases.json").write_text(json.dumps(rows), encoding="utf-8")
    monkeypatch.setattr(evaluator, "EVAL_DIR", tmp_path)
    try:
        evaluator._load("safe_cases.json")
    except ValueError as exc:
        assert "safe case IDs" in str(exc)
    else:
        raise AssertionError("unsafe corpus identity was accepted")


def test_all_public_fixtures_have_reports_and_audit_rows(tmp_path):
    summary = evaluate_public_fixtures(output_dir=tmp_path, db_url=f"sqlite:///{tmp_path / 'fixtures.db'}")
    assert {item.fixture for item in summary.fixtures} == set(FIXTURE_ORDER)
    for item in summary.fixtures:
        assert Path(item.json_path).exists()
        assert Path(item.markdown_path).exists()
        assert item.audit_counts["tasks"] == 1
        assert item.audit_counts["inputs"] == 1
        assert item.audit_counts["filter_intercepts"] == 3
        assert item.audit_counts["sandbox_runs"] == 3
        assert item.audit_counts["findings"] == item.findings_count
        assert item.audit_counts["telemetry_summaries"] == 1
        assert item.audit_counts["reports"] == 1
    assert sum(item.findings_count for item in summary.fixtures) > 0


def test_dry_run_acceptance_finishes_under_120_seconds(tmp_path):
    started = time.monotonic()
    evaluate_acceptance(output_dir=tmp_path, db_url=f"sqlite:///{tmp_path / 'full.db'}", include_fixtures=True)
    assert time.monotonic() - started < 120


def test_required_docker_gate_and_final_runtime_docs():
    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    readme = (root / "examples" / "skills_code_review_agent" / "README.md").read_text(encoding="utf-8")
    docker_tests = (Path(__file__).with_name("test_skills_code_review_agent_docker.py")).read_text(encoding="utf-8")
    assert "code-review-docker:" in workflow
    assert 'pytest -m "not docker_required"' in workflow
    assert "docker info" in workflow
    assert "pytest.skip" not in docker_tests
    assert "optional container" not in readme.lower()
    assert "falls back to local" not in readme.lower()
