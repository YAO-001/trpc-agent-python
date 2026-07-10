# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Rule engine tests for the skills code review agent example."""

from __future__ import annotations

from agent.dedupe import dedupe_findings
from agent.dedupe import dedupe_warnings
from agent.diff_parser import parse_unified_diff
from agent.input_resolver import EXAMPLE_DIR
from agent.models import Finding
from agent.models import ReviewWarning
from agent.rule_engine import RuleEngine
from agent.secret_redactor import SecretRedactor


def _run_fixture(name: str):
    diff = (EXAMPLE_DIR / "fixtures" / f"{name}.diff").read_text(encoding="utf-8")
    redacted = SecretRedactor().redact_text(diff)
    return RuleEngine().run(parse_unified_diff(redacted.text)), redacted


def test_every_rule_category_is_covered_by_fixtures():
    categories = set()
    warning_categories = set()
    for fixture in [
            "security",
            "secret_redaction",
            "async_resource_leak",
            "db_lifecycle",
            "missing_tests",
    ]:
        result, _ = _run_fixture(fixture)
        categories.update(finding.category for finding in result.findings)
        warning_categories.update(warning.category for warning in result.warnings)
        warning_categories.update(warning.category for warning in result.needs_human_review)

    assert {"security", "secret", "async_resource", "database"}.issubset(categories)
    assert "test" in warning_categories


def test_security_fixture_detects_all_security_patterns():
    result, _ = _run_fixture("security")
    titles = {finding.title for finding in result.findings}

    assert "subprocess invoked with shell=True" in titles
    assert "dynamic code execution on request-controlled data" in titles
    assert "SQL query uses string interpolation with user data" in titles
    assert "yaml.load used without SafeLoader" in titles
    assert "pickle.loads called on request-controlled data" in titles


def test_secret_fixture_redacts_before_findings():
    result, redacted = _run_fixture("secret_redaction")

    assert redacted.summary.total_redactions >= 6
    assert {"aws_access_key", "github_token", "openai_key", "jwt", "pem_private_key"}.issubset(redacted.summary.by_type)
    assert any(finding.category == "secret" for finding in result.findings)
    for raw in [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEF",
            "sk-1234567890abcdef1234567890abcdef",
            "correct-horse-battery-staple",
    ]:
        assert raw not in redacted.text


def test_dummy_secret_not_high_confidence_finding():
    diff = """diff --git a/app/config.py b/app/config.py
index 1111111..2222222 100644
--- a/app/config.py
+++ b/app/config.py
@@ -1,2 +1,4 @@
+token = "example-token"
+password = "changeme"
"""
    redacted = SecretRedactor().redact_text(diff)
    result = RuleEngine().run(parse_unified_diff(redacted.text))

    assert not any(finding.category == "secret" and finding.severity == "high" for finding in result.findings)


def test_deduplicate_same_file_line_category_keeps_highest_and_merges_sources():
    low = Finding(
        severity="low",
        category="security",
        file="app.py",
        line=10,
        title="same issue",
        evidence="low",
        recommendation="fix",
        confidence=0.7,
        source=["rule:a"],
    )
    high = Finding(
        severity="high",
        category="security",
        file="app.py",
        line=10,
        title="same issue",
        evidence="high",
        recommendation="fix",
        confidence=0.9,
        source=["rule:b"],
    )

    deduped = dedupe_findings([low, high])

    assert len(deduped) == 1
    assert deduped[0].severity == "high"
    assert deduped[0].source == ["rule:a", "rule:b"]


def test_low_confidence_missing_tests_routes_to_warning():
    result, _ = _run_fixture("missing_tests")

    assert not result.findings
    assert any(warning.category == "test" and not warning.needs_human_review for warning in result.warnings)


def test_deduplicate_sandbox_failure_warnings_merges_sources():
    first = ReviewWarning(
        category="sandbox",
        title="sandbox smoke test failed",
        message="sandbox_failure fixture intentionally returns a non-zero smoke-test status.",
        confidence=0.8,
        source=["skill:smoke_test"],
        needs_human_review=True,
    )
    duplicate = ReviewWarning(
        category="sandbox",
        title="sandbox smoke test failed",
        message="sandbox_failure fixture intentionally returns a non-zero smoke-test status.",
        confidence=1.0,
        source=["sandbox_runner"],
        needs_human_review=True,
    )

    deduped = dedupe_warnings([first, duplicate])

    assert len(deduped) == 1
    assert deduped[0].confidence == 1.0
    assert deduped[0].source == ["sandbox_runner", "skill:smoke_test"]
    assert deduped[0].needs_human_review is True
