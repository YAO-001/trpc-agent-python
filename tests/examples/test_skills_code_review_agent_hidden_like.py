# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Hidden-like regression fixtures for the code-review Skill static script."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from agent.diff_parser import parse_unified_diff
from agent.input_resolver import EXAMPLE_DIR
from agent.redaction_boundary import RedactionBoundary
from agent.result_normalizer import ReviewCandidates
from agent.result_normalizer import ResultNormalizer
from agent.rule_engine import RuleEngine

SCRIPT = EXAMPLE_DIR / "skills" / "code-review" / "scripts" / "run_static_review.py"


def _fake_live_token() -> str:
    return "ghp_" + ("A" * 40)


def _line(file: str, line: int, content: str) -> dict[str, Any]:
    return {"file": file, "line": line, "content": content}


def _payload(changed_files: list[str], added_lines: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "task_id": "hidden-like",
        "fixture_names": ["hidden_like"],
        "changed_files": changed_files,
        "added_lines": added_lines,
    }


def _redacted_secret_payload(raw: str) -> tuple[dict[str, Any], RedactionBoundary]:
    boundary = RedactionBoundary()
    content = boundary.text(f'api_key = "{raw}"').text
    payload = _payload(
        ["src/app/settings.py", "tests/test_settings.py"],
        [_line("src/app/settings.py", 12, content)],
    )
    payload["redaction_summary"] = boundary.summary.model_dump(mode="json")
    return payload, boundary


def _run_static_review(tmp_path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    input_path = tmp_path / "review_input.json"
    output_path = tmp_path / "findings.json"
    input_path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    return json.loads(output_path.read_text(encoding="utf-8"))


def _normalize_host(diff: str, boundary: RedactionBoundary):
    return ResultNormalizer(boundary).normalize(RuleEngine().run(parse_unified_diff(diff), boundary.summary))


def _normalize_sandbox(output: dict[str, Any]):
    return ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(
            findings=output["findings"],
            warnings=output["warnings"],
            needs_human_review=output["needs_human_review"],
        ))


def _review_items(output: dict[str, Any]) -> list[dict[str, Any]]:
    return [*output["findings"], *output["warnings"], *output["needs_human_review"]]


def _high_findings(output: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in output["findings"] if item["severity"] in {"critical", "high"}]


DANGEROUS_CASES = [
    (
        "subprocess_shell_user_input",
        ["src/app/search.py", "tests/test_search.py"],
        [_line("src/app/search.py", 10, 'subprocess.run(f"grep {user_input}", shell=True)')],
        "security",
    ),
    (
        "os_system_request_path",
        ["src/app/files.py", "tests/test_files.py"],
        [_line("src/app/files.py", 20, 'os.system("rm -rf " + request.args["path"])')],
        "security",
    ),
    (
        "eval_request_json",
        ["src/app/expr.py", "tests/test_expr.py"],
        [_line("src/app/expr.py", 30, 'eval(request.json["expr"])')],
        "security",
    ),
    (
        "yaml_loader_request_data",
        ["src/app/config.py", "tests/test_config.py"],
        [_line("src/app/config.py", 40, "yaml.load(request.data, Loader=yaml.Loader)")],
        "security",
    ),
    (
        "pickle_request_body",
        ["src/app/profile.py", "tests/test_profile.py"],
        [_line("src/app/profile.py", 50, "pickle.loads(request.body)")],
        "security",
    ),
    (
        "sql_f_string_request_args",
        ["src/app/users.py", "tests/test_users.py"],
        [_line(
            "src/app/users.py",
            60,
            'cursor.execute(f"SELECT * FROM users WHERE id={request.args[\'id\']}")',
        )],
        "security",
    ),
    (
        "sqlite_connect_without_close",
        ["src/app/repository.py", "tests/test_repository.py"],
        [_line("src/app/repository.py", 70, 'db = sqlite3.connect("app.db")')],
        "database",
    ),
    (
        "aiohttp_session_without_close",
        ["src/app/client.py", "tests/test_client.py"],
        [_line("src/app/client.py", 80, "session = aiohttp.ClientSession()")],
        "async_resource",
    ),
    (
        "production_hardcoded_token",
        ["src/app/settings.py", "tests/test_settings.py"],
        [_line("src/app/settings.py", 90, f'api_key = "{_fake_live_token()}"')],
        "secret",
    ),
    (
        "production_change_without_tests",
        ["src/app/service.py"],
        [_line("src/app/service.py", 100, "def changed_behavior(): return 1")],
        "test",
    ),
]


def _safe_payload() -> dict[str, Any]:
    return _payload(
        ["src/app/safe.py", "tests/test_safe.py", "tests/fixtures/secrets.py"],
        [
            _line("src/app/safe.py", 10, 'subprocess.run(["grep", user_input], shell=False)'),
            _line("src/app/safe.py", 11, 'cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))'),
            _line("src/app/safe.py", 12, 'stmt = text("select * from users where id=:id").bindparams(bindparam("id"))'),
            _line("src/app/safe.py", 13, 'session.execute(stmt, {"id": user_id})'),
            _line("src/app/safe.py", 14, "with open(path) as f:"),
            _line("src/app/safe.py", 15, "    data = f.read()"),
            _line("src/app/safe.py", 16, "async with aiohttp.ClientSession() as session:"),
            _line("src/app/safe.py", 17, 'conn = sqlite3.connect("app.db")'),
            _line("src/app/safe.py", 18, "try:"),
            _line("src/app/safe.py", 19, "    run_query(conn)"),
            _line("src/app/safe.py", 20, "finally:"),
            _line("src/app/safe.py", 21, "    conn.close()"),
            _line("src/app/safe.py", 22, "config = yaml.safe_load(data)"),
            _line("src/app/safe.py", 23, "pickle.loads(TRUSTED_LOCAL_BYTES)"),
            _line("tests/fixtures/secrets.py", 5, 'api_key = "dummy-secret-for-tests"'),
            _line("tests/fixtures/secrets.py", 6, 'password = "changeme"'),
        ],
    )


def test_hidden_like_dangerous_cases_hit_expected_category(tmp_path):
    misses = []
    for name, changed_files, added_lines, expected_category in DANGEROUS_CASES:
        output = _run_static_review(tmp_path / name, _payload(changed_files, added_lines))
        categories = {item["category"] for item in _review_items(output)}
        if expected_category not in categories:
            misses.append((name, expected_category, output))

    assert not misses


def test_hidden_like_safe_cases_do_not_emit_high_or_critical_findings(tmp_path):
    output = _run_static_review(tmp_path, _safe_payload())

    assert _high_findings(output) == []


def test_hidden_like_low_confidence_secret_routes_to_warning_not_high(tmp_path):
    raw = "dummy-secret-for-tests"
    payload, _ = _redacted_secret_payload(raw)
    output = _run_static_review(tmp_path, payload)
    normalized = _normalize_sandbox(output)

    assert any(item["category"] == "secret" for item in output["findings"])
    assert not any(item["category"] == "secret" for item in [*output["warnings"], *output["needs_human_review"]])
    assert not any(item.category == "secret" for item in normalized.findings)
    warning = next(item for item in normalized.needs_human_review if item.category == "secret")
    assert warning.confidence == 0.58
    assert raw not in json.dumps(payload, ensure_ascii=False, sort_keys=True)
    assert raw not in json.dumps(output, ensure_ascii=False, sort_keys=True)


@pytest.mark.parametrize(
    ("raw", "expected_confidence", "expected_bucket"),
    (
        ("dummy-secret-for-tests", 0.58, "warning"),
        ("production-secret-value-987", 0.99, "finding"),
        ("realtestcredential123", 0.99, "finding"),
        ("latest-production-secret-987", 0.99, "finding"),
    ),
)
def test_hidden_like_host_and_sandbox_secret_confidence_match(
    tmp_path,
    raw: str,
    expected_confidence: float,
    expected_bucket: str,
):
    payload, boundary = _redacted_secret_payload(raw)
    content = payload["added_lines"][0]["content"]
    diff = f"""diff --git a/src/app/settings.py b/src/app/settings.py
index 1111111..2222222 100644
--- a/src/app/settings.py
+++ b/src/app/settings.py
@@ -0,0 +1 @@
+{content}
"""
    host = _normalize_host(diff, boundary)
    sandbox_output = _run_static_review(tmp_path / expected_bucket, payload)
    sandbox = _normalize_sandbox(sandbox_output)

    host_items = [*host.findings, *host.warnings, *host.needs_human_review]
    sandbox_items = [*sandbox.findings, *sandbox.warnings, *sandbox.needs_human_review]
    host_secret = next(item for item in host_items if item.category == "secret")
    sandbox_secret = next(item for item in sandbox_items if item.category == "secret")
    assert host_secret.confidence == sandbox_secret.confidence == expected_confidence
    assert bool(host.findings) is (expected_bucket == "finding")
    assert bool(sandbox.findings) is (expected_bucket == "finding")
    assert raw not in json.dumps(payload, ensure_ascii=False, sort_keys=True)
    assert raw not in json.dumps(sandbox_output, ensure_ascii=False, sort_keys=True)


def test_hidden_like_real_secret_cannot_be_downgraded_by_leading_dummy(tmp_path):
    dummy = "dummy-secret-for-tests"
    real = "production-secret-value-987"
    boundary = RedactionBoundary()
    content = boundary.text(f'api_key="{dummy}"; password="{real}"').text
    payload = _payload(
        ["src/app/settings.py", "tests/test_settings.py"],
        [_line("src/app/settings.py", 12, content)],
    )
    payload["redaction_summary"] = boundary.summary.model_dump(mode="json")
    diff = f"""diff --git a/src/app/settings.py b/src/app/settings.py
index 1111111..2222222 100644
--- a/src/app/settings.py
+++ b/src/app/settings.py
@@ -0,0 +1 @@
+{content}
"""

    host = _normalize_host(diff, boundary)
    sandbox = _run_static_review(tmp_path, payload)

    host_secret = next(item for item in host.findings if item.category == "secret")
    sandbox_secret = next(item for item in sandbox["findings"] if item["category"] == "secret")
    assert host_secret.confidence == sandbox_secret["confidence"] == 0.99
    assert dummy not in json.dumps(sandbox, ensure_ascii=False, sort_keys=True)
    assert real not in json.dumps(sandbox, ensure_ascii=False, sort_keys=True)


def test_hidden_like_hash_prefix_collision_defaults_to_high_confidence(tmp_path):
    dummy = "dummy-105690"
    real = "production-104491"
    boundary = RedactionBoundary()
    dummy_placeholder = boundary.text(f'api_key="{dummy}"').text
    real_placeholder = boundary.text(f'password="{real}"').text
    content = f"{dummy_placeholder}; {real_placeholder}"
    payload = _payload(
        ["src/app/settings.py", "tests/test_settings.py"],
        [_line("src/app/settings.py", 12, content)],
    )
    payload["redaction_summary"] = boundary.summary.model_dump(mode="json")
    diff = f"""diff --git a/src/app/settings.py b/src/app/settings.py
index 1111111..2222222 100644
--- a/src/app/settings.py
+++ b/src/app/settings.py
@@ -0,0 +1 @@
+{content}
"""

    host = _normalize_host(diff, boundary)
    sandbox = _run_static_review(tmp_path, payload)

    host_secret = next(item for item in host.findings if item.category == "secret")
    sandbox_secret = next(item for item in sandbox["findings"] if item["category"] == "secret")
    assert host_secret.confidence == sandbox_secret["confidence"] == 0.99


def test_hidden_like_only_test_changes_do_not_warn_missing_tests(tmp_path):
    output = _run_static_review(
        tmp_path,
        _payload(
            ["tests/test_service.py", "tests/fixtures/service_fixture.py"],
            [_line("tests/test_service.py", 8, "def test_service_behavior(): pass")],
        ),
    )

    assert not any(item["category"] == "test" for item in output["warnings"])


def test_hidden_like_rule_engine_keeps_dummy_fixture_secret_out_of_high_findings():
    diff = """diff --git a/tests/fixtures/config.py b/tests/fixtures/config.py
index 1111111..2222222 100644
--- a/tests/fixtures/config.py
+++ b/tests/fixtures/config.py
@@ -0,0 +1,2 @@
+api_key = "dummy-secret-for-tests"
+password = "changeme"
"""
    boundary = RedactionBoundary()
    redacted = boundary.text(diff)
    result = _normalize_host(redacted.text, boundary)

    assert not any(finding.category == "secret" and finding.severity in {"critical", "high"}
                   for finding in result.findings)
    assert "dummy-secret-for-tests" not in redacted.text
    assert "changeme" not in redacted.text


def test_hidden_like_precision_recall(tmp_path):
    expected_detections = 0
    expected_total = len(DANGEROUS_CASES)
    detection_rows = []
    for name, changed_files, added_lines, expected_category in DANGEROUS_CASES:
        output = _run_static_review(tmp_path / name, _payload(changed_files, added_lines))
        hit = any(item["category"] == expected_category for item in _review_items(output))
        expected_detections += int(hit)
        detection_rows.append({"case": name, "expected_category": expected_category, "detected": hit})

    safe_output = _run_static_review(tmp_path / "safe", _safe_payload())
    false_high_findings = _high_findings(safe_output)
    summary = {
        "expected_detections": expected_detections,
        "expected_total": expected_total,
        "false_high_findings": false_high_findings,
        "detections": detection_rows,
    }
    summary_path = tmp_path / "eval_hidden_like_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    assert expected_detections == expected_total
    assert false_high_findings == []
    assert json.loads(summary_path.read_text(encoding="utf-8")) == summary
