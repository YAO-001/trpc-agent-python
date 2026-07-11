# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Redaction-boundary regression tests for the code-review example."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import agent.sandbox_runner as sandbox_module
from agent.execution_request import ExecutionOutputSpec
from agent.execution_request import ExecutionRequest
from agent.input_resolver import EXAMPLE_DIR
from agent.models import DRY_RUN_TIMESTAMP
from agent.models import FilterIntercept
from agent.models import RedactionEvent
from agent.models import RedactionSummary
from agent.models import ReviewReport
from agent.models import ReviewTask
from agent.models import ReviewTaskStatus
from agent.models import SandboxRun
from agent.models import TelemetrySummary
from agent.orchestrator import _finalize_persistence_bundle
from agent.orchestrator import ReviewOrchestrator
from agent.redaction_boundary import RedactionBoundary
from agent.report_builder import ReportBuilder
from agent.secret_redactor import RedactionResult
from agent.secret_redactor import SecretRedactor
from agent.storage import ReviewStorage


@pytest.mark.parametrize(
    ("raw", "forbidden"),
    (
        ('password = "strong passphrase 987"', ("strong passphrase 987", )),
        ('passwd="passwd-value-987"', ("passwd-value-987", )),
        ('pwd: "pwd-value-987"', ("pwd-value-987", )),
        ('client_secret: "opaque-client-secret-123"', ("opaque-client-secret-123", )),
        ('apiKey = "camel-case-key-123456"', ("camel-case-key-123456", )),
        ('access_token="access-token-123456"', ("access-token-123456", )),
        ('refresh-token: "refresh-token-123456"', ("refresh-token-123456", )),
        ('Authorization: Bearer bearer-token-123456789', ("bearer-token-123456789", )),
        ('postgresql://alice:plain-password@db/reviews', ("alice", "plain-password")),
        ('{"password": "json-password-123"}', ("json-password-123", )),
        ('api_key = "dummy-secret-for-tests"', ("dummy-secret-for-tests", )),
    ),
)
def test_boundary_redacts_every_supported_secret_format(raw: str, forbidden: tuple[str, ...]):
    boundary = RedactionBoundary()

    safe = boundary.text(raw)

    assert raw != safe.text
    assert boundary.summary.total_redactions >= 1
    for value in forbidden:
        assert value not in safe.text


def test_dummy_secret_is_redacted_and_marked_likely_placeholder():
    raw = "dummy-secret-for-tests"
    boundary = RedactionBoundary()

    safe = boundary.text(f'api_key = "{raw}"')

    assert raw not in safe.text
    assert boundary.summary.events
    assert all(event.likely_placeholder for event in boundary.summary.events)


@pytest.mark.parametrize(
    "raw",
    (
        'password="abc,def;ghi}"',
        'password="abc\\\"def,ghi"',
        "password='abc,def;ghi}'",
    ),
)
def test_quoted_assignments_redact_punctuation_and_escaped_quotes(raw: str):
    boundary = RedactionBoundary()

    result = boundary.text(raw)

    assert "abc" not in result.text
    assert "def" not in result.text
    assert boundary.summary.total_redactions == 1


def test_fake_unclosed_placeholder_does_not_disable_later_redaction():
    raw = "production-secret-value-987"
    boundary = RedactionBoundary()

    result = boundary.text(f'print("[REDACTED:")\npassword="{raw}"')

    assert raw not in result.text
    assert boundary.summary.total_redactions == 1


@pytest.mark.parametrize(
    "malicious",
    (
        '[REDACTED:SECRET:password="production-secret-value-987":deadbeef]',
        "[REDACTED:SECRET:production-secret-value-987:deadbeef]",
    ),
)
def test_unrecognized_placeholder_types_cannot_hide_plaintext(malicious: str):
    boundary = RedactionBoundary()

    result = boundary.text(malicious)

    assert "production-secret-value-987" not in result.text
    assert boundary.summary.total_redactions >= 1


def test_malformed_placeholder_with_delimiters_is_cleaned_as_a_whole():
    raw = "production-secret-value-987"
    malicious = f"[REDACTED:SECRET:x,{raw}:deadbeef]"

    result = RedactionBoundary().text(malicious)

    assert raw not in result.text
    assert result.text.count("[REDACTED:SECRET:") == 1


def test_unclosed_malformed_placeholder_is_cleaned_through_end_of_string():
    raw = "production-secret-value-987"
    malicious = f"[REDACTED:SECRET:x,{raw}"

    result = RedactionBoundary().text(malicious)

    assert raw not in result.text
    assert result.text.count("[REDACTED:SECRET:") == 1


def test_generated_placeholder_is_idempotent():
    placeholder = SecretRedactor.placeholder("generic_assignment", "production-secret-value-987")

    result = SecretRedactor().redact_text(placeholder)

    assert result.text == placeholder
    assert result.summary.total_redactions == 0


def test_unquoted_code_expression_is_not_rewritten_as_a_secret():
    source = 'token = os.getenv("TOKEN")'
    boundary = RedactionBoundary()

    result = boundary.text(source)

    assert result.text == source
    assert boundary.summary.total_redactions == 0


@pytest.mark.parametrize("spacing", (" ", "\t", " \t "))
def test_unquoted_code_expression_with_spacing_is_not_rewritten(spacing: str):
    source = f'token = os.getenv{spacing}("TOKEN")'

    result = RedactionBoundary().text(source)

    assert result.text == source
    assert result.summary.total_redactions == 0


@pytest.mark.parametrize("prefix", ("b", "r", "u", "br", "rb", "B", "RF"))
def test_prefixed_string_literals_are_redacted(prefix: str):
    raw = "production-secret-value-987"

    result = RedactionBoundary().text(f'password = {prefix}"{raw}"')

    assert raw not in result.text
    assert result.summary.total_redactions == 1


@pytest.mark.parametrize("quote", ('"""', "'''"))
def test_triple_quoted_string_literals_are_redacted(quote: str):
    raw = "production,secret;value}987"

    result = RedactionBoundary().text(f"password = r{quote}{raw}{quote}")

    assert raw not in result.text
    assert result.summary.total_redactions == 1


@pytest.mark.parametrize("raw", ("realtestcredential123", "latest-production-secret-987"))
def test_test_substrings_do_not_mark_real_credentials_as_placeholders(raw: str):
    boundary = RedactionBoundary()

    boundary.text(f'password="{raw}"')

    assert boundary.summary.events[0].likely_placeholder is False


def test_boundary_accumulates_events_across_text_calls():
    boundary = RedactionBoundary()

    boundary.text('password="first-real-password"')
    boundary.text('client_secret="second-real-secret"')

    assert boundary.summary.total_redactions == 2


class _SequenceRedactor:

    def __init__(self) -> None:
        self._flags = iter((True, False))

    def redact_text(self, text: str) -> RedactionResult:
        likely_placeholder = next(self._flags)
        placeholder = "[REDACTED:SECRET:generic_assignment:01234567]"
        return RedactionResult(
            text=placeholder,
            summary=RedactionSummary(
                total_redactions=1,
                by_type={"generic_assignment": 1},
                events=[
                    RedactionEvent(
                        secret_type="generic_assignment",
                        sha256="0123456789abcdef",
                        placeholder=placeholder,
                        count=1,
                        likely_placeholder=likely_placeholder,
                    )
                ],
            ),
        )


def test_boundary_merges_placeholder_metadata_with_logical_and():
    boundary = RedactionBoundary(redactor=_SequenceRedactor())

    boundary.text("placeholder occurrence")
    boundary.text("real occurrence")

    assert boundary.summary.total_redactions == 2
    assert boundary.summary.events[0].count == 2
    assert boundary.summary.events[0].likely_placeholder is False


def test_boundary_summary_is_an_isolated_snapshot():
    boundary = RedactionBoundary()
    boundary.text('password="real-password-value"')

    exposed = boundary.summary
    exposed.events[0].count = 99
    exposed.by_type["generic_assignment"] = 99

    assert boundary.summary.total_redactions == 1
    assert boundary.summary.events[0].count == 1
    assert boundary.summary.by_type["generic_assignment"] == 1


def test_boundary_clean_recurses_keys_values_lists_and_tuples_without_leaks():
    secrets = {
        "key": "key-secret-value",
        "token": "nested-token-value",
        "list": "list-password-value",
        "tuple": "tuple-password-value",
    }
    boundary = RedactionBoundary()
    value = {
        f'password="{secrets["key"]}"': {
            "ToKeN": [secrets["token"], {
                "password": (secrets["list"], secrets["tuple"])
            }]
        },
        "safe": [0, False, None, "public"],
    }

    cleaned = boundary.clean(value)
    serialized = json.dumps(cleaned, ensure_ascii=False, sort_keys=True)

    assert isinstance(cleaned, dict)
    assert isinstance(next(iter(cleaned.values()))["ToKeN"], list)
    assert isinstance(next(iter(cleaned.values()))["ToKeN"][1]["password"], list)
    assert cleaned["safe"] == [0, False, None, "public"]
    assert all(raw not in serialized for raw in secrets.values())


def test_boundary_clean_converts_unknown_objects_to_safe_json_strings():
    raw = "opaque-path-secret-987"
    boundary = RedactionBoundary()

    cleaned = boundary.clean({"path": Path(f"token={raw}")})
    serialized = json.dumps(cleaned, ensure_ascii=False, sort_keys=True)

    assert isinstance(cleaned["path"], str)
    assert raw not in serialized


def test_non_sqlite_display_url_hides_username_password_and_query_secret():
    boundary = RedactionBoundary()
    raw = "postgresql://alice:plain-password@db.example:5432/reviews?token=query-secret"

    displayed = boundary.display_db_url(raw)

    assert displayed == "postgresql://db.example:5432/reviews"
    assert "alice" not in displayed
    assert "plain-password" not in displayed
    assert "query-secret" not in displayed


@pytest.mark.parametrize(
    "db_url",
    (
        "postgresql://alice:pw@db/token%3Ddatabase-secret",
        "sqlite:///tmp/token%253Ddatabase%252Dsecret.db",
    ),
)
def test_display_db_url_redacts_repeatedly_encoded_database_secrets(db_url):
    displayed = RedactionBoundary().display_db_url(db_url)

    assert "database-secret" not in displayed
    assert "database%2Dsecret" not in displayed
    assert "database%252Dsecret" not in displayed


def test_report_builder_preserves_json_primitives_under_sensitive_keys(tmp_path):
    task_id = "task-json-primitives"
    input_summary = {
        "token": 123,
        "password": False,
        "client_secret": None,
        "nested": {
            "auth-token": 7
        },
    }
    builder = ReportBuilder(
        output_dir=tmp_path / "out",
        db_url=f"sqlite:///{tmp_path / 'review.db'}",
    )

    report = builder.build(
        task_id=task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        findings=[],
        warnings=[],
        needs_human_review=[],
        filter_intercepts=[],
        sandbox_runs=[],
        telemetry=TelemetrySummary(task_id=task_id, task_status=ReviewTaskStatus.COMPLETED),
        redaction_summary=RedactionSummary(),
        input_summary=input_summary,
    )
    json_text, _, safe_report = builder.write(report)

    assert safe_report.input_summary == input_summary
    assert json.loads(json_text)["input_summary"] == input_summary


def test_orchestrator_persistence_bundle_preserves_json_primitives():
    task_id = "task-json-primitives"
    input_summary = {
        "token": 123,
        "password": False,
        "client_secret": None,
        "nested": {
            "auth-token": 7
        },
    }
    telemetry = TelemetrySummary(task_id=task_id, task_status=ReviewTaskStatus.COMPLETED)
    report = ReviewReport(
        task_id=task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        conclusion="No deterministic findings.",
        telemetry=telemetry,
        input_summary=input_summary,
    )

    bundle = _finalize_persistence_bundle(
        boundary=RedactionBoundary(),
        task=ReviewTask(task_id=task_id, input_type="fixture"),
        redacted_input=input_summary,
        decisions=[],
        runs=[],
        findings=[],
        warnings=[],
        needs_human_review=[],
        telemetry=telemetry,
        report=report,
    )

    assert {key: bundle["input"][key] for key in input_summary} == input_summary
    assert bundle["report"].input_summary == input_summary


def test_storage_json_columns_preserve_primitives_and_redact_strings(tmp_path):
    task_id = "task-storage-json-primitives"
    raw = "opaque-storage-secret-987"
    structured = {
        "token": 123,
        "password": False,
        "client_secret": None,
        "nested": {
            "auth-token": 7
        },
        "api_key": raw,
    }
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    telemetry = TelemetrySummary(task_id=task_id, task_status=ReviewTaskStatus.COMPLETED)
    report = ReviewReport(
        task_id=task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        conclusion="No deterministic findings.",
        telemetry=telemetry,
        input_summary=structured,
    )
    intercept = FilterIntercept(
        intercept_id="intercept-storage-json-primitives",
        task_id=task_id,
        request_id=f"{task_id}:storage-json",
        decision="allow",
        error_kind="",
        reason="structured metadata is allowed",
        command=["python3", "scripts/run_static_review.py"],
        runtime="container",
        metadata=structured,
    )

    storage.save_task(ReviewTask(task_id=task_id, input_type="fixture", dry_run=True))
    storage.save_input(
        task_id=task_id,
        redacted_diff="",
        changed_files=["src/public.py"],
        redaction_summary=RedactionSummary(),
        input_metadata=structured,
    )
    storage.save_filter_intercepts([intercept])
    storage.save_report(
        report=report,
        json_report=json.dumps(report.model_dump(mode="json"), ensure_ascii=False, sort_keys=True),
        markdown_report="# Safe report\n",
        json_path="out/review_report.json",
        markdown_path="out/review_report.md",
    )

    rows = storage.query_task(task_id)
    input_metadata = json.loads(rows["review_inputs"][0]["input_metadata_json"])
    filter_metadata = json.loads(rows["filter_intercepts"][0]["metadata_json"])
    persisted_report = json.loads(rows["reports"][0]["json_report"])
    dumped = storage.dump_task_text(task_id)
    dumped_rows = json.loads(dumped)

    for payload in (input_metadata, filter_metadata, persisted_report["input_summary"]):
        assert payload["token"] == 123
        assert payload["password"] is False
        assert payload["client_secret"] is None
        assert payload["nested"]["auth-token"] == 7
        assert raw not in json.dumps(payload, ensure_ascii=False, sort_keys=True)
    assert json.loads(dumped_rows["reports"][0]["json_report"])["input_summary"]["token"] == 123
    assert json.loads(dumped_rows["review_inputs"][0]["input_metadata_json"])["password"] is False
    assert json.loads(dumped_rows["filter_intercepts"][0]["metadata_json"])["client_secret"] is None
    assert raw not in dumped


def test_storage_rejects_invalid_json_blob(tmp_path):
    task_id = "task-invalid-json"
    storage = ReviewStorage(f"sqlite:///{tmp_path / 'review.db'}")
    report = ReviewReport(
        task_id=task_id,
        task_status=ReviewTaskStatus.COMPLETED,
        conclusion="No deterministic findings.",
        telemetry=TelemetrySummary(task_id=task_id, task_status=ReviewTaskStatus.COMPLETED),
    )

    with pytest.raises(ValueError, match="json_report must contain valid JSON"):
        storage.save_report(
            report=report,
            json_report="{not-json",
            markdown_report="# Safe report\n",
            json_path="out/review_report.json",
            markdown_path="out/review_report.md",
        )


def test_exception_text_is_redacted_before_it_becomes_a_model_field():
    raw = "exception-secret-987"

    cleaned = RedactionBoundary().text(RuntimeError(f"client_secret={raw}")).text

    assert raw not in cleaned


def test_raw_secret_never_reaches_report_database_or_logs(tmp_path, monkeypatch, caplog):
    raw = "opaque-runtime-token-987654"

    class SecretBearingHarness:

        def __init__(self, *args, **kwargs):
            del args, kwargs

        def execute_one(self, **kwargs):
            request = kwargs["request"]
            return SandboxRun(
                run_id=f"sandbox-{request.request_id}",
                task_id=request.task_id,
                request_id=request.request_id,
                runtime=request.runtime,
                command=list(request.command_argv),
                exit_code=0,
                stderr=f"client_secret={raw}",
                created_at=DRY_RUN_TIMESTAMP,
            )

    caplog.set_level("DEBUG")
    monkeypatch.setattr(sandbox_module, "TrpcSkillToolSetHarness", SecretBearingHarness)
    db_url = f"sqlite:///{tmp_path / 'review.db'}"
    output_dir = tmp_path / "out"

    report = ReviewOrchestrator(db_url=db_url, output_dir=output_dir).review(
        fixture="clean",
        dry_run=True,
        runtime="container",
    )

    report_payload = report.model_dump(mode="json")
    storage = ReviewStorage(db_url)
    storage_rows = storage.query_task(report.task_id)
    combined = "\n".join([
        (output_dir / "review_report.json").read_text(encoding="utf-8"),
        (output_dir / "review_report.md").read_text(encoding="utf-8"),
        json.dumps(report_payload, ensure_ascii=False, sort_keys=True),
        storage.dump_task_text(report.task_id),
        (tmp_path / "review.db").read_bytes().decode("utf-8", errors="ignore"),
    ])
    assert raw not in combined
    assert raw not in caplog.text
    expected_count = report.redaction_summary.total_redactions
    assert report.telemetry.redaction_count == expected_count
    assert report.section_summary["metrics"]["redaction_count"] == expected_count
    assert json.loads(storage_rows["review_inputs"][0]["redaction_summary_json"])["total_redactions"] == expected_count
    assert json.loads(storage_rows["telemetry_summaries"][0]["metrics_json"])["redaction_count"] == expected_count
    assert len(report.filter_intercepts) == 3
    assert all(item.decision == "allow" for item in report.filter_intercepts)
    assert len(storage_rows["filter_intercepts"]) == 3


@pytest.mark.parametrize("output_key", ("prod-token\\", "prod-token"))
def test_composite_output_key_redacts_value_across_persistence_sinks(
    tmp_path,
    monkeypatch,
    output_key,
):
    raw = "opaque-cross-json-987654"

    class SecretBearingHarness:

        def __init__(self, *args, **kwargs):
            del args, kwargs

        def execute_one(self, **kwargs):
            request = kwargs["request"]
            return SandboxRun(
                run_id=f"sandbox-{request.request_id}",
                task_id=request.task_id,
                request_id=request.request_id,
                runtime=request.runtime,
                command=list(request.command_argv),
                exit_code=0,
                output_files={output_key: raw},
                created_at=DRY_RUN_TIMESTAMP,
            )

    monkeypatch.setattr(sandbox_module, "TrpcSkillToolSetHarness", SecretBearingHarness)
    db_url = f"sqlite:///{tmp_path / 'review.db'}"
    output_dir = tmp_path / "out"

    report = ReviewOrchestrator(db_url=db_url, output_dir=output_dir).review(
        fixture="clean",
        dry_run=True,
        runtime="container",
    )

    storage = ReviewStorage(db_url)
    storage_rows = storage.query_task(report.task_id)
    persisted_report = json.loads(storage_rows["reports"][0]["json_report"])
    persisted_input_summary = json.loads(storage_rows["review_inputs"][0]["redaction_summary_json"])
    persisted_telemetry = json.loads(storage_rows["telemetry_summaries"][0]["metrics_json"])
    combined = "\n".join([
        json.dumps(report.model_dump(mode="json"), ensure_ascii=False, sort_keys=True),
        (output_dir / "review_report.json").read_text(encoding="utf-8"),
        (output_dir / "review_report.md").read_text(encoding="utf-8"),
        json.dumps(storage_rows, ensure_ascii=False, sort_keys=True),
        storage.dump_task_text(report.task_id),
        (tmp_path / "review.db").read_bytes().decode("utf-8", errors="ignore"),
    ])
    counts = [
        report.redaction_summary.total_redactions,
        report.telemetry.redaction_count,
        report.section_summary["metrics"]["redaction_count"],
        persisted_report["redaction_summary"]["total_redactions"],
        persisted_input_summary["total_redactions"],
        persisted_telemetry["redaction_count"],
    ]

    assert raw not in combined
    assert counts[0] > 0
    assert len(set(counts)) == 1


def test_legacy_harness_redactor_records_redactions_without_dynamic_attributes(
    tmp_path,
    monkeypatch,
):
    raw = "legacy-raw-secret-987"

    class LegacyHarness:
        __slots__ = ("runtime", "redactor")

        def __init__(self, *, runtime, policy, redactor):
            del policy
            self.runtime = runtime
            self.redactor = redactor

        def execute_one(self, **kwargs):
            request = kwargs["request"]
            redacted = self.redactor.redact_text(f"client_secret={raw}")
            assert raw not in redacted.text
            return SandboxRun(
                run_id=f"sandbox-{request.request_id}",
                task_id=request.task_id,
                request_id=request.request_id,
                runtime=request.runtime,
                command=list(request.command_argv),
                stdout=redacted.text,
                created_at=DRY_RUN_TIMESTAMP,
            )

    monkeypatch.setattr(sandbox_module, "TrpcSkillToolSetHarness", LegacyHarness)

    report = ReviewOrchestrator(
        db_url=f"sqlite:///{tmp_path / 'review.db'}",
        output_dir=tmp_path / "out",
    ).review(
        fixture="clean",
        dry_run=True,
        runtime="container",
    )

    assert report.redaction_summary.total_redactions > 0
    assert report.telemetry.redaction_count == report.redaction_summary.total_redactions
    assert report.section_summary["metrics"]["redaction_count"] == report.redaction_summary.total_redactions


def test_clean_preserves_distinct_keys_when_placeholder_prefixes_collide():
    raw_keys = ("token=dummy-105690", "token=production-104491")

    cleaned = RedactionBoundary().clean({raw_keys[0]: "first", raw_keys[1]: "second"})
    serialized = json.dumps(cleaned, ensure_ascii=False, sort_keys=True)

    assert len(cleaned) == 2
    assert all(raw not in serialized for raw in raw_keys)
    assert len(set(cleaned)) == 2


def test_trpc_output_sanitization_preserves_redacted_key_collisions():
    raw_keys = ("token=dummy-105690", "token=production-104491")
    boundary = RedactionBoundary()
    harness = sandbox_module.TrpcSkillToolSetHarness(
        runtime="container",
        policy=sandbox_module.ReviewExecutionPolicy(),
        boundary=boundary,
    )
    request = ExecutionRequest(
        request_id="task-1:skill-run:1",
        task_id="task-1",
        runtime="container",
        skill="code-review",
        command_argv=("python3", "scripts/run_static_review.py"),
        cwd="$SKILLS_DIR/code-review",
        stdin="",
        editor_text="",
        inputs=(),
        legacy_output_files=(),
        output_spec=ExecutionOutputSpec(
            max_files=16,
            max_file_bytes=1024,
            max_total_bytes=2048,
        ),
        env=(),
        network_access=False,
        timeout_seconds=30,
        output_budget_bytes=2048,
        save_as_artifacts=False,
        omit_inline_content=False,
        artifact_prefix="",
    )

    run = harness._run_from_skill_output(
        request,
        {"output_files": [
            {
                "name": raw_keys[0],
                "content": "first"
            },
            {
                "name": raw_keys[1],
                "content": "second"
            },
        ]},
        dry_run=True,
    )
    serialized = json.dumps(run.output_files, ensure_ascii=False, sort_keys=True)

    assert len(run.output_files) == 2
    assert len(set(run.output_files)) == 2
    assert len(set(run.output_files.values())) == 2
    assert all(SecretRedactor.PLACEHOLDER_RE.fullmatch(value) for value in run.output_files.values())
    assert all(raw not in serialized for raw in raw_keys)
    assert "first" not in serialized
    assert "second" not in serialized
    assert run.output_truncated is False


def test_clean_resolves_collision_with_an_existing_generated_suffix():
    raw_keys = ("token=dummy-105690", "token=production-104491")
    base_key = f"token={SecretRedactor.placeholder('generic_assignment', 'dummy-105690')}"
    first_digest = SecretRedactor.digest(raw_keys[0])
    second_digest = SecretRedactor.digest(raw_keys[1])
    adversarial_key = f"{base_key}#{first_digest}"
    adversarial_digest = SecretRedactor.digest(adversarial_key)

    cleaned = RedactionBoundary().clean({
        raw_keys[0]: 1,
        raw_keys[1]: 2,
        adversarial_key: 3,
    })

    assert set(cleaned.values()) == {1, 2, 3}
    assert set(cleaned) == {
        f"{base_key}#{first_digest}",
        f"{base_key}#{second_digest}",
        f"{adversarial_key}#{adversarial_digest}",
    }


def test_orchestrator_sanitizes_complete_payload_before_sandbox(tmp_path, monkeypatch):
    raw = "opaque-input-token-987"
    diff_path = tmp_path / f"token={raw}.diff"
    diff_path.write_text(
        """diff --git a/src/config.py b/src/config.py
index 1111111..2222222 100644
--- a/src/config.py
+++ b/src/config.py
@@ -0,0 +1,2 @@
+client_secret = "opaque-input-token-987"
+print("safe context")
""",
        encoding="utf-8",
    )
    file_list = tmp_path / "files.txt"
    file_list.write_text(f"src/token={raw}.py\n", encoding="utf-8")
    captures: list[dict] = []
    owned_paths: list[Path] = []

    class CapturingHarness:

        def __init__(self, *, runtime, policy, redactor):
            self.runtime = runtime

        def execute_one(self, *, task_id, review_input, request, policy_context, dry_run):
            source = request.inputs[0].src
            owned_path = Path(source.removeprefix("host://"))
            assert owned_path.is_file()
            assert policy_context.allowed_input_sources == frozenset({source})
            captures.append(json.loads(json.dumps(review_input, ensure_ascii=False)))
            captures[-1]["owned_input"] = json.loads(owned_path.read_text(encoding="utf-8"))
            owned_paths.append(owned_path)
            return SandboxRun(
                run_id=f"sandbox-{request.request_id}",
                task_id=request.task_id,
                request_id=request.request_id,
                runtime=request.runtime,
                command=list(request.command_argv),
                created_at=DRY_RUN_TIMESTAMP,
            )

    monkeypatch.setattr(sandbox_module, "TrpcSkillToolSetHarness", CapturingHarness)
    report = ReviewOrchestrator(
        example_dir=EXAMPLE_DIR,
        db_url=f"sqlite:///{tmp_path / 'review.db'}",
        output_dir=tmp_path / "out",
    ).review(
        diff_file=str(diff_path),
        file_list=str(file_list),
        dry_run=True,
        runtime="container",
    )

    assert len(captures) == 3
    for payload in captures:
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        assert raw not in serialized
        assert {
            "task_id",
            "input_type",
            "input_ref",
            "fixture_names",
            "file_list",
            "changed_files",
            "added_lines",
            "redaction_summary",
            "rule_warnings",
            "rule_needs_human_review",
        }.issubset(payload)
        assert all("content" in line and "context_before" in line and "context_after" in line
                   for line in payload["added_lines"])
        assert payload["owned_input"] == {key: value for key, value in payload.items() if key != "owned_input"}
    assert raw not in json.dumps(report.model_dump(mode="json"), ensure_ascii=False, sort_keys=True)
    assert owned_paths and all(not path.exists() for path in owned_paths)
