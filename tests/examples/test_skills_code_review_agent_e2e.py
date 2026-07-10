# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""End-to-end tests for the skills code review agent example."""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from agent import agent_factory
from agent import sandbox_runner as sandbox_module
from agent.agent_factory import prepare_execution_plan
from agent.filter_policy import ReviewExecutionPolicy
from agent.input_resolver import EXAMPLE_DIR
from agent.models import SandboxRun
from agent.orchestrator import ReviewOrchestrator
from agent.sandbox_artifact_loader import load_sandbox_artifacts
from agent.sandbox_runner import HarnessExecutionResult
from agent.sandbox_runner import SandboxRunner
from agent.secret_redactor import SecretRedactor
from agent.storage import ReviewStorage
from trpc_agent_sdk.skills import FsSkillRepository
from trpc_agent_sdk.tools import BaseTool

RAW_SAMPLE_SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEF",
    "sk-1234567890abcdef1234567890abcdef",
    "correct-horse-battery-staple",
    "FAKEKEYDATA",
]


def test_acceptance_matrix_has_test_references():
    readme = (EXAMPLE_DIR / "README.md").read_text(encoding="utf-8")
    rows = []
    in_matrix = False
    for line in readme.splitlines():
        if line.startswith("| Requirement |"):
            in_matrix = True
            continue
        if in_matrix and not line.startswith("|"):
            break
        if not in_matrix or set(line.replace("|", "").strip()) <= {"-", " "}:
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        rows.append(cells)

    assert rows
    for cells in rows:
        assert len(cells) >= 3
        evidence = cells[2]
        assert re.search(r"(test_|python -m pytest|run_review\.py)", evidence), cells


def _run_static_review_script(tmp_path, payload):
    input_path = tmp_path / "review_input.json"
    output_path = tmp_path / "findings.json"
    input_path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(EXAMPLE_DIR / "skills" / "code-review" / "scripts" / "run_static_review.py"),
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


@pytest.mark.parametrize(
    ("command", "error_kind"),
    (
        (("rm", "-rf", "/"), "policy_denied"),
        (("pip", "install", "unapproved-package"), "approval_required"),
    ),
)
def test_filter_nonallow_request_returns_before_harness_lookup(monkeypatch, command, error_kind):
    runner = SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        redactor=SecretRedactor(),
    )
    harness_calls = []
    decision_callbacks = []
    run_callbacks = []

    class ExplodingHarness:

        def execute_one(self, **kwargs):
            raise AssertionError(f"non-allow request reached harness: {kwargs}")

    def exploding_lookup(*, runtime):
        harness_calls.append(runtime)
        return ExplodingHarness()

    monkeypatch.setattr(runner, "_harness_for_runtime", exploding_lookup, raising=False)

    review_input = {
        "task_id": "task-filter",
        "fixture_names": [],
    }
    with prepare_execution_plan(task_id="task-filter",
                                runtime="local",
                                review_input=review_input,
                                redactor=SecretRedactor()) as plan:
        request = plan.requests[0].model_copy(update={
            "request_id": "task-filter:mutated",
            "command_argv": command,
        })
        result = runner.run(
            task_id="task-filter",
            review_input=review_input,
            runtime="local",
            dry_run=True,
            requests=[request],
            policy_context=plan.policy_context,
            on_decision=decision_callbacks.append,
            on_run=run_callbacks.append,
        )

    assert harness_calls == []
    assert result.runs == []
    assert run_callbacks == []
    assert len(result.decisions) == 1
    assert decision_callbacks == result.decisions
    assert result.decisions[0].metadata["error_kind"] == error_kind


def test_code_review_repository_has_no_dynamic_run_env():
    repository = FsSkillRepository(str(EXAMPLE_DIR / "skills"))

    assert repository.skill_run_env("code-review") == {}


def test_local_inherited_env_keys_are_minimal_on_posix():
    host_env = {
        "PATH": "/usr/bin",
        "TMPDIR": "/tmp",
        "TEMP": "/tmp/temp",
        "TMP": "/tmp/tmp",
        "SystemRoot": "posix-system-root-secret",
        "COMSPEC": "posix-comspec-secret",
        "WINDIR": "posix-windir-secret",
        "PATHEXT": "posix-pathext-secret",
        "Path": "posix-path-alias-secret",
        "HOME": "home-secret",
        "PYTHONPATH": "pythonpath-secret",
        "API_TOKEN": "api-token-secret",
    }

    inherited = sandbox_module._inherited_platform_env(host_env, platform_name="posix")

    assert inherited == {
        "PATH": "/usr/bin",
        "TMPDIR": "/tmp",
        "TEMP": "/tmp/temp",
        "TMP": "/tmp/tmp",
    }


def test_local_inherited_env_keys_keep_windows_launch_requirements():
    host_env = {
        "PATH": "C:\\Windows\\System32",
        "Path": "C:\\Windows\\System32",
        "TMPDIR": "C:\\TempDir",
        "TEMP": "C:\\Temp",
        "TMP": "C:\\Tmp",
        "PATHEXT": ".EXE;.CMD",
        "SYSTEMROOT": "C:\\Windows-upper",
        "SystemRoot": "C:\\Windows",
        "WINDIR": "C:\\Windows",
        "COMSPEC": "C:\\Windows\\System32\\cmd.exe",
        "HOME": "home-secret",
        "PYTHONPATH": "pythonpath-secret",
        "API_TOKEN": "api-token-secret",
    }

    inherited = sandbox_module._inherited_platform_env(host_env, platform_name="nt")

    assert inherited == {
        key: value
        for key, value in host_env.items() if key not in {"HOME", "PYTHONPATH", "API_TOKEN"}
    }


def test_runner_evaluates_supplied_requests_then_executes_allowed_requests_in_id_order(monkeypatch):
    events = []

    class RecordingHarness:

        def execute_one(self, *, task_id, review_input, request, policy_context, dry_run):
            events.append(("execute", request.request_id))
            return HarnessExecutionResult(runs=[
                SandboxRun(
                    run_id=f"sandbox_{request.request_id}",
                    task_id=task_id,
                    runtime=request.runtime,
                    command=list(request.command_argv),
                    decision="allow",
                    output_files={},
                    created_at="1970-01-01T00:00:00+00:00",
                )
            ])

    runner = SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        redactor=SecretRedactor(),
    )
    monkeypatch.setattr(runner, "_harness_for_runtime", lambda *, runtime: RecordingHarness(), raising=False)
    review_input = {"task_id": "task-order", "fixture_names": []}
    decisions = []
    runs = []

    with prepare_execution_plan(task_id="task-order",
                                runtime="local",
                                review_input=review_input,
                                redactor=SecretRedactor()) as plan:
        supplied = list(reversed(plan.requests))
        result = runner.run(
            task_id="task-order",
            review_input=review_input,
            runtime="local",
            dry_run=True,
            requests=supplied,
            policy_context=plan.policy_context,
            on_decision=lambda item: (decisions.append(item), events.append(("decision", item.metadata["request_id"]))),
            on_run=lambda item: (runs.append(item), events.append(("run", item.run_id))),
        )

    assert [item.metadata["request_id"] for item in decisions] == [request.request_id for request in supplied]
    assert [event for event in events if event[0] == "execute"
            ] == [("execute", request.request_id) for request in sorted(supplied, key=lambda item: item.request_id)]
    assert all(event[0] == "decision" for event in events[:3])
    assert runs == result.runs
    assert result.decisions == decisions


def test_explicit_local_harness_does_not_inherit_sensitive_host_env(monkeypatch):
    host_values = {
        "API_TOKEN": "host-api-token-value",
        "HOME": "host-home-secret-value",
        "PYTHONPATH": "host-python-path-secret-value",
    }
    for name, value in host_values.items():
        monkeypatch.setenv(name, value)
    captured_envs = []
    real_run = sandbox_module.subprocess.run

    def checked_run(*args, **kwargs):
        captured_envs.append(dict(kwargs["env"]))
        return real_run(*args, **kwargs)

    monkeypatch.setattr(sandbox_module.subprocess, "run", checked_run)
    runner = SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        redactor=SecretRedactor(),
    )
    review_input = {"task_id": "task-safe-env", "fixture_names": []}

    with prepare_execution_plan(task_id="task-safe-env",
                                runtime="local",
                                review_input=review_input,
                                redactor=SecretRedactor()) as plan:
        result = runner.run(
            task_id="task-safe-env",
            review_input=review_input,
            runtime="local",
            dry_run=True,
            requests=[plan.requests[2]],
            policy_context=plan.policy_context,
        )

    assert captured_envs
    assert all(name not in captured_envs[0] for name in host_values)
    assert captured_envs[0]["PYTHONUNBUFFERED"] == "1"
    assert captured_envs[0]["TRPC_AGENT_SKILL_NAME"] == "code-review"
    serialized_output = json.dumps(result.runs[0].output_files, sort_keys=True)
    for raw_value in host_values.values():
        assert raw_value not in serialized_output


def _install_sdk_output_toolset(monkeypatch, *, mutate_args, output, handler_calls):

    class RealSkillRunTool(BaseTool):

        def __init__(self):
            super().__init__(name="skill_run", description="exercise the real BaseTool filter chain")

        async def _run_async_impl(self, *, tool_context, args):
            handler_calls.append(copy.deepcopy(args))
            return output

    class ToolProxy:
        name = "skill_run"

        def __init__(self):
            self.real_tool = RealSkillRunTool()

        async def run_async(self, *, tool_context, args):
            forwarded = copy.deepcopy(args)
            mutate_args(forwarded)
            return await self.real_tool.run_async(tool_context=tool_context, args=forwarded)

    class FakeToolSet:

        async def get_tools(self, context):
            return [ToolProxy()]

    monkeypatch.setattr(agent_factory, "create_skill_tool_set", lambda runtime: FakeToolSet())


def test_skill_run_sdk_blocked_response_never_becomes_allow_run(monkeypatch):
    handler_calls = []

    def remove_inline(args):
        del args["outputs"]["inline"]

    _install_sdk_output_toolset(
        monkeypatch,
        mutate_args=remove_inline,
        output={"exit_code": 0},
        handler_calls=handler_calls,
    )
    runner = SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        redactor=SecretRedactor(),
    )
    review_input = {"task_id": "task-sdk-block", "fixture_names": []}
    on_runs = []

    with prepare_execution_plan(task_id="task-sdk-block",
                                runtime="container",
                                review_input=review_input,
                                redactor=SecretRedactor()) as plan:
        result = runner.run(
            task_id="task-sdk-block",
            review_input=review_input,
            runtime="container",
            dry_run=True,
            requests=[plan.requests[0]],
            policy_context=plan.policy_context,
            on_run=on_runs.append,
        )

    assert handler_calls == []
    assert result.runs == []
    assert on_runs == []
    assert result.needs_human_review
    assert "integrity" in result.needs_human_review[0].message.lower()


def test_skill_run_non_mapping_sdk_output_fails_closed(monkeypatch):
    handler_calls = []
    _install_sdk_output_toolset(
        monkeypatch,
        mutate_args=lambda args: None,
        output="not-a-mapping",
        handler_calls=handler_calls,
    )
    runner = SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        redactor=SecretRedactor(),
    )
    review_input = {"task_id": "task-sdk-type", "fixture_names": []}

    with prepare_execution_plan(task_id="task-sdk-type",
                                runtime="container",
                                review_input=review_input,
                                redactor=SecretRedactor()) as plan:
        result = runner.run(
            task_id="task-sdk-type",
            review_input=review_input,
            runtime="container",
            dry_run=True,
            requests=[plan.requests[0]],
            policy_context=plan.policy_context,
        )

    assert len(handler_calls) == 1
    assert result.runs == []
    assert result.needs_human_review


def test_skill_run_handler_receives_callback_canonicalized_plain_dict(monkeypatch):
    handler_calls = []

    def make_equivalent_but_noncanonical(args):
        args["command"] = ("python3 'scripts/run_static_review.py' --input work/inputs/review_input.json "
                           "--output out/findings.json")
        args["inputs"] = tuple(args["inputs"])

    _install_sdk_output_toolset(
        monkeypatch,
        mutate_args=make_equivalent_but_noncanonical,
        output={
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 0,
            "stdout": "",
            "stderr": "",
            "output_files": [],
            "warnings": [],
        },
        handler_calls=handler_calls,
    )
    runner = SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        redactor=SecretRedactor(),
    )
    review_input = {"task_id": "task-sdk-canonical", "fixture_names": []}

    with prepare_execution_plan(task_id="task-sdk-canonical",
                                runtime="container",
                                review_input=review_input,
                                redactor=SecretRedactor()) as plan:
        canonical_args = plan.requests[0].to_skill_run_args()
        result = runner.run(
            task_id="task-sdk-canonical",
            review_input=review_input,
            runtime="container",
            dry_run=True,
            requests=[plan.requests[0]],
            policy_context=plan.policy_context,
        )

    assert handler_calls == [canonical_args]
    assert len(result.runs) == 1
    assert result.runs[0].decision == "allow"


def test_skill_static_review_emits_real_security_finding(tmp_path):
    report = ReviewOrchestrator(db_url=f"sqlite:///{tmp_path / 'review.db'}", output_dir=tmp_path / "out").review(
        fixture="security",
        dry_run=True,
        runtime="local",
    )

    skill_findings = [finding for finding in report.findings if "skill:run_static_review" in finding.source]

    assert skill_findings
    assert any(title in {finding.title
                         for finding in skill_findings} for title in {
                             "subprocess invoked with shell=True",
                             "dynamic code execution in changed code",
                         })  # noqa: E126


def test_skill_static_review_emits_database_or_resource_finding(tmp_path):
    report = ReviewOrchestrator(db_url=f"sqlite:///{tmp_path / 'review.db'}", output_dir=tmp_path / "out").review(
        fixture="async_resource_leak",
        dry_run=True,
        runtime="local",
    )

    skill_findings = [finding for finding in report.findings if "skill:run_static_review" in finding.source]

    assert skill_findings
    assert any(finding.category in {"database", "resource", "async_resource"} for finding in skill_findings)


def test_skill_static_review_safe_patterns_do_not_false_positive(tmp_path):
    output = _run_static_review_script(
        tmp_path,
        {
            "task_id":
            "safe-patterns",
            "fixture_names": [],
            "changed_files": ["app/safe.py"],
            "added_lines": [
                {
                    "file": "app/safe.py",
                    "line": 10,
                    "content": 'subprocess.run(["ls", "-la"], shell=False)',
                },
                {
                    "file": "app/safe.py",
                    "line": 11,
                    "content": "with open(path) as f:"
                },
                {
                    "file": "app/safe.py",
                    "line": 12,
                    "content": "    data = f.read()"
                },
                {
                    "file": "app/safe.py",
                    "line": 13,
                    "content": "conn = sqlite3.connect(path)"
                },
                {
                    "file": "app/safe.py",
                    "line": 14,
                    "content": "try:"
                },
                {
                    "file": "app/safe.py",
                    "line": 15,
                    "content": "    pass"
                },
                {
                    "file": "app/safe.py",
                    "line": 16,
                    "content": "finally:"
                },
                {
                    "file": "app/safe.py",
                    "line": 17,
                    "content": "    conn.close()"
                },
                {
                    "file": "app/safe.py",
                    "line": 18,
                    "content": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                },
                {
                    "file": "app/safe.py",
                    "line": 19,
                    "content": 'subprocess.run(["python", "--version"], shell=False)',
                },
                {
                    "file": "app/safe.py",
                    "line": 20,
                    "content": "async with aiohttp.ClientSession() as session:"
                },
            ],
        },
    )

    finding_keys = {(item["category"], item["title"]) for item in output["findings"]}
    assert ("security", "subprocess invoked with shell=True") not in finding_keys
    assert ("resource", "file handle may not be closed") not in finding_keys
    assert ("database", "database connection/session may not be closed") not in finding_keys
    assert not any(item["severity"] == "high" for item in output["findings"])


def test_aiohttp_client_session_is_not_database_finding(tmp_path):
    output = _run_static_review_script(
        tmp_path,
        {
            "task_id": "aiohttp-only",
            "changed_files": ["app/worker.py"],
            "fixture_names": [],
            "added_lines": [{
                "file": "app/worker.py",
                "line": 5,
                "content": "session = aiohttp.ClientSession()",
            }],
        },
    )

    assert not any(item["category"] == "database" for item in output["findings"])
    assert any(item["category"] == "async_resource" for item in output["findings"])


def test_sandbox_artifact_invalid_schema_becomes_human_review_warning():
    runs = [
        SandboxRun(
            run_id="sandbox_bad_json",
            task_id="task-artifact",
            runtime="local",
            command=["python3", "scripts/run_static_review.py"],
            output_files={"out/findings.json": "{not-json"},
        ),
        SandboxRun(
            run_id="sandbox_bad_finding",
            task_id="task-artifact",
            runtime="local",
            command=["python3", "scripts/run_static_review.py"],
            output_files={
                "out/findings.json":
                json.dumps({
                    "findings": [{
                        "severity": "urgent",
                        "category": "security",
                        "file": "app.py",
                        "line": "not-a-line",
                        "title": "bad finding",
                        "evidence": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
                        "recommendation": "fix",
                        "confidence": 0.9,
                    }],
                    "needs_human_review":
                    True,
                })
            },
        ),
    ]

    artifacts = load_sandbox_artifacts(runs, redactor=SecretRedactor())

    assert artifacts.findings == []
    assert len(artifacts.needs_human_review) >= 3
    assert all("AKIAIOSFODNN7EXAMPLE" not in warning.message for warning in artifacts.needs_human_review)
    assert any("sandbox:run_static_review" in warning.source for warning in artifacts.needs_human_review)


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


def test_review_report_contains_required_sections(tmp_path):
    output_dir = tmp_path / "out"
    ReviewOrchestrator(db_url=f"sqlite:///{tmp_path / 'review.db'}", output_dir=output_dir).review(
        fixture="all",
        dry_run=True,
        runtime="local",
    )

    report_json = json.loads((output_dir / "review_report.json").read_text(encoding="utf-8"))
    markdown = (output_dir / "review_report.md").read_text(encoding="utf-8")

    for key in [
            "findings_summary",
            "severity_stats",
            "human_review",
            "filter_summary",
            "metrics",
            "sandbox_summary",
            "recommendations",
    ]:
        assert key in report_json["section_summary"]

    for heading in [
            "## Findings Summary",
            "## Severity Stats",
            "## Human Review",
            "## Filter Summary",
            "## Metrics",
            "## Sandbox Summary",
            "## Recommendations",
    ]:
        assert heading in markdown


def test_query_task_returns_full_audit_chain(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'review.db'}"
    report = ReviewOrchestrator(db_url=db_url, output_dir=tmp_path / "out").review(
        fixture="security",
        dry_run=True,
        runtime="local",
    )

    rows = ReviewStorage(db_url).query_task(report.task_id)

    assert rows["task"]["task_id"] == report.task_id
    assert rows["input"]["task_id"] == report.task_id
    assert rows["sandbox_runs"]
    assert isinstance(rows["filter_intercepts"], list)
    assert rows["telemetry"]["task_id"] == report.task_id
    assert rows["findings"]
    assert rows["reports"][0]["task_id"] == report.task_id
    assert rows["report"]["task_id"] == report.task_id


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


def test_sandbox_failure_keeps_static_review_stable_without_test_marker(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'review.db'}"
    output_dir = tmp_path / "out"
    report = ReviewOrchestrator(db_url=db_url, output_dir=output_dir).review(
        fixture="sandbox_failure",
        dry_run=True,
        runtime="local",
    )

    assert not report.findings
    json_text = (output_dir / "review_report.json").read_text(encoding="utf-8")
    assert "skill-only static review marker" not in json_text
    rows = ReviewStorage(db_url).query_task(report.task_id)
    assert rows["findings"] == []
    static_run = next(run for run in report.sandbox_runs if "run_static_review.py" in " ".join(run.command))
    assert static_run.exit_code == 0
    assert any(warning.title == "sandbox smoke test failed" for warning in report.needs_human_review)
    assert not any(warning.title == "sandbox command failed" for warning in report.needs_human_review)


def test_container_runtime_uses_trpc_skill_tool_set_harness(tmp_path, monkeypatch):
    calls = {}

    class FakeTrpcSkillToolSetHarness:

        def __init__(self, *, runtime, policy, redactor):
            calls["runtime"] = runtime
            self.runtime = runtime

        def execute_one(self, *, task_id, review_input, request, policy_context, dry_run):
            calls.setdefault("requests", []).append(request)
            payload = {
                "findings": [{
                    "severity": "medium",
                    "category": "sandbox",
                    "file": "src/container_only.py",
                    "line": 7,
                    "title": "container skill finding",
                    "evidence": "mocked SkillToolSet output",
                    "recommendation": "Keep container SkillToolSet artifacts in the final review.",
                    "confidence": 0.91,
                    "source": ["mock"],
                }]
            }
            output_files = ({
                "out/findings.json": json.dumps(payload)
            } if request.command_argv[1] == "scripts/run_static_review.py" else {})
            return HarnessExecutionResult(runs=[
                SandboxRun(
                    run_id=f"sandbox_{task_id}_{request.request_id.rsplit(':', 1)[-1]}",
                    task_id=task_id,
                    runtime=self.runtime,
                    command=list(request.command_argv),
                    decision="allow",
                    output_files=output_files,
                    created_at="1970-01-01T00:00:00+00:00",
                )
            ])

    monkeypatch.setattr(sandbox_module, "TrpcSkillToolSetHarness", FakeTrpcSkillToolSetHarness)

    report = ReviewOrchestrator(db_url=f"sqlite:///{tmp_path / 'review.db'}", output_dir=tmp_path / "out").review(
        fixture="clean",
        dry_run=True,
        runtime="container",
    )

    assert calls["runtime"] == "container"
    assert calls["requests"]
    assert any(finding.title == "container skill finding" and "skill:run_static_review" in finding.source
               for finding in report.findings)


def test_sandbox_artifact_findings_are_merged_with_rule_findings(tmp_path, monkeypatch):

    class FakeTrpcSkillToolSetHarness:

        def __init__(self, *, runtime, policy, redactor):
            self.runtime = runtime

        def execute_one(self, *, task_id, review_input, request, policy_context, dry_run):
            payload = {
                "findings": [{
                    "severity": "medium",
                    "category": "sandbox",
                    "file": "src/container_only.py",
                    "line": 7,
                    "title": "container-only review finding",
                    "evidence": "artifact evidence",
                    "recommendation": "Keep sandbox artifacts in final findings.",
                    "confidence": 0.91,
                    "source": "mock",
                }]
            }
            output_files = ({
                "out/findings.json": json.dumps(payload)
            } if request.command_argv[1] == "scripts/run_static_review.py" else {})
            return HarnessExecutionResult(runs=[
                SandboxRun(
                    run_id=f"sandbox_{task_id}_{request.request_id.rsplit(':', 1)[-1]}",
                    task_id=task_id,
                    runtime=self.runtime,
                    command=list(request.command_argv),
                    decision="allow",
                    output_files=output_files,
                    created_at="1970-01-01T00:00:00+00:00",
                )
            ])

    monkeypatch.setattr(sandbox_module, "TrpcSkillToolSetHarness", FakeTrpcSkillToolSetHarness)
    db_url = f"sqlite:///{tmp_path / 'review.db'}"
    report = ReviewOrchestrator(db_url=db_url, output_dir=tmp_path / "out").review(
        fixture="security",
        dry_run=True,
        runtime="container",
    )
    rows = ReviewStorage(db_url).query_task(report.task_id)
    report_titles = {finding.title for finding in report.findings}
    db_titles = {row["title"] for row in rows["findings"]}

    assert "subprocess invoked with shell=True" in report_titles
    assert "container-only review finding" in report_titles
    assert report_titles.issubset(db_titles)
    sandbox_finding = next(finding for finding in report.findings if finding.title == "container-only review finding")
    assert "sandbox:run_static_review" in sandbox_finding.source


def test_container_runtime_optional_integration_documented(tmp_path):
    readme = (EXAMPLE_DIR / "README.md").read_text(encoding="utf-8")
    assert ("python examples/skills_code_review_agent/run_review.py review "
            "--fixture security --dry-run --runtime container") in readme

    try:
        result = subprocess.run(["docker", "info"], check=False, capture_output=True, text=True, timeout=20)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip("Docker is not available for optional container SkillToolSet integration.")
    if result.returncode != 0:
        pytest.skip("Docker is not running for optional container SkillToolSet integration.")

    report = ReviewOrchestrator(db_url=f"sqlite:///{tmp_path / 'review.db'}", output_dir=tmp_path / "out").review(
        fixture="security",
        dry_run=True,
        runtime="container",
    )

    assert report.sandbox_runs
    assert all(run.runtime == "container" for run in report.sandbox_runs)
    has_skill_source = any("skill:" in source for finding in report.findings for source in finding.source)
    has_artifacts = any(run.output_files for run in report.sandbox_runs)
    assert has_skill_source or has_artifacts


def test_auto_runtime_stays_container_when_container_execution_fails(tmp_path, monkeypatch):

    class FailingTrpcSkillToolSetHarness:

        def __init__(self, *, runtime, policy, redactor):
            self.runtime = runtime

        def execute_one(self, *, task_id, review_input, request, policy_context, dry_run):
            raise RuntimeError("docker unavailable")

    monkeypatch.setattr(sandbox_module, "TrpcSkillToolSetHarness", FailingTrpcSkillToolSetHarness)

    report = ReviewOrchestrator(db_url=f"sqlite:///{tmp_path / 'review.db'}", output_dir=tmp_path / "out").review(
        fixture="clean",
        dry_run=True,
        runtime="auto",
    )

    assert report.input_summary["effective_runtime"] == "container"
    assert report.telemetry.filter_needs_review_count == 0
    assert any(warning.title == "container runtime failed" for warning in report.needs_human_review)
    assert report.sandbox_runs == []


def test_local_sandbox_truncates_large_output_and_scrubs_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "raw-secret-value")
    runner = SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        redactor=SecretRedactor(),
    )
    safe_input = {"task_id": "task-safe-env", "fixture_names": []}
    with prepare_execution_plan(task_id="task-safe-env",
                                runtime="local",
                                review_input=safe_input,
                                redactor=SecretRedactor()) as plan:
        env_result = runner.run(
            task_id="task-safe-env",
            review_input=safe_input,
            runtime="local",
            dry_run=True,
            requests=[plan.requests[2]],
            policy_context=plan.policy_context,
        )
    smoke = json.loads(env_result.runs[0].output_files["out/smoke.json"])
    assert smoke["secret_token_in_env"] is False

    monkeypatch.setattr(sandbox_module, "MAX_STDOUT_CHARS", 24)
    monkeypatch.setattr(sandbox_module, "MAX_OUTPUT_FILE_BYTES", 96)
    large_input = {
        "task_id": "task-large-output",
        "fixture_names": [],
        "emit_large_output": 512,
    }
    with prepare_execution_plan(task_id="task-large-output",
                                runtime="local",
                                review_input=large_input,
                                redactor=SecretRedactor()) as plan:
        large_result = runner.run(
            task_id="task-large-output",
            review_input=large_input,
            runtime="local",
            dry_run=True,
            requests=[plan.requests[2]],
            policy_context=plan.policy_context,
        )
    run = large_result.runs[0]
    assert run.stdout_truncated is True
    assert run.output_truncated is True
    assert "raw-secret-value" not in run.stdout
    assert "raw-secret-value" not in json.dumps(run.output_files, sort_keys=True)
    assert run.output_file_count == 1
    assert run.output_bytes > 0


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


def test_filter_deny_before_container_execution_is_persisted(tmp_path, monkeypatch):

    class UnexpectedTrpcSkillToolSetHarness:

        def __init__(self, *, runtime, policy, redactor):
            self.runtime = runtime

        def execute_one(self, *, task_id, review_input, request, policy_context, dry_run):
            raise AssertionError("container harness must not run denied commands")

    monkeypatch.setattr(sandbox_module, "TrpcSkillToolSetHarness", UnexpectedTrpcSkillToolSetHarness)
    db_url = f"sqlite:///{tmp_path / 'review.db'}"

    report = ReviewOrchestrator(db_url=db_url, output_dir=tmp_path / "out").demo_filter(
        dry_run=True,
        runtime="container",
    )
    rows = ReviewStorage(db_url).query_task(report.task_id)

    assert report.sandbox_runs == []
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
