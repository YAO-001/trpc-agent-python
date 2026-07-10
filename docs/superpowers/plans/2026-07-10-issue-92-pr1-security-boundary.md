# Issue #92 PR1 Security Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure no untrusted SkillRun field reaches input staging or execution before a complete allow decision, and no raw secret reaches Sandbox, logs, reports, or SQL.

**Architecture:** Build one immutable `ExecutionRequest` per command with a globally unique task-scoped request ID. PolicyGate compares every field against a command-bound contract before calling either harness. One stateful `RedactionBoundary` performs input redaction and final sink cleaning while accumulating a single audit summary.

**Tech Stack:** Python, Pydantic v2, SQLAlchemy URL helpers, pytest, tRPC SkillToolSet.

---

### Task 1: Model complete immutable requests with unique IDs

**Files:**
- Create: `examples/skills_code_review_agent/agent/execution_request.py`
- Modify: `examples/skills_code_review_agent/agent/agent_factory.py:45-91`
- Create: `tests/examples/test_skills_code_review_agent_policy.py`

- [ ] **Step 1: Write failing completeness, uniqueness, and immutability tests**

Create:

```python
import pytest
from pydantic import ValidationError

from agent.agent_factory import build_execution_requests
from agent.execution_request import ExecutionEnv
from agent.execution_request import ExecutionInput
from agent.execution_request import ExecutionOutputSpec
from agent.execution_request import ExecutionRequest
from agent.execution_request import PolicyContext


def _input(
    *,
    src="host:///tmp/task-1/review_input.json",
    dst="skills/code-review/work/inputs/review_input.json",
):
    return ExecutionInput(src=src, dst=dst, mode="copy", pin=False)


def _env(name: str, value: str):
    return ExecutionEnv(name=name, value=value)


def _output(
    *,
    globs=("skills/code-review/out/findings.json",),
    max_files=1,
    max_file_bytes=262144,
    max_total_bytes=262144,
):
    return ExecutionOutputSpec(
        globs=globs,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
        save=False,
        inline=True,
        name_template="",
    )


def _valid_request(**changes):
    request = ExecutionRequest(
        request_id="task-1:skill-run:1",
        task_id="task-1",
        runtime="container",
        skill="code-review",
        command_argv=(
            "python3",
            "scripts/run_static_review.py",
            "--input",
            "work/inputs/review_input.json",
            "--output",
            "out/findings.json",
        ),
        cwd="$SKILLS_DIR/code-review",
        stdin="",
        editor_text="",
        inputs=(_input(),),
        legacy_output_files=(),
        output_spec=_output(),
        env=(_env("PYTHONUNBUFFERED", "1"),),
        network_access=False,
        timeout_seconds=30,
        output_budget_bytes=262144,
        save_as_artifacts=False,
        omit_inline_content=False,
        artifact_prefix="",
    )
    return request.model_copy(update=changes)


def _context():
    return PolicyContext(
        task_id="task-1",
        runtime="container",
        allowed_input_sources=frozenset({"host:///tmp/task-1/review_input.json"}),
    )


def test_execution_request_preserves_every_skill_run_field():
    request = ExecutionRequest.from_skill_run_args(
        request_id="task-1:skill-run:1",
        task_id="task-1",
        runtime="container",
        args={
            "command": (
                "python3 scripts/run_static_review.py "
                "--input work/inputs/review_input.json --output out/findings.json"
            ),
            "cwd": "$SKILLS_DIR/code-review",
            "skill": "code-review",
            "stdin": "",
            "editor_text": "",
            "inputs": [{
                "src": "host:///tmp/task-1/review_input.json",
                "dst": "skills/code-review/work/inputs/review_input.json",
                "mode": "copy",
                "pin": False,
            }],
            "output_files": [],
            "outputs": {
                "globs": ["skills/code-review/out/findings.json"],
                "max_files": 1,
                "max_file_bytes": 262144,
                "max_total_bytes": 262144,
                "save": False,
                "inline": True,
                "name_template": "",
            },
            "env": {"PYTHONUNBUFFERED": "1"},
            "network_access": False,
            "timeout": 30,
            "save_as_artifacts": False,
            "omit_inline_content": False,
            "artifact_prefix": "",
        },
    )
    assert request.command_argv[0] == "python3"
    assert request.skill == "code-review"
    assert request.inputs[0].mode == "copy"
    assert request.inputs[0].pin is False
    assert request.output_spec.globs == ("skills/code-review/out/findings.json",)
    assert request.legacy_output_files == ()
    assert request.stdin == request.editor_text == request.artifact_prefix == ""
    assert request.save_as_artifacts is request.omit_inline_content is False
    assert request.env[0].name == "PYTHONUNBUFFERED"
    assert request.timeout_seconds == 30
    assert request.output_budget_bytes == 262144


def test_three_calls_have_distinct_stable_request_ids(tmp_path):
    path = tmp_path / "review.json"
    path.write_text("{}", encoding="utf-8")
    first = build_execution_requests("task-1", "container", str(path))
    second = build_execution_requests("task-1", "container", str(path))
    assert [item.request_id for item in first] == [
        "task-1:skill-run:1",
        "task-1:skill-run:2",
        "task-1:skill-run:3",
    ]
    assert first == second


def test_request_and_nested_values_are_immutable():
    request = _valid_request()
    with pytest.raises(ValidationError):
        request.timeout_seconds = 5
    with pytest.raises(ValidationError):
        request.inputs[0].src = "host:///root/.ssh/id_rsa"
    with pytest.raises(ValidationError):
        request.env[0].value = "0"


def test_unmodeled_skill_run_field_fails_closed():
    args = _valid_request().to_skill_run_args()
    args["future_unmodeled_field"] = "must-not-be-ignored"
    with pytest.raises(ValueError, match="unmodeled SkillRun fields"):
        ExecutionRequest.from_skill_run_args(
            request_id="task-1:skill-run:1",
            task_id="task-1",
            runtime="container",
            args=args,
        )
```

- [ ] **Step 2: Run the tests and verify the module is missing**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_policy.py -v
```

Expected: collection fails because `execution_request.py` does not exist.

- [ ] **Step 3: Implement frozen request types**

Create:

```python
from __future__ import annotations

import shlex
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ExecutionInput(FrozenModel):
    src: str
    dst: str
    mode: Literal["copy"]
    pin: bool = False


class ExecutionEnv(FrozenModel):
    name: str
    value: str


class ExecutionOutputSpec(FrozenModel):
    globs: tuple[str, ...] = ()
    max_files: int = 0
    max_file_bytes: int = 0
    max_total_bytes: int = 0
    save: bool = False
    inline: bool = False
    name_template: str = ""


MODELED_SKILL_RUN_FIELDS = frozenset({
    "skill",
    "command",
    "cwd",
    "env",
    "stdin",
    "editor_text",
    "output_files",
    "timeout",
    "save_as_artifacts",
    "omit_inline_content",
    "artifact_prefix",
    "inputs",
    "outputs",
    "network_access",
})


class ExecutionRequest(FrozenModel):
    request_id: str
    task_id: str
    runtime: Literal["container", "local"]
    skill: str
    command_argv: tuple[str, ...]
    cwd: str
    stdin: str = ""
    editor_text: str = ""
    inputs: tuple[ExecutionInput, ...]
    legacy_output_files: tuple[str, ...] = ()
    output_spec: ExecutionOutputSpec
    env: tuple[ExecutionEnv, ...] = ()
    network_access: bool = False
    timeout_seconds: int
    output_budget_bytes: int
    save_as_artifacts: bool = False
    omit_inline_content: bool = False
    artifact_prefix: str = ""

    @classmethod
    def from_skill_run_args(
        cls,
        *,
        request_id: str,
        task_id: str,
        runtime: str,
        args: dict,
    ) -> "ExecutionRequest":
        unknown = set(args) - MODELED_SKILL_RUN_FIELDS
        if unknown:
            raise ValueError(
                f"unmodeled SkillRun fields: {sorted(unknown)}"
            )
        output = ExecutionOutputSpec.model_validate(args.get("outputs") or {})
        env = tuple(
            ExecutionEnv(name=str(key), value=str(value))
            for key, value in sorted(dict(args.get("env") or {}).items())
        )
        return cls(
            request_id=request_id,
            task_id=task_id,
            runtime=runtime,
            skill=str(args.get("skill") or ""),
            command_argv=tuple(shlex.split(str(args.get("command") or ""), posix=True)),
            cwd=str(args.get("cwd") or ""),
            stdin=str(args.get("stdin") or ""),
            editor_text=str(args.get("editor_text") or ""),
            inputs=tuple(ExecutionInput.model_validate(item) for item in args.get("inputs") or []),
            legacy_output_files=tuple(str(item) for item in args.get("output_files") or []),
            output_spec=output,
            env=env,
            network_access=bool(args.get("network_access")),
            timeout_seconds=int(args.get("timeout") or 0),
            output_budget_bytes=output.max_total_bytes,
            save_as_artifacts=bool(args.get("save_as_artifacts")),
            omit_inline_content=bool(args.get("omit_inline_content")),
            artifact_prefix=str(args.get("artifact_prefix") or ""),
        )

    def to_skill_run_args(self) -> dict[str, object]:
        return {
            "skill": self.skill,
            "command": shlex.join(self.command_argv),
            "cwd": self.cwd,
            "stdin": self.stdin,
            "editor_text": self.editor_text,
            "output_files": list(self.legacy_output_files),
            "timeout": self.timeout_seconds,
            "save_as_artifacts": self.save_as_artifacts,
            "omit_inline_content": self.omit_inline_content,
            "artifact_prefix": self.artifact_prefix,
            "inputs": [item.model_dump(mode="json") for item in self.inputs],
            "outputs": self.output_spec.model_dump(mode="json"),
            "env": {item.name: item.value for item in self.env},
            "network_access": self.network_access,
        }


class PolicyContext(FrozenModel):
    task_id: str
    runtime: Literal["container", "local"]
    allowed_input_sources: frozenset[str]
    allowed_cwd: str = "$SKILLS_DIR/code-review"
    max_timeout_seconds: int = 60
    max_output_bytes: int = 256 * 1024


class ExecutionPlan(FrozenModel):
    requests: tuple[ExecutionRequest, ...]
    policy_context: PolicyContext
```

The tuple-based env and nested frozen models are required; do not use a mutable `dict` inside the frozen request. The explicit top-level field set is a forward-compatibility security boundary: a newly introduced SDK argument is denied until this mirror, policy, mutation matrix, and canonical call are deliberately updated.

- [ ] **Step 4: Build declarative calls and requests together**

Each call in `build_skill_run_calls` uses an empty legacy `output_files` list and exactly one declarative output:

```python
def _output_spec(path: str) -> dict[str, object]:
    return {
        "globs": [path],
        "max_files": 1,
        "max_file_bytes": 256 * 1024,
        "max_total_bytes": 256 * 1024,
        "save": False,
        "inline": True,
        "name_template": "",
    }


def build_execution_requests(
    task_id: str,
    runtime: str,
    input_path: str,
) -> list[ExecutionRequest]:
    calls = build_skill_run_calls(input_path)
    return [
        ExecutionRequest.from_skill_run_args(
            request_id=f"{task_id}:skill-run:{index}",
            task_id=task_id,
            runtime=runtime,
            args=call,
        )
        for index, call in enumerate(calls, start=1)
    ]
```

Add the trusted preparation context in `agent_factory.py`:

```python
@contextmanager
def prepare_execution_plan(
    *,
    task_id: str,
    runtime: str,
    review_input: dict[str, Any],
    redactor: SecretRedactor,
):
    effective_runtime = "container" if runtime == "auto" else runtime
    with tempfile.TemporaryDirectory(prefix="skills_code_review_input_") as tmp:
        input_path = Path(tmp) / "review_input.json"
        serialized = json.dumps(review_input, ensure_ascii=False, sort_keys=True)
        safe_payload = json.loads(redactor.redact_text(serialized).text)
        input_path.write_text(
            json.dumps(safe_payload, ensure_ascii=False, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        requests = tuple(
            build_execution_requests(task_id, effective_runtime, str(input_path))
        )
        context = PolicyContext(
            task_id=task_id,
            runtime=effective_runtime,
            allowed_input_sources=frozenset({
                f"host://{input_path.resolve().as_posix()}"
            }),
        )
        yield ExecutionPlan(requests=requests, policy_context=context)
```

The context manager owns the already-redacted file until every `execute_one` call returns. The trusted allowed source is derived from that owned path, never from a candidate request.

Every canonical call explicitly includes `skill="code-review"`, empty `stdin/editor_text/output_files/artifact_prefix`, `save_as_artifacts=False`, `omit_inline_content=False`, `network_access=False`, the safe env, and `pin=False` on its input. Remove policy-relevant `run_tool_kwargs` from `create_skill_tool_set`; after this change, SkillRunTool may not apply timeout/artifact defaults after the callback has validated the request.

- [ ] **Step 5: Run model tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_policy.py -v
```

Expected: all Task 1 tests pass.

- [ ] **Step 6: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/execution_request.py',
  'examples/skills_code_review_agent/agent/agent_factory.py',
  'tests/examples/test_skills_code_review_agent_policy.py'
)
git add @stage
git commit -m "feat(review): model complete sandbox requests"
```

### Task 2: Validate every field before staging

**Files:**
- Modify: `examples/skills_code_review_agent/agent/filter_policy.py:39-155`
- Modify: `examples/skills_code_review_agent/agent/agent_factory.py:16-113`
- Modify: `examples/skills_code_review_agent/agent/sandbox_runner.py:65-77,190-556`
- Modify: `examples/skills_code_review_agent/agent/orchestrator.py:64-260`
- Test: `tests/examples/test_skills_code_review_agent_policy.py`
- Modify: `tests/examples/test_skills_code_review_agent_e2e.py`

- [ ] **Step 1: Add a complete invalid-request matrix**

Use `_valid_request(**changes)` to create new Pydantic objects with `model_copy(update=...)`. Parameterize these mutations and assert `decision == "deny"`:

```python
@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"task_id": "other"}, "task id"),
        ({"skill": "other-skill"}, "skill"),
        ({"cwd": "/"}, "cwd"),
        ({"stdin": "secret input"}, "stdin"),
        ({"editor_text": "overwrite"}, "editor"),
        ({"inputs": ()}, "exactly one input"),
        ({"inputs": (_input(), _input())}, "exactly one input"),
        ({"inputs": (ExecutionInput.model_construct(
            src="host:///tmp/task-1/review_input.json",
            dst="skills/code-review/work/inputs/review_input.json",
            mode="link",
            pin=False,
        ),)}, "input mode"),
        ({"inputs": (_input(src="host:///root/.ssh/id_rsa"),)}, "input source"),
        ({"inputs": (_input(dst="skills/code-review/scripts/run_static_review.py"),)}, "input destination"),
        ({"inputs": (_input(dst="../review.json"),)}, "input destination"),
        ({"inputs": (_input().model_copy(update={"pin": True}),)}, "input pin"),
        ({"command_argv": ("python3", "unapproved.py")}, "command"),
        ({"legacy_output_files": ("skills/code-review/out/findings.json",)}, "legacy output"),
        ({"env": (_env("FOO", "bar"),)}, "environment"),
        ({"env": (_env("PYTHONPATH", "/tmp/evil"),)}, "environment"),
        ({"network_access": True}, "network"),
        ({"timeout_seconds": 0}, "timeout"),
        ({"timeout_seconds": -1}, "timeout"),
        ({"timeout_seconds": 61}, "timeout"),
        ({"output_spec": _output(globs=())}, "exactly one output"),
        ({"output_spec": _output(globs=(
            "skills/code-review/out/findings.json",
            "skills/code-review/out/secrets.json",
        ))}, "exactly one output"),
        ({"output_spec": _output(globs=("skills/code-review/out/secrets.json",))}, "command output"),
        ({"output_spec": _output(max_files=2)}, "output file count"),
        ({"output_spec": _output(max_file_bytes=0)}, "output budget"),
        ({"output_spec": _output(max_file_bytes=262145)}, "output budget"),
        ({"output_spec": _output(max_total_bytes=0)}, "output budget"),
        ({"output_spec": _output(max_total_bytes=262145)}, "output budget"),
        ({"output_spec": _output().model_copy(update={"save": True})}, "output save"),
        ({"output_spec": _output().model_copy(update={"inline": False})}, "output inline"),
        ({"output_spec": _output().model_copy(update={"name_template": "secret-{name}"})}, "output name"),
        ({"output_budget_bytes": 1}, "output budget"),
        ({"save_as_artifacts": True}, "artifact persistence"),
        ({"omit_inline_content": True}, "inline content"),
        ({"artifact_prefix": "outside"}, "artifact prefix"),
    ],
)
def test_policy_rejects_every_untrusted_field(changes, reason):
    decision = ReviewExecutionPolicy().evaluate(
        _valid_request().model_copy(update=changes),
        _context(),
    )
    assert decision.decision == "deny"
    assert reason in decision.intercept.reason
```

Add explicit tests that the three canonical requests are allowed and each command is bound to only its own output glob.

Add `test_code_review_repository_has_no_dynamic_run_env`, asserting `repository.skill_run_env("code-review") == {}`, and an env-smoke test that places `API_TOKEN/HOME/PYTHONPATH` secrets in the host process, executes the explicit local harness, and proves the Skill output contains none of them. Caller env is the request contract; SDK-injected env is limited to fixed workspace directory variables plus `TRPC_AGENT_SKILL_NAME=code-review`. Remove `HOME` and `PYTHONPATH` from LocalSkillHarness's inherited safe-env keys; keep only platform launch essentials and explicit constants.

- [ ] **Step 2: Prove deny and approval-required never reach a harness**

```python
from agent.filter_policy import ReviewExecutionPolicy
from agent.input_resolver import EXAMPLE_DIR
from agent.sandbox_runner import SandboxRunner
from agent.secret_redactor import SecretRedactor


def _runner(tmp_path):
    return SandboxRunner(
        example_dir=EXAMPLE_DIR,
        policy=ReviewExecutionPolicy(dry_run=True),
        redactor=SecretRedactor(),
    )


def _request_for_decision(decision: str):
    command = (
        ("rm", "-rf", "/")
        if decision == "deny"
        else ("pip", "install", "unapproved-package")
    )
    return _valid_request(command_argv=command)


@pytest.mark.parametrize("decision", ["deny", "needs_human_review"])
def test_non_allow_decision_never_stages_or_executes(tmp_path, monkeypatch, decision):
    calls = []

    class ExplodingHarness:
        def execute_one(self, **kwargs):
            calls.append(kwargs)
            raise AssertionError("harness must not be called")

    runner = _runner(tmp_path)
    monkeypatch.setattr(runner, "_harness_for_runtime", lambda runtime: ExplodingHarness())
    request = _request_for_decision(decision)
    result = runner.run(
        task_id=request.task_id,
        review_input={"task_id": request.task_id},
        runtime=request.runtime,
        dry_run=True,
        requests=[request],
        policy_context=_context(),
    )
    assert calls == []
    assert result.runs == []
    assert [item.decision for item in result.decisions] == [decision]
    assert result.decisions[0].metadata["error_kind"] == {
        "deny": "policy_denied",
        "needs_human_review": "approval_required",
    }[decision]
```

`_request_for_decision("deny")` uses a destructive unapproved command. `_request_for_decision("needs_human_review")` uses a syntactically valid but approval-gated package-install command. Neither helper stubs the policy result.

- [ ] **Step 3: Implement an exact command contract**

Define:

```python
COMMAND_CONTRACTS = {
    (
        "python3",
        "scripts/run_static_review.py",
        "--input",
        "work/inputs/review_input.json",
        "--output",
        "out/findings.json",
    ): "skills/code-review/out/findings.json",
    (
        "python3",
        "scripts/secret_scan.py",
        "--input",
        "work/inputs/review_input.json",
        "--output",
        "out/secrets.json",
    ): "skills/code-review/out/secrets.json",
    (
        "python3",
        "scripts/smoke_test.py",
        "--input",
        "work/inputs/review_input.json",
        "--output",
        "out/smoke.json",
    ): "skills/code-review/out/smoke.json",
}
ALLOWED_ENV = {("PYTHONUNBUFFERED", "1")}
APPROVAL_REQUIRED_PROGRAMS = {"pip", "pip3", "npm", "yarn", "pnpm"}
DECISION_ERROR_KIND = {
    "allow": "",
    "deny": "policy_denied",
    "needs_human_review": "approval_required",
}
```

`ReviewExecutionPolicy.evaluate(request, context)` checks, in order:

1. task ID and runtime equal the context; skill is exactly `code-review`;
2. cwd is exactly the code-review Skill; stdin and editor text are empty;
3. exactly one unpinned `copy` input uses the task-approved host URI and exact `skills/code-review/work/inputs/review_input.json` destination;
4. legacy output_files is empty; exactly one declarative output glob uses `max_files=1`, positive per-file/total budgets at most 256 KiB, `save=False`, `inline=True`, empty name template, and `output_budget_bytes == max_total_bytes`;
5. env is a subset of `ALLOWED_ENV`, network is false, timeout is within 1-60 seconds, artifact saving/omission are false, and artifact prefix is empty;
6. after all non-command fields pass, use one mutually exclusive command branch: an exact `COMMAND_CONTRACTS` match with its bound output returns allow; an executable in `APPROVAL_REQUIRED_PROGRAMS` returns `needs_human_review`; every other command returns deny.

Normalize workspace paths with `PurePosixPath`; reject absolute paths, `..`, backslash traversal, and protected Skill destinations before comparing.

Every evaluation returns a `PolicyDecision` with a `FilterIntercept`, including allow. Its request metadata contains `request_id` and the canonical `DECISION_ERROR_KIND[decision]`, but no raw host path or env value. PR2 promotes that safe metadata value to an indexed model/database field; the names are fixed here so deny/approval cannot disappear from the unified error taxonomy.

- [ ] **Step 4: Pass validated requests through both harnesses**

Use this single runner interface for PR1-PR4:

```python
def run(
    self,
    *,
    task_id: str,
    review_input: dict,
    runtime: str,
    dry_run: bool,
    requests: list[ExecutionRequest],
    policy_context: PolicyContext,
    on_decision: Callable[[FilterIntercept], None] | None = None,
    on_run: Callable[[SandboxRun], None] | None = None,
) -> SandboxResult:
```

Evaluate every request against the supplied trusted context before choosing a harness. Append and callback every decision immediately. If no request is allowed, return before harness lookup. Otherwise choose one harness and call `execute_one(..., request=request)` once per allowed request, in request-ID order; delete every `commands=` and list-based harness API. Never derive `allowed_input_sources` from `requests`. This is the same interface PR2 uses to attach exactly one SandboxRun to each request.

Rename the internal `SandboxResult.intercepts` collection to `decisions` because it now contains allow records as well as actual interceptions. The external report/database field remains `filter_intercepts` for schema compatibility; orchestrator passes `sandbox_result.decisions` into it.

Migrate both orchestration paths in this task:

```python
with prepare_execution_plan(
    task_id=task_id,
    runtime=runtime,
    review_input=review_input,
    redactor=redactor,
) as plan:
    sandbox_result = sandbox.run(
        task_id=task_id,
        review_input=review_input,
        runtime=runtime,
        dry_run=dry_run,
        requests=list(plan.requests),
        policy_context=plan.policy_context,
    )
```

`demo_filter` opens the same context, model-copies its first request with a distinct `request_id` and `command_argv=("rm", "-rf", "/")`, and passes that request with the unchanged trusted context. It no longer uses `commands=`.

For SDK defense in depth, bind the already-created request by command:

```python
def make_review_before_tool_callback(policy, policy_context, requests_by_command):
    def callback(context, tool, args: dict, response=None):
        if getattr(tool, "name", "") != "skill_run":
            return None
        command = tuple(shlex.split(str(args.get("command") or ""), posix=True))
        expected = requests_by_command.get(command)
        if expected is None:
            return {"blocked": True, "decision": "deny", "reason": "unknown request"}
        try:
            actual = ExecutionRequest.from_skill_run_args(
                request_id=expected.request_id,
                task_id=expected.task_id,
                runtime=expected.runtime,
                args=args,
            )
        except (TypeError, ValueError, ValidationError):
            return {
                "blocked": True,
                "decision": "deny",
                "reason": "request could not be parsed safely",
            }
        decision = policy.evaluate(actual, policy_context)
        if decision.decision == "allow" and actual == expected:
            return None
        return {
            "blocked": True,
            "decision": decision.decision if actual == expected else "deny",
            "reason": decision.intercept.reason if actual == expected else "request changed after validation",
        }
    return callback
```

The SDK callback is an integrity guard only: it does not invoke `on_decision` and does not persist a second record for the same `(task_id, request_id)`.

Add a callback regression that removes explicit `outputs.inline` from canonical args. Because the mirror model uses the SDK default `False` while the expected request is explicitly `True`, equality fails and the callback returns a structured deny. The same test adds an unknown top-level SkillRun argument, covers invalid nested fields/modes, and asserts parsing exceptions are caught, never propagated.

- [ ] **Step 5: Run policy and execution-boundary tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_policy.py -v
python -m pytest tests/examples/test_skills_code_review_agent_e2e.py -k "filter or skill_run" -v
```

Expected: all selected tests pass; no non-allow request constructs or calls a harness.

- [ ] **Step 6: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/filter_policy.py',
  'examples/skills_code_review_agent/agent/agent_factory.py',
  'examples/skills_code_review_agent/agent/sandbox_runner.py',
  'examples/skills_code_review_agent/agent/orchestrator.py',
  'tests/examples/test_skills_code_review_agent_policy.py',
  'tests/examples/test_skills_code_review_agent_e2e.py'
)
git add @stage
git commit -m "fix(review): gate complete requests before staging"
```

### Task 3: Redact every secret format and sanitize Sandbox input

**Files:**
- Create: `examples/skills_code_review_agent/agent/redaction_boundary.py`
- Modify: `examples/skills_code_review_agent/agent/secret_redactor.py:32-147`
- Modify: `examples/skills_code_review_agent/agent/models.py:185-195`
- Modify: `examples/skills_code_review_agent/agent/orchestrator.py:64-181`
- Modify: `examples/skills_code_review_agent/agent/rule_engine.py:25-119`
- Modify: `examples/skills_code_review_agent/skills/code-review/scripts/run_static_review.py`
- Create: `tests/examples/test_skills_code_review_agent_redaction.py`

- [ ] **Step 1: Write a comprehensive failing redaction corpus**

```python
@pytest.mark.parametrize("text,raw", [
    ('password = "strong passphrase 987"', "strong passphrase 987"),
    ('passwd="passwd-value-987"', "passwd-value-987"),
    ('pwd: "pwd-value-987"', "pwd-value-987"),
    ('client_secret: "opaque-client-secret-123"', "opaque-client-secret-123"),
    ('apiKey = "camel-case-key-123456"', "camel-case-key-123456"),
    ('access_token="access-token-123456"', "access-token-123456"),
    ('refresh-token: "refresh-token-123456"', "refresh-token-123456"),
    ('Authorization: Bearer bearer-token-123456789', "bearer-token-123456789"),
    ('postgresql://alice:plain-password@db/reviews', "plain-password"),
    ('{"password": "json-password-123"}', "json-password-123"),
    ('api_key = "dummy-secret-for-tests"', "dummy-secret-for-tests"),
])
def test_boundary_redacts_common_secret_formats(text, raw):
    boundary = RedactionBoundary()
    result = boundary.text(text)
    assert raw not in result.text
    assert boundary.summary.total_redactions >= 1


def test_dummy_value_is_redacted_but_marked_placeholder():
    boundary = RedactionBoundary()
    result = boundary.text('api_key = "dummy-secret-for-tests"')
    assert "dummy-secret-for-tests" not in result.text
    assert result.summary.events[0].likely_placeholder is True


def test_boundary_accumulates_redactions_across_calls():
    boundary = RedactionBoundary()
    boundary.text('token="first-secret-123"')
    boundary.text('passwd="second-secret-456"')
    assert boundary.summary.total_redactions == 2


def test_credential_url_redacts_username_and_password():
    result = RedactionBoundary().text(
        "postgresql://alice:plain-password@db/reviews"
    )
    assert "alice" not in result.text
    assert "plain-password" not in result.text
```

- [ ] **Step 2: Add a failing Sandbox-input leak test**

Use a capturing harness and a diff/input reference containing `opaque-input-token-987`; assert the raw value is absent from the complete serialized `review_input` passed to the harness. This test must inspect the harness argument, not only final report files.

- [ ] **Step 3: Extend patterns without a dummy bypass**

Use case-insensitive patterns for these aliases:

```python
SECRET_ALIASES = (
    r"password",
    r"passwd",
    r"pwd",
    r"token",
    r"access[_-]?token",
    r"refresh[_-]?token",
    r"api[_-]?key",
    r"apikey",
    r"secret",
    r"client[_-]?secret",
    r"authorization",
)
ASSIGNMENT_RE = re.compile(
    rf"(?i)(?P<prefix>\b(?:{'|'.join(SECRET_ALIASES)})\b\s*[:=]\s*)"
    r"(?P<quote>['\"]?)(?P<value>[^'\"\s,;}]+(?: [^'\"\n,;}]+)*)(?P=quote)"
)
BEARER_RE = re.compile(r"(?i)(?P<prefix>authorization\s*:\s*bearer\s+)(?P<value>[^\s,;]+)")
CREDENTIAL_URL_RE = re.compile(
    r"(?P<prefix>[a-z][a-z0-9+.-]*://)(?P<value>[^@/\s]+)(?P<suffix>@)",
    re.IGNORECASE,
)
```

Always replace the captured value and reconstruct optional `prefix`, quote, and `suffix` groups so URL syntax remains valid. Add `likely_placeholder: bool = False` to `RedactionEvent`; dummy/test/example/changeme only set metadata. When merging repeated events, `likely_placeholder` remains true only if every occurrence for that digest is placeholder-like.

- [ ] **Step 4: Implement a stateful sink boundary**

```python
class RedactionBoundary:
    def __init__(self, redactor: SecretRedactor | None = None) -> None:
        self.redactor = redactor or SecretRedactor()
        self._events: dict[tuple[str, str], RedactionEvent] = {}

    def text(self, value: object) -> RedactionResult:
        result = self.redactor.redact_text(str(value or ""))
        self._merge(result.summary)
        return result

    def clean(self, value):
        if isinstance(value, dict):
            return {
                self.text(str(key)).text: self.clean(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self.clean(item) for item in value]
        if isinstance(value, str):
            return self.text(value).text
        return value

    @property
    def summary(self) -> RedactionSummary:
        events = sorted(self._events.values(), key=lambda item: (item.secret_type, item.sha256))
        by_type: dict[str, int] = {}
        for event in events:
            by_type[event.secret_type] = by_type.get(event.secret_type, 0) + event.count
        return RedactionSummary(
            total_redactions=sum(item.count for item in events),
            by_type=by_type,
            events=events,
        )

    def display_db_url(self, db_url: str) -> str:
        url = make_url(db_url)
        if url.get_backend_name() == "sqlite":
            return self.text(db_url).text
        public = URL.create(
            drivername=url.drivername,
            host=url.host,
            port=url.port,
            database=url.database,
        )
        return public.render_as_string(hide_password=True)
```

`_merge` sums counts for the `(secret_type, sha256)` key and combines `likely_placeholder` with logical AND.

- [ ] **Step 5: Sanitize the complete Sandbox payload and preserve confidence**

Upgrade `prepare_execution_plan` to accept the stateful boundary and write only `boundary.clean(review_input)`. Construct `review_input` only from cleaned values. `input_ref`, changed files, added-line content/context, redaction metadata, warnings, and exception-derived fields must all be included before `SandboxRunner.run`; the owned temporary file and every request URI remain unchanged for the full context lifetime.

Change `RuleEngine.run(parsed_diff, redaction_summary)`. Match placeholder hashes to summary events and assign confidence `0.58` for `likely_placeholder`, otherwise `0.99`. Pass the same event metadata to the static sandbox script so it makes the same candidate confidence choice.

- [ ] **Step 6: Run redaction, rule, and Sandbox-input tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_redaction.py -v
python -m pytest tests/examples/test_skills_code_review_agent_rules.py -v
python -m pytest tests/examples/test_skills_code_review_agent_hidden_like.py -v
```

Expected: all tests pass; dummy values are redacted and low confidence, never plaintext.

- [ ] **Step 7: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/redaction_boundary.py',
  'examples/skills_code_review_agent/agent/secret_redactor.py',
  'examples/skills_code_review_agent/agent/models.py',
  'examples/skills_code_review_agent/agent/orchestrator.py',
  'examples/skills_code_review_agent/agent/rule_engine.py',
  'examples/skills_code_review_agent/skills/code-review/scripts/run_static_review.py',
  'tests/examples/test_skills_code_review_agent_redaction.py',
  'tests/examples/test_skills_code_review_agent_rules.py',
  'tests/examples/test_skills_code_review_agent_hidden_like.py'
)
git add @stage
git commit -m "fix(review): redact all inputs and secret formats"
```

### Task 4: Apply final redaction to every persistence sink

**Files:**
- Modify: `examples/skills_code_review_agent/agent/orchestrator.py:64-260`
- Modify: `examples/skills_code_review_agent/agent/report_builder.py:24-263`
- Modify: `examples/skills_code_review_agent/agent/sandbox_runner.py:110-183,384-437,489-518`
- Modify: `examples/skills_code_review_agent/agent/storage.py:131-339`
- Modify: `trpc_agent_sdk/skills/tools/_skill_run.py:795-811`
- Test: `tests/examples/test_skills_code_review_agent_redaction.py`
- Modify: `tests/skills/tools/test_skill_run.py`

- [ ] **Step 1: Add an end-to-end leak scan**

```python
def test_raw_secret_never_reaches_report_database_or_logs(tmp_path, monkeypatch, caplog):
    raw = "opaque-runtime-token-987654"

    class SecretBearingHarness:
        def __init__(self, *args, **kwargs):
            pass

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

    monkeypatch.setattr(
        "agent.sandbox_runner.TrpcSkillToolSetHarness",
        SecretBearingHarness,
    )
    db_url = f"sqlite:///{tmp_path / 'review.db'}"
    output_dir = tmp_path / "out"
    report = ReviewOrchestrator(db_url=db_url, output_dir=output_dir).review(
        fixture="clean",
        dry_run=True,
        runtime="container",
    )
    combined = "\n".join([
        (output_dir / "review_report.json").read_text(encoding="utf-8"),
        (output_dir / "review_report.md").read_text(encoding="utf-8"),
        ReviewStorage(db_url).dump_task_text(report.task_id),
    ])
    assert raw not in combined
    assert raw not in caplog.text


def test_exception_text_is_redacted_before_it_becomes_a_model_field():
    raw = "exception-secret-987"
    cleaned = RedactionBoundary().text(
        RuntimeError(f"client_secret={raw}")
    ).text
    assert raw not in cleaned


def test_non_sqlite_display_url_hides_username_and_password(tmp_path):
    boundary = RedactionBoundary()
    shown = boundary.display_db_url("postgresql://alice:plain-password@db/reviews")
    assert "alice" not in shown
    assert "plain-password" not in shown
```

In the SDK SkillRun tests, use the real `SkillRunTool` with a fake `WorkspaceRuntime` whose program result is non-zero and whose stderr is `client_secret=raw-sdk-log-secret-987`. Set `caplog` to DEBUG, prove the returned tool payload still contains the fixture value (so the fake exercised the real result path), and assert it never appears in `caplog.text`. The example-level test above separately proves the harness boundary removes that value before report/database persistence.

- [ ] **Step 2: Run the focused tests**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_redaction.py -k "never_reaches or exception_text or display_url" -v
```

Expected: FAIL because exception text and the DSN username/password can reach sinks.

- [ ] **Step 3: Thread one boundary through all producers and sinks**

Construct one `RedactionBoundary` per orchestration. Pass it to SandboxRunner, ReviewStorage, and ReportBuilder. Replace every direct `str(exc)`, stdout/stderr conversion, artifact string, Filter reason/metadata, input metadata, SQL row, and report field conversion with `boundary.text(...).text` or `boundary.clean(...)`.

The SDK must not log raw program streams before the example boundary can run. Replace SkillRun's non-zero-exit log with metadata only:

```python
logger.info(
    "Skill program failed: exit_code=%s, stderr_bytes=%s",
    ret.exit_code,
    len((ret.stderr or "").encode("utf-8", errors="replace")),
)
```

Do not log command stdin, environment, stdout, stderr, or output-file content at any level on this path.

Storage uses:

```python
class ReviewStorage:
    def __init__(self, db_url=DEFAULT_DB_URL, boundary=None):
        self.boundary = boundary or RedactionBoundary()
        self.engine = create_engine(db_url, future=True)

    def _safe_row(self, row: dict[str, Any]) -> dict[str, Any]:
        return self.boundary.clean(row)
```

Apply `_safe_row` to task/input metadata, every SandboxRun field, findings/warnings, every Filter decision (including allow), telemetry JSON, and report JSON/Markdown. Logger calls receive only cleaned values.

- [ ] **Step 4: Finalize summary after a complete clean pass**

Before persistence, create one JSON-compatible bundle containing task, redacted input, decisions, runs, findings, warnings, telemetry, and draft report. Call `boundary.clean(bundle)` once. Then snapshot `boundary.summary`, update telemetry `redaction_count` and the report's `redaction_summary`, and validate the clean bundle back into models. Persistence must consume this validated clean bundle; it may clean again defensively but must never receive the raw bundle.

In `ReportBuilder.write`, perform a final two-pass clean so any newly discovered value is included:

```python
payload = self.boundary.clean(report.model_dump(mode="json"))
payload["redaction_summary"] = self.boundary.summary.model_dump(mode="json")
payload["telemetry"]["redaction_count"] = self.boundary.summary.total_redactions
safe_report = ReviewReport.model_validate(self.boundary.clean(payload))
```

Serialize only `safe_report`. Use `boundary.display_db_url` for the report query hint.

- [ ] **Step 5: Run all PR1 security regressions**

```powershell
python -m pytest tests/examples/test_skills_code_review_agent_policy.py -v
python -m pytest tests/examples/test_skills_code_review_agent_redaction.py -v
python -m pytest tests/examples/test_skills_code_review_agent_rules.py -v
python -m pytest tests/examples/test_skills_code_review_agent_hidden_like.py -v
python -m pytest tests/examples -o addopts= -q
python -m pytest tests/skills/tools/test_skill_run.py -k "nonzero_stderr_is_not_logged" -v
```

Expected: all tests pass; a real Docker test may still be deselected until PR4.

- [ ] **Step 6: Commit**

```powershell
$stage = @(
  'examples/skills_code_review_agent/agent/orchestrator.py',
  'examples/skills_code_review_agent/agent/report_builder.py',
  'examples/skills_code_review_agent/agent/sandbox_runner.py',
  'examples/skills_code_review_agent/agent/storage.py',
  'trpc_agent_sdk/skills/tools/_skill_run.py',
  'tests/examples/test_skills_code_review_agent_redaction.py',
  'tests/skills/tools/test_skill_run.py'
)
git add @stage
git commit -m "fix(review): sanitize every persistence sink"
```

## PR1 exit checklist

- [ ] All three canonical requests have distinct request IDs and immutable nested values.
- [ ] A legal command with malicious inputs, cwd, outputs, env, network, timeout, or budget is denied before harness construction.
- [ ] Empty/multiple inputs and outputs are denied; each command is bound to one output.
- [ ] Every PolicyGate decision, including allow, produces an audit object.
- [ ] Dummy-looking secrets are redacted but retain low-confidence metadata.
- [ ] Complete Sandbox input, exceptions, streams, artifacts, logs, DSNs, reports, and SQL contain no raw corpus secret.
- [ ] The final redaction summary includes redactions discovered at later sinks.
- [ ] Example tests, flake8, YAPF, and staged whitespace checks pass.
