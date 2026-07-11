# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Sandbox execution wrapper used by the example review orchestrator."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any
from typing import Callable

from .execution_request import ExecutionRequest
from .execution_request import PolicyContext
from .filter_policy import ReviewExecutionPolicy
from .models import FilterIntercept
from .models import Finding
from .models import ReviewWarning
from .models import SandboxRun
from .models import utc_now
from .redaction_boundary import RedactionBoundary
from .sandbox_artifact_loader import load_sandbox_artifacts
from .secret_redactor import SecretRedactor

MAX_STDOUT_CHARS = 12000
MAX_STDERR_CHARS = 12000
MAX_OUTPUT_FILE_BYTES = 256 * 1024
MAX_OUTPUT_FILES = 16
_POSIX_LAUNCH_ENV_KEYS = frozenset({
    "PATH",
    "TMPDIR",
    "TEMP",
    "TMP",
})
_WINDOWS_LAUNCH_ENV_KEYS = _POSIX_LAUNCH_ENV_KEYS | frozenset({
    "Path",
    "PATHEXT",
    "SYSTEMROOT",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
})


@dataclass(frozen=True)
class HarnessExecutionResult:
    runs: list[SandboxRun]


@dataclass
class SandboxResult:
    runs: list[SandboxRun]
    decisions: list[FilterIntercept]
    findings: list[Finding]
    warnings: list[ReviewWarning]
    needs_human_review: list[ReviewWarning]
    effective_runtime: str


class _BoundaryRedactor(SecretRedactor):
    """SecretRedactor-compatible adapter that records every loader redaction."""

    def __init__(self, boundary: RedactionBoundary) -> None:
        self.boundary = boundary

    def redact_text(self, text: str) -> Any:
        return self.boundary.text(text)


def _inherited_platform_env(
    host_env: Mapping[str, str],
    *,
    platform_name: str,
) -> dict[str, str]:
    allowed_keys = _WINDOWS_LAUNCH_ENV_KEYS if platform_name == "nt" else _POSIX_LAUNCH_ENV_KEYS
    return {key: value for key, value in host_env.items() if key in allowed_keys}


def _safe_env(*, workspace_root: Path, request: ExecutionRequest) -> dict[str, str]:
    env = _inherited_platform_env(os.environ, platform_name=os.name)
    skill_dir = workspace_root / "skills" / "code-review"
    env.update({
        "PYTHONIOENCODING": "utf-8",
        "WORKSPACE_DIR": str(workspace_root),
        "SKILLS_DIR": str(workspace_root / "skills"),
        "WORK_DIR": str(skill_dir / "work"),
        "OUTPUT_DIR": str(skill_dir / "out"),
        "RUN_DIR": str(workspace_root / "runs" / request.request_id.replace(":", "_")),
        "TRPC_AGENT_SKILL_NAME": "code-review",
    })
    env.update({item.name: item.value for item in request.env})
    return env


def _truncate_text(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    marker = f"\n[TRUNCATED: kept first {limit} chars]\n"
    return text[:limit] + marker, True


def _normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _read_output_file(path: Path, *, limit: int) -> tuple[str, bool]:
    raw = path.read_bytes()
    truncated = len(raw) > limit
    if truncated:
        raw = raw[:limit]
    text = raw.decode("utf-8", errors="replace")
    if truncated:
        text += f"\n[TRUNCATED: kept first {limit} bytes]\n"
    return text, truncated


def _sanitize_stream(text: object, *, boundary: RedactionBoundary, limit: int) -> tuple[str, bool]:
    redacted = _normalize_newlines(boundary.text(text).text)
    return _truncate_text(redacted, limit)


def _sanitize_output_mapping(
    output_map: dict[str, str],
    *,
    boundary: RedactionBoundary,
    already_truncated: bool,
    max_files: int,
    max_file_bytes: int,
) -> tuple[dict[str, str], bool]:
    output_truncated = already_truncated
    sorted_items = sorted(output_map.items())
    selected_items = sorted_items[:max(0, max_files)]
    output_truncated = output_truncated or len(selected_items) < len(sorted_items)
    cleaned = boundary.clean(dict(selected_items))
    limited: dict[str, str] = {}
    for safe_name, content in cleaned.items():
        redacted = _normalize_newlines(content)
        truncated_content, was_truncated = _truncate_text(redacted, max_file_bytes)
        output_truncated = output_truncated or was_truncated
        limited[safe_name] = truncated_content
    return limited, output_truncated


def _failure_warning(run: SandboxRun, *, boundary: RedactionBoundary) -> ReviewWarning:
    message = run.stderr or run.stdout or run.warning or "sandbox command failed or timed out"
    payload = boundary.clean({
        "category": "sandbox",
        "title": "sandbox command failed",
        "message": f"{' '.join(run.command)} exited with {run.exit_code}: {message}",
        "confidence": 1.0,
        "source": ["sandbox_runner"],
        "needs_human_review": True,
    })
    return ReviewWarning.model_validate(payload)


def _run_has_human_review_artifact(run: SandboxRun) -> bool:
    for content in run.output_files.values():
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        value = data.get("needs_human_review")
        if value is True:
            return True
        if isinstance(value, dict):
            return True
        if isinstance(value, list) and any(isinstance(item, dict) for item in value):
            return True
    return False


def _runtime_warning(title: object, message: object, *, boundary: RedactionBoundary) -> ReviewWarning:
    return ReviewWarning.model_validate(
        boundary.clean({
            "category": "sandbox",
            "title": title,
            "message": message,
            "confidence": 1.0,
            "source": ["sandbox_runner"],
            "needs_human_review": True,
        }))


class LocalSkillHarness:
    """Explicit local runtime that stages and executes one validated request."""

    def __init__(
        self,
        *,
        skill_dir: Path,
        boundary: RedactionBoundary | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        if boundary is not None and redactor is not None:
            raise ValueError("pass boundary or redactor, not both")
        self.skill_dir = skill_dir
        self.boundary = boundary or RedactionBoundary(redactor=redactor)
        self.redactor = self.boundary.redactor

    def execute_one(
        self,
        *,
        task_id: str,
        review_input: dict[str, Any],
        request: ExecutionRequest,
        policy_context: PolicyContext,
        dry_run: bool,
    ) -> HarnessExecutionResult:
        del policy_context, review_input
        with tempfile.TemporaryDirectory(prefix="skills_code_review_") as tmp:
            workspace_root = Path(tmp)
            workspace_skill = workspace_root / "skills" / "code-review"
            ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "work", "out")
            shutil.copytree(self.skill_dir, workspace_skill, ignore=ignore)
            (workspace_skill / "out").mkdir(parents=True, exist_ok=True)
            input_spec = request.inputs[0]
            source = Path(input_spec.src.removeprefix("host://"))
            destination = workspace_root.joinpath(*PurePosixPath(input_spec.dst).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            run = self._run_request(
                task_id=task_id,
                request=request,
                workspace_root=workspace_root,
                cwd=workspace_skill,
                dry_run=dry_run,
            )
        return HarnessExecutionResult(runs=[run])

    def _collect_outputs(
        self,
        *,
        workspace_root: Path,
        cwd: Path,
        request: ExecutionRequest,
    ) -> tuple[dict[str, str], bool]:
        output_map: dict[str, str] = {}
        output_truncated = False
        max_files = min(request.output_spec.max_files, MAX_OUTPUT_FILES)
        max_file_bytes = min(request.output_spec.max_file_bytes, MAX_OUTPUT_FILE_BYTES)
        for pattern in request.output_spec.globs:
            matches = sorted(workspace_root.glob(pattern)) if "*" in pattern else [workspace_root / pattern]
            for path in matches:
                if not path.is_file():
                    continue
                if len(output_map) >= max_files:
                    output_truncated = True
                    return output_map, output_truncated
                content, truncated = _read_output_file(path, limit=max_file_bytes)
                output_truncated = output_truncated or truncated
                output_map[path.relative_to(cwd).as_posix()] = content
        return output_map, output_truncated

    def _run_request(
        self,
        *,
        task_id: str,
        request: ExecutionRequest,
        workspace_root: Path,
        cwd: Path,
        dry_run: bool,
    ) -> SandboxRun:
        started = time.perf_counter()
        logical_command = list(request.command_argv)
        try:
            result = subprocess.run(
                [sys.executable, *logical_command[1:]],
                cwd=str(cwd),
                check=False,
                capture_output=True,
                text=True,
                timeout=request.timeout_seconds,
                env=_safe_env(workspace_root=workspace_root, request=request),
            )
            timed_out = False
            exit_code = result.returncode
            stdout = result.stdout
            stderr = result.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = -1
            stdout = exc.stdout or ""
            stderr = exc.stderr or "command timed out"
        output_map, file_truncated = self._collect_outputs(
            workspace_root=workspace_root,
            cwd=cwd,
            request=request,
        )
        output_map, output_truncated = _sanitize_output_mapping(
            output_map,
            boundary=self.boundary,
            already_truncated=file_truncated,
            max_files=min(request.output_spec.max_files, MAX_OUTPUT_FILES),
            max_file_bytes=min(request.output_spec.max_file_bytes, MAX_OUTPUT_FILE_BYTES),
        )
        stdout, stdout_truncated = _sanitize_stream(stdout, boundary=self.boundary, limit=MAX_STDOUT_CHARS)
        stderr, stderr_truncated = _sanitize_stream(stderr, boundary=self.boundary, limit=MAX_STDERR_CHARS)
        payload = self.boundary.clean({
            "run_id": "sandbox_" + request.request_id.replace(":", "_"),
            "task_id": task_id,
            "runtime": "local",
            "command": logical_command,
            "decision": "allow",
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_ms": 0 if dry_run else int((time.perf_counter() - started) * 1000),
            "stdout": stdout,
            "stderr": stderr,
            "output_files": output_map,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "output_truncated": output_truncated,
            "warning": "" if exit_code == 0 and not timed_out else "sandbox command failed or timed out",
            "created_at": utc_now(dry_run),
        })
        return SandboxRun.model_validate(payload)


class TrpcSkillToolSetHarness:
    """Container SkillToolSet execution path for one validated request."""

    def __init__(
        self,
        *,
        runtime: str,
        policy: ReviewExecutionPolicy,
        boundary: RedactionBoundary | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        if boundary is not None and redactor is not None:
            raise ValueError("pass boundary or redactor, not both")
        self.runtime = runtime
        self.policy = policy
        self.boundary = boundary or RedactionBoundary(redactor=redactor)
        self.redactor = self.boundary.redactor

    def execute_one(
        self,
        *,
        task_id: str,
        review_input: dict[str, Any],
        request: ExecutionRequest,
        policy_context: PolicyContext,
        dry_run: bool,
    ) -> HarnessExecutionResult:
        del review_input
        return asyncio.run(
            self._execute_one_async(
                task_id=task_id,
                request=request,
                policy_context=policy_context,
                dry_run=dry_run,
            ))

    async def _execute_one_async(
        self,
        *,
        task_id: str,
        request: ExecutionRequest,
        policy_context: PolicyContext,
        dry_run: bool,
    ) -> HarnessExecutionResult:
        from trpc_agent_sdk.abc import AgentABC
        from trpc_agent_sdk.context import InvocationContext
        from trpc_agent_sdk.context import create_agent_context
        from trpc_agent_sdk.context import reset_invocation_ctx
        from trpc_agent_sdk.context import set_invocation_ctx
        from trpc_agent_sdk.sessions import InMemorySessionService

        from .agent_factory import create_skill_tool_set
        from .agent_factory import make_review_before_tool_callback

        before_callback = make_review_before_tool_callback(
            self.policy,
            policy_context,
            {request.command_argv: request},
        )

        class SkillHarnessAgent(AgentABC):
            before_tool_callback: Any = None
            after_tool_callback: Any = None

            def get_subagents(self) -> list[AgentABC]:
                return []

            async def run_async(self, parent_context):  # pragma: no cover - harness only needs tool context
                if False:
                    yield parent_context

        tool_set = create_skill_tool_set(runtime=self.runtime)
        service = InMemorySessionService()
        session = await service.create_session(
            app_name="skills_code_review_agent",
            user_id="dry-run",
            session_id=request.request_id.replace(":", "-"),
        )
        ctx = InvocationContext(
            session_service=service,
            invocation_id=f"invocation-{request.request_id}",
            agent=SkillHarnessAgent(
                name="code_review_skill_harness",
                before_tool_callback=before_callback,
            ),
            agent_context=create_agent_context(),
            session=session,
        )
        token = set_invocation_ctx(ctx)
        try:
            tools = await tool_set.get_tools(ctx)
            run_tool = next(tool for tool in tools if getattr(tool, "name", "") == "skill_run")
            output = await run_tool.run_async(tool_context=ctx, args=request.to_skill_run_args())
            if not isinstance(output, Mapping):
                raise RuntimeError("SDK integrity failure: skill_run returned a non-mapping response")
            output_data = dict(output)
            if output_data.get("blocked"):
                raise RuntimeError("SDK integrity guard blocked skill_run before execution")
            run = self._run_from_skill_output(task_id, request, output_data, dry_run=dry_run)
        finally:
            reset_invocation_ctx(token)
        return HarnessExecutionResult(runs=[run])

    def _run_from_skill_output(
        self,
        task_id: str,
        request: ExecutionRequest,
        output: dict[str, Any],
        *,
        dry_run: bool,
    ) -> SandboxRun:
        output_map: dict[str, str] = {}
        output_truncated = False
        max_files = min(request.output_spec.max_files, MAX_OUTPUT_FILES)
        max_file_bytes = min(request.output_spec.max_file_bytes, MAX_OUTPUT_FILE_BYTES)
        for item in output.get("output_files", []) or []:
            if len(output_map) >= max_files:
                output_truncated = True
                break
            name = str(item.get("name") or "")
            if not name:
                continue
            output_map[name] = str(item.get("content") or "")
            output_truncated = output_truncated or bool(item.get("truncated"))
        output_map, output_truncated = _sanitize_output_mapping(
            output_map,
            boundary=self.boundary,
            already_truncated=output_truncated,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
        )
        stdout, stdout_truncated = _sanitize_stream(
            output.get("stdout") or "",
            boundary=self.boundary,
            limit=MAX_STDOUT_CHARS,
        )
        stderr, stderr_truncated = _sanitize_stream(
            output.get("stderr") or "",
            boundary=self.boundary,
            limit=MAX_STDERR_CHARS,
        )
        warning = "; ".join(self.boundary.text(item).text for item in output.get("warnings", []) or [])
        payload = self.boundary.clean({
            "run_id": "sandbox_" + request.request_id.replace(":", "_"),
            "task_id": task_id,
            "runtime": self.runtime,
            "command": list(request.command_argv),
            "decision": "allow",
            "exit_code": int(output.get("exit_code") or 0),
            "timed_out": bool(output.get("timed_out")),
            "duration_ms": 0 if dry_run else int(output.get("duration_ms") or 0),
            "stdout": stdout,
            "stderr": stderr,
            "output_files": output_map,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "output_truncated": output_truncated,
            "warning": warning,
            "created_at": utc_now(dry_run),
        })
        return SandboxRun.model_validate(payload)


class SandboxRunner:

    def __init__(
        self,
        *,
        example_dir: Path,
        policy: ReviewExecutionPolicy,
        boundary: RedactionBoundary | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        if boundary is not None and redactor is not None:
            raise ValueError("pass boundary or redactor, not both")
        self.example_dir = example_dir
        self.skill_dir = example_dir / "skills" / "code-review"
        self.policy = policy
        self.boundary = boundary or RedactionBoundary(redactor=redactor)
        self.redactor = self.boundary.redactor

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
        if runtime not in {"local", "container", "auto"}:
            raise ValueError(f"unsupported runtime {runtime!r}")
        effective_runtime = "container" if runtime == "auto" else runtime
        if task_id != policy_context.task_id:
            raise ValueError("task_id does not match policy context")
        if effective_runtime != policy_context.runtime:
            raise ValueError("runtime does not match policy context")

        safe_review_input = self.boundary.clean(review_input)
        decisions: list[FilterIntercept] = []
        allowed_requests: list[ExecutionRequest] = []
        for request in requests:
            result = self.policy.evaluate(request, policy_context)
            safe_intercept = FilterIntercept.model_validate(
                self.boundary.clean(result.intercept.model_dump(mode="json")))
            decisions.append(safe_intercept)
            if on_decision is not None:
                on_decision(safe_intercept)
            if result.decision == "allow":
                allowed_requests.append(request)
        if not allowed_requests:
            return SandboxResult([], decisions, [], [], [], effective_runtime)

        warnings: list[ReviewWarning] = []
        needs_human_review: list[ReviewWarning] = []
        runs: list[SandboxRun] = []
        try:
            harness = self._harness_for_runtime(runtime=effective_runtime)
        except Exception as exc:  # pylint: disable=broad-except
            needs_human_review.append(
                _runtime_warning(
                    f"{effective_runtime} runtime failed",
                    f"SkillToolSet harness could not be selected: {self.boundary.text(exc).text}",
                    boundary=self.boundary,
                ))
            harness = None

        if harness is not None:
            for request in sorted(allowed_requests, key=lambda item: item.request_id):
                try:
                    execution = harness.execute_one(
                        task_id=task_id,
                        review_input=safe_review_input,
                        request=request,
                        policy_context=policy_context,
                        dry_run=dry_run,
                    )
                except Exception as exc:  # pylint: disable=broad-except
                    needs_human_review.append(
                        _runtime_warning(
                            f"{effective_runtime} runtime failed",
                            f"SkillToolSet execution did not complete: {self.boundary.text(exc).text}",
                            boundary=self.boundary,
                        ))
                    continue
                for run in execution.runs:
                    safe_run = SandboxRun.model_validate(self.boundary.clean(run.model_dump(mode="json")))
                    runs.append(safe_run)
                    if on_run is not None:
                        on_run(safe_run)

        artifacts = load_sandbox_artifacts(runs, redactor=_BoundaryRedactor(self.boundary))
        for run in runs:
            if (run.exit_code != 0 or run.timed_out) and not _run_has_human_review_artifact(run):
                needs_human_review.append(_failure_warning(run, boundary=self.boundary))
        findings = [
            Finding.model_validate(self.boundary.clean(item.model_dump(mode="json"))) for item in artifacts.findings
        ]
        warnings.extend(
            ReviewWarning.model_validate(self.boundary.clean(item.model_dump(mode="json")))
            for item in artifacts.warnings)
        needs_human_review.extend(
            ReviewWarning.model_validate(self.boundary.clean(item.model_dump(mode="json")))
            for item in artifacts.needs_human_review)
        return SandboxResult(
            runs=runs,
            decisions=decisions,
            findings=findings,
            warnings=warnings,
            needs_human_review=needs_human_review,
            effective_runtime=effective_runtime,
        )

    def _harness_for_runtime(self, *, runtime: str):
        if runtime == "local":
            return LocalSkillHarness(skill_dir=self.skill_dir, boundary=self.boundary)
        try:
            return TrpcSkillToolSetHarness(runtime=runtime, policy=self.policy, boundary=self.boundary)
        except TypeError as exc:
            if "unexpected keyword argument 'boundary'" not in self.boundary.text(exc).text:
                raise
            return TrpcSkillToolSetHarness(
                runtime=runtime,
                policy=self.policy,
                redactor=_BoundaryRedactor(self.boundary),
            )
