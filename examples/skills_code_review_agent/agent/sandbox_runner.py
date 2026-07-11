# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Sandbox execution wrapper used by the example review orchestrator."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any
from typing import Callable

from .execution_request import ExecutionRequest
from .execution_request import PolicyContext
from .filter_policy import ReviewExecutionPolicy
from .models import FilterIntercept
from .models import ReviewWarning
from .models import SandboxRun
from .models import utc_now
from .redaction_boundary import RedactionBoundary
from .result_normalizer import PreparedCandidates
from .result_normalizer import ResultNormalizer
from .result_normalizer import ReviewCandidates
from .result_normalizer import merge_prepared_candidates
from .sandbox_artifact_loader import load_sandbox_artifacts
from .secret_redactor import SecretRedactor

MAX_STDOUT_CHARS = 12000
MAX_STDERR_CHARS = 12000
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


@dataclass
class SandboxResult:
    runs: list[SandboxRun]
    decisions: list[FilterIntercept]
    candidates: PreparedCandidates
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


def _safe_env(*, request: ExecutionRequest) -> dict[str, str]:
    env = _inherited_platform_env(os.environ, platform_name=os.name)
    env.update({item.name: item.value for item in request.env})
    return env


def _truncate_text(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    marker = f"\n[TRUNCATED: kept first {limit} chars]\n"
    return text[:limit] + marker, True


def _truncate_utf8_bytes(text: str, limit: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    if limit <= 0:
        return "", True
    return encoded[:limit].decode("utf-8", errors="ignore"), True


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
    max_total_bytes: int,
) -> tuple[dict[str, str], bool]:
    output_truncated = already_truncated
    sorted_items = sorted(output_map.items())
    selected_items = sorted_items[:max(0, max_files)]
    output_truncated = output_truncated or len(selected_items) < len(sorted_items)
    cleaned = boundary.clean(dict(selected_items))
    limited: dict[str, str] = {}
    remaining_bytes = max(0, max_total_bytes)
    for safe_name, content in cleaned.items():
        if remaining_bytes <= 0:
            output_truncated = True
            break
        redacted = _normalize_newlines(content)
        file_budget = min(max(0, max_file_bytes), remaining_bytes)
        truncated_content, was_truncated = _truncate_utf8_bytes(redacted, file_budget)
        output_truncated = output_truncated or was_truncated
        if redacted and not truncated_content:
            break
        limited[safe_name] = truncated_content
        remaining_bytes -= len(truncated_content.encode("utf-8"))
    output_truncated = output_truncated or len(limited) < len(cleaned)
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


def _policy_warning(intercept: FilterIntercept, *, boundary: RedactionBoundary) -> ReviewWarning:
    needs_review = intercept.decision == "needs_human_review"
    title = ("sandbox request requires policy approval" if needs_review else "sandbox request denied by policy")
    return ReviewWarning.model_validate(
        boundary.clean({
            "category": "sandbox",
            "title": title,
            "message": intercept.reason,
            "confidence": 1.0,
            "source": ["review_execution_policy"],
            "needs_human_review": needs_review,
        }))


def _failure_run(
    request: ExecutionRequest,
    exc: object,
    *,
    failure_kind: str,
    dry_run: bool,
    boundary: RedactionBoundary,
) -> SandboxRun:
    payload = boundary.clean({
        "run_id":
        "sandbox_" + hashlib.sha256(f"{request.task_id}:{request.request_id}".encode("utf-8")).hexdigest()[:24],
        "task_id":
        request.task_id,
        "request_id":
        request.request_id,
        "runtime":
        request.runtime,
        "command":
        list(request.command_argv),
        "decision":
        "allow",
        "exit_code":
        -1,
        "failure_kind":
        failure_kind,
        "failure_reason":
        boundary.text(exc).text,
        "warning":
        "sandbox runtime failed before command start",
        "created_at":
        utc_now(dry_run),
    })
    return SandboxRun.model_validate(payload)


def _validated_returned_run(
    value: object,
    request: ExecutionRequest,
    *,
    boundary: RedactionBoundary,
) -> SandboxRun:
    if not isinstance(value, SandboxRun):
        raise TypeError("sandbox harness must return one SandboxRun")
    expected_identity = (
        request.task_id,
        request.request_id,
        request.runtime,
        "allow",
    )
    actual_identity = (
        value.task_id,
        value.request_id,
        value.runtime,
        value.decision,
    )
    if actual_identity != expected_identity:
        raise ValueError("sandbox returned mismatched run identity")
    payload = value.model_dump(mode="json")
    payload["failure_reason"] = ""
    if value.timed_out:
        payload["failure_kind"] = "execution_timeout"
    elif value.exit_code != 0:
        payload["failure_kind"] = "execution_nonzero"
    else:
        payload["failure_kind"] = ""
    cleaned = boundary.clean(payload)
    json.dumps(cleaned, ensure_ascii=False).encode("utf-8")
    return SandboxRun.model_validate(cleaned)


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
    ) -> SandboxRun:
        del policy_context, review_input
        if task_id != request.task_id:
            raise ValueError("task_id does not match execution request")
        with tempfile.TemporaryDirectory(prefix="skills_code_review_") as tmp:
            workspace_root = Path(tmp)
            workspace_skill = workspace_root / "skills" / "code-review"
            ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "work", "out")
            shutil.copytree(self.skill_dir, workspace_skill, ignore=ignore)
            (workspace_skill / "out").mkdir(parents=True, exist_ok=True)
            for input_spec in request.inputs:
                source = Path(input_spec.src.removeprefix("host://"))
                destination = workspace_root.joinpath(*PurePosixPath(input_spec.dst).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            logical_cwd = request.cwd.removeprefix("$SKILLS_DIR/")
            cwd = workspace_root / "skills" / logical_cwd
            run = self._run_request(
                request=request,
                workspace_root=workspace_root,
                cwd=cwd,
                dry_run=dry_run,
            )
        return run

    def _collect_outputs(
        self,
        *,
        workspace_root: Path,
        cwd: Path,
        request: ExecutionRequest,
    ) -> tuple[dict[str, str], bool]:
        output_map: dict[str, str] = {}
        output_truncated = False
        max_files = request.output_spec.max_files
        max_file_bytes = request.output_spec.max_file_bytes
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
        request: ExecutionRequest,
        workspace_root: Path,
        cwd: Path,
        dry_run: bool,
    ) -> SandboxRun:
        started = time.perf_counter()
        logical_command = list(request.command_argv)
        host_command = list(logical_command)
        if host_command[0] == "python3":
            host_command[0] = sys.executable
        try:
            result = subprocess.run(
                host_command,
                cwd=str(cwd),
                check=False,
                capture_output=True,
                text=True,
                input=request.stdin,
                timeout=request.timeout_seconds,
                env=_safe_env(request=request),
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
            max_files=request.output_spec.max_files,
            max_file_bytes=request.output_spec.max_file_bytes,
            max_total_bytes=min(request.output_budget_bytes, request.output_spec.max_total_bytes),
        )
        stdout, stdout_truncated = _sanitize_stream(stdout, boundary=self.boundary, limit=MAX_STDOUT_CHARS)
        stderr, stderr_truncated = _sanitize_stream(stderr, boundary=self.boundary, limit=MAX_STDERR_CHARS)
        payload = self.boundary.clean({
            "run_id": "sandbox_" + request.request_id.replace(":", "_"),
            "task_id": request.task_id,
            "request_id": request.request_id,
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
    ) -> SandboxRun:
        del review_input
        if task_id != request.task_id:
            raise ValueError("task_id does not match execution request")
        return asyncio.run(self._execute_one_async(
            request=request,
            policy_context=policy_context,
            dry_run=dry_run,
        ))

    async def _execute_one_async(
        self,
        *,
        request: ExecutionRequest,
        policy_context: PolicyContext,
        dry_run: bool,
    ) -> SandboxRun:
        from trpc_agent_sdk.abc import AgentABC
        from trpc_agent_sdk.context import InvocationContext
        from trpc_agent_sdk.context import create_agent_context
        from trpc_agent_sdk.context import reset_invocation_ctx
        from trpc_agent_sdk.context import set_invocation_ctx
        from trpc_agent_sdk.sessions import InMemorySessionService

        from .agent_factory import create_skill_tool_set
        from .agent_factory import make_review_before_tool_callback

        canonical_args = request.to_skill_run_args()
        before_callback = make_review_before_tool_callback(
            self.policy,
            policy_context,
            {request.command_argv: request},
            canonical_args_by_command={request.command_argv: canonical_args},
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
            output = await run_tool.run_async(tool_context=ctx, args=canonical_args)
            if not isinstance(output, Mapping):
                raise RuntimeError("SDK integrity failure: skill_run returned a non-mapping response")
            output_data = dict(output)
            if output_data.get("blocked"):
                raise RuntimeError("SDK integrity guard blocked skill_run before execution")
            run = self._run_from_skill_output(request, output_data, dry_run=dry_run)
        finally:
            reset_invocation_ctx(token)
        return run

    def _run_from_skill_output(
        self,
        request: ExecutionRequest,
        output: dict[str, Any],
        *,
        dry_run: bool,
    ) -> SandboxRun:
        output_map: dict[str, str] = {}
        output_truncated = False
        max_files = request.output_spec.max_files
        max_file_bytes = request.output_spec.max_file_bytes
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
            max_total_bytes=min(request.output_budget_bytes, request.output_spec.max_total_bytes),
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
            "task_id": request.task_id,
            "request_id": request.request_id,
            "runtime": request.runtime,
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
        requests: Sequence[ExecutionRequest],
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
        warnings: list[ReviewWarning] = []
        needs_human_review: list[ReviewWarning] = []
        normalizer = ResultNormalizer(self.boundary)
        for request in requests:
            result = self.policy.evaluate(request, policy_context)
            safe_intercept = FilterIntercept.model_validate(
                self.boundary.clean(result.intercept.model_dump(mode="json")))
            decisions.append(safe_intercept)
            if on_decision is not None:
                on_decision(safe_intercept)
            if result.decision == "allow":
                allowed_requests.append(request)
            else:
                warning = _policy_warning(safe_intercept, boundary=self.boundary)
                if result.decision == "needs_human_review":
                    needs_human_review.append(warning)
                else:
                    warnings.append(warning)
        if not allowed_requests:
            return SandboxResult(
                runs=[],
                decisions=decisions,
                candidates=normalizer.prepare(
                    ReviewCandidates(
                        warnings=warnings,
                        needs_human_review=needs_human_review,
                    )),
                effective_runtime=effective_runtime,
            )

        runs: list[SandboxRun] = []
        prepared_batches: list[PreparedCandidates] = []

        def complete_run(run: SandboxRun) -> None:
            artifacts = load_sandbox_artifacts([run], redactor=_BoundaryRedactor(self.boundary))
            prepared = normalizer.prepare(artifacts.candidates)
            invalid_run_ids = {*artifacts.invalid_run_ids, *prepared.invalid_run_ids}
            if run.run_id in invalid_run_ids:
                payload = run.model_dump(mode="json")
                payload.update({
                    "failure_kind": "artifact_invalid",
                    "failure_reason": "sandbox output artifact failed schema validation",
                })
                run = SandboxRun.model_validate(self.boundary.clean(payload))
            if (run.exit_code != 0 or run.timed_out) and not prepared.needs_human_review:
                needs_human_review.append(_failure_warning(run, boundary=self.boundary))
            runs.append(run)
            prepared_batches.append(prepared)
            if on_run is not None:
                on_run(run)

        ordered_requests = sorted(allowed_requests, key=lambda item: item.request_id)
        try:
            harness = self._harness_for_runtime(runtime=effective_runtime)
        except Exception as exc:  # pylint: disable=broad-except
            needs_human_review.append(
                _runtime_warning(
                    f"{effective_runtime} runtime failed",
                    f"SkillToolSet harness could not be selected: {self.boundary.text(exc).text}",
                    boundary=self.boundary,
                ))
            for request in ordered_requests:
                failed_run = _failure_run(
                    request,
                    exc,
                    failure_kind="runtime_unavailable",
                    dry_run=dry_run,
                    boundary=self.boundary,
                )
                complete_run(failed_run)
        else:
            for request in ordered_requests:
                try:
                    returned_run = harness.execute_one(
                        task_id=task_id,
                        review_input=safe_review_input,
                        request=request,
                        policy_context=policy_context,
                        dry_run=dry_run,
                    )
                    safe_run = _validated_returned_run(
                        returned_run,
                        request,
                        boundary=self.boundary,
                    )
                except Exception as exc:  # pylint: disable=broad-except
                    needs_human_review.append(
                        _runtime_warning(
                            f"{effective_runtime} runtime failed",
                            f"SkillToolSet execution did not complete: {self.boundary.text(exc).text}",
                            boundary=self.boundary,
                        ))
                    safe_run = _failure_run(
                        request,
                        exc,
                        failure_kind="orchestration_error",
                        dry_run=dry_run,
                        boundary=self.boundary,
                    )
                complete_run(safe_run)

        prepared_batches.append(
            normalizer.prepare(ReviewCandidates(
                warnings=warnings,
                needs_human_review=needs_human_review,
            )))
        return SandboxResult(
            runs=runs,
            decisions=decisions,
            candidates=merge_prepared_candidates(*prepared_batches),
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
