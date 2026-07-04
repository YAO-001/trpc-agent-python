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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .filter_policy import ALLOWED_SKILL_COMMANDS
from .filter_policy import ReviewExecutionPolicy
from .models import FilterIntercept
from .models import Finding
from .models import ReviewWarning
from .models import SandboxRun
from .models import utc_now
from .sandbox_artifact_loader import load_sandbox_artifacts
from .secret_redactor import SecretRedactor


DEFAULT_OUTPUTS = {
    "scripts/run_static_review.py": ["out/findings.json"],
    "scripts/secret_scan.py": ["out/secrets.json"],
    "scripts/smoke_test.py": ["out/smoke.json"],
}
MAX_STDOUT_CHARS = 12000
MAX_STDERR_CHARS = 12000
MAX_OUTPUT_FILE_BYTES = 256 * 1024
MAX_OUTPUT_FILES = 16
SAFE_ENV_KEYS = {
    "PATH",
    "Path",
    "PATHEXT",
    "SYSTEMROOT",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "PYTHONIOENCODING",
    "PYTHONUNBUFFERED",
}


@dataclass(frozen=True)
class HarnessExecutionResult:
    runs: list[SandboxRun]


@dataclass
class SandboxResult:
    runs: list[SandboxRun]
    intercepts: list[FilterIntercept]
    findings: list[Finding]
    warnings: list[ReviewWarning]
    needs_human_review: list[ReviewWarning]
    effective_runtime: str


def _output_files_for_command(command: list[str]) -> list[str]:
    if len(command) > 1:
        return DEFAULT_OUTPUTS.get(command[1], ["out/*.json"])
    return []


def _safe_env() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key in SAFE_ENV_KEYS}
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUNBUFFERED", "1")
    return env


def _truncate_text(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    marker = f"\n[TRUNCATED: kept first {limit} chars]\n"
    return text[:limit] + marker, True


def _normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _read_output_file(path: Path) -> tuple[str, bool]:
    raw = path.read_bytes()
    truncated = len(raw) > MAX_OUTPUT_FILE_BYTES
    if truncated:
        raw = raw[:MAX_OUTPUT_FILE_BYTES]
    text = raw.decode("utf-8", errors="replace")
    if truncated:
        text += f"\n[TRUNCATED: kept first {MAX_OUTPUT_FILE_BYTES} bytes]\n"
    return text, truncated


def _sanitize_stream(text: str, *, redactor: SecretRedactor, limit: int) -> tuple[str, bool]:
    redacted = redactor.redact_text(_normalize_newlines(text)).text
    return _truncate_text(redacted, limit)


def _sanitize_output_mapping(
    output_map: dict[str, str],
    *,
    redactor: SecretRedactor,
    already_truncated: bool,
) -> tuple[dict[str, str], bool]:
    limited: dict[str, str] = {}
    output_truncated = already_truncated
    for index, (name, content) in enumerate(sorted(output_map.items())):
        if index >= MAX_OUTPUT_FILES:
            output_truncated = True
            break
        redacted = redactor.redact_text(_normalize_newlines(content)).text
        truncated_content, was_truncated = _truncate_text(redacted, MAX_OUTPUT_FILE_BYTES)
        output_truncated = output_truncated or was_truncated
        limited[name] = truncated_content
    return limited, output_truncated


def _failure_warning(run: SandboxRun) -> ReviewWarning:
    message = run.stderr or run.stdout or run.warning or "sandbox command failed or timed out"
    return ReviewWarning(
        category="sandbox",
        title="sandbox command failed",
        message=f"{' '.join(run.command)} exited with {run.exit_code}: {message}",
        confidence=1.0,
        source=["sandbox_runner"],
        needs_human_review=True,
    )


def _runtime_warning(title: str, message: str) -> ReviewWarning:
    return ReviewWarning(
        category="sandbox",
        title=title,
        message=message,
        confidence=1.0,
        source=["sandbox_runner"],
        needs_human_review=True,
    )


class LocalSkillHarness:
    """Explicit development fallback that stages the Skill and runs allowlisted scripts locally."""

    def __init__(self, *, skill_dir: Path, redactor: SecretRedactor) -> None:
        self.skill_dir = skill_dir
        self.redactor = redactor

    def execute(
        self,
        *,
        task_id: str,
        review_input: dict[str, Any],
        commands: list[list[str]],
        dry_run: bool,
    ) -> HarnessExecutionResult:
        with tempfile.TemporaryDirectory(prefix="skills_code_review_") as tmp:
            workspace_skill = Path(tmp) / "code-review"
            ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "work", "out")
            shutil.copytree(self.skill_dir, workspace_skill, ignore=ignore)
            (workspace_skill / "work" / "inputs").mkdir(parents=True, exist_ok=True)
            (workspace_skill / "out").mkdir(parents=True, exist_ok=True)
            input_path = workspace_skill / "work" / "inputs" / "review_input.json"
            input_path.write_text(json.dumps(review_input, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")
            runs = [
                self._run_command(
                    task_id=task_id,
                    run_index=index,
                    logical_command=command,
                    output_files=_output_files_for_command(command),
                    cwd=workspace_skill,
                    dry_run=dry_run,
                )
                for index, command in enumerate(commands, start=1)
            ]
        return HarnessExecutionResult(runs=runs)

    def _collect_outputs(self, *, cwd: Path, output_files: list[str]) -> tuple[dict[str, str], bool]:
        output_map: dict[str, str] = {}
        output_truncated = False
        for pattern in output_files:
            matches = sorted(cwd.glob(pattern)) if "*" in pattern else [cwd / pattern]
            for path in matches:
                if not path.is_file():
                    continue
                if len(output_map) >= MAX_OUTPUT_FILES:
                    output_truncated = True
                    return output_map, output_truncated
                content, truncated = _read_output_file(path)
                output_truncated = output_truncated or truncated
                output_map[path.relative_to(cwd).as_posix()] = content
        return output_map, output_truncated

    def _run_command(
        self,
        *,
        task_id: str,
        run_index: int,
        logical_command: list[str],
        output_files: list[str],
        cwd: Path,
        dry_run: bool,
    ) -> SandboxRun:
        started = time.perf_counter()
        try:
            result = subprocess.run(
                [sys.executable, *logical_command[1:]],
                cwd=str(cwd),
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
                env=_safe_env(),
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
        output_map, file_truncated = self._collect_outputs(cwd=cwd, output_files=output_files)
        output_map, output_truncated = _sanitize_output_mapping(
            output_map,
            redactor=self.redactor,
            already_truncated=file_truncated,
        )
        stdout, stdout_truncated = _sanitize_stream(stdout, redactor=self.redactor, limit=MAX_STDOUT_CHARS)
        stderr, stderr_truncated = _sanitize_stream(stderr, redactor=self.redactor, limit=MAX_STDERR_CHARS)
        return SandboxRun(
            run_id=f"sandbox_{task_id}_{run_index}",
            task_id=task_id,
            runtime="local",
            command=logical_command,
            decision="allow",
            exit_code=exit_code,
            timed_out=timed_out,
            duration_ms=0 if dry_run else int((time.perf_counter() - started) * 1000),
            stdout=stdout,
            stderr=stderr,
            output_files=output_map,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            output_truncated=output_truncated,
            warning="" if exit_code == 0 and not timed_out else "sandbox command failed or timed out",
            created_at=utc_now(dry_run),
        )


class TrpcSkillToolSetHarness:
    """Container SkillToolSet execution path used outside the explicit local fallback."""

    def __init__(self, *, runtime: str, redactor: SecretRedactor) -> None:
        self.runtime = runtime
        self.redactor = redactor

    def execute(
        self,
        *,
        task_id: str,
        review_input: dict[str, Any],
        commands: list[list[str]],
        dry_run: bool,
    ) -> HarnessExecutionResult:
        return asyncio.run(
            self._execute_async(task_id=task_id, review_input=review_input, commands=commands, dry_run=dry_run)
        )

    async def _execute_async(
        self,
        *,
        task_id: str,
        review_input: dict[str, Any],
        commands: list[list[str]],
        dry_run: bool,
    ) -> HarnessExecutionResult:
        from trpc_agent_sdk.abc import AgentABC
        from trpc_agent_sdk.context import InvocationContext
        from trpc_agent_sdk.context import create_agent_context
        from trpc_agent_sdk.context import reset_invocation_ctx
        from trpc_agent_sdk.context import set_invocation_ctx
        from trpc_agent_sdk.sessions import InMemorySessionService

        from .agent_factory import build_skill_run_calls
        from .agent_factory import create_skill_tool_set
        from .agent_factory import review_before_tool_callback

        class SkillHarnessAgent(AgentABC):
            before_tool_callback: Any = review_before_tool_callback
            after_tool_callback: Any = None

            def get_subagents(self) -> list[AgentABC]:
                return []

            async def run_async(self, parent_context):  # pragma: no cover - harness only needs tool context
                if False:
                    yield parent_context

        with tempfile.TemporaryDirectory(prefix="skills_code_review_input_") as tmp:
            input_path = Path(tmp) / "review_input.json"
            input_path.write_text(json.dumps(review_input, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")
            tool_set = create_skill_tool_set(runtime=self.runtime)
            calls_by_command = {call["command"]: call for call in build_skill_run_calls(str(input_path))}
            service = InMemorySessionService()
            session = await service.create_session(app_name="skills_code_review_agent", user_id="dry-run", session_id=task_id)
            ctx = InvocationContext(
                session_service=service,
                invocation_id=f"invocation-{task_id}",
                agent=SkillHarnessAgent(name="code_review_skill_harness"),
                agent_context=create_agent_context(),
                session=session,
            )
            token = set_invocation_ctx(ctx)
            try:
                tools = await tool_set.get_tools(ctx)
                run_tool = next(tool for tool in tools if getattr(tool, "name", "") == "skill_run")
                runs: list[SandboxRun] = []
                for index, command in enumerate(commands, start=1):
                    call = calls_by_command.get(" ".join(command))
                    if not call:
                        continue
                    output = await run_tool.run_async(tool_context=ctx, args=call)
                    runs.append(self._run_from_skill_output(task_id, index, command, output, dry_run=dry_run))
            finally:
                reset_invocation_ctx(token)
        return HarnessExecutionResult(runs=runs)

    def _run_from_skill_output(
        self,
        task_id: str,
        run_index: int,
        command: list[str],
        output: dict[str, Any],
        *,
        dry_run: bool,
    ) -> SandboxRun:
        output_map: dict[str, str] = {}
        output_truncated = False
        for item in output.get("output_files", []) or []:
            if len(output_map) >= MAX_OUTPUT_FILES:
                output_truncated = True
                break
            name = str(item.get("name") or "")
            if not name:
                continue
            output_map[name] = str(item.get("content") or "")
            output_truncated = output_truncated or bool(item.get("truncated"))
        output_map, output_truncated = _sanitize_output_mapping(
            output_map,
            redactor=self.redactor,
            already_truncated=output_truncated,
        )
        stdout, stdout_truncated = _sanitize_stream(
            str(output.get("stdout") or ""),
            redactor=self.redactor,
            limit=MAX_STDOUT_CHARS,
        )
        stderr, stderr_truncated = _sanitize_stream(
            str(output.get("stderr") or ""),
            redactor=self.redactor,
            limit=MAX_STDERR_CHARS,
        )
        warning = "; ".join(str(item) for item in output.get("warnings", []) or [])
        return SandboxRun(
            run_id=f"sandbox_{task_id}_{run_index}",
            task_id=task_id,
            runtime=self.runtime,
            command=command,
            decision="allow",
            exit_code=int(output.get("exit_code") or 0),
            timed_out=bool(output.get("timed_out")),
            duration_ms=0 if dry_run else int(output.get("duration_ms") or 0),
            stdout=stdout,
            stderr=stderr,
            output_files=output_map,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            output_truncated=output_truncated,
            warning=warning,
            created_at=utc_now(dry_run),
        )


class SandboxRunner:
    def __init__(self, *, example_dir: Path, policy: ReviewExecutionPolicy, redactor: SecretRedactor) -> None:
        self.example_dir = example_dir
        self.skill_dir = example_dir / "skills" / "code-review"
        self.policy = policy
        self.redactor = redactor

    def run(
        self,
        *,
        task_id: str,
        review_input: dict,
        runtime: str,
        dry_run: bool,
        commands: list[list[str]] | None = None,
    ) -> SandboxResult:
        if runtime not in {"local", "container", "auto", "cube"}:
            raise ValueError(f"unsupported runtime {runtime!r}")
        effective_runtime = "container" if runtime == "auto" else runtime
        logical_commands = commands or [list(command) for command in ALLOWED_SKILL_COMMANDS]
        intercepts: list[FilterIntercept] = []
        allowed_commands: list[list[str]] = []
        for command in logical_commands:
            output_files = _output_files_for_command(command)
            decision = self.policy.evaluate(
                command=command,
                runtime=effective_runtime,
                output_files=output_files,
                timeout=30,
            )
            intercept = decision.intercept.model_copy(update={"task_id": task_id})
            if decision.decision in {"deny", "needs_human_review"}:
                intercepts.append(intercept)
                continue
            allowed_commands.append(command)
        if not allowed_commands:
            return SandboxResult([], intercepts, [], [], [], effective_runtime)

        warnings: list[ReviewWarning] = []
        needs_human_review: list[ReviewWarning] = []
        runs: list[SandboxRun] = []
        try:
            runs = self._execute_harness(
                task_id=task_id,
                review_input=review_input,
                runtime=effective_runtime,
                commands=allowed_commands,
                dry_run=dry_run,
            ).runs
        except Exception as exc:  # pylint: disable=broad-except
            if runtime == "auto":
                intercepts.append(self.policy.runtime_fallback(task_id=task_id, from_runtime="container", to_runtime="local"))
                needs_human_review.append(
                    _runtime_warning(
                        "container runtime fell back to local",
                        f"Container SkillToolSet execution failed and auto runtime used local fallback: {exc}",
                    )
                )
                effective_runtime = "local"
                runs = self._execute_harness(
                    task_id=task_id,
                    review_input=review_input,
                    runtime=effective_runtime,
                    commands=allowed_commands,
                    dry_run=dry_run,
                ).runs
            else:
                needs_human_review.append(
                    _runtime_warning(
                        f"{effective_runtime} runtime failed",
                        f"SkillToolSet execution did not complete: {exc}",
                    )
                )

        for run in runs:
            if run.exit_code != 0 or run.timed_out:
                needs_human_review.append(_failure_warning(run))
        artifacts = load_sandbox_artifacts(runs)
        warnings.extend(artifacts.warnings)
        needs_human_review.extend(artifacts.needs_human_review)
        return SandboxResult(
            runs=runs,
            intercepts=intercepts,
            findings=artifacts.findings,
            warnings=warnings,
            needs_human_review=needs_human_review,
            effective_runtime=effective_runtime,
        )

    def _execute_harness(
        self,
        *,
        task_id: str,
        review_input: dict,
        runtime: str,
        commands: list[list[str]],
        dry_run: bool,
    ) -> HarnessExecutionResult:
        if runtime == "local":
            return LocalSkillHarness(skill_dir=self.skill_dir, redactor=self.redactor).execute(
                task_id=task_id,
                review_input=review_input,
                commands=commands,
                dry_run=dry_run,
            )
        return TrpcSkillToolSetHarness(runtime=runtime, redactor=self.redactor).execute(
            task_id=task_id,
            review_input=review_input,
            commands=commands,
            dry_run=dry_run,
        )
