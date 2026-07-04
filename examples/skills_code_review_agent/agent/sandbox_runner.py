# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Sandbox execution wrapper used by the example review orchestrator."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .filter_policy import ALLOWED_SKILL_COMMANDS
from .filter_policy import ReviewExecutionPolicy
from .models import FilterIntercept
from .models import ReviewWarning
from .models import SandboxRun
from .models import utc_now
from .secret_redactor import SecretRedactor


DEFAULT_OUTPUTS = {
    "scripts/run_static_review.py": ["out/findings.json"],
    "scripts/secret_scan.py": ["out/secrets.json"],
    "scripts/smoke_test.py": ["out/smoke.json"],
}


@dataclass
class SandboxResult:
    runs: list[SandboxRun]
    intercepts: list[FilterIntercept]
    warnings: list[ReviewWarning]
    effective_runtime: str


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
        logical_commands = commands or [list(command) for command in ALLOWED_SKILL_COMMANDS]
        intercepts: list[FilterIntercept] = []
        warnings: list[ReviewWarning] = []
        effective_runtime = runtime
        if runtime == "auto":
            if dry_run or os.environ.get("CI"):
                effective_runtime = "local"
                intercepts.append(self.policy.runtime_fallback(task_id=task_id, from_runtime="container", to_runtime="local"))
                warnings.append(
                    ReviewWarning(
                        category="sandbox",
                        title="container runtime fell back to local",
                        message="Dry-run/CI used the explicit local development runtime instead of requiring Docker.",
                        confidence=1.0,
                        source=["sandbox_runner"],
                        needs_human_review=True,
                    )
                )
            else:
                effective_runtime = "container"
        if effective_runtime not in {"local", "container", "cube"}:
            raise ValueError(f"unsupported runtime {runtime!r}")
        if effective_runtime != "local":
            warning = ReviewWarning(
                category="sandbox",
                title=f"{effective_runtime} runtime not executed by local dry-run harness",
                message="This example wires SkillToolSet for container execution; unit tests use the explicit local fallback.",
                confidence=1.0,
                source=["sandbox_runner"],
                needs_human_review=True,
            )
            return SandboxResult([], intercepts, [*warnings, warning], effective_runtime)

        with tempfile.TemporaryDirectory(prefix="skills_code_review_") as tmp:
            workspace_skill = Path(tmp) / "code-review"
            ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "work", "out")
            shutil.copytree(self.skill_dir, workspace_skill, ignore=ignore)
            (workspace_skill / "work" / "inputs").mkdir(parents=True, exist_ok=True)
            (workspace_skill / "out").mkdir(parents=True, exist_ok=True)
            input_path = workspace_skill / "work" / "inputs" / "review_input.json"
            input_path.write_text(json.dumps(review_input, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")
            runs: list[SandboxRun] = []
            for index, command in enumerate(logical_commands, start=1):
                output_files = DEFAULT_OUTPUTS.get(command[1], ["out/*.json"] if len(command) > 1 else [])
                decision = self.policy.evaluate(command=command, runtime=effective_runtime, output_files=output_files, timeout=30)
                intercept = decision.intercept.model_copy(update={"task_id": task_id})
                if decision.decision in {"deny", "needs_human_review"}:
                    intercepts.append(intercept)
                    continue
                runs.append(
                    self._run_local_command(
                        task_id=task_id,
                        run_index=index,
                        logical_command=command,
                        output_files=output_files,
                        cwd=workspace_skill,
                        dry_run=dry_run,
                    )
                )
        for run in runs:
            if run.exit_code != 0 or run.timed_out:
                warnings.append(
                    ReviewWarning(
                        category="sandbox",
                        title="sandbox command failed",
                        message=f"{' '.join(run.command)} exited with {run.exit_code}: {run.stderr or run.stdout}",
                        confidence=1.0,
                        source=["sandbox_runner"],
                        needs_human_review=True,
                    )
                )
        return SandboxResult(runs, intercepts, warnings, effective_runtime)

    def _run_local_command(
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
        output_map: dict[str, str] = {}
        for rel_path in output_files:
            path = cwd / rel_path
            if path.is_file():
                output_map[rel_path] = path.read_text(encoding="utf-8", errors="replace")
        redacted_outputs, _ = self.redactor.redact_mapping(output_map)
        run_id = f"sandbox_{task_id}_{run_index}"
        return SandboxRun(
            run_id=run_id,
            task_id=task_id,
            runtime="local",
            command=logical_command,
            decision="allow",
            exit_code=exit_code,
            timed_out=timed_out,
            duration_ms=0 if dry_run else int((time.perf_counter() - started) * 1000),
            stdout=self.redactor.redact_text(stdout).text,
            stderr=self.redactor.redact_text(stderr).text,
            output_files=redacted_outputs,
            warning="" if exit_code == 0 and not timed_out else "sandbox command failed or timed out",
            created_at=utc_now(dry_run),
        )

