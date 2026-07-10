# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Immutable, policy-complete requests for skill sandbox execution."""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from typing import Any
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict

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


class FrozenModel(BaseModel):
    """Pydantic base model that forbids mutation and unknown fields."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class ExecutionInput(FrozenModel):
    """A host input copied into the skill workspace."""

    src: str
    dst: str
    mode: Literal["copy"]
    pin: bool = False


class ExecutionEnv(FrozenModel):
    """One deterministic environment variable."""

    name: str
    value: str


class ExecutionOutputSpec(FrozenModel):
    """Bounded declarative output collection settings."""

    globs: tuple[str, ...] = ()
    max_files: int = 0
    max_file_bytes: int = 0
    max_total_bytes: int = 0
    save: bool = False
    inline: bool = False
    name_template: str = ""


class ExecutionRequest(FrozenModel):
    """A complete skill invocation after mutable SDK arguments are modeled."""

    request_id: str
    task_id: str
    runtime: Literal["container", "local"]
    skill: str
    command_argv: tuple[str, ...]
    cwd: str
    stdin: str
    editor_text: str
    inputs: tuple[ExecutionInput, ...]
    legacy_output_files: tuple[str, ...]
    output_spec: ExecutionOutputSpec
    env: tuple[ExecutionEnv, ...]
    network_access: bool
    timeout_seconds: int
    output_budget_bytes: int
    save_as_artifacts: bool
    omit_inline_content: bool
    artifact_prefix: str

    @classmethod
    def from_skill_run_args(
        cls,
        *,
        request_id: str,
        task_id: str,
        runtime: Literal["container", "local"],
        args: Mapping[str, Any],
    ) -> "ExecutionRequest":
        """Validate and freeze a complete SkillRun argument mapping."""
        unmodeled = sorted(set(args) - MODELED_SKILL_RUN_FIELDS)
        if unmodeled:
            raise ValueError(f"unmodeled SkillRun fields: {', '.join(unmodeled)}")

        output_spec = ExecutionOutputSpec.model_validate(args.get("outputs") or {})
        raw_env = args.get("env")
        if raw_env is None:
            raw_env = {}
        if not isinstance(raw_env, Mapping):
            raise ValueError("SkillRun env must be a mapping")
        env = tuple(
            ExecutionEnv(name=str(name), value=str(value))
            for name, value in sorted(raw_env.items(), key=lambda item: str(item[0])))
        inputs = tuple(ExecutionInput.model_validate(value) for value in (args.get("inputs") or ()))
        command = str(args.get("command") or "")
        try:
            timeout_seconds = int(args.get("timeout") or 0)
        except OverflowError as exc:
            raise ValueError("SkillRun timeout must be finite") from exc

        return cls(
            request_id=request_id,
            task_id=task_id,
            runtime=runtime,
            skill=str(args.get("skill") or ""),
            command_argv=tuple(shlex.split(command, posix=True)),
            cwd=str(args.get("cwd") or ""),
            stdin=str(args.get("stdin") or ""),
            editor_text=str(args.get("editor_text") or ""),
            inputs=inputs,
            legacy_output_files=tuple(str(item) for item in (args.get("output_files") or ())),
            output_spec=output_spec,
            env=env,
            network_access=bool(args.get("network_access", False)),
            timeout_seconds=timeout_seconds,
            output_budget_bytes=output_spec.max_total_bytes,
            save_as_artifacts=bool(args.get("save_as_artifacts", False)),
            omit_inline_content=bool(args.get("omit_inline_content", False)),
            artifact_prefix=str(args.get("artifact_prefix") or ""),
        )

    def to_skill_run_args(self) -> dict[str, Any]:
        """Return the complete canonical SkillRun argument mapping."""
        return {
            "skill": self.skill,
            "command": shlex.join(self.command_argv),
            "cwd": self.cwd,
            "env": {
                item.name: item.value
                for item in self.env
            },
            "stdin": self.stdin,
            "editor_text": self.editor_text,
            "output_files": list(self.legacy_output_files),
            "timeout": self.timeout_seconds,
            "save_as_artifacts": self.save_as_artifacts,
            "omit_inline_content": self.omit_inline_content,
            "artifact_prefix": self.artifact_prefix,
            "inputs": [item.model_dump(mode="json") for item in self.inputs],
            "outputs": self.output_spec.model_dump(mode="json"),
            "network_access": self.network_access,
        }


class PolicyContext(FrozenModel):
    """Trusted policy limits associated with an execution plan."""

    task_id: str
    runtime: Literal["container", "local"]
    allowed_input_sources: frozenset[str]
    allowed_cwd: str = "$SKILLS_DIR/code-review"
    max_timeout_seconds: int = 60
    max_output_bytes: int = 256 * 1024


class ExecutionPlan(FrozenModel):
    """Immutable requests and their trusted policy context."""

    requests: tuple[ExecutionRequest, ...]
    policy_context: PolicyContext
