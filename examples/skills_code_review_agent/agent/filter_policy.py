# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Policy gate for complete code-review sandbox requests."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .execution_request import ExecutionEnv
from .execution_request import ExecutionInput
from .execution_request import ExecutionOutputSpec
from .execution_request import ExecutionRequest
from .execution_request import PolicyContext
from .models import FilterIntercept
from .models import utc_now

COMMAND_CONTRACTS: dict[tuple[str, ...], str] = {
    (
        "python3",
        "scripts/run_static_review.py",
        "--input",
        "work/inputs/review_input.json",
        "--output",
        "out/findings.json",
    ):
    "skills/code-review/out/findings.json",
    (
        "python3",
        "scripts/secret_scan.py",
        "--input",
        "work/inputs/review_input.json",
        "--output",
        "out/secrets.json",
    ):
    "skills/code-review/out/secrets.json",
    (
        "python3",
        "scripts/smoke_test.py",
        "--input",
        "work/inputs/review_input.json",
        "--output",
        "out/smoke.json",
    ):
    "skills/code-review/out/smoke.json",
}
ALLOWED_ENV = {("PYTHONUNBUFFERED", "1")}
APPROVAL_REQUIRED_PROGRAMS = {"pip", "pip3", "npm", "yarn", "pnpm"}
DECISION_ERROR_KIND = {
    "allow": "",
    "deny": "policy_denied",
    "needs_human_review": "approval_required",
}

_EXPECTED_INPUT_DESTINATION = "skills/code-review/work/inputs/review_input.json"
_PROTECTED_HOST_PATHS = (
    ("etc", ),
    ("root", ),
    ("var", "run", "docker.sock"),
)
_PROTECTED_SKILL_DESTINATIONS = (
    ("skills", "code-review", "scripts"),
    ("skills", "code-review", "SKILL.md"),
)
_SAFE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    intercept: FilterIntercept


def _normalized_relative_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        return None
    normalized = path.as_posix()
    if normalized in {"", "."}:
        return None
    return normalized


def _path_starts_with(parts: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return len(parts) >= len(prefix) and parts[:len(prefix)] == prefix


def _is_protected_input_source(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("host://") or "\\" in value:
        return True
    host_path = PurePosixPath(value.removeprefix("host://"))
    is_windows_absolute = bool(host_path.parts and host_path.parts[0].endswith(":"))
    if ".." in host_path.parts or not (host_path.is_absolute() or is_windows_absolute):
        return True
    lowered = tuple(part.casefold() for part in host_path.parts if part not in {"/", ""})
    if ".ssh" in lowered:
        return True
    return any(_path_starts_with(lowered, prefix) for prefix in _PROTECTED_HOST_PATHS)


def _is_protected_skill_destination(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(_path_starts_with(parts, prefix) for prefix in _PROTECTED_SKILL_DESTINATIONS)


class ReviewExecutionPolicy:
    """Validate an immutable request against its trusted plan context."""

    def __init__(self, *, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    def evaluate(self, request: object, context: PolicyContext) -> PolicyDecision:
        """Return an auditable decision without staging or executing anything."""
        if not isinstance(request, ExecutionRequest):
            return self._decision("deny", "request must be an ExecutionRequest", request, context)
        if not isinstance(request.request_id, str) or not _SAFE_IDENTIFIER_PATTERN.fullmatch(request.request_id):
            return self._decision("deny", "request id is invalid", request, context)
        if not isinstance(request.task_id, str):
            return self._decision("deny", "task id must be a string", request, context)
        if request.task_id != context.task_id:
            return self._decision("deny", "task id does not match trusted context", request, context)
        if not request.request_id.startswith(f"{request.task_id}:"):
            return self._decision("deny", "request id is not scoped to the task", request, context)
        if not isinstance(request.runtime, str):
            return self._decision("deny", "runtime must be a string", request, context)
        if request.runtime != context.runtime:
            return self._decision("deny", "runtime does not match trusted context", request, context)
        if not isinstance(request.skill, str) or request.skill != "code-review":
            return self._decision("deny", "skill must be exactly code-review", request, context)

        if not isinstance(request.cwd, str) or request.cwd != context.allowed_cwd:
            return self._decision("deny", "cwd does not match the allowed skill directory", request, context)
        if not isinstance(request.stdin, str) or request.stdin != "":
            return self._decision("deny", "stdin must be an empty string", request, context)
        if not isinstance(request.editor_text, str) or request.editor_text != "":
            return self._decision("deny", "editor text must be an empty string", request, context)

        if type(request.inputs) is not tuple or len(request.inputs) != 1:
            return self._decision("deny", "request must contain exactly one input", request, context)
        input_spec = request.inputs[0]
        if not isinstance(input_spec, ExecutionInput):
            return self._decision("deny", "input specification is invalid", request, context)
        if not isinstance(input_spec.mode, str) or input_spec.mode != "copy":
            return self._decision("deny", "input mode must be copy", request, context)
        if type(input_spec.pin) is not bool or input_spec.pin is not False:
            return self._decision("deny", "input pin must be false", request, context)
        if _is_protected_input_source(input_spec.src) or input_spec.src not in context.allowed_input_sources:
            return self._decision("deny", "input source is not trusted", request, context)
        normalized_destination = _normalized_relative_path(input_spec.dst)
        if (normalized_destination is None or _is_protected_skill_destination(normalized_destination)
                or normalized_destination != _EXPECTED_INPUT_DESTINATION):
            return self._decision("deny", "input destination is not allowed", request, context)

        if (type(request.legacy_output_files) is not tuple
                or not all(isinstance(item, str) for item in request.legacy_output_files)
                or request.legacy_output_files):
            return self._decision("deny", "legacy output files must be an empty tuple", request, context)
        output = request.output_spec
        if not isinstance(output, ExecutionOutputSpec):
            return self._decision("deny", "output specification is invalid", request, context)
        if type(output.globs) is not tuple or len(output.globs) != 1:
            return self._decision("deny", "request must declare exactly one output", request, context)
        normalized_output = _normalized_relative_path(output.globs[0])
        if normalized_output is None:
            return self._decision("deny", "command output path is unsafe", request, context)
        if type(output.max_files) is not int or output.max_files != 1:
            return self._decision("deny", "output file count must be one", request, context)
        if not self._valid_budget(output.max_file_bytes, context.max_output_bytes):
            return self._decision("deny", "per-file output budget is invalid", request, context)
        if not self._valid_budget(output.max_total_bytes, context.max_output_bytes):
            return self._decision("deny", "total output budget is invalid", request, context)
        if output.max_file_bytes > output.max_total_bytes:
            return self._decision("deny", "per-file output budget exceeds total output budget", request, context)
        if type(output.save) is not bool or output.save is not False:
            return self._decision("deny", "output save must be false", request, context)
        if type(output.inline) is not bool or output.inline is not True:
            return self._decision("deny", "output inline must be true", request, context)
        if not isinstance(output.name_template, str) or output.name_template != "":
            return self._decision("deny", "output name template must be empty", request, context)
        if (type(request.output_budget_bytes) is not int or request.output_budget_bytes != output.max_total_bytes):
            return self._decision(
                "deny",
                "request output budget does not match output specification",
                request,
                context,
            )

        if type(request.env) is not tuple or not all(isinstance(item, ExecutionEnv) for item in request.env):
            return self._decision("deny", "environment contract is invalid", request, context)
        if not all(isinstance(item.name, str) and isinstance(item.value, str) for item in request.env):
            return self._decision("deny", "environment contract is invalid", request, context)
        env_pairs = tuple((item.name, item.value) for item in request.env)
        if len(env_pairs) != len(set(env_pairs)) or not set(env_pairs).issubset(ALLOWED_ENV):
            return self._decision("deny", "environment is outside the allowed contract", request, context)
        if type(request.network_access) is not bool or request.network_access is not False:
            return self._decision("deny", "network access must be disabled", request, context)
        if (type(request.timeout_seconds) is not int
                or not 1 <= request.timeout_seconds <= context.max_timeout_seconds):
            return self._decision("deny", "timeout is outside the allowed range", request, context)
        if type(request.save_as_artifacts) is not bool or request.save_as_artifacts is not False:
            return self._decision("deny", "artifact persistence must be disabled", request, context)
        if type(request.omit_inline_content) is not bool or request.omit_inline_content is not False:
            return self._decision("deny", "inline content must not be omitted", request, context)
        if not isinstance(request.artifact_prefix, str) or request.artifact_prefix != "":
            return self._decision("deny", "artifact prefix must be empty", request, context)

        if (type(request.command_argv) is not tuple or not request.command_argv
                or not all(isinstance(item, str) for item in request.command_argv)):
            return self._decision("deny", "command must be a nonempty string tuple", request, context)
        command = request.command_argv
        bound_output = COMMAND_CONTRACTS.get(command)
        if bound_output is not None:
            if normalized_output != bound_output:
                return self._decision("deny", "command output does not match its bound output", request, context)
            return self._decision("allow", "request matches the complete code-review contract", request, context)
        executable = PurePosixPath(command[0]).name if command else ""
        if executable in APPROVAL_REQUIRED_PROGRAMS:
            return self._decision(
                "needs_human_review",
                "package installation command requires human approval",
                request,
                context,
            )
        return self._decision("deny", "command is outside the code-review contract", request, context)

    @staticmethod
    def _valid_budget(value: object, maximum: int) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= maximum

    def _decision(
        self,
        decision: str,
        reason: str,
        request: object,
        context: PolicyContext,
    ) -> PolicyDecision:
        trusted_task_id = (context.task_id if isinstance(context.task_id, str)
                           and _SAFE_IDENTIFIER_PATTERN.fullmatch(context.task_id) else "")
        trusted_runtime = context.runtime if context.runtime in {"container", "local"} else ""
        raw_task_id = getattr(request, "task_id", None)
        raw_runtime = getattr(request, "runtime", None)
        raw_request_id = getattr(request, "request_id", None)
        raw_command = getattr(request, "command_argv", None)
        command_is_safe = type(raw_command) is tuple and all(
            isinstance(item, str) and len(item) <= 512 and "host://" not in item.casefold() and not any(
                char.isspace() and char not in {" "} for char in item) for item in raw_command)
        identity_is_safe = (isinstance(raw_task_id, str) and bool(_SAFE_IDENTIFIER_PATTERN.fullmatch(raw_task_id))
                            and raw_task_id == trusted_task_id and isinstance(raw_runtime, str)
                            and raw_runtime in {"container", "local"} and raw_runtime == trusted_runtime
                            and isinstance(raw_request_id, str)
                            and bool(_SAFE_IDENTIFIER_PATTERN.fullmatch(raw_request_id))
                            and raw_request_id.startswith(f"{trusted_task_id}:") and command_is_safe)
        if identity_is_safe:
            task_id = raw_task_id
            runtime = raw_runtime
            request_id = raw_request_id
            command = list(raw_command)
        else:
            task_id = trusted_task_id
            runtime = trusted_runtime
            request_id = "invalid-request"
            command = []
        payload = f"{request_id}:{decision}:{reason}:{' '.join(command)}"
        intercept_id = "filter_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        return PolicyDecision(
            decision=decision,
            intercept=FilterIntercept(
                intercept_id=intercept_id,
                task_id=task_id,
                decision=decision,
                reason=reason,
                command=command,
                runtime=runtime,
                metadata={
                    "request_id": request_id,
                    "error_kind": DECISION_ERROR_KIND[decision],
                },
                created_at=utc_now(self.dry_run),
            ),
        )
