# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Filter-style policy enforced before sandbox execution."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass

from .models import FilterIntercept
from .models import utc_now


ALLOWED_SKILL_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("python3", "scripts/run_static_review.py", "--input", "work/inputs/review_input.json", "--output", "out/findings.json"),
    ("python3", "scripts/secret_scan.py", "--input", "work/inputs/review_input.json", "--output", "out/secrets.json"),
    ("python3", "scripts/smoke_test.py", "--input", "work/inputs/review_input.json", "--output", "out/smoke.json"),
)


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    intercept: FilterIntercept


class ReviewExecutionPolicy:
    def __init__(self, *, max_timeout_sec: int = 60, env_whitelist: set[str] | None = None, dry_run: bool = False) -> None:
        self.max_timeout_sec = max_timeout_sec
        self.env_whitelist = env_whitelist or set()
        self.dry_run = dry_run

    def evaluate(
        self,
        *,
        command: list[str],
        runtime: str,
        output_files: list[str] | None = None,
        env: dict[str, str] | None = None,
        timeout: int = 30,
        network_access: bool = False,
    ) -> PolicyDecision:
        output_files = output_files or []
        env = env or {}
        command_text = " ".join(command)
        lower = command_text.lower()
        deny_reason = self._deny_reason(command, lower, output_files, env, timeout)
        if deny_reason:
            return self._decision("deny", deny_reason, command, runtime)
        review_reason = self._needs_review_reason(command, lower, network_access)
        if review_reason:
            return self._decision("needs_human_review", review_reason, command, runtime)
        if tuple(command) in ALLOWED_SKILL_COMMANDS:
            return self._decision("allow", "command matches code-review skill allowlist", command, runtime)
        return self._decision("needs_human_review", "command is outside the code-review skill allowlist", command, runtime)

    def runtime_fallback(self, *, task_id: str, from_runtime: str, to_runtime: str) -> FilterIntercept:
        intercept = self._decision(
            "needs_human_review",
            "container runtime fell back to explicit local development runtime",
            [f"runtime:{from_runtime}->{to_runtime}"],
            to_runtime,
        ).intercept
        return intercept.model_copy(update={"task_id": task_id})

    def _deny_reason(
        self,
        command: list[str],
        lower: str,
        output_files: list[str],
        env: dict[str, str],
        timeout: int,
    ) -> str:
        if "rm -rf /" in lower or re.search(r"\brm\b.*\s-rf\s+/", lower):
            return "destructive recursive removal is denied"
        if any(token in lower for token in ("mkfs", "shutdown", "reboot")):
            return "host destructive command is denied"
        if "dd if=" in lower:
            return "raw disk copy command is denied"
        if re.search(r"\b(curl|wget)\b.+\|.+\b(bash|sh)\b", lower):
            return "pipe-to-shell download execution is denied"
        blocked_paths = ("/etc", "/root", "~/.ssh", "/var/run/docker.sock")
        for token in command + output_files:
            normalized = token.replace("\\", "/")
            if any(normalized.startswith(path) or path in normalized for path in blocked_paths):
                return f"sandbox access to protected path {token!r} is denied"
        for pattern in output_files:
            normalized = pattern.replace("\\", "/")
            if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized) or "../" in normalized or normalized == "..":
                return f"unsafe output glob {pattern!r} is denied"
        for key in env:
            upper = key.upper()
            if key not in self.env_whitelist and any(marker in upper for marker in ("TOKEN", "SECRET", "PASSWORD", "API_KEY")):
                return f"environment key {key!r} is denied unless explicitly whitelisted"
        if timeout > self.max_timeout_sec:
            return f"timeout {timeout}s exceeds max_timeout_sec={self.max_timeout_sec}"
        return ""

    def _needs_review_reason(self, command: list[str], lower: str, network_access: bool) -> str:
        if network_access:
            return "network access requested"
        executable = os.path.basename(command[0]) if command else ""
        if executable in {"pip", "pip3", "npm", "yarn", "pnpm", "apt", "apt-get", "apk", "yum"}:
            return "package installation command requires human review"
        if re.search(r"\b(pip|pip3|npm|apt-get|apt|apk|yum)\s+install\b", lower):
            return "package installation requires human review"
        if executable not in {"python3", "python"}:
            return f"unknown executable {executable!r} requires human review"
        return ""

    def _decision(self, decision: str, reason: str, command: list[str], runtime: str) -> PolicyDecision:
        payload = f"{decision}:{reason}:{' '.join(command)}:{runtime}"
        intercept_id = "filter_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        return PolicyDecision(
            decision,
            FilterIntercept(
                intercept_id=intercept_id,
                decision=decision,
                reason=reason,
                command=command,
                runtime=runtime,
                metadata={"max_timeout_sec": self.max_timeout_sec},
                created_at=utc_now(self.dry_run),
            ),
        )

