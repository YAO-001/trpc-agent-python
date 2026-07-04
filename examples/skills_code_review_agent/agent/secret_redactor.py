# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Secret detection and stable redaction helpers."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Pattern

from .models import RedactionEvent
from .models import RedactionSummary


@dataclass(frozen=True)
class _SecretPattern:
    secret_type: str
    pattern: Pattern[str]
    value_group: int = 0


@dataclass
class RedactionResult:
    text: str
    summary: RedactionSummary


class SecretRedactor:
    _patterns = [
        _SecretPattern("pem_private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----")),
        _SecretPattern("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
        _SecretPattern("github_token", re.compile(r"\bghp_[A-Za-z0-9_]{36,}\b")),
        _SecretPattern("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
        _SecretPattern("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
        _SecretPattern("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
        _SecretPattern(
            "generic_assignment",
            re.compile(r"(?i)\b(password|token|api_key|secret)\b(\s*[:=]\s*[\"']?)([A-Za-z0-9_./+=:@-]{8,})([\"']?)"),
            value_group=3,
        ),
    ]

    @staticmethod
    def digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @classmethod
    def placeholder(cls, secret_type: str, value: str) -> str:
        return f"[REDACTED:SECRET:{secret_type}:{cls.digest(value)[:8]}]"

    def redact_text(self, text: str) -> RedactionResult:
        events: dict[tuple[str, str], RedactionEvent] = {}
        redacted = text
        for secret_pattern in self._patterns:
            redacted = self._apply_pattern(redacted, secret_pattern, events)
        by_type: dict[str, int] = {}
        for event in events.values():
            by_type[event.secret_type] = by_type.get(event.secret_type, 0) + event.count
        return RedactionResult(
            text=redacted,
            summary=RedactionSummary(
                total_redactions=sum(event.count for event in events.values()),
                by_type=dict(sorted(by_type.items())),
                events=sorted(events.values(), key=lambda item: (item.secret_type, item.sha256)),
            ),
        )

    def _apply_pattern(
        self,
        text: str,
        secret_pattern: _SecretPattern,
        events: dict[tuple[str, str], RedactionEvent],
    ) -> str:
        def replace(match: re.Match[str]) -> str:
            value = match.group(secret_pattern.value_group) if secret_pattern.value_group else match.group(0)
            prefix = text[max(0, match.start() - 24):match.start()]
            if "REDACTED:" in prefix or value.startswith("[REDACTED:SECRET:") or "REDACTED:SECRET" in value:
                return match.group(0)
            digest = self.digest(value)
            placeholder = self.placeholder(secret_pattern.secret_type, value)
            key = (secret_pattern.secret_type, digest)
            if key in events:
                events[key].count += 1
            else:
                events[key] = RedactionEvent(
                    secret_type=secret_pattern.secret_type,
                    sha256=digest,
                    placeholder=placeholder,
                    count=1,
                )
            if not secret_pattern.value_group:
                return placeholder
            start, end = match.span(secret_pattern.value_group)
            return match.group(0)[: start - match.start()] + placeholder + match.group(0)[end - match.start():]

        return secret_pattern.pattern.sub(replace, text)

    def redact_mapping(self, values: dict[str, str]) -> tuple[dict[str, str], RedactionSummary]:
        redacted: dict[str, str] = {}
        merged: dict[tuple[str, str], RedactionEvent] = {}
        for key, value in values.items():
            result = self.redact_text(value)
            redacted[key] = result.text
            for event in result.summary.events:
                merge_key = (event.secret_type, event.sha256)
                if merge_key in merged:
                    merged[merge_key].count += event.count
                else:
                    merged[merge_key] = event.model_copy()
        by_type: dict[str, int] = {}
        for event in merged.values():
            by_type[event.secret_type] = by_type.get(event.secret_type, 0) + event.count
        return redacted, RedactionSummary(
            total_redactions=sum(event.count for event in merged.values()),
            by_type=dict(sorted(by_type.items())),
            events=sorted(merged.values(), key=lambda item: (item.secret_type, item.sha256)),
        )


def redact_text(text: str) -> RedactionResult:
    return SecretRedactor().redact_text(text)
