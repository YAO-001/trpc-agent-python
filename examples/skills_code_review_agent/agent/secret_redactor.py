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
    value_group: int | str = 0
    unquoted_assignment: bool = False


@dataclass
class RedactionResult:
    text: str
    summary: RedactionSummary


class SecretRedactor:
    SECRET_TYPES = (
        "pem_private_key",
        "aws_access_key",
        "github_token",
        "openai_key",
        "jwt",
        "bearer_token",
        "credential_url",
        "generic_assignment",
    )
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
    _alias_pattern = "|".join(SECRET_ALIASES)
    _literal_prefix_pattern = r"(?P<literal_prefix>[bruf]{0,2})"
    DOUBLE_TRIPLE_QUOTED_ASSIGNMENT_RE = re.compile(
        rf"(?P<prefix>\b(?:{_alias_pattern})\b['\"]?\s*[:=]\s*){_literal_prefix_pattern}"
        r'"""(?P<value>[\s\S]*?)"""',
        re.IGNORECASE,
    )
    SINGLE_TRIPLE_QUOTED_ASSIGNMENT_RE = re.compile(
        rf"(?P<prefix>\b(?:{_alias_pattern})\b['\"]?\s*[:=]\s*){_literal_prefix_pattern}"
        r"'''(?P<value>[\s\S]*?)'''",
        re.IGNORECASE,
    )
    DOUBLE_QUOTED_ASSIGNMENT_RE = re.compile(
        rf"(?P<prefix>\b(?:{_alias_pattern})\b['\"]?\s*[:=]\s*){_literal_prefix_pattern}"
        r'"(?P<value>(?:\\.|[^"\\\r\n])*)"',
        re.IGNORECASE,
    )
    SINGLE_QUOTED_ASSIGNMENT_RE = re.compile(
        rf"(?P<prefix>\b(?:{_alias_pattern})\b['\"]?\s*[:=]\s*){_literal_prefix_pattern}"
        r"'(?P<value>(?:\\.|[^'\\\r\n])*)'",
        re.IGNORECASE,
    )
    UNQUOTED_ASSIGNMENT_RE = re.compile(
        rf"(?P<prefix>\b(?:{_alias_pattern})\b['\"]?\s*[:=]\s*)"
        r"(?P<value>[^'\"\s,;}()\[\]{}]+(?: [^'\"\r\n,;}()\[\]{}]+)*)",
        re.IGNORECASE,
    )
    BEARER_RE = re.compile(
        r"(?P<prefix>authorization\s*:\s*bearer\s+)(?P<value>[^\s,;]+)",
        re.IGNORECASE,
    )
    CREDENTIAL_URL_RE = re.compile(
        r"(?P<prefix>[a-z][a-z0-9+.-]*://)(?P<value>[^@/\s]+)(?P<suffix>@)",
        re.IGNORECASE,
    )
    _secret_type_pattern = "|".join(map(re.escape, SECRET_TYPES))
    PLACEHOLDER_RE = re.compile(rf"\[REDACTED:SECRET:(?P<type>{_secret_type_pattern}):(?P<hash>[a-f0-9]{{8}})\]", )
    MALFORMED_PLACEHOLDER_RE = re.compile(r"\[REDACTED:SECRET:[^\]\r\n]*(?:\]|(?=[\r\n]|\Z))")
    _patterns = [
        _SecretPattern("generic_assignment", MALFORMED_PLACEHOLDER_RE),
        _SecretPattern(
            "pem_private_key",
            re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
        ),
        _SecretPattern("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
        _SecretPattern("github_token", re.compile(r"\bghp_[A-Za-z0-9_]{36,}\b")),
        _SecretPattern("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
        _SecretPattern("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
        _SecretPattern("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
        _SecretPattern("bearer_token", BEARER_RE, value_group="value"),
        _SecretPattern("credential_url", CREDENTIAL_URL_RE, value_group="value"),
        _SecretPattern("generic_assignment", DOUBLE_TRIPLE_QUOTED_ASSIGNMENT_RE, value_group="value"),
        _SecretPattern("generic_assignment", SINGLE_TRIPLE_QUOTED_ASSIGNMENT_RE, value_group="value"),
        _SecretPattern("generic_assignment", DOUBLE_QUOTED_ASSIGNMENT_RE, value_group="value"),
        _SecretPattern("generic_assignment", SINGLE_QUOTED_ASSIGNMENT_RE, value_group="value"),
        _SecretPattern(
            "generic_assignment",
            UNQUOTED_ASSIGNMENT_RE,
            value_group="value",
            unquoted_assignment=True,
        ),
    ]

    @staticmethod
    def digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @classmethod
    def placeholder(cls, secret_type: str, value: str) -> str:
        if secret_type not in cls.SECRET_TYPES:
            raise ValueError(f"unsupported redaction secret type {secret_type!r}")
        return f"[REDACTED:SECRET:{secret_type}:{cls.digest(value)[:8]}]"

    @staticmethod
    def _is_likely_placeholder(value: str) -> bool:
        normalized = value.strip().strip("\"'").lower()
        marker = re.search(
            r"(?:^|[^a-z0-9])(?:change-me|changeme|dummy|example|fixture|placeholder|sample|sk-test|tests?)"
            r"(?:$|[^a-z0-9])",
            normalized,
        )
        if marker is not None:
            return True
        return normalized.startswith(("akia", "asia")) and normalized.endswith("example")

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
        placeholder_spans = [item.span() for item in self.PLACEHOLDER_RE.finditer(text)]

        def replace(match: re.Match[str]) -> str:
            value = match.group(secret_pattern.value_group) if secret_pattern.value_group else match.group(0)
            inside_placeholder = any(start <= match.start() < end for start, end in placeholder_spans)
            if inside_placeholder or self.PLACEHOLDER_RE.fullmatch(value):
                return match.group(0)
            if not value:
                return match.group(0)
            if secret_pattern.unquoted_assignment:
                remainder = text[match.end():]
                if remainder.lstrip(" \t")[:1] in {"(", "[", "{", "'", '"'}:
                    return match.group(0)
                prefix = match.groupdict().get("prefix", "").casefold()
                if ("authorization" in prefix and value.casefold() == "bearer"
                        and remainder.lstrip().startswith("[REDACTED:SECRET:bearer_token:")):
                    return match.group(0)
            digest = self.digest(value)
            placeholder = self.placeholder(secret_pattern.secret_type, value)
            key = (secret_pattern.secret_type, digest)
            likely_placeholder = self._is_likely_placeholder(value)
            if key in events:
                events[key].count += 1
                events[key].likely_placeholder = events[key].likely_placeholder and likely_placeholder
            else:
                events[key] = RedactionEvent(
                    secret_type=secret_pattern.secret_type,
                    sha256=digest,
                    placeholder=placeholder,
                    count=1,
                    likely_placeholder=likely_placeholder,
                )
            if not secret_pattern.value_group:
                return placeholder
            start, end = match.span(secret_pattern.value_group)
            return match.group(0)[:start - match.start()] + placeholder + match.group(0)[end - match.start():]

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
                    merged[merge_key].likely_placeholder = (merged[merge_key].likely_placeholder
                                                            and event.likely_placeholder)
                else:
                    merged[merge_key] = event.model_copy(deep=True)
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
