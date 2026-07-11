# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Stateful redaction boundary shared by review inputs and output sinks."""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import unquote

from sqlalchemy.engine import URL
from sqlalchemy.engine import make_url

from .models import RedactionEvent
from .models import RedactionSummary
from .secret_redactor import RedactionResult
from .secret_redactor import SecretRedactor

_SENSITIVE_FIELD_SEARCH_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<alias>{'|'.join(SecretRedactor.SECRET_ALIASES)})(?![A-Za-z0-9_])",
    re.IGNORECASE,
)


def _fully_unquote(value: str) -> str:
    while True:
        decoded = unquote(value)
        if decoded == value:
            return decoded
        value = decoded


class RedactionBoundary:
    """Accumulate redaction evidence while returning only cleaned values."""

    def __init__(self, redactor: SecretRedactor | None = None) -> None:
        self.redactor = redactor or SecretRedactor()
        self._events: dict[tuple[str, str], RedactionEvent] = {}

    def text(self, value: object) -> RedactionResult:
        text = "" if value is None else str(value)
        result = self.redactor.redact_text(text)
        self._merge(result.summary)
        return result

    def clean(self, value: Any) -> Any:
        return self._clean(value, sensitive_field=None)

    def _clean(self, value: Any, *, sensitive_field: str | None) -> Any:
        if isinstance(value, dict):
            cleaned: dict[Any, Any] = {}
            prepared: list[tuple[str, str, Any, str | None]] = []
            for key, item in value.items():
                raw_key = str(key)
                cleaned_key = self.text(raw_key).text
                match = _SENSITIVE_FIELD_SEARCH_RE.search(raw_key)
                child_field = match.group("alias") if match is not None else sensitive_field
                prepared.append((raw_key, cleaned_key, item, child_field))
            key_counts: dict[str, int] = {}
            for _, cleaned_key, _, _ in prepared:
                key_counts[cleaned_key] = key_counts.get(cleaned_key, 0) + 1
            for raw_key, cleaned_key, item, child_field in prepared:
                digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
                if key_counts[cleaned_key] > 1:
                    cleaned_key = f"{cleaned_key}#{digest}"
                while cleaned_key in cleaned:
                    cleaned_key = f"{cleaned_key}#{digest}"
                cleaned[cleaned_key] = self._clean(item, sensitive_field=child_field)
            return cleaned
        if isinstance(value, (list, tuple)):
            return [self._clean(item, sensitive_field=sensitive_field) for item in value]
        if isinstance(value, str):
            safe_value = self.text(value).text
            if sensitive_field is not None:
                prefix = f"{sensitive_field}="
                contextual = self.text(f"{prefix}{safe_value}").text
                if contextual.startswith(prefix):
                    safe_value = contextual[len(prefix):]
            return safe_value
        if value is None or type(value) in {bool, int, float}:
            return value
        return self.text(value).text

    def _merge(self, summary: RedactionSummary) -> None:
        for event in summary.events:
            key = (event.secret_type, event.sha256)
            existing = self._events.get(key)
            if existing is None:
                self._events[key] = event.model_copy(deep=True)
                continue
            existing.count += event.count
            existing.likely_placeholder = existing.likely_placeholder and event.likely_placeholder

    @property
    def summary(self) -> RedactionSummary:
        events = [
            event.model_copy(deep=True) for event in sorted(
                self._events.values(),
                key=lambda item: (item.secret_type, item.sha256),
            )
        ]
        by_type: dict[str, int] = {}
        for event in events:
            by_type[event.secret_type] = by_type.get(event.secret_type, 0) + event.count
        return RedactionSummary(
            total_redactions=sum(event.count for event in events),
            by_type=by_type,
            events=events,
        )

    def display_db_url(self, db_url: str) -> str:
        url = make_url(db_url)
        if url.get_backend_name() == "sqlite":
            decoded = self.text(_fully_unquote(db_url)).text
            rendered = make_url(decoded).render_as_string(hide_password=True)
            return self.text(rendered).text
        host = self.text(_fully_unquote(url.host or "")).text or None
        database = self.text(_fully_unquote(url.database or "")).text if url.database is not None else None
        public = URL.create(
            drivername=url.drivername,
            host=host,
            port=url.port,
            database=database,
        )
        rendered = public.render_as_string(hide_password=True)
        return self.text(rendered).text
