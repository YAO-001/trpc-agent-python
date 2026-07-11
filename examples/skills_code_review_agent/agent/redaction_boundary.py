# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Stateful redaction boundary shared by review inputs and output sinks."""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy.engine import URL
from sqlalchemy.engine import make_url

from .models import RedactionEvent
from .models import RedactionSummary
from .secret_redactor import RedactionResult
from .secret_redactor import SecretRedactor

_SENSITIVE_FIELD_RE = re.compile(
    rf"^(?:{'|'.join(SecretRedactor.SECRET_ALIASES)})$",
    re.IGNORECASE,
)


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
            for key, item in value.items():
                raw_key = str(key)
                cleaned_key = self.text(raw_key).text
                child_field = raw_key if _SENSITIVE_FIELD_RE.fullmatch(raw_key) else sensitive_field
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
            return self.text(db_url).text
        public = URL.create(
            drivername=url.drivername,
            host=url.host,
            port=url.port,
            database=url.database,
        )
        return public.render_as_string(hide_password=True)
