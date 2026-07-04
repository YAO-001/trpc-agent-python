# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Load findings and review warnings from collected Skill sandbox artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .models import Finding
from .models import ReviewWarning
from .models import SandboxRun
from .secret_redactor import SecretRedactor


_ARTIFACT_SKILL_SOURCES = {
    "out/findings.json": ("skill:run_static_review", "sandbox:run_static_review"),
    "out/secrets.json": ("skill:secret_scan", "sandbox:secret_scan"),
    "out/smoke.json": ("skill:smoke_test", "sandbox:smoke_test"),
}
_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_VALID_CATEGORIES = {"security", "secret", "async_resource", "resource", "database", "test", "sandbox"}
_REQUIRED_FINDING_FIELDS = {
    "severity",
    "category",
    "file",
    "line",
    "title",
    "evidence",
    "recommendation",
    "confidence",
}


@dataclass(frozen=True)
class SandboxArtifacts:
    findings: list[Finding]
    warnings: list[ReviewWarning]
    needs_human_review: list[ReviewWarning]


def _sources_for_path(path: str) -> tuple[str, ...]:
    normalized = PurePosixPath(path.replace("\\", "/")).as_posix()
    if normalized in _ARTIFACT_SKILL_SOURCES:
        return _ARTIFACT_SKILL_SOURCES[normalized]
    for suffix, sources in _ARTIFACT_SKILL_SOURCES.items():
        if normalized.endswith(f"/{suffix}"):
            return sources
    stem = PurePosixPath(normalized).stem or "unknown"
    return f"skill:{stem}", f"sandbox:{stem}"


def _coerce_sources(value: Any, required_sources: tuple[str, ...]) -> list[str]:
    if value is None:
        sources: list[str] = []
    elif isinstance(value, str):
        sources = [value]
    else:
        sources = [str(item) for item in value if str(item)]
    sources.extend(required_sources)
    return sorted(set(sources))


def _redact(value: Any, redactor: SecretRedactor | None) -> str:
    text = str(value or "")
    if redactor is None:
        return text
    return redactor.redact_text(text).text


def _coerce_line(value: Any) -> int | None:
    try:
        line = int(value)
    except (TypeError, ValueError):
        return None
    if line < 0:
        return None
    return line


def _coerce_confidence(value: Any, default: float = 1.0) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return default
    if confidence < 0.0 or confidence > 1.0:
        return default
    return confidence


def _artifact_warning(
    *,
    title: str,
    message: str,
    sources: tuple[str, ...],
    redactor: SecretRedactor | None,
    needs_human_review: bool = True,
) -> ReviewWarning:
    return ReviewWarning(
        category="sandbox",
        title=title,
        message=_redact(message, redactor),
        confidence=1.0,
        source=sorted({*sources, "sandbox_artifact_loader"}),
        needs_human_review=needs_human_review,
    )


def _warning_from_payload(
    payload: dict[str, Any],
    *,
    sources: tuple[str, ...],
    needs_human_review: bool,
    redactor: SecretRedactor | None,
) -> ReviewWarning:
    line = _coerce_line(payload.get("line")) or 0
    return ReviewWarning(
        category=str(payload.get("category") or "sandbox"),
        title=_redact(payload.get("title") or "sandbox artifact warning", redactor),
        message=_redact(payload.get("message") or payload.get("evidence") or "", redactor),
        file=_redact(payload.get("file") or "", redactor),
        line=line,
        confidence=_coerce_confidence(payload.get("confidence"), 1.0),
        source=_coerce_sources(payload.get("source"), sources),
        needs_human_review=needs_human_review,
    )


def _validate_finding(payload: dict[str, Any]) -> str:
    missing = sorted(field for field in _REQUIRED_FINDING_FIELDS if field not in payload)
    if missing:
        return f"sandbox finding is missing required fields: {', '.join(missing)}"
    severity = str(payload.get("severity") or "").lower()
    if severity not in _VALID_SEVERITIES:
        return f"sandbox finding has invalid severity {payload.get('severity')!r}"
    category = str(payload.get("category") or "").lower()
    if category not in _VALID_CATEGORIES:
        return f"sandbox finding has invalid category {payload.get('category')!r}"
    if _coerce_line(payload.get("line")) is None:
        return f"sandbox finding has invalid line {payload.get('line')!r}"
    confidence = _coerce_confidence(payload.get("confidence"), -1.0)
    if confidence < 0.0:
        return f"sandbox finding has invalid confidence {payload.get('confidence')!r}"
    return ""


def _finding_from_payload(
    payload: dict[str, Any],
    *,
    sources: tuple[str, ...],
    redactor: SecretRedactor | None,
) -> Finding:
    return Finding(
        severity=str(payload.get("severity") or "low").lower(),
        category=str(payload.get("category") or "sandbox").lower(),
        file=_redact(payload.get("file") or "", redactor),
        line=_coerce_line(payload.get("line")) or 0,
        title=_redact(payload.get("title") or "sandbox artifact finding", redactor),
        evidence=_redact(payload.get("evidence") or "", redactor),
        recommendation=_redact(payload.get("recommendation") or "Review the sandbox artifact output.", redactor),
        confidence=float(payload.get("confidence") or 1.0),
        source=_coerce_sources(payload.get("source"), sources),
    )


def _iter_payload_items(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = data.get(key)
    if not value:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


class SandboxArtifactLoader:
    def __init__(self, *, redactor: SecretRedactor | None = None) -> None:
        self.redactor = redactor

    def load(self, runs: list[SandboxRun]) -> SandboxArtifacts:
        findings: list[Finding] = []
        warnings: list[ReviewWarning] = []
        needs_human_review: list[ReviewWarning] = []

        for run in runs:
            for path, content in sorted(run.output_files.items()):
                sources = _sources_for_path(path)
                try:
                    data = json.loads(content)
                except json.JSONDecodeError:
                    needs_human_review.append(
                        _artifact_warning(
                            title="sandbox artifact is not valid JSON",
                            message=f"{path} could not be parsed as JSON.",
                            sources=sources,
                            redactor=self.redactor,
                        )
                    )
                    continue
                if not isinstance(data, dict):
                    needs_human_review.append(
                        _artifact_warning(
                            title="sandbox artifact has invalid schema",
                            message=f"{path} must contain a JSON object.",
                            sources=sources,
                            redactor=self.redactor,
                        )
                    )
                    continue
                for item in _iter_payload_items(data, "findings"):
                    reason = _validate_finding(item)
                    if reason:
                        needs_human_review.append(
                            _artifact_warning(
                                title="sandbox finding has invalid schema",
                                message=f"{path}: {reason}",
                                sources=sources,
                                redactor=self.redactor,
                            )
                        )
                        continue
                    findings.append(_finding_from_payload(item, sources=sources, redactor=self.redactor))
                for item in _iter_payload_items(data, "warnings"):
                    warnings.append(
                        _warning_from_payload(
                            item,
                            sources=sources,
                            needs_human_review=False,
                            redactor=self.redactor,
                        )
                    )
                needs_value = data.get("needs_human_review")
                if isinstance(needs_value, bool) and needs_value:
                    needs_human_review.append(
                        _artifact_warning(
                            title="sandbox artifact requested human review",
                            message=f"{path} set needs_human_review=true.",
                            sources=sources,
                            redactor=self.redactor,
                        )
                    )
                for item in _iter_payload_items(data, "needs_human_review"):
                    needs_human_review.append(
                        _warning_from_payload(
                            item,
                            sources=sources,
                            needs_human_review=True,
                            redactor=self.redactor,
                        )
                    )

        return SandboxArtifacts(findings=findings, warnings=warnings, needs_human_review=needs_human_review)


def load_sandbox_artifacts(runs: list[SandboxRun], redactor: SecretRedactor | None = None) -> SandboxArtifacts:
    return SandboxArtifactLoader(redactor=redactor).load(runs)
