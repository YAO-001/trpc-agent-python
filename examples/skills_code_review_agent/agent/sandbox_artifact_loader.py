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


_ARTIFACT_SKILL_SOURCES = {
    "out/findings.json": "skill:run_static_review",
    "out/secrets.json": "skill:secret_scan",
    "out/smoke.json": "skill:smoke_test",
}


@dataclass(frozen=True)
class SandboxArtifacts:
    findings: list[Finding]
    warnings: list[ReviewWarning]
    needs_human_review: list[ReviewWarning]


def _source_for_path(path: str) -> str:
    normalized = PurePosixPath(path.replace("\\", "/")).as_posix()
    if normalized in _ARTIFACT_SKILL_SOURCES:
        return _ARTIFACT_SKILL_SOURCES[normalized]
    for suffix, source in _ARTIFACT_SKILL_SOURCES.items():
        if normalized.endswith(f"/{suffix}"):
            return source
    return f"skill:{PurePosixPath(normalized).stem or 'unknown'}"


def _coerce_sources(value: Any, required_source: str) -> list[str]:
    if value is None:
        sources: list[str] = []
    elif isinstance(value, str):
        sources = [value]
    else:
        sources = [str(item) for item in value if str(item)]
    sources.append(required_source)
    return sorted(set(sources))


def _warning_from_payload(payload: dict[str, Any], *, source: str, needs_human_review: bool) -> ReviewWarning:
    return ReviewWarning(
        category=str(payload.get("category") or "sandbox"),
        title=str(payload.get("title") or "sandbox artifact warning"),
        message=str(payload.get("message") or payload.get("evidence") or ""),
        file=str(payload.get("file") or ""),
        line=int(payload.get("line") or 0),
        confidence=float(payload.get("confidence") or 1.0),
        source=_coerce_sources(payload.get("source"), source),
        needs_human_review=needs_human_review,
    )


def _finding_from_payload(payload: dict[str, Any], *, source: str) -> Finding:
    return Finding(
        severity=str(payload.get("severity") or "low"),
        category=str(payload.get("category") or "sandbox"),
        file=str(payload.get("file") or ""),
        line=int(payload.get("line") or 0),
        title=str(payload.get("title") or "sandbox artifact finding"),
        evidence=str(payload.get("evidence") or ""),
        recommendation=str(payload.get("recommendation") or "Review the sandbox artifact output."),
        confidence=float(payload.get("confidence") or 1.0),
        source=_coerce_sources(payload.get("source"), source),
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


def load_sandbox_artifacts(runs: list[SandboxRun]) -> SandboxArtifacts:
    findings: list[Finding] = []
    warnings: list[ReviewWarning] = []
    needs_human_review: list[ReviewWarning] = []

    for run in runs:
        for path, content in sorted(run.output_files.items()):
            source = _source_for_path(path)
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                needs_human_review.append(
                    ReviewWarning(
                        category="sandbox",
                        title="sandbox artifact is not valid JSON",
                        message=f"{path} could not be parsed as JSON.",
                        confidence=1.0,
                        source=[source, "sandbox_artifact_loader"],
                        needs_human_review=True,
                    )
                )
                continue
            if not isinstance(data, dict):
                continue
            for item in _iter_payload_items(data, "findings"):
                findings.append(_finding_from_payload(item, source=source))
            for item in _iter_payload_items(data, "warnings"):
                warnings.append(_warning_from_payload(item, source=source, needs_human_review=False))
            for item in _iter_payload_items(data, "needs_human_review"):
                needs_human_review.append(_warning_from_payload(item, source=source, needs_human_review=True))

    return SandboxArtifacts(findings=findings, warnings=warnings, needs_human_review=needs_human_review)
