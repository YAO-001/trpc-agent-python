# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Decode raw review candidates from collected Skill sandbox artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import PurePosixPath

from .models import ReviewWarning
from .models import SandboxRun
from .result_normalizer import CandidateOrigin
from .result_normalizer import OriginCandidate
from .result_normalizer import ReviewCandidates
from .result_normalizer import contains_unicode_surrogate
from .secret_redactor import SecretRedactor

_ARTIFACT_SKILL_SOURCES = {
    "out/findings.json": ("skill:run_static_review", "sandbox:run_static_review"),
    "out/secrets.json": ("skill:secret_scan", "sandbox:secret_scan"),
    "out/smoke.json": ("skill:smoke_test", "sandbox:smoke_test"),
}
_CANDIDATE_BUCKETS = ("findings", "warnings", "needs_human_review")


@dataclass(frozen=True)
class SandboxArtifacts:
    candidates: ReviewCandidates
    invalid_run_ids: frozenset[str] = frozenset()


def _normalized_path(path: str) -> str:
    return PurePosixPath(path.replace("\\", "/")).as_posix()


def _sources_for_path(path: str) -> tuple[str, ...]:
    normalized = _normalized_path(path)
    if normalized in _ARTIFACT_SKILL_SOURCES:
        return _ARTIFACT_SKILL_SOURCES[normalized]
    for suffix, sources in _ARTIFACT_SKILL_SOURCES.items():
        if normalized.endswith(f"/{suffix}"):
            return sources
    stem = PurePosixPath(normalized).stem or "unknown"
    return f"skill:{stem}", f"sandbox:{stem}"


def _origin(run: SandboxRun, path: str) -> CandidateOrigin:
    normalized = _normalized_path(path)
    sources = {
        *_sources_for_path(normalized),
        f"sandbox_run:{run.run_id}",
        f"sandbox_artifact:{normalized}",
    }
    return CandidateOrigin(
        run_id=run.run_id,
        path=normalized,
        trusted_sources=tuple(sorted(sources)),
        allow_legacy_resource=True,
    )


def _redact(value: object, redactor: SecretRedactor | None) -> str:
    text = "" if value is None else str(value)
    if redactor is None:
        return text
    return redactor.redact_text(text).text


def _clean_raw(value: object, redactor: SecretRedactor | None) -> object:
    if isinstance(value, str):
        return _redact(value, redactor)
    if not isinstance(value, (dict, list)) or redactor is None:
        return value

    root: object = {} if isinstance(value, dict) else [None] * len(value)
    pending: list[tuple[dict | list, dict | list]] = [(value, root)]
    while pending:
        source, target = pending.pop()
        items = source.items() if isinstance(source, dict) else enumerate(source)
        for key, item in items:
            if isinstance(item, dict):
                cleaned: object = {}
                pending.append((item, cleaned))
            elif isinstance(item, list):
                cleaned = [None] * len(item)
                pending.append((item, cleaned))
            elif isinstance(item, str):
                cleaned = _redact(item, redactor)
            else:
                cleaned = item
            target[key] = cleaned
    return root


def _artifact_warning(
    *,
    title: str,
    message: str,
    origin: CandidateOrigin,
    redactor: SecretRedactor | None,
) -> ReviewWarning:
    return ReviewWarning(
        category="sandbox",
        title=title,
        message=_redact(message, redactor),
        confidence=1.0,
        source=sorted({*origin.trusted_sources, "sandbox_artifact_loader"}),
        needs_human_review=True,
    )


def _reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


class SandboxArtifactLoader:

    def __init__(self, *, redactor: SecretRedactor | None = None) -> None:
        self.redactor = redactor

    def load(self, runs: list[SandboxRun]) -> SandboxArtifacts:
        findings: list[OriginCandidate] = []
        warnings: list[OriginCandidate] = []
        needs_human_review: list[OriginCandidate] = []
        validation_errors: list[OriginCandidate] = []
        invalid_run_ids: set[str] = set()
        buckets = {
            "findings": findings,
            "warnings": warnings,
            "needs_human_review": needs_human_review,
        }

        for run in runs:
            for path, content in sorted(run.output_files.items()):
                origin = _origin(run, path)

                def add_issue(title: str, message: str) -> None:
                    invalid_run_ids.add(run.run_id)
                    warning = _artifact_warning(
                        title=title,
                        message=message,
                        origin=origin,
                        redactor=self.redactor,
                    )
                    validation_errors.append(OriginCandidate(warning, origin))

                try:
                    data = json.loads(content, parse_constant=_reject_nonfinite_json)
                except (json.JSONDecodeError, ValueError, TypeError, OverflowError, RecursionError):
                    add_issue(
                        "sandbox artifact is not valid JSON",
                        f"{origin.path} could not be parsed as strict JSON.",
                    )
                    continue
                if not isinstance(data, dict):
                    add_issue(
                        "sandbox artifact has invalid schema",
                        f"{origin.path} must contain a JSON object.",
                    )
                    continue
                if contains_unicode_surrogate(data):
                    add_issue(
                        "sandbox artifact contains invalid Unicode",
                        f"{origin.path} contains non-UTF-8 Unicode data.",
                    )
                    continue

                for key in _CANDIDATE_BUCKETS:
                    if key not in data:
                        continue
                    values = data[key]
                    if not isinstance(values, list):
                        add_issue(
                            f"sandbox artifact {key} has invalid schema",
                            f"{origin.path}: {key} must be an array.",
                        )
                        continue
                    for value in values:
                        buckets[key].append(OriginCandidate(_clean_raw(value, self.redactor), origin))
                        if not isinstance(value, dict):
                            invalid_run_ids.add(run.run_id)

        return SandboxArtifacts(
            candidates=ReviewCandidates(
                findings=findings,
                warnings=warnings,
                needs_human_review=needs_human_review,
                validation_errors=validation_errors,
            ),
            invalid_run_ids=frozenset(invalid_run_ids),
        )


def load_sandbox_artifacts(
    runs: list[SandboxRun],
    redactor: SecretRedactor | None = None,
) -> SandboxArtifacts:
    return SandboxArtifactLoader(redactor=redactor).load(runs)
