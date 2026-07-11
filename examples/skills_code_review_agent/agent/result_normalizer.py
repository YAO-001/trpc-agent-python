# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Single schema, redaction, confidence-routing, and deduplication boundary."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from typing import Sequence

from pydantic import BaseModel
from pydantic import Field
from pydantic import ValidationError

from .dedupe import dedupe_findings
from .dedupe import dedupe_warnings
from .models import Finding
from .models import ReviewWarning
from .redaction_boundary import RedactionBoundary

_RESERVED_PROVENANCE_PREFIXES = (
    "host:",
    "redactor:",
    "rule:",
    "sandbox:",
    "sandbox_artifact:",
    "sandbox_run:",
    "skill:",
)
_RESERVED_PROVENANCE_VALUES = {
    "result_normalizer",
    "review_execution_policy",
    "sandbox_artifact_loader",
    "sandbox_runner",
}


@dataclass(frozen=True)
class CandidateOrigin:
    """Trusted provenance added by an input adapter, never by candidate data."""

    run_id: str = ""
    path: str = ""
    trusted_sources: tuple[str, ...] = ()
    allow_legacy_resource: bool = False


@dataclass(frozen=True)
class OriginCandidate:
    """A raw candidate paired with trusted provenance."""

    value: Any
    origin: CandidateOrigin = CandidateOrigin()


@dataclass(frozen=True)
class ReviewCandidates:
    findings: Sequence[Any] = ()
    warnings: Sequence[Any] = ()
    needs_human_review: Sequence[Any] = ()
    validation_errors: Sequence[Any] = ()


@dataclass(frozen=True)
class PreparedCandidates:
    """Schema-valid candidates that have not been routed or deduplicated."""

    findings: tuple[Finding, ...] = ()
    warnings: tuple[ReviewWarning, ...] = ()
    needs_human_review: tuple[ReviewWarning, ...] = ()
    validation_errors: tuple[ReviewWarning, ...] = ()
    invalid_run_ids: frozenset[str] = frozenset()


class NormalizedReviewResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    warnings: list[ReviewWarning] = Field(default_factory=list)
    needs_human_review: list[ReviewWarning] = Field(default_factory=list)
    dropped_count: int = Field(default=0, ge=0)
    validation_errors: list[ReviewWarning] = Field(default_factory=list)


def merge_prepared_candidates(*batches: PreparedCandidates) -> PreparedCandidates:
    return PreparedCandidates(
        findings=tuple(item for batch in batches for item in batch.findings),
        warnings=tuple(item for batch in batches for item in batch.warnings),
        needs_human_review=tuple(item for batch in batches for item in batch.needs_human_review),
        validation_errors=tuple(item for batch in batches for item in batch.validation_errors),
        invalid_run_ids=frozenset(run_id for batch in batches for run_id in batch.invalid_run_ids),
    )


def _warning_from_candidate(candidate: Finding, *, needs_review: bool) -> ReviewWarning:
    return ReviewWarning(
        category=candidate.category,
        title=candidate.title,
        message=f"{candidate.evidence} Recommendation: {candidate.recommendation}",
        file=candidate.file,
        line=candidate.line,
        confidence=candidate.confidence,
        source=candidate.source,
        needs_human_review=needs_review,
    )


def _validation_details(error: Exception) -> str:
    if not isinstance(error, ValidationError):
        return type(error).__name__
    details: list[str] = []
    for item in error.errors(include_input=False, include_url=False):
        location = ".".join(str(value) for value in item.get("loc", ())) or "candidate"
        details.append(f"{location}:{item.get('type', 'validation_error')}")
    return ", ".join(sorted(details)) or "validation_error"


def contains_unicode_surrogate(value: Any) -> bool:
    pending = [value]
    visited: set[int] = set()
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                return True
            continue
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in visited:
                continue
            visited.add(identity)
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, (list, tuple, set, frozenset)):
            identity = id(item)
            if identity in visited:
                continue
            visited.add(identity)
            pending.extend(item)
    return False


def _with_trusted_sources(
    payload: dict[str, Any],
    origin: CandidateOrigin,
    *,
    trusted_value: bool,
) -> dict[str, Any]:
    value = payload.get("source")
    if value is None:
        sources: list[str] = []
    elif isinstance(value, str):
        sources = [value]
    elif isinstance(value, (list, tuple, set, frozenset)) and all(isinstance(item, str) for item in value):
        sources = list(value)
    else:
        return payload
    has_trusted_origin = bool(origin.run_id or origin.path or origin.trusted_sources or origin.allow_legacy_resource)
    if has_trusted_origin and not trusted_value and any(
            source in _RESERVED_PROVENANCE_VALUES or source.startswith(_RESERVED_PROVENANCE_PREFIXES)
            for source in sources):
        raise ValueError("candidate source uses reserved provenance")
    payload["source"] = sorted({*sources, *origin.trusted_sources})
    return payload


class ResultNormalizer:
    high_confidence_threshold = 0.80
    low_confidence_threshold = 0.50

    def __init__(self, boundary: RedactionBoundary) -> None:
        self.boundary = boundary

    @staticmethod
    def _unwrap(value: Any) -> tuple[Any, CandidateOrigin]:
        if isinstance(value, OriginCandidate):
            return value.value, value.origin
        return value, CandidateOrigin()

    def _schema_error(
        self,
        *,
        kind: str,
        index: int,
        error: Exception,
        origin: CandidateOrigin,
    ) -> ReviewWarning:
        message = f"{kind} {index} failed schema validation: {_validation_details(error)}"
        payload = self.boundary.clean({
            "category": "sandbox",
            "title": f"review {kind} has invalid schema",
            "message": message,
            "confidence": 1.0,
            "source": sorted({"result_normalizer", *origin.trusted_sources}),
            "needs_human_review": True,
        })
        return ReviewWarning.model_validate(payload)

    def _payload(self, value: Any, origin: CandidateOrigin, *, finding: bool) -> dict[str, Any]:
        trusted_value = ((finding and isinstance(value, Finding)) or (not finding and isinstance(value, ReviewWarning)))
        if finding and isinstance(value, Finding):
            payload = value.model_dump(mode="json")
        elif not finding and isinstance(value, ReviewWarning):
            payload = value.model_dump(mode="json")
        elif isinstance(value, Mapping):
            payload = dict(value)
        else:
            kind = "finding" if finding else "warning"
            raise TypeError(f"{kind} candidate must be a mapping")
        if contains_unicode_surrogate((payload, origin.run_id, origin.path, origin.trusted_sources)):
            raise ValueError("candidate contains non-UTF-8 Unicode data")
        allowed_fields = set(Finding.model_fields if finding else ReviewWarning.model_fields)
        if set(payload) - allowed_fields:
            raise ValueError("candidate contains unsupported fields")
        if finding:
            payload.pop("dedupe_key", None)
        if origin.allow_legacy_resource and payload.get("category") == "resource":
            payload["category"] = "async_resource"
        return _with_trusted_sources(payload, origin, trusted_value=trusted_value)

    def _finding(self, value: Any, index: int) -> tuple[Finding | None, ReviewWarning | None, str]:
        raw, origin = self._unwrap(value)
        try:
            payload = self._payload(raw, origin, finding=True)
            cleaned = self.boundary.clean(payload)
            return Finding.model_validate(cleaned), None, ""
        except Exception as exc:  # candidate data must never escape the boundary
            return None, self._schema_error(kind="candidate", index=index, error=exc, origin=origin), origin.run_id

    def _warning(
        self,
        value: Any,
        *,
        index: int,
        needs_review: bool,
    ) -> tuple[ReviewWarning | None, ReviewWarning | None, str]:
        raw, origin = self._unwrap(value)
        try:
            payload = self._payload(raw, origin, finding=False)
            payload["needs_human_review"] = needs_review
            cleaned = self.boundary.clean(payload)
            return ReviewWarning.model_validate(cleaned), None, origin.run_id
        except Exception as exc:  # candidate data must never escape the boundary
            return None, self._schema_error(kind="warning", index=index, error=exc, origin=origin), origin.run_id

    def prepare(self, *batches: ReviewCandidates) -> PreparedCandidates:
        """Validate and redact candidates without routing or deduplicating them."""
        findings: list[Finding] = []
        warnings: list[ReviewWarning] = []
        needs_human_review: list[ReviewWarning] = []
        validation_errors: list[ReviewWarning] = []
        invalid_run_ids: set[str] = set()
        candidate_index = 0
        warning_index = 0

        for batch in batches:
            for value in batch.findings:
                candidate_index += 1
                candidate, error, invalid_run_id = self._finding(value, candidate_index)
                if error is not None:
                    validation_errors.append(error)
                    if invalid_run_id:
                        invalid_run_ids.add(invalid_run_id)
                elif candidate is not None:
                    findings.append(candidate)
            for values, needs_review, is_validation_error in (
                (batch.warnings, False, False),
                (batch.needs_human_review, True, False),
                (batch.validation_errors, True, True),
            ):
                for value in values:
                    warning_index += 1
                    warning, error, invalid_run_id = self._warning(
                        value,
                        index=warning_index,
                        needs_review=needs_review,
                    )
                    if error is not None:
                        validation_errors.append(error)
                    elif warning is not None:
                        if is_validation_error:
                            validation_errors.append(warning)
                        elif needs_review:
                            needs_human_review.append(warning)
                        else:
                            warnings.append(warning)
                    if (error is not None or is_validation_error) and invalid_run_id:
                        invalid_run_ids.add(invalid_run_id)

        return PreparedCandidates(
            findings=tuple(findings),
            warnings=tuple(warnings),
            needs_human_review=tuple(needs_human_review),
            validation_errors=tuple(validation_errors),
            invalid_run_ids=frozenset(invalid_run_ids),
        )

    def finalize(self, *batches: PreparedCandidates) -> NormalizedReviewResult:
        """Route and deduplicate all prepared host and sandbox candidates once."""
        candidates = [item for batch in batches for item in batch.findings]
        routed_warnings = [
            item for batch in batches for item in (*batch.warnings, *batch.needs_human_review, *batch.validation_errors)
        ]
        validation_errors = [item for batch in batches for item in batch.validation_errors]

        identity_counts = Counter((item.file, item.line, item.category) for item in candidates)
        findings: list[Finding] = []
        dropped_count = 0
        for candidate in dedupe_findings(candidates):
            if candidate.confidence >= self.high_confidence_threshold:
                findings.append(candidate)
            elif candidate.confidence >= self.low_confidence_threshold:
                needs_review = candidate.severity in {"medium", "high", "critical"}
                routed_warnings.append(_warning_from_candidate(candidate, needs_review=needs_review))
            else:
                dropped_count += identity_counts[(candidate.file, candidate.line, candidate.category)]

        merged_warnings = dedupe_warnings(routed_warnings)
        warnings = [item for item in merged_warnings if not item.needs_human_review]
        needs_human_review = [item for item in merged_warnings if item.needs_human_review]
        return NormalizedReviewResult(
            findings=findings,
            warnings=warnings,
            needs_human_review=needs_human_review,
            dropped_count=dropped_count,
            validation_errors=dedupe_warnings(validation_errors),
        )

    def normalize(self, *batches: ReviewCandidates | PreparedCandidates) -> NormalizedReviewResult:
        """Convenience API for callers that do not need pre-persistence validation."""
        prepared = [batch if isinstance(batch, PreparedCandidates) else self.prepare(batch) for batch in batches]
        return self.finalize(*prepared)
