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

CandidateValue = Finding | Mapping[str, Any]
WarningValue = ReviewWarning | Mapping[str, Any]


@dataclass(frozen=True)
class ReviewCandidates:
    findings: Sequence[CandidateValue] = ()
    warnings: Sequence[WarningValue] = ()
    needs_human_review: Sequence[WarningValue] = ()
    validation_errors: Sequence[WarningValue] = ()


class NormalizedReviewResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    warnings: list[ReviewWarning] = Field(default_factory=list)
    needs_human_review: list[ReviewWarning] = Field(default_factory=list)
    dropped_count: int = Field(default=0, ge=0)
    validation_errors: list[ReviewWarning] = Field(default_factory=list)


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


class ResultNormalizer:
    high_confidence_threshold = 0.80
    low_confidence_threshold = 0.50

    def __init__(self, boundary: RedactionBoundary) -> None:
        self.boundary = boundary

    def _schema_error(self, *, kind: str, index: int, error: Exception) -> ReviewWarning:
        message = f"{kind} {index} failed schema validation: {_validation_details(error)}"
        return ReviewWarning(
            category="sandbox",
            title=f"review {kind} has invalid schema",
            message=self.boundary.text(message).text,
            confidence=1.0,
            source=["result_normalizer"],
            needs_human_review=True,
        )

    def _finding(self, value: CandidateValue, index: int) -> tuple[Finding | None, ReviewWarning | None]:
        try:
            if isinstance(value, Finding):
                payload = value.model_dump(mode="json")
            elif isinstance(value, Mapping):
                payload = dict(value)
            else:
                raise TypeError("finding candidate must be a mapping")
            payload.pop("dedupe_key", None)
            cleaned = self.boundary.clean(payload)
            return Finding.model_validate(cleaned), None
        except Exception as exc:  # candidate data must never escape the boundary
            return None, self._schema_error(kind="candidate", index=index, error=exc)

    def _warning(
        self,
        value: WarningValue,
        *,
        index: int,
        needs_review: bool,
    ) -> tuple[ReviewWarning | None, ReviewWarning | None]:
        try:
            if isinstance(value, ReviewWarning):
                payload = value.model_dump(mode="json")
            elif isinstance(value, Mapping):
                payload = dict(value)
            else:
                raise TypeError("warning candidate must be a mapping")
            payload["needs_human_review"] = needs_review
            cleaned = self.boundary.clean(payload)
            return ReviewWarning.model_validate(cleaned), None
        except Exception as exc:  # candidate data must never escape the boundary
            return None, self._schema_error(kind="warning", index=index, error=exc)

    def normalize(self, *batches: ReviewCandidates) -> NormalizedReviewResult:
        candidates: list[Finding] = []
        routed_warnings: list[ReviewWarning] = []
        validation_errors: list[ReviewWarning] = []
        candidate_index = 0
        warning_index = 0

        for batch in batches:
            for value in batch.findings:
                candidate_index += 1
                candidate, error = self._finding(value, candidate_index)
                if error is not None:
                    validation_errors.append(error)
                    routed_warnings.append(error)
                elif candidate is not None:
                    candidates.append(candidate)
            for values, needs_review, is_validation_error in (
                (batch.warnings, False, False),
                (batch.needs_human_review, True, False),
                (batch.validation_errors, True, True),
            ):
                for value in values:
                    warning_index += 1
                    warning, error = self._warning(value, index=warning_index, needs_review=needs_review)
                    if error is not None:
                        validation_errors.append(error)
                        routed_warnings.append(error)
                    elif warning is not None:
                        if is_validation_error:
                            validation_errors.append(warning)
                        routed_warnings.append(warning)

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
