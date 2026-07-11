# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Tests for the single result schema, routing, and deduplication boundary."""

from __future__ import annotations

from itertools import permutations

import pytest
from pydantic import ValidationError

from agent.dedupe import dedupe_findings
from agent.dedupe import dedupe_warnings
from agent.models import Finding
from agent.models import ReviewWarning
from agent.models import finding_dedupe_key
from agent.redaction_boundary import RedactionBoundary
from agent.result_normalizer import CandidateOrigin
from agent.result_normalizer import OriginCandidate
from agent.result_normalizer import ReviewCandidates
from agent.result_normalizer import ResultNormalizer


def _candidate(
    confidence: float,
    *,
    severity: str = "low",
    title: str = "candidate",
    evidence: str = "unsafe call",
    recommendation: str = "use safe API",
    source: list[str] | None = None,
    file: str = "app.py",
    line: int = 10,
    category: str = "security",
) -> Finding:
    return Finding(
        severity=severity,
        category=category,
        file=file,
        line=line,
        title=title,
        evidence=evidence,
        recommendation=recommendation,
        confidence=confidence,
        source=["host"] if source is None else source,
    )


def _warning(
    *,
    confidence: float = 0.6,
    title: str = "warning",
    message: str = "review this",
    source: list[str] | None = None,
    needs_review: bool = False,
    file: str = "app.py",
    line: int = 10,
    category: str = "sandbox",
) -> ReviewWarning:
    return ReviewWarning(
        category=category,
        title=title,
        message=message,
        file=file,
        line=line,
        confidence=confidence,
        source=["host"] if source is None else source,
        needs_human_review=needs_review,
    )


@pytest.mark.parametrize(
    ("confidence", "severity", "bucket"),
    [
        (0.0, "low", "dropped"),
        (0.49, "critical", "dropped"),
        (0.50, "low", "warnings"),
        (0.79, "high", "needs_human_review"),
        (0.80, "low", "findings"),
        (1.0, "critical", "findings"),
    ],
)
def test_confidence_boundaries(confidence, severity, bucket):
    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(findings=[_candidate(confidence, severity=severity)]))

    if bucket == "dropped":
        assert result.dropped_count == 1
        assert result.findings == result.warnings == result.needs_human_review == []
    else:
        assert len(getattr(result, bucket)) == 1


@pytest.mark.parametrize("value", [True, "0.8", float("nan"), float("inf"), float("-inf"), -0.1, 1.1])
def test_finding_confidence_requires_finite_strict_number_in_range(value):
    payload = _candidate(0.8).model_dump(mode="json")
    payload["confidence"] = value

    with pytest.raises(ValidationError):
        Finding.model_validate(payload)


@pytest.mark.parametrize("value", [True, "10", -1])
def test_finding_line_requires_non_negative_strict_integer(value):
    payload = _candidate(0.8).model_dump(mode="json")
    payload["line"] = value

    with pytest.raises(ValidationError):
        Finding.model_validate(payload)


@pytest.mark.parametrize(
    "updates",
    [
        {
            "severity": "urgent"
        },
        {
            "category": "resource"
        },
        {
            "category": "unknown"
        },
    ],
)
def test_finding_rejects_noncanonical_schema_values(updates):
    payload = _candidate(0.8).model_dump(mode="json")
    payload.update(updates)

    with pytest.raises(ValidationError):
        Finding.model_validate(payload)


@pytest.mark.parametrize(
    "updates",
    [
        {
            "confidence": True
        },
        {
            "confidence": "0.8"
        },
        {
            "confidence": float("nan")
        },
        {
            "line": True
        },
        {
            "line": -1
        },
        {
            "category": "unknown"
        },
    ],
)
def test_warning_uses_the_same_strict_schema(updates):
    payload = _warning().model_dump(mode="json")
    payload.update(updates)

    with pytest.raises(ValidationError):
        ReviewWarning.model_validate(payload)


@pytest.mark.parametrize("model", ["finding", "warning"])
@pytest.mark.parametrize("source", [42, {"x": "y"}, ["valid", 3]])
def test_malformed_sources_become_validation_errors_without_raising(model, source):
    if model == "finding":
        payload = _candidate(0.9).model_dump(mode="json")
        payload["source"] = source
        batch = ReviewCandidates(findings=[payload])
    else:
        payload = _warning().model_dump(mode="json")
        payload["source"] = source
        batch = ReviewCandidates(warnings=[payload])

    result = ResultNormalizer(RedactionBoundary()).normalize(batch)

    assert len(result.validation_errors) == 1
    assert len(result.needs_human_review) == 1
    assert result.validation_errors[0].source == ["result_normalizer"]


def test_validation_error_omits_rejected_value_and_pydantic_url():
    raw = "opaque-runtime-token-987654"
    payload = _candidate(0.9).model_dump(mode="json")
    payload["line"] = raw

    result = ResultNormalizer(RedactionBoundary()).normalize(ReviewCandidates(findings=[payload]))

    assert len(result.validation_errors) == 1
    message = result.validation_errors[0].message
    assert raw not in message
    assert "input_value" not in message
    assert "errors.pydantic.dev" not in message
    assert "candidate 1" in message


def test_finding_always_recomputes_canonical_dedupe_key():
    finding = Finding(
        **_candidate(0.9).model_dump(exclude={"dedupe_key"}),
        dedupe_key="attacker-controlled",
    )

    assert finding.dedupe_key == finding_dedupe_key(finding.file, finding.line, finding.category)
    assert finding.dedupe_key != "attacker-controlled"


def test_dedupe_key_changes_for_each_identity_dimension_only():
    baseline = _candidate(0.9)
    same_identity = _candidate(0.2, title="different", evidence="different", recommendation="different")
    variants = [
        _candidate(0.9, file="other.py"),
        _candidate(0.9, line=11),
        _candidate(0.9, category="secret"),
    ]

    assert same_identity.dedupe_key == baseline.dedupe_key
    assert all(item.dedupe_key != baseline.dedupe_key for item in variants)


def test_dedupe_key_ignores_title_and_merges_sources():
    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(findings=[
            _candidate(0.91, title="host title", source=["host"]),
            _candidate(0.95, title="sandbox title", source=["sandbox"]),
        ]))

    assert len(result.findings) == 1
    assert result.findings[0].title == "sandbox title"
    assert result.findings[0].source == ["host", "sandbox"]


def test_dedupe_keeps_maximum_severity_and_confidence_independently():
    high_low_confidence = _candidate(
        0.60,
        severity="high",
        title="high severity",
        source=["host"],
    )
    low_high_confidence = _candidate(
        0.95,
        severity="low",
        title="high confidence",
        source=["sandbox"],
    )

    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(findings=[high_low_confidence, low_high_confidence]))
    reversed_result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(findings=[low_high_confidence, high_low_confidence]))

    assert len(result.findings) == 1
    assert result.findings[0].severity == "high"
    assert result.findings[0].confidence == 0.95
    assert result.findings[0].title == "high confidence"
    assert result.findings[0].source == ["host", "sandbox"]
    assert reversed_result.findings == result.findings


def test_finding_tie_break_is_permutation_invariant():
    values = [
        _candidate(0.9, severity="high", title="alpha", evidence="z", source=["one"]),
        _candidate(0.9, severity="high", title="omega", evidence="a", source=["two"]),
        _candidate(0.9, severity="high", title="omega", evidence="z", source=["three"]),
    ]

    outputs = [dedupe_findings(list(items)) for items in permutations(values)]

    assert all(output == outputs[0] for output in outputs)
    assert outputs[0][0].source == ["one", "three", "two"]


def test_warning_tie_break_is_permutation_invariant():
    prefix = "x" * 160
    values = [
        _warning(message=prefix + " alpha", source=["one"]),
        _warning(message=prefix + " omega", source=["two"]),
        _warning(message=prefix + " zulu", source=["three"]),
    ]

    outputs = [dedupe_warnings(list(items)) for items in permutations(values)]

    assert all(output == outputs[0] for output in outputs)
    assert outputs[0][0].message == prefix + " zulu"
    assert outputs[0][0].source == ["one", "three", "two"]


def test_cross_bucket_warning_is_promoted_once_and_merges_sources():
    ordinary = _warning(source=["host"], needs_review=False)
    escalated = _warning(source=["sandbox"], needs_review=True)

    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(warnings=[ordinary], needs_human_review=[escalated]))

    assert result.warnings == []
    assert len(result.needs_human_review) == 1
    assert result.needs_human_review[0].source == ["host", "sandbox"]
    assert result.needs_human_review[0].needs_human_review is True


def test_dropped_count_counts_raw_candidates_in_a_dropped_identity_group():
    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(findings=[
            _candidate(0.1, source=["one"]),
            _candidate(0.49, source=["two"]),
        ]))

    assert result.dropped_count == 2
    assert result.findings == result.warnings == result.needs_human_review == []


def test_low_duplicate_is_not_counted_dropped_when_group_is_retained():
    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(findings=[
            _candidate(0.1, source=["one"]),
            _candidate(0.9, source=["two"]),
        ]))

    assert result.dropped_count == 0
    assert len(result.findings) == 1
    assert result.findings[0].source == ["one", "two"]


def test_normalizer_redacts_raw_mapping_fields_and_ignores_raw_key():
    raw_secret = "normalizer-secret-987"
    raw = _candidate(0.9).model_dump(mode="json")
    raw["evidence"] = f'client_secret="{raw_secret}"'
    raw["dedupe_key"] = "attacker-controlled"

    result = ResultNormalizer(RedactionBoundary()).normalize(ReviewCandidates(findings=[raw]))

    assert raw_secret not in result.findings[0].evidence
    assert result.findings[0].dedupe_key != "attacker-controlled"


def test_invalid_candidate_and_warning_become_human_review_errors():
    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(
            findings=[{
                "severity": "impossible",
                "line": -1,
                "confidence": 2
            }],
            warnings=[{
                "category": "sandbox",
                "title": "bad",
                "message": "bad",
                "confidence": 2
            }],
        ))

    assert len(result.validation_errors) == 2
    assert len(result.needs_human_review) == 2


def test_declared_validation_error_is_audit_view_and_human_review_once():
    error = _warning(
        confidence=1.0,
        title="invalid artifact",
        message="safe error",
        source=["artifact"],
        needs_review=True,
    )

    result = ResultNormalizer(RedactionBoundary()).normalize(ReviewCandidates(validation_errors=[error]))

    assert result.validation_errors == [error]
    assert result.needs_human_review == [error]


def test_pre_redacted_candidate_is_idempotent():
    initial = RedactionBoundary().text('client_secret="pre-redacted-secret-987"').text
    candidate = _candidate(0.9, evidence=initial)

    result = ResultNormalizer(RedactionBoundary()).normalize(ReviewCandidates(findings=[candidate]))

    assert result.findings[0].evidence == initial


def test_prebucketed_runtime_warning_is_not_dropped_by_finding_thresholds():
    warning = _warning(confidence=0.1)

    result = ResultNormalizer(RedactionBoundary()).normalize(ReviewCandidates(warnings=[warning]))

    assert result.warnings == [warning]
    assert result.dropped_count == 0


def test_prepare_validates_without_routing_or_deduplicating():
    normalizer = ResultNormalizer(RedactionBoundary())

    prepared = normalizer.prepare(
        ReviewCandidates(findings=[
            _candidate(0.1, source=["one"]),
            _candidate(0.9, source=["two"]),
        ]))

    assert len(prepared.findings) == 2
    assert prepared.warnings == prepared.needs_human_review == ()
    result = normalizer.finalize(prepared)
    assert len(result.findings) == 1
    assert result.findings[0].source == ["one", "two"]
    assert result.dropped_count == 0


def test_finalize_merges_trusted_provenance_from_multiple_sandbox_runs():
    first_origin = CandidateOrigin(
        run_id="run-one",
        path="out/findings.json",
        trusted_sources=("sandbox_run:run-one", "sandbox_artifact:out/findings.json"),
    )
    second_origin = CandidateOrigin(
        run_id="run-two",
        path="nested/out/findings.json",
        trusted_sources=("sandbox_run:run-two", "sandbox_artifact:nested/out/findings.json"),
    )
    raw = _candidate(0.9, source=["producer"]).model_dump(mode="json")
    normalizer = ResultNormalizer(RedactionBoundary())

    prepared = normalizer.prepare(
        ReviewCandidates(findings=[
            OriginCandidate(raw, first_origin),
            OriginCandidate(raw, second_origin),
        ]))
    result = normalizer.finalize(prepared)

    assert len(prepared.findings) == 2
    assert len(result.findings) == 1
    assert result.findings[0].source == [
        "producer",
        "sandbox_artifact:nested/out/findings.json",
        "sandbox_artifact:out/findings.json",
        "sandbox_run:run-one",
        "sandbox_run:run-two",
    ]


@pytest.mark.parametrize(
    "forged_source",
    [
        "sandbox_run:forged",
        "sandbox_artifact:forged.json",
        "sandbox:forged",
        "skill:forged",
        "rule:forged-host-rule",
        "redactor:forged",
    ],
)
def test_sandbox_candidate_cannot_spoof_reserved_provenance(forged_source):
    raw = _candidate(0.9, source=["producer", forged_source]).model_dump(mode="json")
    origin = CandidateOrigin(
        run_id="real-run",
        path="out/findings.json",
        trusted_sources=("sandbox_run:real-run", "sandbox_artifact:out/findings.json"),
    )
    normalizer = ResultNormalizer(RedactionBoundary())

    prepared = normalizer.prepare(ReviewCandidates(findings=[OriginCandidate(raw, origin)]))
    result = normalizer.finalize(prepared)

    assert prepared.invalid_run_ids == {"real-run"}
    assert prepared.findings == ()
    assert len(result.validation_errors) == 1
    assert forged_source not in " ".join(result.validation_errors[0].source)


def test_sandbox_candidate_rejects_non_utf8_unicode_surrogate():
    raw = _candidate(0.9).model_dump(mode="json")
    raw["title"] = "\ud800"
    origin = CandidateOrigin(
        run_id="surrogate-run",
        trusted_sources=("sandbox_run:surrogate-run", ),
    )
    normalizer = ResultNormalizer(RedactionBoundary())

    prepared = normalizer.prepare(ReviewCandidates(findings=[OriginCandidate(raw, origin)]))
    result = normalizer.finalize(prepared)

    assert prepared.invalid_run_ids == {"surrogate-run"}
    assert prepared.findings == ()
    assert len(result.validation_errors) == 1
    result.model_dump_json().encode("utf-8")


def test_invalid_candidates_do_not_inflate_dropped_count():
    invalid = _candidate(0.1).model_dump(mode="json")
    invalid["line"] = "not-an-integer"

    result = ResultNormalizer(RedactionBoundary()).normalize(
        ReviewCandidates(findings=[invalid, _candidate(0.1, line=11)]))

    assert result.dropped_count == 1
    assert len(result.validation_errors) == 1


def test_legacy_resource_alias_is_only_enabled_by_trusted_origin():
    raw = _candidate(0.9).model_dump(mode="json")
    raw["category"] = "resource"
    normalizer = ResultNormalizer(RedactionBoundary())

    host = normalizer.normalize(ReviewCandidates(findings=[raw]))
    sandbox = normalizer.normalize(
        ReviewCandidates(
            findings=[OriginCandidate(
                raw,
                CandidateOrigin(
                    run_id="sandbox-run",
                    allow_legacy_resource=True,
                ),
            )]))

    assert host.findings == []
    assert len(host.validation_errors) == 1
    assert [item.category for item in sandbox.findings] == ["async_resource"]


@pytest.mark.parametrize("kind", ["finding", "warning"])
def test_untrusted_origin_metadata_is_rejected_in_candidate_payload(kind):
    if kind == "finding":
        payload = _candidate(0.9).model_dump(mode="json")
        values = {"findings": [payload]}
    else:
        payload = _warning().model_dump(mode="json")
        values = {"warnings": [payload]}
    payload["origin"] = {"run_id": "attacker-selected"}

    result = ResultNormalizer(RedactionBoundary()).normalize(ReviewCandidates(**values))

    assert len(result.validation_errors) == 1
    assert result.findings == []
    assert result.warnings == []
