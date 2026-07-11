# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Independent, frozen-corpus acceptance evaluation for Issue #92."""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from pydantic import BaseModel
from pydantic import Field
from sqlalchemy import select

from .input_resolver import FIXTURE_ORDER
from .orchestrator import ReviewOrchestrator
from .storage import ReviewStorage
from .storage import review_tasks

ResultKey = tuple[str, int, str]
EVAL_DIR = Path(__file__).resolve().parents[1] / "eval"
_EXPECTED_COUNTS = {"high_risk_cases.json": 10, "safe_cases.json": 15, "secret_cases.json": 20}
_SAFE_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class FixtureAcceptance(BaseModel):
    fixture: str
    task_id: str
    json_path: str
    markdown_path: str
    findings_count: int
    audit_counts: dict[str, int]


class FixtureAcceptanceSummary(BaseModel):
    fixtures: list[FixtureAcceptance]


class CorpusAcceptanceSummary(BaseModel):
    high_risk_recall: float
    safe_false_positive_rate: float
    secret_redaction_recall: float
    high_risk_detected: int
    high_risk_total: int
    safe_false_positives: int
    safe_locations: int
    secrets_redacted: int
    secrets_total: int
    high_risk_misses: dict[str, list[list[Any]]] = Field(default_factory=dict)
    safe_case_false_positives: dict[str, list[list[Any]]] = Field(default_factory=dict)
    raw_secret_leaks: list[str] = Field(default_factory=list)
    wall_clock_seconds: float = 0.0
    fixtures: list[FixtureAcceptance] = Field(default_factory=list)
    summary_path: str = ""


def detection_recall(expected: set[ResultKey], predictions: set[ResultKey]) -> float:
    return 1.0 if not expected else len(expected & predictions) / len(expected)


def false_positive_rate(safe_locations: int, predictions: set[ResultKey]) -> float:
    if safe_locations <= 0:
        raise ValueError("safe corpus must contain labeled locations")
    return len(predictions) / safe_locations


def _load(name: str) -> list[dict[str, Any]]:
    rows = json.loads((EVAL_DIR / name).read_text(encoding="utf-8"))
    if not isinstance(rows, list) or len(rows) != _EXPECTED_COUNTS[name]:
        raise ValueError(f"{name} must contain exactly {_EXPECTED_COUNTS[name]} cases")
    ids = [row.get("id") for row in rows if isinstance(row, dict)]
    if len(ids) != len(rows) or len(set(ids)) != len(ids) or any(
            not isinstance(item, str) or _SAFE_ID_RE.fullmatch(item) is None for item in ids):
        raise ValueError(f"{name} must contain unique safe case IDs")
    if name == "secret_cases.json":
        raw_values = [row.get("raw_value") for row in rows]
        digests = [hashlib.sha256(item.encode("utf-8")).hexdigest() for item in raw_values if isinstance(item, str)]
        if (len(digests) != len(rows) or len(set(raw_values)) != len(rows) or len(set(digests)) != len(rows)
                or any(not isinstance(row.get("text"), str) or not row.get("text") for row in rows)):
            raise ValueError("secret corpus values and digests must be unique non-empty strings")
        return rows
    expected_keys: list[ResultKey] = []
    for row in rows:
        changed_files = row.get("changed_files")
        added_lines = row.get("added_lines")
        if not isinstance(changed_files, list) or not changed_files or not isinstance(added_lines, list):
            raise ValueError(f"{name} cases require changed_files and added_lines")
        normalized = [_safe_relative_path(item) for item in changed_files]
        if len(set(normalized)) != len(normalized):
            raise ValueError(f"{name} changed_files must be unique")
        for line in added_lines:
            if (not isinstance(line, dict) or _safe_relative_path(line.get("file")) not in normalized
                    or type(line.get("line")) is not int or line["line"] <= 0
                    or not isinstance(line.get("content"), str)):
                raise ValueError(f"{name} contains an invalid added line")
        if name == "high_risk_cases.json":
            label = row.get("expected")
            if not isinstance(label, dict):
                raise ValueError("high-risk cases require one explicit expected key")
            key = (_safe_relative_path(label.get("file")), label.get("line"), label.get("category"))
            if key[0] not in normalized or type(key[1]) is not int or key[1] <= 0 or not isinstance(key[2], str):
                raise ValueError("high-risk expected key is invalid")
            expected_keys.append(key)
    if expected_keys and len(set(expected_keys)) != len(expected_keys):
        raise ValueError("high-risk expected keys must be unique")
    return rows


def _safe_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("corpus paths must be non-empty relative POSIX paths")
    path = PurePosixPath(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts or path.as_posix() != value:
        raise ValueError("corpus paths must be normalized relative POSIX paths")
    return value


def _case_diff(case: dict[str, Any]) -> str:
    lines_by_file: dict[str, list[dict[str, Any]]] = {path: [] for path in case["changed_files"]}
    for line in case["added_lines"]:
        lines_by_file[line["file"]].append(line)
    chunks: list[str] = []
    for path, rows in lines_by_file.items():
        rows = sorted(rows, key=lambda item: item["line"])
        if not rows:
            rows = [{"line": 1, "content": "# frozen acceptance companion change"}]
        for row in rows:
            contexts = list(row.get("context_after", []))
            count = 1 + len(contexts)
            chunks.extend([
                f"diff --git a/{path} b/{path}",
                "new file mode 100644",
                "index 0000000..1111111",
                "--- /dev/null",
                f"+++ b/{path}",
                f"@@ -0,0 +{row['line']},{count} @@",
                f"+{row['content']}",
                *[f"+{item}" for item in contexts],
            ])
    return "\n".join(chunks) + "\n"


def _predictions(report: Any) -> set[ResultKey]:
    keys = {(item.file, item.line, item.category) for item in report.findings}
    for item in [*report.warnings, *report.needs_human_review]:
        if item.category != "sandbox" and item.file:
            keys.add((item.file, item.line, item.category))
    return keys


def _run_case(case: dict[str, Any], *, output_dir: Path, db_url: str) -> Any:
    corpus_root = (output_dir / "corpora").resolve()
    case_dir = (corpus_root / case["id"]).resolve()
    if case_dir.parent != corpus_root:
        raise ValueError("corpus case directory escapes the output root")
    case_dir.mkdir(parents=True, exist_ok=True)
    diff_path = case_dir / "input.diff"
    diff_path.write_text(_case_diff(case), encoding="utf-8")
    return ReviewOrchestrator(db_url=db_url, output_dir=case_dir).review(diff_file=str(diff_path),
                                                                         dry_run=True,
                                                                         runtime="local")


def evaluate_corpora(*, output_dir: str | Path, db_url: str) -> CorpusAcceptanceSummary:
    started = time.monotonic()
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    high_risk = _load("high_risk_cases.json")
    safe = _load("safe_cases.json")
    secret_cases = _load("secret_cases.json")

    expected: set[ResultKey] = set()
    detected: set[ResultKey] = set()
    misses: dict[str, list[list[Any]]] = {}
    for case in high_risk:
        key_data = case["expected"]
        key = (key_data["file"], key_data["line"], key_data["category"])
        predictions = _predictions(_run_case(case, output_dir=output, db_url=db_url))
        expected.add(key)
        detected.update(predictions & {key})
        if key not in predictions:
            misses[case["id"]] = [list(key)]

    safe_false_positive_count = 0
    false_positives: dict[str, list[list[Any]]] = {}
    for case in safe:
        predictions = _predictions(_run_case(case, output_dir=output, db_url=db_url))
        safe_false_positive_count += len(predictions)
        if predictions:
            false_positives[case["id"]] = [list(item) for item in sorted(predictions)]

    secret_case = {
        "id":
        "secret-redaction-corpus",
        "changed_files": ["src/secret_corpus.py", "tests/test_secret_corpus.py"],
        "added_lines": [{
            "file": "src/secret_corpus.py",
            "line": 10 + index,
            "content": item["text"]
        } for index, item in enumerate(secret_cases)],
    }
    secret_report = _run_case(secret_case, output_dir=output, db_url=db_url)
    event_digests = {event.sha256 for event in secret_report.redaction_summary.events}
    redacted = sum(
        hashlib.sha256(item["raw_value"].encode("utf-8")).hexdigest() in event_digests for item in secret_cases)
    secret_output = output / "corpora" / secret_case["id"]
    report_paths = [secret_output / Path(secret_report.report_paths[key]).name for key in ("json", "markdown")]
    if any(not path.is_file() or secret_output.resolve() not in path.resolve().parents for path in report_paths):
        raise ValueError("secret corpus report path is missing or outside its output directory")
    persisted = {
        str(path): path.read_text(encoding="utf-8")
        for path in output.rglob("*") if path.is_file() and path.suffix.lower() in {".json", ".md"}
    }
    storage = ReviewStorage(db_url)
    with storage.engine.connect() as connection:
        task_ids = connection.execute(select(review_tasks.c.task_id)).scalars().all()
    persisted.update({f"database:{task_id}": storage.dump_task_text(task_id) for task_id in task_ids})
    leaks = [
        f"{item['id']}:{location}" for item in secret_cases for location, text in persisted.items()
        if item["raw_value"] in text
    ]

    summary = CorpusAcceptanceSummary(
        high_risk_recall=detection_recall(expected, detected),
        safe_false_positive_rate=safe_false_positive_count / len(safe),
        secret_redaction_recall=redacted / len(secret_cases),
        high_risk_detected=len(detected),
        high_risk_total=len(expected),
        safe_false_positives=safe_false_positive_count,
        safe_locations=len(safe),
        secrets_redacted=redacted,
        secrets_total=len(secret_cases),
        high_risk_misses=misses,
        safe_case_false_positives=false_positives,
        raw_secret_leaks=leaks,
        wall_clock_seconds=time.monotonic() - started,
    )
    return _write_summary(summary, output)


def evaluate_public_fixtures(*, output_dir: str | Path, db_url: str) -> FixtureAcceptanceSummary:
    output = Path(output_dir)
    fixtures: list[FixtureAcceptance] = []
    storage = ReviewStorage(db_url)
    for fixture in FIXTURE_ORDER:
        report = ReviewOrchestrator(db_url=db_url, output_dir=output / "fixtures" / fixture).review(fixture=fixture,
                                                                                                    dry_run=True,
                                                                                                    runtime="local")
        rows = storage.query_task(report.task_id)
        fixture_output = output / "fixtures" / fixture
        fixtures.append(
            FixtureAcceptance(
                fixture=fixture,
                task_id=report.task_id,
                json_path=str(fixture_output / Path(report.report_paths["json"]).name),
                markdown_path=str(fixture_output / Path(report.report_paths["markdown"]).name),
                findings_count=len(report.findings),
                audit_counts={
                    "tasks": len(rows["review_tasks"]),
                    "inputs": len(rows["review_inputs"]),
                    "filter_intercepts": len(rows["filter_intercepts"]),
                    "sandbox_runs": len(rows["sandbox_runs"]),
                    "findings": len(rows["findings"]),
                    "telemetry_summaries": len(rows["telemetry_summaries"]),
                    "reports": len(rows["reports"]),
                },
            ))
    return FixtureAcceptanceSummary(fixtures=fixtures)


def evaluate_acceptance(*,
                        output_dir: str | Path,
                        db_url: str,
                        include_fixtures: bool = False) -> CorpusAcceptanceSummary:
    started = time.monotonic()
    summary = evaluate_corpora(output_dir=output_dir, db_url=db_url)
    if include_fixtures:
        summary.fixtures = evaluate_public_fixtures(output_dir=output_dir, db_url=db_url).fixtures
    summary.wall_clock_seconds = time.monotonic() - started
    return _write_summary(summary, Path(output_dir))


def _write_summary(summary: CorpusAcceptanceSummary, output_dir: Path) -> CorpusAcceptanceSummary:
    path = output_dir / "acceptance_summary.json"
    summary.summary_path = str(path)
    path.write_text(json.dumps(summary.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")
    return summary
