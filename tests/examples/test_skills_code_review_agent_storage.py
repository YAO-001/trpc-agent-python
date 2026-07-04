# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""SQL storage tests for the skills code review agent example."""

from __future__ import annotations

from agent.models import Finding
from agent.models import RedactionSummary
from agent.models import ReviewTask
from agent.models import SandboxRun
from agent.models import TelemetrySummary
from agent.storage import ReviewStorage


def test_storage_roundtrip_by_task_id(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'review.db'}"
    storage = ReviewStorage(db_url)
    task = ReviewTask(
        task_id="task-storage",
        input_type="fixture",
        input_ref="fixture:clean",
        runtime="local",
        dry_run=True,
        status="completed",
        created_at="1970-01-01T00:00:00+00:00",
    )
    finding = Finding(
        severity="high",
        category="security",
        file="app.py",
        line=3,
        title="danger",
        evidence="redacted evidence",
        recommendation="fix it",
        confidence=0.9,
        source=["rule:test"],
    )

    storage.reset_task(task.task_id)
    storage.save_task(task)
    storage.save_input(
        task_id=task.task_id,
        redacted_diff="diff --git a/app.py b/app.py\n",
        changed_files=["app.py"],
        redaction_summary=RedactionSummary(),
        input_metadata={"fixture_names": ["clean"]},
    )
    storage.save_sandbox_runs(
        [
            SandboxRun(
                run_id="sandbox-task-storage-1",
                task_id=task.task_id,
                runtime="local",
                command=["python3", "scripts/run_static_review.py"],
                decision="allow",
                output_files={"out/findings.json": "{}"},
            )
        ]
    )
    storage.save_findings(task.task_id, [finding])
    storage.save_telemetry(TelemetrySummary(task_id=task.task_id, findings_count=1))

    rows = storage.query_task(task.task_id)

    assert rows["review_tasks"][0]["task_id"] == task.task_id
    assert rows["findings"][0]["title"] == "danger"
    assert rows["sandbox_runs"][0]["output_file_count"] == 1
    assert rows["sandbox_runs"][0]["output_bytes"] == 2
    assert "redacted evidence" in storage.dump_task_text(task.task_id)
