#!/usr/bin/env python3
# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Stdlib-only smoke test script for the code-review Skill."""

from __future__ import annotations

import argparse
import json
import os
import socket
from pathlib import Path


def _input_is_contained(input_path: Path) -> bool:
    resolved = input_path.resolve()
    skills_dir = os.environ.get("SKILLS_DIR")
    skill_root = ((Path(skills_dir) / "code-review") if skills_dir else Path(__file__).resolve().parents[1])
    expected_root = (skill_root / "work" / "inputs").resolve()
    scripts_root = (skill_root / "scripts").resolve()
    return resolved.parent == expected_root and scripts_root not in resolved.parents


def _network_probe_is_blocked() -> bool:
    try:
        with socket.create_connection(("192.0.2.1", 9), timeout=0.2):
            return False
    except OSError:
        return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    input_path = Path(args.input)
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    input_contained = _input_is_contained(input_path)
    network_probe_blocked = _network_probe_is_blocked()
    # Local development intentionally has network access; the probe is evidence
    # consumed by the required container test, not a finding by itself.
    ok = bool(payload.get("task_id")) and input_contained
    large_output_size = int(payload.get("emit_large_output") or 0)
    if large_output_size:
        print("x" * large_output_size)
    output = {
        "task_id": payload.get("task_id", ""),
        "status": "ok" if ok else "failed",
        "message": "review input is well formed" if ok else "missing task_id",
        "secret_token_in_env": "SECRET_TOKEN" in os.environ,
        "input_contained": input_contained,
        "network_probe_blocked": network_probe_blocked,
        "findings": [],
        "warnings": [],
        "needs_human_review": [],
    }
    if large_output_size:
        output["large_payload"] = "y" * large_output_size
    exit_code = 0 if ok else 1
    if "sandbox_failure" in payload.get("fixture_names", []):
        output["status"] = "failed"
        output["message"] = "intentional fixture smoke failure"
        output["needs_human_review"].append({
            "category": "sandbox",
            "title": "sandbox smoke test failed",
            "message": "sandbox_failure fixture intentionally returns a non-zero smoke-test status.",
            "confidence": 1.0,
            "source": ["smoke_test.py"],
            "needs_human_review": True,
        })
        exit_code = 2
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
