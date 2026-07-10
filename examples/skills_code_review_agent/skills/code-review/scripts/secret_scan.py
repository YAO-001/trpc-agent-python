#!/usr/bin/env python3
# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Stdlib-only redaction placeholder scanner."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PLACEHOLDER_RE = re.compile(r"\[REDACTED:SECRET:([^:\]]+):([a-f0-9]{8})\]")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    by_type = {}
    for line in payload.get("added_lines", []):
        for secret_type, _digest in PLACEHOLDER_RE.findall(line.get("content", "")):
            by_type[secret_type] = by_type.get(secret_type, 0) + 1
    output = {
        "task_id": payload.get("task_id", ""),
        "status": "ok",
        "redacted_secret_placeholders": sum(by_type.values()),
        "by_type": dict(sorted(by_type.items())),
        "findings": [],
        "warnings": [],
        "needs_human_review": [],
    }
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
