# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Convenience entry point for the skills code review agent example."""

from __future__ import annotations

import sys
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parents[1]
for import_path in (REPO_ROOT, THIS_DIR):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from agent.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
