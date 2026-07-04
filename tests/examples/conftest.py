# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Test import setup for examples that are not installed packages."""

from __future__ import annotations

import sys
from pathlib import Path


EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "examples" / "skills_code_review_agent"
if str(EXAMPLE_DIR) not in sys.path:
    sys.path.insert(0, str(EXAMPLE_DIR))

