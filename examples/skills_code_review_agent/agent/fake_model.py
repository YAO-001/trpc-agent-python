# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Deterministic fake model used to document dry-run behavior."""

from __future__ import annotations


class FakeReviewModel:
    def complete(self, prompt: str) -> str:
        return "dry-run: deterministic rule engine completed"
