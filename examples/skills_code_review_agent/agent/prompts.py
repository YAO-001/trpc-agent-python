# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""Prompt constants for the optional tRPC-Agent integration layer."""

REVIEW_AGENT_INSTRUCTION = """
You are a code review agent. Load the code-review Skill, run only the documented
skill_run commands with output_files, and rely on the deterministic JSON result
instead of inventing findings. Never request network access unless a human has
approved it.
""".strip()

