# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# This file is part of tRPC-Agent-Python and is licensed under Apache-2.0.
#
# Portions of this file are derived from HKUDS/nanobot (MIT License):
# https://github.com/HKUDS/nanobot.git
#
# Copyright (c) 2025 nanobot contributors
#
# See the project LICENSE / third-party attribution notices for details.
#
"""Heartbeat service - periodic agent wake-up to check for tasks."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from typing import Callable
from typing import Coroutine

try:
    from nanobot.heartbeat import service as heartbeat_service_package
except ModuleNotFoundError:

    class _FallbackHeartbeatService:
        """Minimal heartbeat base for nanobot versions without heartbeat."""

        def __init__(
            self,
            workspace: Path,
            provider: Any,
            model: str,
            on_execute: Callable[[str], Coroutine[Any, Any, str]] | None = None,
            on_notify: Callable[[str], Coroutine[Any, Any, None]] | None = None,
            interval_s: int = 30 * 60,
            enabled: bool = True,
        ):
            self.workspace = Path(workspace)
            self.provider = provider
            self.model = model
            self.on_execute = on_execute
            self.on_notify = on_notify
            self.interval_s = interval_s
            self.enabled = enabled
            self._task: asyncio.Task | None = None

        async def start(self) -> None:
            if not self.enabled or self._task is not None:
                return
            self._task = asyncio.create_task(self._run_loop())

        def stop(self) -> None:
            if self._task is None:
                return
            self._task.cancel()
            self._task = None

        async def _run_loop(self) -> None:
            while True:
                await asyncio.sleep(self.interval_s)
                with suppress(Exception):
                    await self._run_once()

        async def _run_once(self) -> None:
            heartbeat_file = self.workspace / "HEARTBEAT.md"
            if not heartbeat_file.exists():
                return

            content = heartbeat_file.read_text(encoding="utf-8")
            action, tasks = await self._decide(content)
            if action != "run" or not tasks or self.on_execute is None:
                return

            response = await self.on_execute(tasks)
            if self.on_notify is not None:
                await self.on_notify(response)

        async def _decide(self, content: str) -> tuple[str, str]:
            return "skip", ""

    heartbeat_service_package = SimpleNamespace(HeartbeatService=_FallbackHeartbeatService)
from trpc_agent_sdk.models import LLMModel
from trpc_agent_sdk.models import LlmRequest
from trpc_agent_sdk.types import Content
from trpc_agent_sdk.types import FunctionDeclaration
from trpc_agent_sdk.types import GenerateContentConfig
from trpc_agent_sdk.types import Part
from trpc_agent_sdk.types import Schema
from trpc_agent_sdk.types import Tool
from trpc_agent_sdk.types import Type

_HEARTBEAT_SYSTEM: str = "You are a heartbeat agent. Call the heartbeat tool to report your decision."

_HEARTBEAT_DECLARATION: FunctionDeclaration = FunctionDeclaration(
    name="heartbeat",
    description="Report heartbeat decision after reviewing tasks.",
    parameters=Schema(
        type=Type.OBJECT,
        properties={
            "action":
            Schema(
                type=Type.STRING,
                enum=["skip", "run"],
                description="skip = nothing to do, run = has active tasks",
            ),
            "tasks":
            Schema(
                type=Type.STRING,
                description="Natural-language summary of active tasks (required for run)",
            ),
        },
        required=["action"],
    ),
)


class ClawHeartbeatService(heartbeat_service_package.HeartbeatService):
    """trpc_claw heartbeat service.

    Replaces the nanobot LLMProvider.chat() call in the parent _decide
    with a direct LLMModel.generate_async() call so the service works
    inside the trpc_claw framework.
    """

    def __init__(
        self,
        workspace: Path,
        provider: LLMModel,
        model: str,
        on_execute: Callable[[str], Coroutine[Any, Any, str]] | None = None,
        on_notify: Callable[[str], Coroutine[Any, Any, None]] | None = None,
        interval_s: int = 30 * 60,
        enabled: bool = True,
    ):
        """Initialize the heartbeat service.

        Args:
            workspace: The workspace path.
            provider: The LLM provider.
            model: The model name.
            on_execute: The on_execute callback.
            on_notify: The on_notify callback.
            interval_s: The interval in seconds.
            enabled: Whether the service is enabled.
        """
        super().__init__(
            workspace=workspace,
            provider=provider,
            model=model,
            on_execute=on_execute,
            on_notify=on_notify,
            interval_s=interval_s,
            enabled=enabled,
        )

    async def _decide(self, content: str) -> tuple[str, str]:
        """Phase 1: ask LLM to decide skip/run via virtual tool call.

        Mirrors HeartbeatService._decide but drives LLMModel instead of
        LLMProvider.

        Args:
            content: The content to review.

        Returns:
            tuple[str, str]: The action and tasks.
            - action: The action to take.
            - tasks: The tasks to review.
                - skip: Nothing to do.
                - run: Has active tasks.
        """
        request = LlmRequest(
            model=self.model,
            contents=[
                Content(
                    role="user",
                    parts=[
                        Part(text=("Review the following HEARTBEAT.md and decide "
                                   "whether there are active tasks.\n\n"
                                   f"{content}"))
                    ],
                )
            ],
            config=GenerateContentConfig(
                system_instruction=_HEARTBEAT_SYSTEM,
                tools=[Tool(function_declarations=[_HEARTBEAT_DECLARATION])],
            ),
        )

        response = None
        model: LLMModel = self.provider
        async for resp in model.generate_async(request, stream=False):
            if resp.content:
                response = resp
                break

        if response is None or response.content is None:
            return "skip", ""

        for part in response.content.parts or []:
            fc = getattr(part, "function_call", None)
            if fc and getattr(fc, "name", None) == "heartbeat":
                args: dict[str, Any] = dict(fc.args) if fc.args else {}
                return args.get("action", "skip"), args.get("tasks", "")

        return "skip", ""
