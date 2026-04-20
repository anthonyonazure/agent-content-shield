"""
Agent Content Shield — Python Middleware Adapter

Ergonomics modeled on Guardian SDK's async context manager pattern so
migration / A-B testing between the two is straightforward. Three entry
points for Python LLM frameworks (LangChain, LlamaIndex, AutoGen,
CrewAI, Phidata, plain SDK calls):

    1. async context manager — wrap a single LLM call
    2. decorator             — wrap a function that returns an LLM reply
    3. direct function call  — for imperative / custom glue

Example:

    from agent_content_shield.python_middleware import Shield

    shield = Shield(session_id="user-42")

    async with shield.guard(prompt) as guard:
        response = await llm.acomplete(prompt)
        verdict = guard.check_output(response)
        if verdict.verdict == "BLOCK":
            response = verdict.redacted_output

    @shield.protect
    async def reply(prompt: str) -> str:
        return await llm.acomplete(prompt)
"""

from __future__ import annotations

import functools
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from core.post_flight import PostFlightResult, scan_output as _scan_output
from core.escalation_tracker import (
    TurnResult,
    record_turn as _record_turn,
)


@dataclass
class GuardContext:
    """Handle returned by ``Shield.guard()``; exposes the turn's
    pre-flight escalation check and a ``check_output`` helper that runs
    the post-flight scan on the model's response."""

    session_id: str
    prompt: str
    turn: TurnResult
    context: str = "general"

    def check_output(self, response: str) -> PostFlightResult:
        return _scan_output(response, context=self.context)


class Shield:
    """Middleware entry point bound to a session id.

    A ``Shield`` instance is safe to share across concurrent requests
    for the same user/session — the underlying escalation tracker is
    keyed on session id and uses an in-memory store. Instantiate one
    shield per end-user (or per conversation) to keep their turns
    isolated from other users'.
    """

    def __init__(
        self,
        session_id: str,
        *,
        context: str = "general",
        window_size: int = 5,
        threshold: float = 0.5,
    ) -> None:
        self.session_id = session_id
        self.context = context
        self.window_size = window_size
        self.threshold = threshold

    def record(self, prompt: str) -> TurnResult:
        return _record_turn(
            self.session_id,
            prompt,
            window_size=self.window_size,
            threshold=self.threshold,
        )

    def scan(self, response: str) -> PostFlightResult:
        return _scan_output(response, context=self.context)

    @asynccontextmanager
    async def guard(self, prompt: str):
        """Async context manager — yields a ``GuardContext``.

        Recording the turn happens on enter; the caller can then run
        the LLM call inside the ``async with`` body and invoke
        ``ctx.check_output(response)`` to post-flight-scan the result.
        """
        turn = self.record(prompt)
        try:
            yield GuardContext(
                session_id=self.session_id,
                prompt=prompt,
                turn=turn,
                context=self.context,
            )
        finally:
            # No teardown state — kept for future telemetry hooks.
            pass

    def protect(
        self, fn: Callable[..., Awaitable[str]]
    ) -> Callable[..., Awaitable[str]]:
        """Decorator: wraps ``async def reply(prompt: str) -> str``.

        Records the turn (escalation check), awaits the wrapped function,
        then post-flight-scans the returned string. If the post-flight
        verdict is REDACT or BLOCK, returns the redacted output in place
        of the original.

        The wrapped function must take ``prompt`` as its first positional
        argument. Enforced, not inferred — inferring would mask bugs.
        """

        @functools.wraps(fn)
        async def wrapped(prompt: str, *args: Any, **kwargs: Any) -> str:
            self.record(prompt)
            response = await fn(prompt, *args, **kwargs)
            verdict = self.scan(response)
            if verdict.verdict in {"REDACT", "BLOCK"} and verdict.redacted_output:
                return verdict.redacted_output
            return response

        return wrapped


__all__ = ["Shield", "GuardContext"]
