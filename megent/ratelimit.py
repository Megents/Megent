"""Megent rate-limiting feature.

Enforces a sliding-window request cap per agent identity: a single agent
identity may not exceed ``max_calls`` tool calls within ``window_seconds``.
When the limit is hit the call is denied (deny-by-default) — the caller
(``Runtime.enforce``) logs the block to the audit trail.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, Optional


def _now() -> float:
    return time.time()


@dataclass
class RateLimitReport:
    identity: str
    count: int
    max_calls: int
    window_seconds: float
    exceeded: bool
    retry_after: float

    def __str__(self) -> str:
        status = "⛔ EXCEEDED" if self.exceeded else "✅ OK"
        line = (
            f"Rate Limit [{self.identity}] — {status}: "
            f"{self.count}/{self.max_calls} calls in {self.window_seconds:g}s"
        )
        if self.exceeded:
            line += f" (retry in {self.retry_after:.1f}s)"
        return line


class RateLimitPolicy:
    """Sliding-window per-identity rate limiter.

    Args:
        max_calls: Maximum number of tool calls permitted per identity within
            ``window_seconds``. ``0`` denies every call.
        window_seconds: Length of the sliding window in seconds (default 60).
        identity_fn: Maps ``(tool_name, args, agent_id)`` to the bucket key.
            Defaults to the agent identity, falling back to ``"default"`` when
            no identity is attributed — matching ``BudgetPolicy`` semantics.
    """

    def __init__(
        self,
        max_calls: int,
        window_seconds: float = 60.0,
        identity_fn: Optional[Callable[[str, Dict[str, Any], Optional[str]], str]] = None,
    ):
        if max_calls < 0:
            raise ValueError("max_calls must be >= 0")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.identity_fn = identity_fn or (lambda tn, a, aid: aid or "default")
        self._buckets: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, calls: Deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while calls and calls[0] <= cutoff:
            calls.popleft()

    def reset(self, identity: str) -> None:
        with self._lock:
            self._buckets.pop(identity, None)

    def report(self, identity: str) -> RateLimitReport:
        now = _now()
        with self._lock:
            calls = self._buckets.get(identity, deque())
            self._prune(calls, now)
            count = len(calls)
            retry_after = (
                max(0.0, self.window_seconds - (now - calls[0]))
                if count >= self.max_calls and calls
                else 0.0
            )
        return RateLimitReport(
            identity=identity,
            count=count,
            max_calls=self.max_calls,
            window_seconds=self.window_seconds,
            exceeded=count >= self.max_calls,
            retry_after=retry_after,
        )

    def check(
        self,
        tool_name: str,
        args: Dict[str, Any],
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Consume one token for ``agent_id`` if under the limit.

        Returns a decision dict with ``action`` of ``"allow"`` or ``"deny"``.
        A denied call is NOT recorded, so a flood of blocked attempts cannot
        keep pushing the window forward.
        """
        identity = self.identity_fn(tool_name, args, agent_id)
        now = _now()

        with self._lock:
            calls = self._buckets.setdefault(identity, deque())
            self._prune(calls, now)

            if len(calls) >= self.max_calls:
                retry_after = (
                    max(0.0, self.window_seconds - (now - calls[0])) if calls else 0.0
                )
                reason = (
                    f"rate limit exceeded: {len(calls)}/{self.max_calls} calls "
                    f"in {self.window_seconds:g}s for '{identity}'"
                )
                return {
                    "action": "deny",
                    "identity": identity,
                    "reason": reason,
                    "retry_after": round(retry_after, 3),
                }

            calls.append(now)
            count = len(calls)

        return {
            "action": "allow",
            "identity": identity,
            "count": count,
            "max_calls": self.max_calls,
            "window_seconds": self.window_seconds,
        }
