"""Megent graceful-stop feature."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set


@dataclass
class SoftStop:
    reason: str
    tool_name: str
    stop_message: str = ""

    def __str__(self) -> str:
        msg = self.stop_message or (f"[MEGENT STOP] Tool '{self.tool_name}' was halted gracefully. Reason: {self.reason}. Do not retry.")
        return msg

    def __repr__(self) -> str:
        return f"SoftStop(tool={self.tool_name!r}, reason={self.reason!r})"


def is_stopped(result: Any) -> bool:
    return isinstance(result, SoftStop)


class GracefulStop:
    def __init__(self, tools: List[str] | None = None, reason: str = "Tool execution halted by policy.", stop_message: str = ""):
        self._lock = threading.Lock()
        self._stopped: Set[str] = set(tools or [])
        self.reason = reason
        self.stop_message = stop_message

    def stop(self, tool_name: str, reason: Optional[str] = None) -> None:
        with self._lock:
            self._stopped.add(tool_name)
        if reason:
            self.reason = reason

    def stop_all(self, reason: Optional[str] = None) -> None:
        with self._lock:
            self._stopped.add("*")
        if reason:
            self.reason = reason

    def resume(self, tool_name: str) -> None:
        with self._lock:
            self._stopped.discard(tool_name)
            self._stopped.discard("*")

    def clear(self) -> None:
        with self._lock:
            self._stopped.clear()

    def _is_stopped(self, tool_name: str) -> bool:
        with self._lock:
            return "*" in self._stopped or tool_name in self._stopped

    def evaluate(self, tool_name: str, args: Dict[str, Any], **_) -> Dict[str, Any]:
        if not self._is_stopped(tool_name):
            return {"action": "allow"}

        sentinel = SoftStop(reason=self.reason, tool_name=tool_name, stop_message=self.stop_message)
        return {"action": "stop", "sentinel": sentinel, "reason": self.reason}
