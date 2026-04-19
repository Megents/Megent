"""Megent budget feature."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


def _estimate_tokens(obj: Any) -> int:
    import json

    try:
        text = json.dumps(obj, default=str)
    except Exception:
        text = str(obj)
    return max(1, len(text) // 4)


@dataclass
class SessionBudget:
    session_id: str
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost: float = 0.0
    start_time: float = field(default_factory=time.time)
    last_call_time: float = field(default_factory=time.time)
    exceeded_reason: Optional[str] = None

    @property
    def wall_seconds(self) -> float:
        return time.time() - self.start_time

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def is_exceeded(self) -> bool:
        return self.exceeded_reason is not None


@dataclass
class BudgetReport:
    session_id: str
    calls: int
    total_tokens: int
    estimated_cost: float
    wall_seconds: float
    exceeded: bool
    exceeded_reason: Optional[str]
    max_calls: Optional[int]
    max_cost_usd: Optional[float]
    max_wall_seconds: Optional[float]

    def __str__(self) -> str:
        status = "⛔ EXCEEDED" if self.exceeded else "✅ OK"
        lines = [
            f"Budget Report [{self.session_id}] — {status}",
            f"  Calls      : {self.calls}" + (f" / {self.max_calls}" if self.max_calls else ""),
            f"  Tokens     : {self.total_tokens:,}",
            f"  Est. cost  : ${self.estimated_cost:.4f}" + (f" / ${self.max_cost_usd:.4f}" if self.max_cost_usd else ""),
            f"  Wall time  : {self.wall_seconds:.1f}s" + (f" / {self.max_wall_seconds}s" if self.max_wall_seconds else ""),
        ]
        if self.exceeded:
            lines.append(f"  Reason     : {self.exceeded_reason}")
        return "\n".join(lines)


class BudgetPolicy:
    def __init__(self, max_calls: Optional[int] = None, max_cost_usd: Optional[float] = None, max_wall_seconds: Optional[float] = None, cost_per_1k_input_tokens: float = 0.0025, cost_per_1k_output_tokens: float = 0.010, on_exceeded: str = "stop", session_id_fn=None):
        self.max_calls = max_calls
        self.max_cost_usd = max_cost_usd
        self.max_wall_seconds = max_wall_seconds
        self.cost_per_1k_input_tokens = cost_per_1k_input_tokens
        self.cost_per_1k_output_tokens = cost_per_1k_output_tokens
        self.on_exceeded = on_exceeded
        self.session_id_fn = session_id_fn or (lambda tn, a, aid: aid or "default")
        self._sessions: Dict[str, SessionBudget] = {}
        self._lock = threading.Lock()

    def _get_session(self, session_id: str) -> SessionBudget:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionBudget(session_id=session_id)
            return self._sessions[session_id]

    def reset_session(self, session_id: str) -> None:
        with self._lock:
            self._sessions[session_id] = SessionBudget(session_id=session_id)

    def report(self, session_id: str) -> BudgetReport:
        s = self._get_session(session_id)
        return BudgetReport(session_id=session_id, calls=s.calls, total_tokens=s.total_tokens, estimated_cost=s.estimated_cost, wall_seconds=s.wall_seconds, exceeded=s.is_exceeded(), exceeded_reason=s.exceeded_reason, max_calls=self.max_calls, max_cost_usd=self.max_cost_usd, max_wall_seconds=self.max_wall_seconds)

    def record_result(self, session_id: str, tool_name: str, result: Any, output_tokens: Optional[int] = None) -> None:
        s = self._get_session(session_id)
        out = output_tokens if output_tokens is not None else _estimate_tokens(result)

        with self._lock:
            s.output_tokens += out
            s.estimated_cost += (out / 1000) * self.cost_per_1k_output_tokens
            s.last_call_time = time.time()

    def _check_limits(self, s: SessionBudget) -> Optional[str]:
        if self.max_calls is not None and s.calls >= self.max_calls:
            return f"call limit reached ({s.calls}/{self.max_calls})"
        if self.max_cost_usd is not None and s.estimated_cost >= self.max_cost_usd:
            return f"cost limit reached (${s.estimated_cost:.4f}/${self.max_cost_usd:.4f})"
        if self.max_wall_seconds is not None and s.wall_seconds >= self.max_wall_seconds:
            return f"time limit reached ({s.wall_seconds:.1f}s/{self.max_wall_seconds}s)"
        return None

    def evaluate(self, tool_name: str, args: Dict[str, Any], agent_id: Optional[str] = None) -> Dict[str, Any]:
        session_id = self.session_id_fn(tool_name, args, agent_id)
        s = self._get_session(session_id)

        exceeded = self._check_limits(s)
        if exceeded:
            s.exceeded_reason = exceeded
            return self._exceeded_response(tool_name, session_id, exceeded)

        in_tokens = _estimate_tokens(args)
        with self._lock:
            s.calls += 1
            s.input_tokens += in_tokens
            s.estimated_cost += (in_tokens / 1000) * self.cost_per_1k_input_tokens
            s.last_call_time = time.time()

        return {"action": "allow", "session_id": session_id, "budget": {"calls": s.calls, "estimated_cost": round(s.estimated_cost, 6), "wall_seconds": round(s.wall_seconds, 2)}}

    def _exceeded_response(self, tool_name: str, session_id: str, reason: str) -> Dict[str, Any]:
        msg = f"[Megent Budget] Agent halted — {reason}. Session: {session_id}. Tool: {tool_name}."

        if self.on_exceeded == "raise":
            raise BudgetExceededError(msg)

        if self.on_exceeded == "stop":
            from megent.stop import SoftStop

            return {"action": "stop", "sentinel": SoftStop(reason=reason, tool_name=tool_name, stop_message=msg), "session_id": session_id, "reason": reason}

        return {"action": "deny", "session_id": session_id, "reason": reason}


class BudgetExceededError(RuntimeError):
    """Raised when on_exceeded='raise' and a budget limit is hit."""
