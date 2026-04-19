"""Megent awareness feature."""

from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional, Set


@dataclass
class ToolEvent:
    tool_name: str
    args: Dict[str, Any]
    result: Any = None
    timestamp: float = field(default_factory=time.time)
    agent_id: Optional[str] = None


@dataclass
class AlertReport:
    detector: str
    tool_name: str
    reason: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


def _token_overlap(a: str, b: str, stopwords: Set[str] | None = None) -> float:
    sw = stopwords or {
        "the", "a", "an", "of", "in", "to", "and", "or", "is",
        "for", "on", "at", "by", "with", "from",
    }

    def tok(s: str) -> Set[str]:
        words = re.findall(r"\w+", s.lower())
        return {w for w in words if w not in sw and len(w) > 2}

    ta, tb = tok(a), tok(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _flatten_args(args: Dict[str, Any]) -> str:
    parts = []
    for v in args.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict):
            parts.append(_flatten_args(v))
        elif isinstance(v, list):
            parts.extend(str(x) for x in v)
    return " ".join(parts)


class ExfiltrationDetector:
    name = "ExfiltrationDetector"

    SOURCE_PATTERNS = re.compile(r"get|fetch|read|load|retrieve|download|query|select|find", re.I)
    EGRESS_PATTERNS = re.compile(r"search|send|post|upload|email|webhook|http|request|write|export", re.I)

    def __init__(self, threshold: float = 0.25, window: int = 5, source_tools: Optional[List[str]] = None, egress_tools: Optional[List[str]] = None):
        self.threshold = threshold
        self.window = window
        self.source_tools = source_tools
        self.egress_tools = egress_tools

    def _is_source(self, name: str) -> bool:
        if self.source_tools:
            return name in self.source_tools
        return bool(self.SOURCE_PATTERNS.search(name))

    def _is_egress(self, name: str) -> bool:
        if self.egress_tools:
            return name in self.egress_tools
        return bool(self.EGRESS_PATTERNS.search(name))

    def check(self, current: ToolEvent, history: List[ToolEvent]) -> Optional[AlertReport]:
        if not self._is_egress(current.tool_name):
            return None

        current_text = _flatten_args(current.args)

        for past in history[-self.window:]:
            if not self._is_source(past.tool_name):
                continue

            source_text = _flatten_args(past.args)
            if past.result and isinstance(past.result, (str, dict)):
                result_str = past.result if isinstance(past.result, str) else _flatten_args(past.result)
                source_text += " " + result_str

            overlap = _token_overlap(current_text, source_text)

            if overlap >= self.threshold:
                return AlertReport(
                    detector=self.name,
                    tool_name=current.tool_name,
                    reason=(
                        f"Potential data exfiltration: '{current.tool_name}' called after '{past.tool_name}' with "
                        f"{overlap:.0%} token overlap"
                    ),
                    severity="critical" if overlap > 0.5 else "high",
                    evidence={
                        "source_tool": past.tool_name,
                        "egress_tool": current.tool_name,
                        "overlap_score": round(overlap, 3),
                        "source_args": past.args,
                        "egress_args": current.args,
                    },
                )
        return None


class LoopDetector:
    name = "LoopDetector"

    def __init__(self, max_calls: int = 5, window_seconds: float = 60.0):
        self.max_calls = max_calls
        self.window_seconds = window_seconds

    def check(self, current: ToolEvent, history: List[ToolEvent]) -> Optional[AlertReport]:
        now = current.timestamp
        cutoff = now - self.window_seconds
        recent = [e for e in history if e.tool_name == current.tool_name and e.timestamp >= cutoff]

        if len(recent) >= self.max_calls:
            return AlertReport(
                detector=self.name,
                tool_name=current.tool_name,
                reason=(
                    f"Loop detected: '{current.tool_name}' called {len(recent) + 1}x in {self.window_seconds}s "
                    f"(limit {self.max_calls})"
                ),
                severity="high",
                evidence={"call_count": len(recent) + 1, "window_seconds": self.window_seconds, "timestamps": [e.timestamp for e in recent]},
            )
        return None


class EscalationDetector:
    name = "EscalationDetector"

    STAGES = [
        re.compile(r"read|get|fetch|list|find", re.I),
        re.compile(r"write|update|modify|create|save|set", re.I),
        re.compile(r"execute|run|deploy|delete|remove|drop|destroy", re.I),
    ]

    def __init__(self, window: int = 8):
        self.window = window

    def _stage(self, name: str) -> Optional[int]:
        for i, pat in enumerate(self.STAGES):
            if pat.search(name):
                return i
        return None

    def check(self, current: ToolEvent, history: List[ToolEvent]) -> Optional[AlertReport]:
        cs = self._stage(current.tool_name)
        if cs != 2:
            return None

        recent = history[-self.window:]
        has_read = any(self._stage(e.tool_name) == 0 for e in recent)
        has_write = any(self._stage(e.tool_name) == 1 for e in recent)

        if has_read and has_write:
            chain = [e.tool_name for e in recent if self._stage(e.tool_name) is not None]
            return AlertReport(
                detector=self.name,
                tool_name=current.tool_name,
                reason=f"Escalation chain detected: read → write → execute ending at '{current.tool_name}'",
                severity="critical",
                evidence={"chain": chain + [current.tool_name]},
            )
        return None


class ShadowDetector:
    name = "ShadowDetector"

    def __init__(self, window: int = 8):
        self.window = window

    def check(self, current: ToolEvent, history: List[ToolEvent]) -> Optional[AlertReport]:
        current_text = _flatten_args(current.args)
        if not current_text:
            return None

        for past in history[-self.window:]:
            for token in re.findall(r"\w+", _flatten_args(past.args)):
                if token and token in current_text:
                    return AlertReport(
                        detector=self.name,
                        tool_name=current.tool_name,
                        reason=f"Shadowed argument reused from previous tool '{past.tool_name}'",
                        severity="medium",
                        evidence={"source_tool": past.tool_name, "match": token},
                    )
        return None


class AwarenessGuard:
    def __init__(self, detectors: List[Any], window: int = 20, on_alert: str = "deny", alert_callback: Optional[Callable[[AlertReport, ToolEvent], None]] = None, session_id_fn: Optional[Callable] = None):
        self.detectors = detectors
        self.window = window
        self.on_alert = on_alert
        self.alert_callback = alert_callback
        self.session_id_fn = session_id_fn or (lambda args, aid: aid or "default")
        self._history: Dict[str, Deque[ToolEvent]] = {}

    def _get_history(self, session_id: str) -> List[ToolEvent]:
        return list(self._history.get(session_id, deque()))

    def _record(self, session_id: str, event: ToolEvent) -> None:
        if session_id not in self._history:
            self._history[session_id] = deque(maxlen=self.window)
        self._history[session_id].append(event)

    def record_result(self, session_id: str, tool_name: str, result: Any) -> None:
        q = self._history.get(session_id)
        if q:
            for event in reversed(q):
                if event.tool_name == tool_name and event.result is None:
                    event.result = result
                    break

    def evaluate(self, tool_name: str, args: Dict[str, Any], agent_id: Optional[str] = None) -> Dict[str, Any]:
        session_id = self.session_id_fn(args, agent_id)
        current = ToolEvent(tool_name=tool_name, args=args, agent_id=agent_id)
        history = self._get_history(session_id)

        alert: Optional[AlertReport] = None
        for detector in self.detectors:
            alert = detector.check(current, history)
            if alert:
                break

        self._record(session_id, current)

        if alert is None:
            return {"action": "allow", "alert": None, "session_id": session_id}

        if self.on_alert == "callback" and self.alert_callback:
            self.alert_callback(alert, current)
            return {"action": "allow", "alert": alert, "session_id": session_id}

        if self.on_alert == "allow":
            return {"action": "allow", "alert": alert, "session_id": session_id}

        return {"action": "deny", "alert": alert, "session_id": session_id, "reason": alert.reason}
