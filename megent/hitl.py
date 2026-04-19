"""Megent human-in-the-loop feature."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class ReviewVerdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    MODIFY = "modify"


@dataclass
class ReviewRequest:
    tool_name: str
    args: Dict[str, Any]
    agent_id: Optional[str]
    timestamp: float = field(default_factory=time.time)
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReviewOutcome:
    verdict: ReviewVerdict
    modified_args: Optional[Dict[str, Any]] = None
    feedback: Optional[str] = None
    reviewer: Optional[str] = None


def cli_reviewer(request: ReviewRequest) -> ReviewOutcome:
    print("\n" + "═" * 60)
    print("  🔍  MEGENT HUMAN REVIEW REQUIRED")
    print("═" * 60)
    print(f"  Tool     : {request.tool_name}")
    print(f"  Agent    : {request.agent_id or 'unknown'}")
    print(f"  Args     : {request.args}")
    if request.context:
        print(f"  Context  : {request.context}")
    print("═" * 60)
    print("  [a] Allow   [d] Deny   [m] Modify args")

    while True:
        choice = input("  Your decision: ").strip().lower()
        if choice == "a":
            feedback = input("  Feedback (optional): ").strip() or None
            return ReviewOutcome(verdict=ReviewVerdict.ALLOW, feedback=feedback, reviewer="cli")
        if choice == "d":
            reason = input("  Reason for denial: ").strip() or None
            return ReviewOutcome(verdict=ReviewVerdict.DENY, feedback=reason, reviewer="cli")
        if choice == "m":
            print(f"  Current args: {request.args}")
            import json

            raw = input("  Enter modified args as JSON: ").strip()
            try:
                modified = json.loads(raw)
                feedback = input("  Feedback (optional): ").strip() or None
                return ReviewOutcome(verdict=ReviewVerdict.MODIFY, modified_args=modified, feedback=feedback, reviewer="cli")
            except json.JSONDecodeError:
                print("  ❌ Invalid JSON, try again.")
        else:
            print("  Invalid choice. Enter a, d, or m.")


def webhook_reviewer(url: str, secret: Optional[str] = None) -> Callable:
    import uuid, json, urllib.request

    def reviewer(request: ReviewRequest) -> ReviewOutcome:
        payload = json.dumps({"review_id": str(uuid.uuid4()), "tool_name": request.tool_name, "args": request.args, "agent_id": request.agent_id, "timestamp": request.timestamp, "context": request.context}).encode()

        headers = {"Content-Type": "application/json"}
        if secret:
            import hmac, hashlib

            sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
            headers["X-Megent-Signature"] = f"sha256={sig}"

        req = urllib.request.Request(url, data=payload, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        return ReviewOutcome(verdict=ReviewVerdict(data["verdict"]), modified_args=data.get("modified_args"), feedback=data.get("feedback"), reviewer=data.get("reviewer", url))

    return reviewer


class HITLPolicy:
    def __init__(self, tools: List[str], reviewer: Callable[[ReviewRequest], ReviewOutcome], timeout_seconds: float = 120.0, on_timeout: str = "deny", require_feedback: bool = False):
        self.tools = set(tools)
        self.reviewer = reviewer
        self.timeout_seconds = timeout_seconds
        self.on_timeout = on_timeout
        self.require_feedback = require_feedback

    def _needs_review(self, tool_name: str) -> bool:
        return "*" in self.tools or tool_name in self.tools

    def evaluate(self, tool_name: str, args: Dict[str, Any], agent_id: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self._needs_review(tool_name):
            return {"action": "allow", "args": args, "hitl": False}

        request = ReviewRequest(tool_name=tool_name, args=args, agent_id=agent_id, context=context or {})

        outcome: Optional[ReviewOutcome] = None
        error: Optional[Exception] = None

        def _call():
            nonlocal outcome, error
            try:
                outcome = self.reviewer(request)
            except Exception as e:  # noqa: BLE001
                error = e

        thread = threading.Thread(target=_call, daemon=True)
        thread.start()
        thread.join(timeout=self.timeout_seconds)

        if outcome is None and error is None:
            if self.on_timeout == "allow":
                return {"action": "allow", "args": args, "hitl": True, "feedback": "auto-allowed on timeout"}
            if self.on_timeout == "raise":
                raise TimeoutError(f"[Megent HITL] No review received within {self.timeout_seconds}s for tool '{tool_name}'")
            return {"action": "deny", "args": args, "hitl": True, "feedback": "auto-denied: review timed out"}

        if error:
            raise RuntimeError(f"[Megent HITL] Reviewer raised: {error}") from error

        if outcome.verdict == ReviewVerdict.DENY:
            return {"action": "deny", "args": args, "hitl": True, "feedback": outcome.feedback, "reviewer": outcome.reviewer}

        final_args = outcome.modified_args if outcome.verdict == ReviewVerdict.MODIFY and outcome.modified_args else args

        return {"action": "allow", "args": final_args, "hitl": True, "feedback": outcome.feedback, "reviewer": outcome.reviewer, "modified": outcome.verdict == ReviewVerdict.MODIFY}
