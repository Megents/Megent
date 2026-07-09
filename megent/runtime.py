from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Optional

from .audit import AuditLogger
from .exceptions import PolicyViolation
from .identity import agent_id_from_token
from .pii import mask_args
from .permissions import PermissionStore
from .policy import Policy, load_policy
from .ratelimit import RateLimitPolicy


class Runtime:
    """
    The Megent policy runtime.

    Intercepts tool calls, enforces the loaded policy, masks PII,
    and emits structured audit events — before the tool executes.
    """

    def __init__(
        self,
        policy: Optional[Policy] = None,
        policy_path: Optional[str] = None,
        policy_name: Optional[str] = None,
        policy_repo: Optional[str] = None,
        audit: Optional[AuditLogger] = None,
        rate_limit: Optional[RateLimitPolicy] = None,
        permissions: Optional[PermissionStore] = None,
    ):
        self._policy = policy or load_policy(
            policy_path,
            policy_name=policy_name,
            policy_repo=policy_repo,
        )
        self._audit = audit or AuditLogger()
        self._rate_limit = rate_limit
        self._permissions = permissions

    # ------------------------------------------------------------------
    # Core enforcement
    # ------------------------------------------------------------------

    def enforce(
        self,
        tool_name: str,
        args: dict[str, Any],
        agent_token: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Enforce policy on a tool call.

        Returns the (possibly PII-masked) args if the call is allowed.
        Raises PolicyViolation if the call is blocked.
        """
        agent_id = agent_id_from_token(agent_token)

        # Rate limiting is checked before policy evaluation so a single agent
        # identity cannot exceed its call budget regardless of the per-tool
        # decision. A limit hit is a deny-by-default block, logged to audit.
        if self._rate_limit is not None:
            rl = self._rate_limit.check(tool_name, args, agent_id)
            if rl.get("action") == "deny":
                reason = str(rl.get("reason") or "rate limit exceeded")
                masked_args, _ = mask_args(args, self._policy.pii_fields_for(tool_name))
                self._audit.block(
                    tool=tool_name,
                    reason=reason,
                    agent_id=agent_id,
                    args=masked_args,
                )
                raise PolicyViolation(tool_name, reason)

        # Capability permission check runs after the rate limit and before the
        # existing policy evaluation. Deny-by-default: an identity with no
        # entry (or a tool outside its allowlist) is blocked. A snapshot is
        # taken once so a concurrent hot reload cannot half-apply mid-call.
        if self._permissions is not None:
            perm = self._permissions.evaluate(agent_id, tool_name, args)
            if not perm.allowed:
                reason = perm.detail or "permission denied"
                masked_args, _ = mask_args(args, self._policy.pii_fields_for(tool_name))
                self._audit.permission_denied(
                    tool=tool_name,
                    denial_reason=perm.reason or "no_policy",
                    reason=reason,
                    agent_id=agent_id,
                    args=masked_args,
                    policy_version=perm.version,
                )
                raise PolicyViolation(tool_name, reason)

        decision = self._policy.evaluate(tool_name, args, agent_id=agent_id)
        action = decision.get("action", "allow")

        if action == "deny":
            reason = str(decision.get("reason") or "blocked by policy")
            masked_args = decision.get("masked_args") or decision.get("args") or args
            self._audit.block(
                tool=tool_name,
                reason=reason,
                agent_id=agent_id,
                args=masked_args,
            )
            raise PolicyViolation(tool_name, reason)

        masked_args = decision.get("args") or args
        masked_fields = decision.get("masked_fields") or []

        self._audit.allow(
            tool=tool_name,
            agent_id=agent_id,
            args=masked_args,
            masked_fields=masked_fields,
        )
        return {
            "args": masked_args,
            "session_id": decision.get("session_id"),
            "masked_fields": masked_fields,
            "decision": decision,
            "agent_id": agent_id,
        }

    # ------------------------------------------------------------------
    # Wrapping helpers (used by guard decorator and wrap())
    # ------------------------------------------------------------------

    def wrap_callable(
        self,
        fn: Callable[..., Any],
        tool_name: Optional[str] = None,
        agent_token: Optional[str] = None,
    ) -> Callable[..., Any]:
        """Return a new callable that enforces policy before calling fn."""
        name = tool_name or fn.__name__
        # Bind against the original signature so positional/keyword calls stay equivalent.
        signature = inspect.signature(fn)

        @functools.wraps(fn)
        def _wrapper(*args: Any, **kwargs: Any) -> Any:
            bound_args = signature.bind(*args, **kwargs)
            decision = self.enforce(name, dict(bound_args.arguments), agent_token)
            safe_values = decision["args"]

            # Rebuild args from the sanitized mapping and preserve call semantics.
            bound_args.arguments.clear()
            bound_args.arguments.update(safe_values)
            result = fn(*bound_args.args, **bound_args.kwargs)

            post = self._policy.postprocess(
                name,
                result,
                agent_id=decision.get("agent_id"),
                session_id=decision.get("session_id"),
            )
            if isinstance(post, dict) and "result" in post:
                return post["result"]
            return result

        return _wrapper
