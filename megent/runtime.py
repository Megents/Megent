from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Optional

from .audit import AuditLogger
from .exceptions import PolicyViolation
from .identity import agent_id_from_token
from .pii import mask_args
from .policy import Policy, load_policy


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
        audit: Optional[AuditLogger] = None,
    ):
        self._policy = policy or load_policy(policy_path)
        self._audit = audit or AuditLogger()

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
        pii_fields = self._policy.pii_fields_for(tool_name)
        masked_args, masked_fields = mask_args(args, pii_fields)

        if not self._policy.is_allowed(tool_name):
            self._audit.block(
                tool=tool_name,
                reason="not in policy allowlist",
                agent_id=agent_id,
                args=masked_args,
            )
            raise PolicyViolation(tool_name, "not in policy allowlist")

        self._audit.allow(
            tool=tool_name,
            agent_id=agent_id,
            args=masked_args,
            masked_fields=masked_fields,
        )
        return masked_args

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
            safe_values = self.enforce(name, dict(bound_args.arguments), agent_token)

            # Rebuild args from the sanitized mapping and preserve call semantics.
            bound_args.arguments.clear()
            bound_args.arguments.update(safe_values)
            return fn(*bound_args.args, **bound_args.kwargs)

        return _wrapper
