from __future__ import annotations

import functools
from typing import Any, Callable, Optional, TypeVar, overload

from .runtime import Runtime

F = TypeVar("F", bound=Callable[..., Any])

# ---------------------------------------------------------------------------
# Module-level default runtime (lazy, loaded on first use)
# ---------------------------------------------------------------------------

_default_runtime: Optional[Runtime] = None


def _get_runtime() -> Runtime:
    global _default_runtime
    if _default_runtime is None:
        _default_runtime = Runtime()
    return _default_runtime


def configure(
    policy_path: Optional[str] = None,
    **runtime_kwargs: Any,
) -> Runtime:
    """
    Explicitly configure the module-level runtime.
    Call this once at startup, before any @guard or wrap() usage.

        import megent
        megent.configure(policy_path="megent.yaml")
    """
    global _default_runtime
    _default_runtime = Runtime(policy_path=policy_path, **runtime_kwargs)
    return _default_runtime


# ---------------------------------------------------------------------------
# @guard decorator
# ---------------------------------------------------------------------------

@overload
def guard(fn: F) -> F: ...

@overload
def guard(
    *,
    tool_name: Optional[str] = None,
    agent_token: Optional[str] = None,
    policy: Optional[str] = None,
    runtime: Optional[Runtime] = None,
) -> Callable[[F], F]: ...


def guard(
    fn: Optional[F] = None,
    *,
    tool_name: Optional[str] = None,
    agent_token: Optional[str] = None,
    policy: Optional[str] = None,
    runtime: Optional[Runtime] = None,
) -> Any:
    """
    Decorator that enforces Megent policy before a tool function executes.

    Usage (bare):
        @mgnt.guard
        def send_email(to: str, subject: str, body: str): ...

    Usage (with options):
        @mgnt.guard(tool_name="send_email", agent_token=token)
        def send_email(...): ...
    """
    def decorator(func: F) -> F:
        rt = runtime or (Runtime(policy_path=policy) if policy else _get_runtime())
        name = tool_name or func.__name__

        @functools.wraps(func)
        def wrapper(**kwargs: Any) -> Any:
            safe_kwargs = rt.enforce(name, kwargs, agent_token)
            return func(**safe_kwargs)

        return wrapper  # type: ignore[return-value]

    if fn is not None:
        # Called as @guard (no parentheses)
        return decorator(fn)

    # Called as @guard(...)
    return decorator


# ---------------------------------------------------------------------------
# wrap() — for third-party / dynamic agents
# ---------------------------------------------------------------------------

def wrap(
    fn: Callable[..., Any],
    *,
    tool_name: Optional[str] = None,
    agent_token: Optional[str] = None,
    policy: Optional[str] = None,
    runtime: Optional[Runtime] = None,
) -> Callable[..., Any]:
    """
    Wrap any callable with Megent policy enforcement at runtime.

    This is the preferred pattern for third-party agents or tools you
    don't own:

        safe_execute = mgnt.wrap(third_party_agent.execute_sql)
        safe_execute(query="SELECT * FROM users")
    """
    rt = runtime or (Runtime(policy_path=policy) if policy else _get_runtime())
    return rt.wrap_callable(fn, tool_name=tool_name, agent_token=agent_token)
