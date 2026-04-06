from __future__ import annotations

import pytest

from megent import guard, wrap
from megent.exceptions import PolicyViolation
from megent.policy import Policy, ToolPolicy
from megent.runtime import Runtime


def _runtime_allowing(*tool_names: str) -> Runtime:
    tools = {
        name: ToolPolicy(name=name, allowed=True)
        for name in tool_names
    }
    return Runtime(policy=Policy(default_action="deny", tools=tools))


def test_guard_supports_positional_arguments() -> None:
    rt = _runtime_allowing("add")

    @guard(runtime=rt)
    def add(left: int, right: int) -> int:
        return left + right

    assert add(2, 3) == 5


def test_wrap_supports_mixed_argument_styles() -> None:
    rt = _runtime_allowing("multiply")

    def multiply(left: int, right: int, *, scale: int = 1) -> int:
        return left * right * scale

    safe_multiply = wrap(multiply, runtime=rt)
    assert safe_multiply(2, 4, scale=2) == 16


def test_wrap_preserves_type_error_for_bad_call_signature() -> None:
    rt = _runtime_allowing("divide")

    def divide(left: int, right: int) -> float:
        return left / right

    safe_divide = wrap(divide, runtime=rt)

    with pytest.raises(TypeError):
        safe_divide(1)


def test_wrap_still_blocks_disallowed_tools() -> None:
    rt = Runtime(policy=Policy(default_action="deny", tools={}))

    def delete_everything(target: str) -> str:
        return target

    safe_delete = wrap(delete_everything, runtime=rt)

    with pytest.raises(PolicyViolation):
        safe_delete("prod-db")
