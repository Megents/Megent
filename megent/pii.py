from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Built-in patterns
# ---------------------------------------------------------------------------

_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "phone": re.compile(r"\+?1?\s?[\(\-]?\d{3}[\)\-\s]?\s?\d{3}[\-\s]?\d{4}"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

MASK = "[REDACTED]"


def _mask_string(value: str, fields: list[str]) -> tuple[str, list[str]]:
    """Apply pattern-based masking to a string value."""
    matched: list[str] = []
    for field in fields:
        pattern = _PATTERNS.get(field)
        if pattern and pattern.search(value):
            value = pattern.sub(MASK, value)
            matched.append(field)
    return value, matched


def mask_args(
    args: dict[str, Any],
    pii_fields: list[str],
) -> tuple[dict[str, Any], list[str]]:
    """
    Recursively walk tool call arguments and mask any PII.

    Returns:
        (masked_args, list_of_field_types_that_were_masked)
    """
    if not pii_fields:
        return args, []

    all_masked: list[str] = []

    def _walk(obj: Any) -> Any:
        if isinstance(obj, str):
            cleaned, found = _mask_string(obj, pii_fields)
            all_masked.extend(found)
            return cleaned
        if isinstance(obj, dict):
            return {k: _walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(item) for item in obj]
        return obj

    return _walk(args), list(set(all_masked))
