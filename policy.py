from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    raise ImportError("Install PyYAML: pip install pyyaml") from exc

from .exceptions import PolicyLoadError


@dataclass
class ToolPolicy:
    name: str
    allowed: bool = False
    pii_mask: list[str] = field(default_factory=list)
    # Future: rate_limit, require_approval, allowed_args, ...


@dataclass
class Policy:
    version: str = "1"
    default_action: str = "deny"          # deny | allow
    tools: dict[str, ToolPolicy] = field(default_factory=dict)
    pii_mask: list[str] = field(default_factory=list)  # global PII mask

    def is_allowed(self, tool_name: str) -> bool:
        if tool_name in self.tools:
            return self.tools[tool_name].allowed
        return self.default_action == "allow"

    def pii_fields_for(self, tool_name: str) -> list[str]:
        """Merge global + tool-level PII mask fields."""
        tool_fields = self.tools.get(tool_name, ToolPolicy(tool_name)).pii_mask
        return list(set(self.pii_mask + tool_fields))


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _parse_tool(name: str, raw: Any) -> ToolPolicy:
    if raw is None:
        raw = {}
    if isinstance(raw, bool):
        return ToolPolicy(name=name, allowed=raw)
    return ToolPolicy(
        name=name,
        allowed=bool(raw.get("allow", False)),
        pii_mask=raw.get("pii_mask", []),
    )


def load_policy(path: Optional[str] = None) -> Policy:
    """
    Load a policy from a YAML file.

    Resolution order:
      1. Explicit `path` argument
      2. MEGENT_POLICY env var
      3. ./megent.yaml in the current working directory
    """
    resolved = (
        path
        or os.environ.get("MEGENT_POLICY")
        or str(Path.cwd() / "megent.yaml")
    )

    try:
        with open(resolved, "r") as f:
            raw = yaml.safe_load(f) or {}
    except FileNotFoundError:
        raise PolicyLoadError(f"Policy file not found: {resolved}")
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"Invalid YAML in policy file: {exc}")

    tools_raw: dict[str, Any] = raw.get("tools", {})
    tools = {name: _parse_tool(name, cfg) for name, cfg in tools_raw.items()}

    return Policy(
        version=str(raw.get("version", "1")),
        default_action=raw.get("default_action", "deny"),
        tools=tools,
        pii_mask=raw.get("pii_mask", []),
    )
