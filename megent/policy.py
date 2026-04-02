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


def _looks_like_pack_name(value: str) -> bool:
    if not value:
        return False
    if "/" in value or "\\" in value:
        return False
    return Path(value).suffix == ""


def _resolve_pack_policy_path(pack_name: str) -> Path:
    pack_dir = _installed_policies_root() / pack_name
    policy_path = pack_dir / "policy.yaml"
    verified_marker = pack_dir / "verified"

    if not policy_path.exists():
        raise PolicyLoadError(
            f"Policy pack '{pack_name}' is not installed at {policy_path}. "
            f"Run `megent policy install {pack_name}`."
        )

    if not verified_marker.exists():
        raise PolicyLoadError(
            f"Policy pack '{pack_name}' is not verified. "
            f"Run `megent policy verify {pack_name}`."
        )

    return policy_path


def _installed_policies_root() -> Path:
    return Path.home() / ".megent" / "policies"


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _require_verified_if_installed_path(policy_path: Path) -> None:
    policies_root = _installed_policies_root()
    if not _is_within(policy_path, policies_root):
        return

    relative = policy_path.resolve(strict=False).relative_to(
        policies_root.resolve(strict=False)
    )
    if not relative.parts:
        return

    pack_name = relative.parts[0]
    verified_marker = policies_root / pack_name / "verified"
    if not verified_marker.exists():
        raise PolicyLoadError(
            f"Policy pack '{pack_name}' is not verified. "
            f"Run `megent policy verify {pack_name}`."
        )


def _resolve_policy_location(path: Optional[str]) -> str:
    candidate = path or os.environ.get("MEGENT_POLICY")
    if candidate:
        if _looks_like_pack_name(candidate):
            return str(_resolve_pack_policy_path(candidate))
        return candidate
    return str(Path.cwd() / "megent.yaml")


def load_policy(path: Optional[str] = None) -> Policy:
    """
    Load a policy from a YAML file.

    Megent intentionally loads one policy per runtime instance in v1.
    Multi-pack composition and conflict-resolution semantics (for example,
    deny-wins overlays) are planned for a future v2 design.

        Resolution order:
            1. Explicit `path` argument
            2. MEGENT_POLICY env var
            3. Named registry pack (no path separators and no extension)
                 -> ~/.megent/policies/<name>/policy.yaml
            4. ./megent.yaml in the current working directory
    """
    resolved = _resolve_policy_location(path)
    _require_verified_if_installed_path(Path(resolved))

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
