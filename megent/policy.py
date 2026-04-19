from __future__ import annotations

import fnmatch
import json
import os
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    raise ImportError("Install PyYAML: pip install pyyaml") from exc

from .exceptions import PolicyLoadError
from .pii import mask_args, mask_value


@dataclass
class ToolPolicy:
    name: str
    allowed: bool = False
    pii_mask: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PolicyRule:
    id: str
    tool: tuple[str, ...]
    action: str
    condition: Optional[str] = None
    message: Optional[str] = None
    description: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Policy:
    name: str = "local-policy"
    version: str = "1"
    description: str = ""
    severity: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    default_action: str = "deny"
    rules: list[PolicyRule] = field(default_factory=list)
    tools: dict[str, ToolPolicy] = field(default_factory=dict)
    pii_mask: list[str] = field(default_factory=list)
    on_violation: dict[str, Any] = field(default_factory=dict)
    source: Optional[str] = None
    _session_state: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)

    def is_allowed(self, tool_name: str) -> bool:
        if self.rules:
            rule = self._match_rule(tool_name, phase="pre", args={}, context={}, session_id="default")
            if rule is not None:
                return rule.action != "deny"
            return self.default_action == "allow"

        if tool_name in self.tools:
            return self.tools[tool_name].allowed
        return self.default_action == "allow"

    def pii_fields_for(self, tool_name: str) -> list[str]:
        tool_fields = self.tools.get(tool_name, ToolPolicy(tool_name)).pii_mask
        fields = list(dict.fromkeys(self.pii_mask + tool_fields))
        if self.rules:
            for rule in self.rules:
                if _tool_matches(rule.tool, tool_name):
                    fields.extend(_rule_pii_fields(rule))
        return list(dict.fromkeys(fields))

    def _match_rule(
        self,
        tool_name: str,
        phase: str,
        args: dict[str, Any],
        context: dict[str, Any],
        session_id: str,
    ) -> Optional[PolicyRule]:
        state = self._state_for(session_id)
        for rule in self.rules:
            if not _tool_matches(rule.tool, tool_name):
                continue
            if not self._condition_matches(
                rule=rule,
                tool_name=tool_name,
                args=args,
                context=context,
                state=state,
                phase=phase,
                result=None,
            ):
                continue
            return rule
        return None

    def evaluate(
        self,
        tool_name: str,
        args: dict[str, Any],
        agent_id: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
        session_id: Optional[str] = None,
        phase: str = "pre",
    ) -> dict[str, Any]:
        """Evaluate a policy before a tool call or after a result is produced."""
        if not self.rules:
            if phase == "post":
                return {"action": "allow", "result": context.get("result") if context else None, "session_id": session_id}

            pii_fields = self.pii_fields_for(tool_name)
            masked_args, masked_fields = mask_args(args, pii_fields)
            if not self.is_allowed(tool_name):
                return {
                    "action": "deny",
                    "session_id": session_id,
                    "reason": "not in policy allowlist",
                    "masked_args": masked_args,
                    "masked_fields": masked_fields,
                }
            return {
                "action": "allow",
                "args": masked_args,
                "session_id": session_id,
                "masked_fields": masked_fields,
            }

        session_id = session_id or self._session_key(agent_id)
        state = self._state_for(session_id)

        if phase == "pre":
            self._record_call(state, tool_name)

        for rule in self.rules:
            if not _tool_matches(rule.tool, tool_name):
                continue
            if not self._condition_matches(
                rule=rule,
                tool_name=tool_name,
                args=args,
                context=context or {},
                state=state,
                phase=phase,
                result=None,
            ):
                continue

            patterns = _rule_pii_fields(rule)

            if rule.action in {"mask", "redact"}:
                if phase == "post":
                    result = (context or {}).get("result")
                    masked_result, masked_fields = mask_value(result, patterns or self.pii_mask)
                    return {
                        "action": "allow",
                        "result": masked_result,
                        "masked_fields": masked_fields,
                        "session_id": session_id,
                        "rule_id": rule.id,
                        "policy": self.name,
                    }

                masked_args, masked_fields = mask_args(args, patterns or self.pii_mask)
                return {
                    "action": "allow",
                    "args": masked_args,
                    "session_id": session_id,
                    "rule_id": rule.id,
                    "policy": self.name,
                    "masked_fields": masked_fields,
                }

            if rule.action == "allow":
                masked_args, masked_fields = mask_args(args, self.pii_fields_for(tool_name))
                return {
                    "action": "allow",
                    "args": masked_args,
                    "session_id": session_id,
                    "rule_id": rule.id,
                    "policy": self.name,
                    "reason": rule.message,
                    "masked_fields": masked_fields,
                }

            if rule.action == "log":
                masked_args, masked_fields = mask_args(args, self.pii_fields_for(tool_name))
                return {
                    "action": "allow",
                    "args": masked_args,
                    "session_id": session_id,
                    "rule_id": rule.id,
                    "policy": self.name,
                    "reason": rule.message,
                    "audit": True,
                    "masked_fields": masked_fields,
                }

            if rule.action == "require_approval":
                return {
                    "action": "deny",
                    "session_id": session_id,
                    "rule_id": rule.id,
                    "policy": self.name,
                    "reason": rule.message or "approval required",
                    "approval_required": True,
                    "metadata": rule.metadata,
                }

            if rule.action == "deny":
                return {
                    "action": "deny",
                    "session_id": session_id,
                    "rule_id": rule.id,
                    "policy": self.name,
                    "reason": rule.message or "blocked by policy",
                    "metadata": rule.metadata,
                }

        if phase == "post":
            result = (context or {}).get("result")
            masked_result, masked_fields = mask_value(result, self.pii_mask)
            return {
                "action": "allow",
                "result": masked_result,
                "session_id": session_id,
                "masked_fields": masked_fields,
                "policy": self.name,
            }

        masked_args, masked_fields = mask_args(args, self.pii_fields_for(tool_name))
        return {
            "action": "allow",
            "args": masked_args,
            "session_id": session_id,
            "policy": self.name,
            "masked_fields": masked_fields,
        }

    def postprocess(
        self,
        tool_name: str,
        result: Any,
        agent_id: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
        session_id: Optional[str] = None,
    ) -> dict[str, Any]:
        return self.evaluate(
            tool_name=tool_name,
            args={},
            agent_id=agent_id,
            context={**(context or {}), "result": result},
            session_id=session_id,
            phase="post",
        )

    def _session_key(self, agent_id: Optional[str]) -> str:
        return agent_id or "default"

    @classmethod
    def compose(cls, *policies: "Policy", name: str = "composed-policy") -> "Policy":
        """Combine multiple policies into one deny-wins policy object."""
        if not policies:
            raise PolicyLoadError("compose() requires at least one policy")

        composed_rules: list[PolicyRule] = []
        composed_tools: dict[str, ToolPolicy] = {}
        composed_pii: list[str] = []
        composed_tags: list[str] = []
        composed_frameworks: list[str] = []
        descriptions: list[str] = []
        sources: list[str] = []

        for policy in policies:
            composed_rules.extend(policy.rules)
            composed_tools.update(policy.tools)
            composed_pii.extend(policy.pii_mask)
            composed_tags.extend(policy.tags)
            composed_frameworks.extend(policy.frameworks)
            if policy.description:
                descriptions.append(policy.description)
            if policy.source:
                sources.append(policy.source)

        return cls(
            name=name,
            version="1.0",
            description="; ".join(dict.fromkeys(descriptions)),
            tags=list(dict.fromkeys(composed_tags)),
            frameworks=list(dict.fromkeys(composed_frameworks)),
            default_action="deny",
            rules=composed_rules,
            tools=composed_tools,
            pii_mask=list(dict.fromkeys(composed_pii)),
            source=" + ".join(sources) if sources else None,
        )

    def _state_for(self, session_id: str) -> dict[str, Any]:
        state = self._session_state.get(session_id)
        if state is None:
            state = {
                "timestamps": deque(),
                "tool_timestamps": {},
            }
            self._session_state[session_id] = state
        return state

    def _record_call(self, state: dict[str, Any], tool_name: str) -> None:
        now = _now()
        timestamps: deque[float] = state["timestamps"]
        tool_timestamps: dict[str, deque[float]] = state["tool_timestamps"]

        timestamps.append(now)
        _prune_old(timestamps, now, _rule_window_seconds(self.rules) or 60)

        tool_queue = tool_timestamps.setdefault(tool_name, deque())
        tool_queue.append(now)
        _prune_old(tool_queue, now, _rule_window_seconds(self.rules) or 60)

    def _condition_matches(
        self,
        rule: PolicyRule,
        tool_name: str,
        args: dict[str, Any],
        context: dict[str, Any],
        state: dict[str, Any],
        phase: str,
        result: Any,
    ) -> bool:
        if not rule.condition:
            return True

        if rule.condition == "input_contains_pii":
            return bool(_mask_probe(args, _rule_pii_fields(rule) or self.pii_mask)[1])

        if rule.condition == "output_contains_pii" and phase == "post":
            target = context.get("result", result)
            return bool(_mask_probe(target, _rule_pii_fields(rule) or self.pii_mask)[1])

        if rule.condition == "rate_exceeded":
            window = int(rule.metadata.get("window_seconds", 60))
            max_calls = int(rule.metadata.get("max_calls", 0))
            return _count_recent(state["timestamps"], window) > max_calls >= 0

        if rule.condition == "per_tool_rate_exceeded":
            window = int(rule.metadata.get("window_seconds", 60))
            max_calls = int(rule.metadata.get("max_calls_per_tool", 0))
            queue = state["tool_timestamps"].get(tool_name, deque())
            return _count_recent(queue, window) > max_calls >= 0

        return True


def _normalize_pii_mask(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PolicyLoadError(f"{field_name} must be a list of strings")

    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise PolicyLoadError(f"{field_name} must contain only strings")
        normalized.append(item)
    return normalized


def _normalize_tool_refs(value: Any, field_name: str = "tool") -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        refs: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise PolicyLoadError(f"{field_name} must contain only strings")
            refs.append(item)
        return tuple(refs)
    raise PolicyLoadError(f"{field_name} must be a string or list of strings")


def _parse_rule(raw: Any) -> PolicyRule:
    if not isinstance(raw, dict):
        raise PolicyLoadError("Each rule must be a mapping")

    if "id" not in raw or "tool" not in raw or "action" not in raw:
        raise PolicyLoadError("Each rule requires id, tool, and action")

    metadata = raw.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise PolicyLoadError("Rule metadata must be a mapping")

    return PolicyRule(
        id=str(raw["id"]),
        tool=_normalize_tool_refs(raw["tool"]),
        action=str(raw["action"]),
        condition=str(raw.get("condition")) if raw.get("condition") is not None else None,
        message=str(raw.get("message")) if raw.get("message") is not None else None,
        description=str(raw.get("description")) if raw.get("description") is not None else None,
        metadata=metadata,
    )


def _parse_tool(name: str, raw: Any) -> ToolPolicy:
    if raw is None:
        raw = {}
    if isinstance(raw, bool):
        return ToolPolicy(name=name, allowed=raw)
    if not isinstance(raw, dict):
        raise PolicyLoadError(f"Tool policy for '{name}' must be a mapping or boolean")
    return ToolPolicy(
        name=name,
        allowed=bool(raw.get("allow", False)),
        pii_mask=_normalize_pii_mask(raw.get("pii_mask", []), f"tools.{name}.pii_mask"),
    )


def _resolve_pack_from_repo(repo_root: Path, name: str) -> Optional[Path]:
    registry_path = repo_root / "registry.json"
    if not registry_path.exists():
        return None

    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyLoadError(f"Invalid registry JSON in policy repo: {registry_path}") from exc

    policies = registry.get("policies", [])
    if not isinstance(policies, list):
        raise PolicyLoadError(f"Policy registry must contain a 'policies' list: {registry_path}")

    for entry in policies:
        if not isinstance(entry, dict) or entry.get("name") != name:
            continue
        pack_path = repo_root / str(entry.get("path", "")) / "policy.yaml"
        if pack_path.exists():
            return pack_path
    return None


def _installed_policies_root() -> Path:
    return Path.home() / ".megent" / "policies"


def _resolve_installed_pack(name: str) -> Optional[Path]:
    pack_path = _installed_policies_root() / name / "policy.yaml"
    verified_marker = pack_path.parent / "verified"
    if pack_path.exists():
        if not verified_marker.exists():
            raise PolicyLoadError(
                f"Policy pack '{name}' is not verified. Run `megent policy verify {name}`."
            )
        return pack_path
    return None


def _resolve_policy_location(
    path: Optional[str],
    policy_name: Optional[str] = None,
    policy_repo: Optional[str] = None,
) -> str:
    candidate = policy_name or path or os.environ.get("MEGENT_POLICY")
    if candidate:
        candidate_path = Path(candidate)
        if candidate_path.exists():
            installed_root = _installed_policies_root()
            if candidate_path.is_relative_to(installed_root):
                if candidate_path.name == "policy.yaml":
                    verified_marker = candidate_path.parent / "verified"
                    if not verified_marker.exists():
                        raise PolicyLoadError(
                            f"Policy pack '{candidate_path.parent.name}' is not verified. Run `megent policy verify {candidate_path.parent.name}`."
                        )
                elif candidate_path.is_dir():
                    pack_path = candidate_path / "policy.yaml"
                    if pack_path.exists():
                        verified_marker = candidate_path / "verified"
                        if not verified_marker.exists():
                            raise PolicyLoadError(
                                f"Policy pack '{candidate_path.name}' is not verified. Run `megent policy verify {candidate_path.name}`."
                            )
                        return str(pack_path)
            return str(candidate_path)

        repo_candidate = policy_repo or os.environ.get("MEGENT_POLICY_REPO")
        if repo_candidate:
            repo_root = Path(repo_candidate)
            if repo_root.exists():
                repo_pack = _resolve_pack_from_repo(repo_root, candidate)
                if repo_pack is not None:
                    return str(repo_pack)

        installed_pack = _resolve_installed_pack(candidate)
        if installed_pack is not None:
            return str(installed_pack)

        return candidate

    return str(Path.cwd() / "megent.yaml")


def _validate_rule_structure(raw: Any) -> list[PolicyRule]:
    if not isinstance(raw, list):
        raise PolicyLoadError("'rules' must be a list")
    return [_parse_rule(item) for item in raw]


def _rule_pii_fields(rule: PolicyRule) -> list[str]:
    metadata = rule.metadata or {}
    patterns = metadata.get("patterns")
    if not isinstance(patterns, list):
        return []
    return [str(item) for item in patterns if isinstance(item, str)]


def _tool_matches(tool_refs: tuple[str, ...], tool_name: str) -> bool:
    for ref in tool_refs:
        if ref == "*":
            return True
        if any(ch in ref for ch in "*?["):
            if fnmatch.fnmatch(tool_name, ref):
                return True
            continue
        normalized_ref = ref.removeprefix("megent:")
        normalized_tool = tool_name.removeprefix("megent:")
        if tool_name == ref or normalized_tool == normalized_ref:
            return True
    return False


def _now() -> float:
    import time

    return time.time()


def _prune_old(values: deque[float], now: float, window_seconds: int) -> None:
    cutoff = now - window_seconds
    while values and values[0] < cutoff:
        values.popleft()


def _count_recent(values: deque[float], window_seconds: int) -> int:
    now = _now()
    _prune_old(values, now, window_seconds)
    return len(values)


def _rule_window_seconds(rules: list[PolicyRule]) -> Optional[int]:
    windows: list[int] = []
    for rule in rules:
        metadata = rule.metadata or {}
        window = metadata.get("window_seconds")
        if isinstance(window, int):
            windows.append(window)
    return min(windows) if windows else None


def _mask_probe(value: Any, pii_fields: list[str]) -> tuple[Any, list[str]]:
    return mask_value(value, pii_fields)


def load_policy(
    path: Optional[str] = None,
    policy_name: Optional[str] = None,
    policy_repo: Optional[str] = None,
) -> Policy:
    """Load a policy from a YAML file, policy repo, or built-in static pack."""
    resolved = _resolve_policy_location(path, policy_name=policy_name, policy_repo=policy_repo)

    try:
        raw_text = Path(resolved).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise PolicyLoadError(f"Policy file not found: {resolved}")

    try:
        raw = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"Invalid YAML in policy file: {exc}")

    if not isinstance(raw, dict):
        raise PolicyLoadError("Policy root must be a mapping")

    if "rules" in raw:
        rules = _validate_rule_structure(raw.get("rules", []))
        default_action = str(raw.get("default_action", "allow"))
        if default_action not in {"allow", "deny"}:
            raise PolicyLoadError("'default_action' must be either 'allow' or 'deny'")

        on_violation = raw.get("on_violation") or {}
        if not isinstance(on_violation, dict):
            raise PolicyLoadError("'on_violation' must be a mapping")

        return Policy(
            name=str(raw.get("name", Path(resolved).stem)),
            version=str(raw.get("version", "1.0")),
            description=str(raw.get("description", "")),
            severity=str(raw.get("severity")) if raw.get("severity") is not None else None,
            tags=[str(item) for item in raw.get("tags", []) if isinstance(item, str)],
            frameworks=[str(item) for item in raw.get("frameworks", []) if isinstance(item, str)],
            default_action=default_action,
            rules=rules,
            pii_mask=_normalize_pii_mask(raw.get("pii_mask", []), "pii_mask"),
            on_violation=on_violation,
            source=resolved,
        )

    tools_raw = raw.get("tools", {})
    if not isinstance(tools_raw, dict):
        raise PolicyLoadError("'tools' must be a mapping of tool names to rule configs")

    tools = {name: _parse_tool(name, cfg) for name, cfg in tools_raw.items()}
    default_action = raw.get("default_action", "deny")
    if default_action not in {"allow", "deny"}:
        raise PolicyLoadError("'default_action' must be either 'allow' or 'deny'")

    return Policy(
        name=str(raw.get("name", Path(resolved).stem)),
        version=str(raw.get("version", "1")),
        description=str(raw.get("description", "")),
        default_action=default_action,
        tools=tools,
        pii_mask=_normalize_pii_mask(raw.get("pii_mask", []), "pii_mask"),
        source=resolved,
    )


def compose_policies(
    *items: str | Policy,
    name: str = "composed-policy",
    policy_repo: Optional[str] = None,
) -> Policy:
    """Load and combine policies from names, paths, or Policy objects."""
    loaded: list[Policy] = []
    for item in items:
        if isinstance(item, Policy):
            loaded.append(item)
        else:
            loaded.append(load_policy(item, policy_repo=policy_repo))
    return Policy.compose(*loaded, name=name)
