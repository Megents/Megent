"""Capability-based tool permissions with hot-reloadable policy files.

Each agent identity is granted an explicit allowlist of tools. Everything
else is denied (deny-by-default). Policies live in a YAML/JSON file that can
be swapped at runtime without restarting the engine.

Design highlights
-----------------
* **Deny-by-default** — an identity with no entry can call nothing.
* **Explicit wildcards** — ``"*"`` grants a group, but only when the identity
  opts in; it is never implicit.
* **Precedence**: explicit deny > explicit allow > wildcard > default deny.
* **O(1) lookup** — the file is precompiled into an in-memory index at load
  time (:class:`CompiledPermissions`); nothing is parsed per request.
* **Atomic hot reload** — :class:`PermissionStore` holds an immutable compiled
  snapshot behind an atomic pointer. Readers grab the current snapshot once and
  finish on it; a reload compiles+validates a *new* snapshot and swaps the
  pointer. Readers never block on writers, and a half-applied state is never
  observable. A bad file keeps the old snapshot active — the engine never fails
  open to "allow all".
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    raise ImportError("Install PyYAML: pip install pyyaml") from exc

from .exceptions import MegentError

logger = logging.getLogger("megent.permissions")

# Denial reasons surfaced to the audit trail. Kept as constants so callers and
# tests share one source of truth.
NO_POLICY = "no_policy"
EXPLICIT_DENY = "explicit_deny"
CONSTRAINT_VIOLATION = "constraint_violation"


class PermissionConfigError(MegentError):
    """Raised when a permission file cannot be parsed or fails validation."""


@dataclass(frozen=True)
class PermissionConstraint:
    """Optional per-tool restrictions applied once a tool is otherwise allowed.

    ``max_args_bytes``  — cap on the JSON-serialized size of the call args.
    ``path_keys``       — arg keys whose values are treated as filesystem paths.
    ``allowed_paths``   — glob patterns; every path arg must match one of these.
    """

    max_args_bytes: Optional[int] = None
    path_keys: tuple[str, ...] = ()
    allowed_paths: tuple[str, ...] = ()

    def check(self, args: dict[str, Any]) -> Optional[str]:
        """Return ``None`` if args satisfy the constraint, else a reason string."""
        if self.max_args_bytes is not None:
            try:
                size = len(json.dumps(args, default=str).encode("utf-8"))
            except (TypeError, ValueError):
                size = len(str(args).encode("utf-8"))
            if size > self.max_args_bytes:
                return f"args size {size}B exceeds max {self.max_args_bytes}B"

        if self.allowed_paths:
            for key in self.path_keys:
                if key not in args:
                    continue
                value = args[key]
                if not isinstance(value, str):
                    return f"path arg '{key}' must be a string"
                if not any(fnmatch.fnmatch(value, pat) for pat in self.allowed_paths):
                    return f"path '{value}' for arg '{key}' is outside allowed paths"
        return None


@dataclass
class Decision:
    """Outcome of a permission evaluation."""

    action: str  # "allow" | "deny"
    identity: Optional[str]
    tool: str
    reason: Optional[str] = None  # denial reason constant, when denied
    detail: Optional[str] = None  # human-readable detail (e.g. constraint msg)
    # Version/hash of the exact snapshot this decision was evaluated against.
    # Stamped by CompiledPermissions.evaluate so audit provenance stays
    # consistent even if a hot reload swaps the active snapshot afterwards.
    version: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


@dataclass(frozen=True)
class IdentityIndex:
    """Precompiled grants for a single identity — pure lookups, no parsing."""

    explicit_deny: frozenset[str] = frozenset()
    explicit_allow: dict[str, PermissionConstraint] = field(default_factory=dict)
    wildcard: bool = False
    wildcard_constraint: Optional[PermissionConstraint] = None


@dataclass(frozen=True)
class CompiledPermissions:
    """Immutable, precompiled snapshot of a permission file.

    Instances are never mutated after construction, so they can be shared
    across threads and swapped atomically. Lookup is O(1) per call.
    """

    version: str
    identities: dict[str, IdentityIndex] = field(default_factory=dict)
    source: Optional[str] = None

    def evaluate(
        self, identity: Optional[str], tool: str, args: Optional[dict[str, Any]] = None
    ) -> Decision:
        # Stamp the decision with this snapshot's version so a concurrent
        # reload cannot desync the logged provenance from the actual verdict.
        decision = self._decide(identity, tool, args or {})
        decision.version = self.version
        return decision

    def _decide(
        self, identity: Optional[str], tool: str, args: dict[str, Any]
    ) -> Decision:
        index = self.identities.get(identity) if identity is not None else None
        if index is None:
            # Deny-by-default: no entry for this identity → nothing allowed.
            return Decision(
                action="deny",
                identity=identity,
                tool=tool,
                reason=NO_POLICY,
                detail="identity has no permission entry",
            )

        # Precedence: explicit deny > explicit allow > wildcard > default deny.
        if tool in index.explicit_deny:
            return Decision(
                action="deny",
                identity=identity,
                tool=tool,
                reason=EXPLICIT_DENY,
                detail="tool is explicitly denied",
            )

        if tool in index.explicit_allow:
            return self._apply_constraint(
                index.explicit_allow[tool], identity, tool, args
            )

        if index.wildcard:
            return self._apply_constraint(
                index.wildcard_constraint or PermissionConstraint(),
                identity,
                tool,
                args,
            )

        return Decision(
            action="deny",
            identity=identity,
            tool=tool,
            reason=NO_POLICY,
            detail="tool not in identity allowlist",
        )

    @staticmethod
    def _apply_constraint(
        constraint: PermissionConstraint,
        identity: Optional[str],
        tool: str,
        args: dict[str, Any],
    ) -> Decision:
        violation = constraint.check(args)
        if violation is not None:
            return Decision(
                action="deny",
                identity=identity,
                tool=tool,
                reason=CONSTRAINT_VIOLATION,
                detail=violation,
            )
        return Decision(action="allow", identity=identity, tool=tool)


# ---------------------------------------------------------------------------
# Parsing / compilation
# ---------------------------------------------------------------------------

def _parse_constraint(raw: dict[str, Any], where: str) -> PermissionConstraint:
    max_bytes = raw.get("max_args_bytes")
    if max_bytes is not None:
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
            raise PermissionConfigError(f"{where}.max_args_bytes must be a non-negative int")

    path_keys = raw.get("path_keys", [])
    if not isinstance(path_keys, list) or not all(isinstance(k, str) for k in path_keys):
        raise PermissionConfigError(f"{where}.path_keys must be a list of strings")

    allowed_paths = raw.get("allowed_paths", [])
    if not isinstance(allowed_paths, list) or not all(
        isinstance(p, str) for p in allowed_paths
    ):
        raise PermissionConfigError(f"{where}.allowed_paths must be a list of strings")

    if allowed_paths and not path_keys:
        raise PermissionConfigError(
            f"{where}.allowed_paths requires path_keys to name the path arguments"
        )

    return PermissionConstraint(
        max_args_bytes=max_bytes,
        path_keys=tuple(path_keys),
        allowed_paths=tuple(allowed_paths),
    )


def _parse_tool_grant(name: str, raw: Any, where: str) -> tuple[bool, PermissionConstraint]:
    """Return (allowed, constraint) for one tool entry."""
    if isinstance(raw, bool):
        return raw, PermissionConstraint()
    if raw is None:
        return True, PermissionConstraint()
    if not isinstance(raw, dict):
        raise PermissionConfigError(
            f"{where}: tool '{name}' must be a bool or a mapping"
        )
    allowed = raw.get("allow", True)
    if not isinstance(allowed, bool):
        raise PermissionConfigError(f"{where}: tool '{name}' 'allow' must be a bool")
    return allowed, _parse_constraint(raw, f"{where}.{name}")


def _compile_identity(name: str, raw: Any) -> IdentityIndex:
    if not isinstance(raw, dict):
        raise PermissionConfigError(f"identity '{name}' must be a mapping")

    tools_raw = raw.get("tools", {})
    if not isinstance(tools_raw, dict):
        raise PermissionConfigError(f"identity '{name}'.tools must be a mapping")

    deny_raw = raw.get("deny", [])
    if not isinstance(deny_raw, list) or not all(isinstance(t, str) for t in deny_raw):
        raise PermissionConfigError(f"identity '{name}'.deny must be a list of strings")

    explicit_allow: dict[str, PermissionConstraint] = {}
    wildcard = False
    wildcard_constraint: Optional[PermissionConstraint] = None

    for tool_name, tool_raw in tools_raw.items():
        if not isinstance(tool_name, str):
            raise PermissionConfigError(f"identity '{name}': tool names must be strings")
        allowed, constraint = _parse_tool_grant(
            tool_name, tool_raw, f"identity '{name}'.tools"
        )
        if tool_name == "*":
            # Wildcards are an explicit opt-in only. A `"*": false` entry is a
            # no-op (it grants nothing) rather than a global deny.
            if allowed:
                wildcard = True
                wildcard_constraint = constraint
            continue
        if allowed:
            explicit_allow[tool_name] = constraint
        # `allow: false` in the tools map is treated as "not granted here";
        # use the top-level `deny:` list for an explicit, precedence-winning deny.

    return IdentityIndex(
        explicit_deny=frozenset(deny_raw),
        explicit_allow=explicit_allow,
        wildcard=wildcard,
        wildcard_constraint=wildcard_constraint,
    )


def compile_permissions(raw: Any, version: str, source: Optional[str] = None) -> CompiledPermissions:
    """Compile a parsed permission mapping into an immutable index.

    Raises :class:`PermissionConfigError` on any schema problem. Never returns
    a permissive fallback.
    """
    if not isinstance(raw, dict):
        raise PermissionConfigError("permission file root must be a mapping")

    identities_raw = raw.get("identities")
    if identities_raw is None:
        raise PermissionConfigError("permission file must define an 'identities' mapping")
    if not isinstance(identities_raw, dict):
        raise PermissionConfigError("'identities' must be a mapping")

    identities: dict[str, IdentityIndex] = {}
    for name, entry in identities_raw.items():
        if not isinstance(name, str):
            raise PermissionConfigError("identity keys must be strings")
        identities[name] = _compile_identity(name, entry)

    return CompiledPermissions(version=version, identities=identities, source=source)


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def compile_permissions_text(text: str, source: Optional[str] = None) -> CompiledPermissions:
    """Parse YAML/JSON text and compile it. Version is a hash of the bytes."""
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise PermissionConfigError(f"invalid YAML/JSON in permission file: {exc}") from exc
    version = _hash_bytes(text.encode("utf-8"))
    return compile_permissions(raw, version=version, source=source)


def load_permissions(path: str) -> CompiledPermissions:
    """Read and compile a permission file from disk."""
    text = Path(path).read_text(encoding="utf-8")
    return compile_permissions_text(text, source=str(path))


# ---------------------------------------------------------------------------
# Hot-reloadable store
# ---------------------------------------------------------------------------

class PermissionStore:
    """Holds the active compiled permissions behind an atomic pointer.

    Reads (:meth:`evaluate` / :meth:`current`) never block: they read the
    ``_current`` attribute once, which is atomic in CPython, and operate on that
    immutable snapshot. A reload compiles + validates a brand-new snapshot and
    only then rebinds ``_current`` — an atomic pointer swap. In-flight
    evaluations finish on the snapshot they started with; a half-applied state
    is never observable.

    If ``watch=True`` a daemon thread polls the file (every ``poll_interval``
    seconds) and reloads on change. An invalid new file keeps the current
    snapshot active and emits a ``policy-reload-failed`` audit event.
    """

    def __init__(
        self,
        path: str,
        *,
        audit: Any = None,
        watch: bool = False,
        poll_interval: float = 5.0,
        on_reload_failed: Optional[Callable[[str, str], None]] = None,
    ):
        self._path = str(path)
        self._audit = audit
        self._poll_interval = poll_interval
        self._on_reload_failed = on_reload_failed
        # Reload writers serialize on this lock; readers never take it.
        self._reload_lock = threading.Lock()
        # Initial load must succeed — refuse to start in an unknown state.
        self._current: CompiledPermissions = load_permissions(self._path)
        self._last_signature = self._file_signature()

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        if watch:
            self.start()

    # -- reads -------------------------------------------------------------

    def current(self) -> CompiledPermissions:
        """Return the active snapshot (atomic read; never blocks)."""
        return self._current

    def evaluate(
        self, identity: Optional[str], tool: str, args: Optional[dict[str, Any]] = None
    ) -> Decision:
        # Grab the snapshot once so the whole evaluation is consistent even if a
        # reload swaps the pointer mid-call.
        return self._current.evaluate(identity, tool, args)

    @property
    def version(self) -> str:
        return self._current.version

    # -- reloads -----------------------------------------------------------

    def reload_now(self) -> bool:
        """Attempt an immediate reload. Returns True if the snapshot changed.

        On any parse/schema failure the current snapshot is kept and a
        ``policy-reload-failed`` audit event is emitted. Never fails open.
        """
        with self._reload_lock:
            try:
                text = Path(self._path).read_text(encoding="utf-8")
            except OSError as exc:
                # Transient IO (file mid-replace, momentary lock): keep the old
                # snapshot and retry on the next poll. Not an invalid-content
                # event, so no audit noise.
                logger.debug("permission file read failed (transient): %s", exc)
                return False

            new_version = _hash_bytes(text.encode("utf-8"))
            if new_version == self._current.version:
                self._last_signature = self._file_signature()
                return False

            try:
                compiled = compile_permissions_text(text, source=self._path)
            except PermissionConfigError as exc:
                self._handle_reload_failure(str(exc))
                return False

            # Atomic pointer swap — this single rebind is the entire "apply".
            self._current = compiled
            self._last_signature = self._file_signature()
            logger.info(
                "permissions reloaded from %s (version %s)", self._path, compiled.version
            )
            return True

    def _handle_reload_failure(self, detail: str) -> None:
        logger.warning(
            "policy-reload-failed: keeping active permissions (version %s): %s",
            self._current.version,
            detail,
        )
        if self._audit is not None and hasattr(self._audit, "reload_failed"):
            self._audit.reload_failed(
                path=self._path,
                detail=detail,
                policy_version=self._current.version,
            )
        if self._on_reload_failed is not None:
            self._on_reload_failed(self._path, detail)

    # -- watcher thread ----------------------------------------------------

    def _file_signature(self) -> tuple[float, int]:
        try:
            st = Path(self._path).stat()
            return (st.st_mtime, st.st_size)
        except OSError:
            return (0.0, -1)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._watch_loop, name="megent-permission-watch", daemon=True
        )
        self._thread.start()

    def _watch_loop(self) -> None:
        while not self._stop.wait(self._poll_interval):
            signature = self._file_signature()
            if signature != self._last_signature:
                self.reload_now()

    def close(self) -> None:
        """Stop the watcher thread (idempotent)."""
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=self._poll_interval + 1.0)
            self._thread = None

    def __enter__(self) -> "PermissionStore":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
