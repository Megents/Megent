"""
Megent — AI agent security middleware.

Policy-enforced tool call interception for AI agents.
"""

from .audit import AuditLogger, AuditEvent
from .exceptions import MegentError, PolicyViolation, PolicyLoadError, IdentityError
from .guard import configure, guard, wrap
from .identity import verify_agent_token, agent_id_from_token
from .pii import mask_args
from .policy import Policy, ToolPolicy, load_policy
from .runtime import Runtime

__all__ = [
    # Top-level API
    "configure",
    "guard",
    "wrap",
    # Runtime
    "Runtime",
    # Policy
    "Policy",
    "ToolPolicy",
    "load_policy",
    # PII
    "mask_args",
    # Identity
    "verify_agent_token",
    "agent_id_from_token",
    # Audit
    "AuditLogger",
    "AuditEvent",
    # Exceptions
    "MegentError",
    "PolicyViolation",
    "PolicyLoadError",
    "IdentityError",
]

__version__ = "0.1.0"
