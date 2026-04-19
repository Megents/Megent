"""
Megent — AI agent security middleware.

Policy-enforced tool call interception for AI agents.
"""

from .audit import AuditLogger, AuditEvent
from .exceptions import (
    IdentityError,
    MegentError,
    PolicyLoadError,
    PolicyViolation,
    RegistryError,
    RegistryFetchError,
    RegistryInstallError,
    RegistryVerificationError,
)
from .guard import configure, guard, wrap
from .awareness import AlertReport, AwarenessGuard, EscalationDetector, ExfiltrationDetector, LoopDetector, ShadowDetector, ToolEvent
from .budget import BudgetExceededError, BudgetPolicy, BudgetReport, SessionBudget
from .hitl import HITLPolicy, ReviewOutcome, ReviewRequest, ReviewVerdict, cli_reviewer, webhook_reviewer
from .identity import verify_agent_token, agent_id_from_token
from .pii import mask_args
from .policy import Policy, ToolPolicy, compose_policies, load_policy
from .registry import PolicyAuditResult, PolicyPack, RegistryClient
from .runtime import Runtime
from .stop import GracefulStop, SoftStop, is_stopped

__all__ = [
    # Top-level API
    "configure",
    "guard",
    "wrap",
    # Runtime
    "Runtime",
    # Features
    "AlertReport",
    "AwarenessGuard",
    "BudgetExceededError",
    "BudgetPolicy",
    "BudgetReport",
    "EscalationDetector",
    "ExfiltrationDetector",
    "GracefulStop",
    "HITLPolicy",
    "LoopDetector",
    "ReviewOutcome",
    "ReviewRequest",
    "ReviewVerdict",
    "SessionBudget",
    "ShadowDetector",
    "SoftStop",
    "ToolEvent",
    "cli_reviewer",
    "is_stopped",
    "webhook_reviewer",
    # Policy
    "Policy",
    "ToolPolicy",
    "compose_policies",
    "load_policy",
    "PolicyPack",
    "PolicyAuditResult",
    "RegistryClient",
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
    "RegistryError",
    "RegistryFetchError",
    "RegistryVerificationError",
    "RegistryInstallError",
]

__version__ = "0.1.5"
