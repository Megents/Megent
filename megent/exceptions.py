class MegentError(Exception):
    """Base exception for Megent."""


class PolicyViolation(MegentError):
    """Raised when a tool call is blocked by policy."""

    def __init__(self, tool: str, reason: str):
        self.tool = tool
        self.reason = reason
        super().__init__(f"Tool '{tool}' blocked: {reason}")


class PolicyLoadError(MegentError):
    """Raised when a policy file cannot be loaded or parsed."""


class PolicyNotFoundError(MegentError):
    """Raised when a named policy pack is not installed."""


class PolicyInstallError(MegentError):
    """Raised when a policy pack cannot be fetched or installed."""


class PolicyVerificationError(MegentError):
    """Raised when policy signature verification fails."""


class IdentityError(MegentError):
    """Raised when agent identity cannot be verified."""
