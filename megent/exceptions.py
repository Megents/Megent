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


class IdentityError(MegentError):
    """Raised when agent identity cannot be verified."""


class RegistryError(MegentError):
    """Base exception for registry client errors."""


class RegistryFetchError(RegistryError):
    """Raised when a policy pack cannot be fetched from a registry."""


class RegistryVerificationError(RegistryError):
    """Raised when signature verification fails for a policy pack."""


class RegistryInstallError(RegistryError):
    """Raised when a verified policy pack cannot be installed locally."""
