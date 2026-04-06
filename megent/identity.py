from __future__ import annotations

import os
from typing import Any, Optional

from .exceptions import IdentityError

_JWT_AVAILABLE = False
try:
    import jwt as pyjwt  # PyJWT
    _JWT_AVAILABLE = True
except ImportError:
    pass


def verify_agent_token(token: str, secret: Optional[str] = None) -> dict[str, Any]:
    """
    Verify a JWT agent token and return its claims.

    The secret is resolved from:
      1. Explicit `secret` argument
      2. MEGENT_JWT_SECRET env var

    If PyJWT is not installed, verification fails closed by default.
    For local/dev-only workflows you can opt into insecure decoding by
    setting MEGENT_ALLOW_INSECURE_TOKEN_DECODE=true.
    """
    resolved_secret = secret or os.environ.get("MEGENT_JWT_SECRET")

    if not _JWT_AVAILABLE:
        import base64
        import json
        import warnings

        # Explicit dev-only escape hatch when PyJWT is unavailable.
        allow_insecure_decode = (
            os.environ.get("MEGENT_ALLOW_INSECURE_TOKEN_DECODE", "").strip().lower()
            in {"1", "true", "yes", "on"}
        )
        if not allow_insecure_decode:
            raise IdentityError(
                "PyJWT is required to verify agent tokens. "
                "Install with: pip install pyjwt. "
                "For development only, set MEGENT_ALLOW_INSECURE_TOKEN_DECODE=true."
            )

        warnings.warn(
            "PyJWT not installed — using INSECURE unverified token decoding. "
            "Do not use this mode in production.",
            stacklevel=3,
        )
        try:
            parts = token.split(".")
            if len(parts) < 2:
                raise ValueError("JWT must include a payload segment")
            payload = parts[1]
            padded_payload = payload + "=" * (-len(payload) % 4)
            decoded = base64.urlsafe_b64decode(padded_payload.encode("utf-8"))
            return json.loads(decoded)
        except Exception as exc:
            raise IdentityError(f"Cannot decode token: {exc}") from exc

    if not resolved_secret:
        raise IdentityError(
            "No JWT secret provided. Set MEGENT_JWT_SECRET or pass secret=."
        )

    try:
        return pyjwt.decode(token, resolved_secret, algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        raise IdentityError("Agent token has expired.")
    except pyjwt.InvalidTokenError as exc:
        raise IdentityError(f"Invalid agent token: {exc}") from exc


def agent_id_from_token(token: Optional[str]) -> Optional[str]:
    """Best-effort extract agent_id claim; returns None if token is absent or invalid."""
    if not token:
        return None
    try:
        claims = verify_agent_token(token)
        return claims.get("agent_id") or claims.get("sub")
    except IdentityError:
        return None
