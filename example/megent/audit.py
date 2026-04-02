from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Optional

logger = logging.getLogger("megent.audit")


@dataclass
class AuditEvent:
    event: Literal["allow", "block", "mask"]
    tool: str
    agent_id: Optional[str]
    timestamp: float = field(default_factory=time.time)
    args: dict[str, Any] = field(default_factory=dict)
    reason: Optional[str] = None
    masked_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class AuditLogger:
    """
    Writes structured audit events to the Python logging system.
    Swap the handler to ship to any SIEM, file, or stream.
    """

    def __init__(self, log_level: int = logging.INFO):
        self._log_level = log_level

    def log(self, event: AuditEvent) -> None:
        logger.log(self._log_level, event.to_json())

    def allow(
        self,
        tool: str,
        agent_id: Optional[str] = None,
        args: dict[str, Any] | None = None,
        masked_fields: list[str] | None = None,
    ) -> None:
        self.log(
            AuditEvent(
                event="allow",
                tool=tool,
                agent_id=agent_id,
                args=args or {},
                masked_fields=masked_fields or [],
            )
        )

    def block(
        self,
        tool: str,
        reason: str,
        agent_id: Optional[str] = None,
        args: dict[str, Any] | None = None,
    ) -> None:
        self.log(
            AuditEvent(
                event="block",
                tool=tool,
                agent_id=agent_id,
                args=args or {},
                reason=reason,
            )
        )
