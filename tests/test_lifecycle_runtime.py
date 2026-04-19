from __future__ import annotations

from pathlib import Path

import megent as mg
import pytest
from megent.audit import AuditEvent, AuditLogger
from megent.exceptions import PolicyViolation


class _CaptureLifecycleLogger(AuditLogger):
    def __init__(self) -> None:
        super().__init__()
        self.events: list[AuditEvent] = []

    def log(self, event: AuditEvent) -> None:
        self.events.append(event)


def _write_policy(path: Path) -> None:
    path.write_text(
        """
version: "1"
default_action: deny

tools:
  send_email:
    allow: true
    pii_mask: [email, phone]
  delete_all_data:
    allow: false
""".strip()
        + "\n",
        encoding="utf-8",
    )


def test_runtime_lifecycle_shows_allow_mask_and_block(tmp_path: Path) -> None:
    policy_path = tmp_path / "megent.yaml"
    _write_policy(policy_path)

    capture = _CaptureLifecycleLogger()
    runtime = mg.Runtime(policy_path=str(policy_path), audit=capture)

    def send_email(to: str, body: str) -> str:
        return f"sent:{to}"

    def delete_all_data(target: str) -> str:
        return f"deleted:{target}"

    safe_send = mg.wrap(send_email, runtime=runtime, tool_name="send_email")
    safe_delete = mg.wrap(delete_all_data, runtime=runtime, tool_name="delete_all_data")

    result = safe_send(
        "ops@example.com",
        "Email jane.doe@example.com and call +1 555 222 3333",
    )
    assert result == "sent:[REDACTED]"

    with pytest.raises(PolicyViolation):
        safe_delete("prod-db")

    assert len(capture.events) == 2

    allow_event = capture.events[0]
    assert allow_event.event == "allow"
    assert allow_event.tool == "send_email"
    assert "email" in allow_event.masked_fields
    assert "phone" in allow_event.masked_fields
    assert "[REDACTED]" in str(allow_event.args)

    block_event = capture.events[1]
    assert block_event.event == "block"
    assert block_event.tool == "delete_all_data"
    assert block_event.reason == "not in policy allowlist"
