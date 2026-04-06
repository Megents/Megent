"""Simple real-world Megent lifecycle demo.

Run steps:
1) pip install megent
2) python example/megent_simple.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# When run as `python example/megent_simple.py`, Python only adds `example/`
# to sys.path, so we insert the project root first to load the local package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import megent as mg
from megent.audit import AuditEvent, AuditLogger
from megent.exceptions import PolicyViolation


class ConsoleLifecycleLogger(AuditLogger):
    """Print ordered runtime lifecycle events for each tool call."""

    def log(self, event: AuditEvent) -> None:
        print(
            "[lifecycle]"
            f" event={event.event}"
            f" tool={event.tool}"
            f" agent={event.agent_id}"
            f" masked={event.masked_fields}"
            f" reason={event.reason}"
        )
        print(f"[lifecycle] args={event.args}")


def _write_policy_file(path: Path) -> None:
    policy_text = (
        "version: \"1\"\n"
        "default_action: deny\n"
        "\n"
        "tools:\n"
        "  send_email:\n"
        "    allow: true\n"
        "    pii_mask: [email, phone]\n"
        "  delete_all_data:\n"
        "    allow: false\n"
    )
    path.write_text(policy_text, encoding="utf-8")


def main() -> None:
    policy_path = Path("megent.yaml")
    _write_policy_file(policy_path)

    runtime = mg.Runtime(policy_path=str(policy_path), audit=ConsoleLifecycleLogger())

    def send_email(to: str, body: str) -> str:
        print(f"[tool] send_email executed to={to}")
        return "ok"

    def delete_all_data(target: str) -> str:
        print(f"[tool] delete_all_data executed target={target}")
        return "deleted"

    safe_send = mg.wrap(send_email, runtime=runtime, tool_name="send_email")
    safe_delete = mg.wrap(delete_all_data, runtime=runtime, tool_name="delete_all_data")

    print("\n=== Allowed Call + PII Masking ===")
    result = safe_send(
        "ops@example.com",
        "Contact me at jane.doe@example.com or +1 555 222 3333",
    )
    print("Result:", result)

    print("\n=== Blocked Call ===")
    try:
        safe_delete("prod-db")
    except PolicyViolation as exc:
        print("Blocked:", exc)


if __name__ == "__main__":
    main()
