"""
Megent usage example.

Shows @guard decorator and wrap() for a simple AI agent tool setup.
"""
import logging
import megent.megent as mgnt

# Show audit logs in console
logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Example 1: @guard decorator on your own tools
# ---------------------------------------------------------------------------

# Configure once at startup (looks for megent.yaml by default)
mgnt.configure(policy_path="megent.yaml")


@mgnt.guard
def send_email(to: str, subject: str, body: str) -> dict:
    """Send an email. Policy-enforced before execution."""
    print(f"  → Sending email to {to}")
    return {"status": "sent"}


@mgnt.guard
def execute_sql(query: str) -> dict:
    """Execute SQL. Blocked by policy."""
    return {"rows": []}


print("=== @guard decorator ===")

# Allowed — passes through
try:
    result = send_email(
        to="user@example.com",
        subject="Hello",
        body="Your SSN 123-45-6789 is on file.",   # SSN gets masked in logs
    )
    print(f"send_email: {result}")
except mgnt.PolicyViolation as e:
    print(f"BLOCKED: {e}")

# Blocked by policy
try:
    execute_sql(query="DROP TABLE users")
except mgnt.PolicyViolation as e:
    print(f"BLOCKED: {e}")


# ---------------------------------------------------------------------------
# Example 2: wrap() for third-party agents
# ---------------------------------------------------------------------------

print("\n=== wrap() for third-party agents ===")

class ThirdPartyAgent:
    def delete_record(self, table: str, record_id: int):
        print(f"  → Deleting {table}/{record_id}")
        return {"deleted": True}

    def read_file(self, path: str):
        print(f"  → Reading {path}")
        return {"content": "..."}


agent = ThirdPartyAgent()

# Wrap individual methods at install time
safe_delete = mgnt.wrap(agent.delete_record, tool_name="delete_record")
safe_read   = mgnt.wrap(agent.read_file,    tool_name="read_file")

try:
    safe_delete(table="users", record_id=42)
except mgnt.PolicyViolation as e:
    print(f"BLOCKED: {e}")

try:
    result = safe_read(path="/data/report.csv")
    print(f"read_file: {result}")
except mgnt.PolicyViolation as e:
    print(f"BLOCKED: {e}")
