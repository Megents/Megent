import megent as mg

mg.configure(policy_path="megent.yaml")
# print(meg)


@mg.guard
def send_email(to: str, subject: str, body: str) -> dict:
    """Send an email. Policy-enforced before execution."""
    print(f"  → Sending email to {to}")
    return {"status": "sent"}

@mg.guard
def execute_sql(query: str) -> dict:
    """Execute SQL. Blocked by policy."""
    return {"rows": []}

@mg.guard
def delete_record():
    return 'ienvenbi'
    
send_email(
    to="user@example.com",
    subject="Test Email",
    body="This is a test email."
)
execute_sql(query="DROP TABLE users")
delete_record()