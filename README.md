# Megent

Policy-based security middleware for AI agents.

Megent sits between your orchestration layer and your AI agents, intercepting every tool call before it executes — enforcing rules, masking sensitive data, and logging everything.

Agent → [tool call] → Megent policy engine → [allow / deny / redact] → Tool
---

## Why Megent

AI agents execute tool calls autonomously. Without a control layer, a single compromised prompt can exfiltrate data, delete records, or call APIs it was never supposed to touch.

Megent gives you deny-by-default security for agent tool calls — without rewriting your agents.

---

## Features

- Deny-by-default — nothing executes unless explicitly allowed by policy
- YAML policy language — define rules in plain text, version them in git
- JWT agent identity — every agent has a passport; every action is authorized against it
- PII masking — redact sensitive data before it reaches tools or logs
- Structured audit logs — full trace of every tool call, decision, and outcome
- Zero agent rewrite — wrap existing agents in one line

---

## Quickstart

pip install megent
### Decorate your agent

import megent as mgnt

@mgnt.guard(policy="policies/agent.yaml")
def my_agent(task: str):
    # your existing agent code
    ...
### Or wrap a third-party agent

secured_agent = mgnt.wrap(agent, policy="policies/agent.yaml")
result = secured_agent.run("summarize the sales report")
### Define a policy

# policies/agent.yaml
version: 1
agent: sales-assistant

rules:
  - tool: read_file
    allow: true
    conditions:
      path_prefix: "/reports/"

  - tool: send_email
    allow: true
    conditions:
      recipient_domain: "@company.com"

  - tool: delete_record
    allow: false

  - tool: "*"
    allow: false  # deny-by-default
---

## Policy Registry CLI

Install and manage policy packs:

```bash
megent policy install stripe
megent policy list
megent policy info stripe
megent policy verify stripe
megent policy remove stripe
```

You can also reference installed packs by name:

```python
import megent as mgnt

@mgnt.guard(policy="stripe")
def billing_agent(prompt: str):
    ...
```

---


## How It Works

┌─────────────────────────────────────────────┐
│              Orchestration Layer             │
│         (LangChain / CrewAI / etc.)          │
└────────────────────┬────────────────────────┘
                     │ tool call
                     ▼
┌─────────────────────────────────────────────┐
│              Megent Policy Engine            │
│  • Verify agent identity (JWT)               │
│  • Evaluate policy rules                     │
│  • Mask PII                                  │
│  • Emit audit log                            │
└────────────────────┬────────────────────────┘
                     │ allow / deny
                     ▼
┌─────────────────────────────────────────────┐
│                  Tool Layer                  │
│       (APIs, databases, file system)         │
└─────────────────────────────────────────────┘
---

## Agent Identity

Each agent is issued a passport — a signed JWT that defines its identity and permitted scope. Megent validates this on every tool call.

passport = mgnt.issue_passport(
    agent_id="sales-assistant-v1",
    scopes=["read_file", "send_email"],
    expires_in="1h"
)
Agents without a valid passport are blocked before any tool executes.

---

## Audit Logs

Every tool call produces a structured log entry:
```json
{
  "timestamp": "2026-03-31T10:22:01Z",
  "agent_id": "sales-assistant-v1",
  "tool": "read_file",
  "decision": "allow",
  "args": { "path": "/reports/q1.pdf" },
  "policy": "policies/agent.yaml",
  "rule_matched": "read_file/path_prefix"
}``
---


## Contributing

Contributions are welcome. Please open an issue before submitting large PRs.

git clone https://github.com/getmagent/megent
cd megent
pip install -e ".[dev]"
pytest
---

## License
<!-- [3/30/2026 11:19 PM] miki:  -->
Apache 2.0 — see [LICENSE](./LICENSE).

---

<p align="center">
  <a href="https://megent.dev">megent.dev</a> · 
  <a href="https://twitter.com/megents">@megents</a>
</p>
