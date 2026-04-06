<div align="center">

```
███╗   ███╗███████╗ ██████╗ ███████╗███╗   ██╗████████╗
████╗ ████║██╔════╝██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
██╔████╔██║█████╗  ██║  ███╗█████╗  ██╔██╗ ██║   ██║   
██║╚██╔╝██║██╔══╝  ██║   ██║██╔══╝  ██║╚██╗██║   ██║   
██║ ╚═╝ ██║███████╗╚██████╔╝███████╗██║ ╚████║   ██║   
╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   
```

**A zero-trust safety layer for AI agents. Wrap tools fast. Ship with confidence.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/megent/)
[![PyPI](https://img.shields.io/pypi/v/megent)](https://pypi.org/project/megent/)
[![Status](https://img.shields.io/badge/status-beta-orange)](https://megent.dev)

[**Docs**](https://megent.dev/docs) · [**Demo**](https://megent.dev/demo) · [**Blog**](https://megent.dev/blog)

</div>

---

## The Problem

AI agents are calling tools. Most of those calls look harmless. But sequences don't lie.

```
agent.read_file("/etc/passwd")          ← looks fine
agent.web_search("paste.bin upload")    ← looks fine  
agent.http_post("https://...")          ← looks fine

# combined? that's data exfiltration.
```

Traditional security tools inspect calls one by one. **Megent enforces policy at execution time.**

Built for teams that want speed without security debt.

---

## How It Works

Megent sits between your agent and its tools, running every call through three primitives:

```
┌─────────────────────────────────────────────────────┐
│                    AGENT RUNTIME                    │
│                                                     │
│  tool_call() ──► [ INTERCEPT ] ──► [ CONTEXT ]      │
│                                          │          │
│                                     [ JUDGE ]       │
│                                          │          │
│                              allow / deny / modify  │
└─────────────────────────────────────────────────────┘
```

| Primitive | Role |
|-----------|------|
| **Intercept** | Hooks into every tool invocation before execution |
| **Context** | Maintains a behavioral window — the sequence of recent calls |
| **Judge** | Evaluates the sequence against your policy rules |

---

## Install

```bash
pip install megent
```

---

## Quickstart

### Drop-in decorator

```python
import megent as mg

mg.configure(policy_path="policies/agent.yaml")

@mg.guard
def send_email(to: str, subject: str, body: str) -> str:
  # your tool implementation
  return "sent"

send_email(
  to="ops@example.com",
  subject="Daily summary",
  body="Contact me at jane.doe@example.com",
)
```

### Wrap an existing agent

```python
import megent as mg

runtime = mg.Runtime(policy_path="policies/agent.yaml")

safe_execute = mg.wrap(
  third_party_agent.execute,
  runtime=runtime,
  tool_name="agent_execute",
)

safe_execute(task="Summarize latest reports")
```

That's it. Megent intercepts every tool call, evaluates it against your policy, and either allows, denies, or modifies it — all without changing your agent code.

---

## Policy Language

Policies are plain YAML. No DSL to learn.

```yaml
# policies/agent.yaml
version: "1"
default_action: deny
pii_mask: [email]

tools:
  read_file:
    allow: true

  send_email:
    allow: true
    pii_mask: [email, phone, ssn]

  delete_all_data:
    allow: false
```

---

## Agent Identity (JWT)

Megent can attribute calls to an agent identity using a JWT (HS256).
Set `MEGENT_JWT_SECRET` (or pass `secret=` to `verify_agent_token`) and
include `agent_id` (or `sub`) in the token claims.

```python
import megent as mg

runtime = mg.Runtime(policy_path="policies/agent.yaml")
token = "<jwt-from-your-auth-system>"

safe_send = mg.wrap(send_email, runtime=runtime, tool_name="send_email", agent_token=token)
safe_send(to="ops@example.com", subject="Ping", body="hello")
```

---

## Audit Log

Every decision is logged in structured JSON.

```json
{
  "event": "allow",
  "tool": "http_post",
  "agent_id": "reports-agent-v2",
  "timestamp": 1767945230.137,
  "args": {
    "body": "[REDACTED]"
  },
  "masked_fields": ["email"]
}
```

Pipe to any SIEM. Query with any log tool.

---

## Framework-agnostic

Megent is not a plugin for LangChain, CrewAI, or any other framework. It is an independent security layer.

You build your agent on whatever platform you want. Megent wraps it.

```
┌──────────────────────────────────────┐
│              MEGENT                  │  ← security layer (this is us)
│  ┌────────────────────────────────┐  │
│  │   your agent (LangChain,       │  │  ← built on any framework
│  │   CrewAI, OpenAI Agents SDK,   │  │
│  │   raw Python, anything)        │  │
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
```

Megent doesn't know or care what your agent is built on. It intercepts tool calls at the boundary — before execution — regardless of the underlying platform.

```python
import megent as mg

# agent built on LangChain? wrap it.
safe_agent = mg.wrap(langchain_agent.invoke, runtime=mg.Runtime(policy_path="policies/agent.yaml"))

# agent built on CrewAI? wrap it.
safe_agent = mg.wrap(crew.kickoff, runtime=mg.Runtime(policy_path="policies/agent.yaml"))

# raw Python agent? same thing.
safe_agent = mg.wrap(my_agent.run, runtime=mg.Runtime(policy_path="policies/agent.yaml"))
```

The platforms (LangChain, CrewAI, OpenAI Agents SDK, AutoGen, LlamaIndex) are where agents are **built**. Megent is where they are **secured**. These are separate concerns.

---

## Threat Coverage

| Attack | Megent Defense |
|--------|---------------|
| Unauthorized tool calls | Per-tool allow/deny policy enforcement |
| Unknown-by-default execution | `default_action: deny` for explicit allowlists |
| PII leakage in arguments | Configurable regex masking (`pii_mask`) |
| Unattributed execution | Optional JWT-based `agent_id` attribution |
| Weak observability | Structured audit events via standard logging |

---
---
## Contributing

Megent is Apache 2.0 licensed and open to contributions.

```bash
git clone https://github.com/Megents/Megent.git
cd megent
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

[Apache 2.0](LICENSE) — free to use, modify, and distribute.

---

<div align="center">

Built for production AI. Designed for developers who ship.

**[megent.dev](https://megent.dev)**

</div>
