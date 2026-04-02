<div align="center">

```
███╗   ███╗███████╗ ██████╗ ███████╗███╗   ██╗████████╗
████╗ ████║██╔════╝██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
██╔████╔██║█████╗  ██║  ███╗█████╗  ██╔██╗ ██║   ██║   
██║╚██╔╝██║██╔══╝  ██║   ██║██╔══╝  ██║╚██╗██║   ██║   
██║ ╚═╝ ██║███████╗╚██████╔╝███████╗██║ ╚████║   ██║   
╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   
```

**Security middleware for AI agents. One decorator. Zero blind spots.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://pypi.org/project/megent/)
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

Traditional security tools inspect calls one by one. **Megent watches the sequence.**

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
import mgnt

@mgnt.guard(policy="policies/agent.yaml")
def run_agent():
    agent.run("Summarize the latest reports and email them to the team.")
```

### Wrap an existing agent

```python
import mgnt

safe_agent = mgnt.wrap(
    agent,
    policy="policies/agent.yaml",
    identity="reports-agent-v2"
)

safe_agent.run("Summarize the latest reports and email them.")
```

That's it. Megent intercepts every tool call, evaluates it against your policy, and either allows, denies, or modifies it — all without changing your agent code.

---

## Policy Language

Policies are plain YAML. No DSL to learn.

```yaml
# policies/agent.yaml
version: "1"
default: deny                        # deny-by-default

rules:
  - name: block_data_exfiltration
    description: Detect read → search → post sequences
    sequence:
      - tool: file_read
        match: { path: "/etc/*" }
      - tool: web_search
        within: 5                    # within 5 calls
      - tool: http_post
        within: 3
    action: deny
    alert: true

  - name: mask_pii_in_emails
    tool: send_email
    transform:
      body:
        - mask: email
        - mask: phone
        - mask: ssn
    action: allow

  - name: allow_approved_tools
    tools: [web_search, read_file, send_slack_message]
    action: allow
```

---

## AgentPassport

Every agent gets a cryptographic identity. Every call is attributed.

```python
passport = mgnt.AgentPassport(
    agent_id="reports-agent-v2",
    permissions=["file_read", "web_search", "send_email"],
    ttl=3600
)

safe_agent = mgnt.wrap(agent, passport=passport)
```

AgentPassport issues a signed JWT per session. Any call made outside the declared permissions is denied — even if the policy file would otherwise allow it.

---

## Audit Log

Every decision is logged in structured JSON.

```json
{
  "ts": "2025-11-12T14:23:01Z",
  "agent": "reports-agent-v2",
  "tool": "http_post",
  "sequence": ["file_read", "web_search", "http_post"],
  "rule_triggered": "block_data_exfiltration",
  "action": "deny",
  "payload_hash": "sha256:e3b0c4..."
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
# agent built on LangChain? wrap it.
safe_agent = mgnt.wrap(langchain_agent, policy="policies/agent.yaml")

# agent built on CrewAI? wrap it.
safe_agent = mgnt.wrap(crew, policy="policies/agent.yaml")

# raw Python agent? same thing.
safe_agent = mgnt.wrap(my_agent, policy="policies/agent.yaml")
```

The platforms (LangChain, CrewAI, OpenAI Agents SDK, AutoGen, LlamaIndex) are where agents are **built**. Megent is where they are **secured**. These are separate concerns.

---

## Threat Coverage

| Attack | Megent Defense |
|--------|---------------|
| Tool call injection | Intercept layer validates call structure |
| Context poisoning | Context window detects anomalous drift |
| Prompt injection → privilege escalation | Sequence analysis flags lateral movement |
| PII leakage | Transform rules mask before execution |
| Shadow tool calls | Deny-by-default blocks undeclared tools |

---
---
## Contributing

Megent is Apache 2.0 licensed and open to contributions.

```bash
git clone https://github.com/getmegent/megent
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
