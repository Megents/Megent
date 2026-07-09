
Quick answer first, then the important warning.

## What is a "Claude Code session"?

Claude Code is Anthropic's CLI coding agent — you run `claude` in your terminal, describe a task, and it reads your codebase, writes code, runs tests, and iterates. A **session** is the transcript of one of those conversations: your prompts + Claude's reasoning + the code it wrote + the commands it ran.

YC asks for this because it shows **how you actually work with AI tools** — how good your prompts are, how you break down problems, how you review the agent's output.

## ⚠️ Do NOT fabricate one

I won't generate a fake session for you to attach — and you shouldn't want one. YC partners read hundreds of these; a fabricated transcript is easy to spot (no real file paths, no errors, no iteration, too clean) and if detected it kills your entire application. You said you built Megent *with* Claude Code — so you already have real sessions. Use one.

## How to get a REAL session (5 minutes)

**Option 1 — Export from inside Claude Code:**
```bash
claude          # open Claude Code in your Megent repo
/resume         # pick a past session (e.g., when you built the policy engine)
/export         # exports the transcript to a file
```

**Option 2 — Find stored transcripts on disk:**
```bash
ls ~/.claude/projects/
# Sessions are stored as .jsonl files per project — find the Megent one
```

**Option 3 — If you can't recover an old one:** start a fresh, real session today. Pick a genuine task on your actual roadmap, e.g.:

> "Add rate-limiting to the Megent policy engine so a single agent identity can't exceed N tool calls per minute. Deny-by-default when the limit is hit, and log the block to the audit trail."

Do the work for real, iterate for real, ship it for real — then export that.

## Which session to pick

Choose one that shows **you** thinking, not just Claude typing. The best sessions for YC show:

1. ✅ A hard, real problem (JWT passport chaining, the deny-by-default interceptor, ThreatAnalyzer scoring)
2. ✅ You correcting Claude when it's wrong ("no, the check must run *before* the tool executes, move it out of the callback")
3. ✅ An error appearing and getting fixed
4. ✅ Tests passing at the end

A session where you pasted one prompt and accepted everything is a *weak* signal even if the code worked.

## README to attach alongside it

Here's a short framing file you can include with the export — fill in the real details:

```markdown
# Claude Code Session — Megent Policy Engine

## Task
[e.g., Implement per-identity rate limiting in the deny-by-default
enforcement engine, blocking before tool execution.]

## Why this session
Shows how we build Megent: architecture decisions stay with us,
Claude Code handles implementation speed. Key moments:

- Line [X]: Claude proposed checking limits inside the tool callback.
  I rejected it — enforcement must happen pre-execution or it's
  observability, not a firewall. Redirected the design.
- Line [X]: Test failure on [real error]. Fixed in two iterations.
- Line [X]: Final tests passing, merged in commit [hash].

## Outcome
Shipped in Megent v[X.X], live at github.com/[your-repo].
Time: [X] hours with Claude Code vs. estimated [X] without.

— Mikiyas Zenebe, Co-Founder/CEO
```

**Bottom line:** the field is optional, so a real, imperfect session beats a polished fake infinitely — and beats leaving it blank slightly. Spend one evening doing a genuine task in your repo with Claude Code, export it, attach it with the README above. That's authentic, fast, and exactly what YC is looking for.