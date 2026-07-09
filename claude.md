# Megent — engine notes

AI agent security middleware: policy-enforced tool-call interception. The
`Runtime` intercepts each tool call, applies enforcement layers, masks PII, and
emits structured audit events before the tool executes.

## Enforcement order (`Runtime.enforce`)

1. **Rate limit** — sliding-window, per-identity, fail-closed. (Merged;
   `megent/ratelimit.py`. Do not modify except at integration points.)
2. **Capability permissions** — per-identity tool allowlist, deny-by-default,
   hot-reloadable (`megent/permissions.py`).
3. **Policy evaluation** — the existing rule/tool policy (`megent/policy.py`).

Each layer denies independently; a deny short-circuits and emits an audit block.

---

## Capability-based tool permissions

Each agent identity gets an **explicit allowlist** of tools; everything else is
denied. The identity key is the JWT-derived `agent_id` (same value the rate
limiter uses); a missing/invalid token resolves to `None`, which — unless an
identity named `None` is listed — is denied everything.

### Policy file schema (YAML or JSON)

```yaml
version: 1
identities:
  billing-agent:
    tools:
      read_invoice: true            # bare `true` → allow, no constraints
      write_file:
        allow: true
        max_args_bytes: 4096        # reject oversized calls
        path_keys: [path]           # arg keys treated as filesystem paths
        allowed_paths:              # each path arg must match one of these globs
          - "/data/invoices/**"
    deny:
      - send_email                  # explicit deny — wins over everything
  reporting-agent:
    tools:
      "*": true                     # wildcard: EXPLICIT opt-in, never implicit
    deny:
      - delete_record
```

- **`identities`** (required mapping). An identity absent from this map can call
  **nothing**.
- **`tools`** — map of tool name → `true` | `false` | `{allow, max_args_bytes,
  path_keys, allowed_paths}`. `false`/omitted means "not granted here" (not a
  deny). `"*"` is the wildcard group and is only active when listed explicitly.
- **`deny`** — list of tool names that are explicitly denied; this wins over an
  allow or wildcard.
- **Constraints** (optional, per grant): `max_args_bytes` caps the
  JSON-serialized args size; `allowed_paths` (requires `path_keys`) restricts
  path-typed args to matching globs.

A full annotated example lives in
[policy-workspace/examples/permissions.yaml](policy-workspace/examples/permissions.yaml).

### Precedence table

| Order | Condition                              | Result                                   |
|-------|----------------------------------------|------------------------------------------|
| 1     | tool in identity's `deny` list         | **deny** → `explicit_deny`               |
| 2     | tool in identity's `tools` (allowed)   | allow, else `constraint_violation`       |
| 3     | identity has explicit `"*"` wildcard   | allow, else `constraint_violation`       |
| 4     | identity absent, or no rule matched    | **deny** → `no_policy` (default deny)     |

### O(1) lookup

The file is compiled once at load into an immutable `CompiledPermissions`
snapshot (`identities → IdentityIndex` of frozenset/dict). Evaluation is pure
dict/set lookups — nothing is parsed per request.

### Hot reload behavior

`PermissionStore` holds the active snapshot behind an atomic pointer:

- Changes apply **without restarting** the engine. With `watch=True` a daemon
  thread polls the file every `poll_interval` seconds (default 5s), comparing
  `(mtime, size)` then a content hash. `reload_now()` forces an immediate check.
- **Atomic swap / copy-on-write**: a reload parses → validates → compiles a
  brand-new snapshot, and only then rebinds the pointer. Readers grab the
  current snapshot once at the start of an evaluation and finish on it —
  in-flight calls use the old policy, new calls use the new one. Readers never
  block on the reload writer. A half-applied state is never observable.
- **Never fails open**: if the new file is invalid (parse or schema error) the
  old snapshot stays active, a `policy-reload-failed` audit event is emitted,
  and a warning is logged. A transient read error (file mid-replace / locked)
  keeps the old snapshot and retries on the next poll **without** an audit event
  (avoids noise during atomic file replaces).

### Audit events

A blocked call emits a block event via `AuditLogger.permission_denied` with:
timestamp, `agent_id` (identity), `tool`, `denial_reason` (`no_policy` |
`explicit_deny` | `constraint_violation`), and `policy_version` (a sha256 hash
of the file). Reload failures emit a `policy-reload-failed` event carrying the
retained policy version. Both reuse the existing `AuditLogger` writer.

### Wiring

```python
from megent import Runtime, PermissionStore, AuditLogger

audit = AuditLogger()
perms = PermissionStore("permissions.yaml", audit=audit, watch=True)
runtime = Runtime(policy=my_policy, audit=audit, permissions=perms)
# ... runtime.enforce(tool, args, agent_token)
perms.close()  # stop the watcher thread (or use as a context manager)
```

`permissions=` is an optional constructor arg — no breaking changes to the
public engine API.
