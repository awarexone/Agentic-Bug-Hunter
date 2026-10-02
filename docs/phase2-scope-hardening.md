# Phase 2 — Scope Hardening

Goal: make scope enforcement genuinely trustworthy for the desktop MVP.

## MVP guarantee (precise)

**Out-of-scope traffic executed by the Agentic Bug Hunter Desktop MVP = 0.**

This guarantee applies to the exact execution path the desktop MVP uses:

```text
Desktop
  → run_agent_hunt()          (agent.py:1662)
  → ToolDispatcher.dispatch() (agent.py:578)
  → AutopilotGuard.check_request()  (memory/audit_log.py:313)
  → ScopeChecker.explain()    (tools/scope_checker.py:357)
  → tool execution
```

On this path the following are verified (see Verification and the enforcement-path
tests):

- **No scope → no execution.** `run_agent_hunt(scope_checker=None)` builds an
  `AutopilotGuard` with `fail_closed=True` (the default), which blocks every
  network tool. Missing scope fails closed.
- **Malformed / ambiguous scope fails closed.** `ScopeChecker` raises
  `ScopeError` at construction for dangerous configs; `explain()` returns
  `in_scope=False` for malformed/ambiguous targets, so they never reach
  execution.
- **The decision cannot be bypassed by the layers above it.** The scope decision
  is made below the UI and below the control interface, inside `dispatch()`
  before any tool runs. The UI/control layer only passes a target + a scope; it
  cannot hand the dispatcher a pre-approved verdict or skip the gate.
- **Blocked actions never reach the network layer.** A blocked decision returns a
  `BLOCKED ...` string from `dispatch()` *instead of* invoking the tool — the
  scanner subprocess is never spawned (proven by the non-execution tests).
- **Blocked actions are auditable** in `agent_trace.jsonl` via
  `AgentTracer.tool_result`, carrying the matched rule + reason from `explain()`.

### What this guarantee does NOT claim

It does **not** claim that every standalone repository script is universally
fail-closed when invoked manually outside the desktop path. The desktop MVP does
not expose those entrypoints. Their exact status is documented honestly under
**Non-MVP residual limitations** and **Future hardening** below; they are kept
off the desktop execution surface rather than silently "fixed" to make this
report look cleaner.

## Where enforcement lives (below the UI)

There is ONE scope decision function — `ScopeChecker.explain()` — and every
entrypoint that can emit traffic routes through it. There is no second, divergent
implementation.

```
             UI / desktop layer (later)
                        |
   +--------------------+--------------------+
   | agent path         | CLI path           | MCP path
   v                    v                    v
run_agent_hunt()   tools/hunt.py main()  mcp server tools
   |                    | set_scope_checker()  | POLICY.set_scope()
   v                    v                    v
ToolDispatcher     run_recon/run_vuln_   adapters.run_recon/run_hunt
.dispatch()        scan/... (module      (scope_checker=POLICY._checker)
   |               _SCOPE_CHECKER)          |
   +--------------------+--------------------+
                        v
              ScopeChecker.explain() / is_in_scope() / filter_file()
                        (tools/scope_checker.py)
```

- The scope decision is made by one function, `ScopeChecker.explain()`, and
  everything else (`is_in_scope`, `filter_urls`, `filter_file`, the guard) is a
  thin caller. There is no second, divergent parser: even the circuit breaker's
  host key now comes from the same `extract_host_port()` used by the scope
  decision.
- **Agent path (the desktop MVP path):** `run_agent_hunt()` →
  `ToolDispatcher.dispatch()` → `AutopilotGuard.check_request()` (scope is gate 0,
  a hard block before circuit breaker and method policy). With no `ScopeChecker`
  supplied it fails closed (blocks everything). The dispatcher also parses the
  real `Host:` out of sqlmap request files and hard-blocks out-of-scope ones, and
  re-filters recon-discovered URL files before any scanner reads them.
- **CLI path (`python3 tools/hunt.py`):** a process-wide `_SCOPE_CHECKER`
  (installed in `main()` from `--scope-domain` / `--scope-exclude`) makes
  `run_recon`, `run_vuln_scan`, `run_graphql_audit`, `run_cve_hunt`, and
  `run_zero_day_fuzzer` refuse an out-of-scope base target *before any subprocess
  spawns*, and filter recon URL files before scanners read them. Base-target
  refusal is fail-closed for **every** target type: a domain, single IP, CIDR
  (every expanded host must be in scope, bounded by `MAX_CIDR_HOSTS`), or list
  file (every entry must be in scope). A domain-only scope therefore cannot
  authorize a CIDR sweep. When no scope is configured the legacy behavior is
  preserved but a loud warning is printed — a hunt without scope is an explicit
  operator choice, never silent.
- **MCP path:** `PolicyEngine` gates the base target + approval; `set_scope`
  fails closed on a dangerous config (`ScopeError`); `authorize_url` now
  correctly constructs the guard (`scope_checker=` keyword) and reads
  `result["decision"]` so the method-approval gate actually fires;
  `adapters.run_recon` / `run_hunt` filter recon-discovered URLs to scope and
  block an out-of-scope base target before the scanner runs; and `run_hunt`
  installs the shared checker into `tools/hunt.py` (`set_scope_checker`) for the
  duration of `hunt_target`, then restores it — so the recon `hunt_target`
  re-runs internally is itself scope-enforced (closing the "filter once, then
  repopulate" gap) rather than only the outer filter pass.
- Our own HTTP client (`tools/safe_http.safe_urlopen`) accepts an optional
  `scope_checker` and refuses to follow a redirect to an out-of-scope host (in
  addition to its existing SSRF guard against private/loopback/metadata hosts).

## Supported pattern grammar

| Form | Meaning |
|---|---|
| `target.com` | exact host only (not subdomains) |
| `*.target.com` | any subdomain, NOT the apex, NOT `evil-target.com` |
| `api.target.com:8443` | host + port constraint (narrows) |
| `cdn.target.com/assets/` | host + path-prefix constraint (narrows) |
| `10.0.0.0/24` | IPv4 CIDR |
| `10.0.0.5` | single IPv4 (treated as /32) |
| `2001:db8::/32` | IPv6 CIDR |
| `2001:db8::1` | single IPv6 |

Rules:

- Matching is anchored suffix, never substring — `evil-target.com` can never
  match `*.target.com`.
- Exclusions deny a subtree: excluding `blog.target.com` also blocks
  `cdn.blog.target.com` (so a broad `*.target.com` allow can't let it back in).
  Exclusions are checked before allows.
- Port/path only ever **narrow** scope; a pattern without them matches any
  port/path.
- Dangerous config raises `ScopeError` at construction (fail-closed at config
  time): wildcards over a public suffix (`*.com`, `*.co.uk`), single-label
  wildcards (`*.internal`), bare `*`, and misplaced wildcards. The three
  production construction sites (`agent.py` CLI, `tools/scope_checker.py` CLI,
  MCP `PolicyEngine.set_scope`) catch it and fail closed rather than crash.

## Normalization / anti-bypass

- Rejects any URL containing a backslash, whitespace, or control character
  (defeats `https://target.com\@evil.com`, CR/LF, tab tricks).
- Rejects non-`http(s)` schemes (`ftp:`, `file:`, `javascript:`).
- Lowercases hosts; strips one trailing FQDN dot (`target.com.` == `target.com`).
- ASCII-only hostname charset (rejects Unicode homoglyphs like Cyrillic `а`).
- Rejects empty labels (`sub..target.com`).
- IP handling via stdlib `ipaddress`, canonical forms only. Alternate encodings
  (decimal `2130706433`, hex `0x7f000001`, octal, short-form `1.2.3`) fail
  closed rather than being canonicalized into an in-scope match.

## Adversarial test matrix

Implemented in `tests/test_scope_hardening.py` (102 cases) alongside the existing
`tests/test_scope_checker.py`, `tests/test_autopilot_guard.py`,
`tests/test_agent_dispatcher_scope.py`, and `tests/test_agent_dispatcher_hardening.py`.

### Allowed (must pass)
`target.com`, `target.com.` (trailing dot), `http://target.com`,
`sub.target.com`, `a.b.c.target.com`, `API.TARGET.COM` (case), bare
`api.target.com`, `api.target.com:8443` (no port rule), `evil.com@target.com`
(real host is `target.com`), in-CIDR IPs, single-IP `/32`, in-range IPv6.

### Blocked (well-formed, out of scope)
`evil.com`, `evil-target.com`, `xtarget.com`, `target.com.evil.com`,
`evil.com/target.com`, `blog.target.com` (excluded), `cdn.blog.target.com`
(excluded subtree), IPs with no IP rule, out-of-CIDR IPs, port/path mismatches.

### Ambiguous (must fail closed)
Decimal/hex/octal/short-form IPs, out-of-range/non-numeric ports, empty labels,
malformed IPv6.

### Malformed (must fail closed)
Empty / `None` / whitespace / non-string, `://broken`, `https://` (no host),
path-only, disallowed schemes, backslash host trick, tab/newline in authority,
spaces, Unicode homoglyph host.

## Verification

- `tests/test_scope_hardening.py`: adversarial matrix (Allowed / Blocked /
  Ambiguous / Malformed / IP-CIDR / port-path / wildcard-guard / explain /
  guard / redirect / parser-unification).
- `tests/test_scope_enforcement_paths.py` (20): the non-execution half of the
  invariant — proves an out-of-scope target on the CLI and MCP paths spawns
  **no** subprocess (an exploding `Popen`/`hunt_target`/`subprocess.run` stand-in
  is never reached), that a domain-only scope refuses a CIDR sweep and an
  out-of-scope list entry, that recon-discovered out-of-scope URLs are filtered
  before scanners read them, that the MCP `run_hunt` path installs and restores
  the shared checker around `hunt_target`, and that the MCP `authorize_url`
  method-approval gate fires after the guard-call fix.
- Desktop-path enforcement (`tests/test_agent_dispatcher_scope.py`,
  `test_agent_dispatcher_hardening.py`, `test_agent_time_budget_gate.py`): prove
  that on the `run_agent_hunt → ToolDispatcher.dispatch` path a blocked decision
  returns a `BLOCKED ...` string and the real tool **never runs**
  (`fake_hunt.calls == []`), that a missing scope blocks every network tool
  (`fail_closed`), and that lookalike / out-of-scope / typo'd targets are blocked.
- Full scope + desktop-path set (scope + guard + dispatcher + enforcement paths +
  time-budget + redirects): **205 passed**.
- Full repository suite: **863 passed, 0 regressions** (was 840 before this
  phase's enforcement-path work).

## What was attacked and what happened

- Hostname boundary (`evil-target.com`, `target.com.evil.com`,
  `evil.com/target.com`, `xtarget.com`): blocked — anchored suffix match, never
  substring.
- Parser divergence (`https://target.com\@evil.com`, tab/newline/space in
  authority, userinfo `@`): rejected at the single canonical parser before any
  host is derived; the guard's `_extract_host` shares that parser.
- Alternate IP encodings (decimal / hex / octal / short-form), malformed IPv6,
  out-of-range/non-numeric ports, empty labels, Unicode homoglyphs: fail closed.
- Public-suffix wildcards (`*.com`, `*.co.uk`, `*`): rejected at construction
  (`ScopeError`); the three production construction sites catch it and fail
  closed rather than crash.
- Direct CLI invocation and MCP hunt against an out-of-scope target: refused
  before any subprocess spawns (proven by the non-execution tests), not merely
  reported out of scope.

## Auditability of blocked actions (MVP)

A blocked dispatch returns a `BLOCKED by scope guard: <reason>` observation that
is written to `agent_trace.jsonl` via `AgentTracer.tool_result`, and the guard's
block dict carries `scope_rule` + `reason` (from `explain()`) so the desktop can
later render which rule rejected an action and why. Blocks are therefore
attributable, not silent, on the MVP path.

### Audit-log decision (structured `AuditLog.log_request`)

`memory/audit_log.AuditLog.log_request()` exists (append-only JSONL with schema
validation, file locking, size-based rotation) but `AutopilotGuard.check_request`
does **not** call it — the guard returns a decision dict and the dispatcher
records the block in the agent trace.

Decision for the MVP: **do not wire `AuditLog` into the guard now; the trace is
sufficient for MVP blocked-action visibility.** Adding a second write here would
duplicate logging purely for architectural neatness. The place structured,
tamper-evident, hash-chained records genuinely belong is **Phase 3 — Evidence /
Provenance Foundation**, whose explicit objective is capture + integrity +
redaction. Wiring the guard's block/allow decisions into the structured audit log
is therefore deferred to Phase 3, where it can be done once, cleanly, as part of
the provenance layer rather than bolted on here. Both dispatch paths — the
tool-calling path (`agent.py:1421`) and the LLM text-fallback path
(`agent.py:1452`) — call `tracer.tool_result`, so a scope block is written to
`agent_trace.jsonl` regardless of which path the model takes.

## Non-MVP residual limitations (off the desktop execution path)

These are honestly documented and kept **out of** the desktop MVP execution
surface. They are not fixed merely to make this report look cleaner.

- **Per-request scoping inside shelled scanners.** External binaries and the bash
  pipelines (`recon_engine.sh`, `vuln_scanner.sh`, nuclei/sqlmap/httpx) receive a
  base target that has been scope-checked and read recon URL files that have been
  filtered, but they then follow their own redirects and probe the hosts in those
  files without re-consulting `ScopeChecker` per request. The guarantee for these
  is "which hosts we *initiate* against are in scope," not per-hop redirect
  scoping. The MVP agent path drives these through the gated dispatcher; direct
  use of the bash pipelines is not a desktop-MVP surface.
- **`safe_urlopen(scope_checker=...)` not threaded through every standalone Python
  scanner.** The redirect-scope enforcement exists and is used where the agent
  path drives requests, but some standalone scanner scripts that call
  `safe_urlopen` do not pass a `scope_checker`. Documented, not silent; does not
  affect the agent path.
- **Raw manual invocation below the gate.** Directly importing a scanner module,
  running a bash script by hand, or running `tools/hunt.py` without
  `--scope-domain` is fail-open by explicit operator choice (the CLI prints a
  loud warning). The desktop MVP does not expose these paths; it uses
  `run_agent_hunt()`, which fails closed with no scope configured. (The CLI/MCP
  entrypoints were additionally hardened this phase — base-target block + recon
  filtering — but they remain non-MVP surfaces and are not part of the MVP
  guarantee.)
- **DNS rebinding.** A host that resolves to different IPs over time is not
  addressed by a name-based allowlist; IP-scoped programs should use CIDR rules.
- **IDN/Unicode hosts.** Must be specified in punycode; raw Unicode hosts fail
  closed by design.

## Future hardening (backlog)

Eventually worth addressing; not required for the MVP guarantee:

1. **Structured audit log wiring** — record guard allow/block decisions into the
   hash-chained provenance store (do this in Phase 3, not as duplicate logging
   now).
2. **Per-request / per-redirect scoping for external scanners** — thread
   `ScopeChecker` (or a scope-aware proxy) through nuclei/sqlmap/httpx so
   redirect hops and file-driven targets are re-checked, not just the initiating
   host.
3. **Thread `safe_urlopen(scope_checker=...)`** through all standalone Python
   scanners so their redirects are scope-enforced like the agent path.
4. **DNS-rebinding mitigation** — pin resolved IPs for the duration of an
   investigation and re-check on change.
5. **`run_sqlmap_on_file` request-line parsing** — today the dispatcher parses
   and scope-checks the request file's `Host:` header (defense-in-depth), and the
   tool is POST so the guard returns `require_approval` (never auto-executes). If
   POST tools are ever auto-approved, also parse a conflicting absolute URL in the
   request line so it can't disagree with the `Host:` header.
