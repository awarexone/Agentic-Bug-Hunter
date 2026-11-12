# Phase Gates — Superpowers Verification Between Every Phase

**The rule the user asked for:** after finishing any phase, and BEFORE starting the next, run the
`superpowers:verification-before-completion` gate against that phase's exit criteria. A phase is
"done" only when fresh evidence proves it — never on a claim, a vibe, or "should be covered."

This is what makes johnwick *effective and efficient*: you never carry a half-finished phase
forward, so later phases don't build on gaps.

## The gate function (applied per phase)

Invoke `superpowers:verification-before-completion`, then:

1. **IDENTIFY** — what command/query proves this phase is complete? (Usually a `coverage.jsonl` query.)
2. **RUN** — execute it fresh, right now.
3. **READ** — full output; count the rows still `untested`/not `done` for this phase's field.
4. **VERIFY** — zero incomplete rows? If not, the phase is NOT done — go back and finish the named rows.
5. **ONLY THEN** advance. State the claim *with* the evidence (the count = 0 output).

> Evidence before claims, always. Expressing satisfaction ("recon looks good, moving on") before
> running the check is a gate violation.

## Per-phase exit criteria (the evidence to produce)

| After phase | Gate query / evidence (must be empty / zero) | Advance when |
|---|---|---|
| **0 Scope lock** | `jq 'select(.in_scope==true)' coverage.jsonl \| wc -l` vs. the raw scope count — must match | every in-scope asset enrolled |
| **1 Understand** | `notes.md` contains threat model + chosen impact goal per major asset | model written |
| **2 Recon+JS** | `jq -c 'select(.in_scope and (.recon!="done" or .js_read!="done"))' coverage.jsonl` → **no rows** | all recon + all JS read |
| **3 Access** | working session material saved in `auth/` AND a live authenticated request succeeds now | session proven live |
| **4 Authed map** | `jq -c 'select(.in_scope and .authed_mapped!="done")' coverage.jsonl` → **no rows** | every authed surface enumerated |
| **5 Hunt** | `jq -c 'select(.in_scope and .status!="covered")' coverage.jsonl` → **no rows** | every asset fully hunted |
| **6 Validate** | every candidate has a full validation-gate verdict (see [validation.md](validation.md)) recorded in `findings/` | all findings gated |

If a gate query returns any rows, name them, go finish them, then re-run the gate. Do not advance
with `untested` rows outstanding — that is the exact failure Rule 1 forbids.

## Efficiency lever: parallelize the fan-out phases

Phase 2 (recon across many subdomains) and Phase 5 (hunting many assets) are embarrassingly parallel.
Use `superpowers:dispatching-parallel-agents` to shard the ledger: one agent per independent
asset/host, each with an isolated slice of `coverage.jsonl`. This is how you get total coverage
*fast* instead of walking hosts one at a time. Merge each agent's ledger updates back before the gate.
