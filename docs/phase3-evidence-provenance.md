# Phase 3 — Evidence / Provenance Foundation

A finding should be traceable without trusting an AI narrative:

```text
Action
→ Scope decision
→ Evidence
→ Finding
→ Validation
→ Report
```

**Captured evidence** is what the dispatcher observed. **Agent claims** (working memory, model text) are not evidence.

## Evidence model

One append-only log per hunt session, beside the existing trace:

```text
recon/<domain>/sessions/<session_id>/
  agent_trace.jsonl      live activity (unchanged role)
  agent_session.json     rolling memory
  evidence.jsonl         durable evidence
  evidence_head.json     tail-truncation anchor
```

`EvidenceStore.capture()` writes one record. Fields that are actually used:

| Field | Role |
|---|---|
| `evidence_id` | stable `ev-` id |
| `session_id`, `step`, `agent` | which hunt, which step, `desktop-mvp` |
| `kind` | `action`, `scope_decision`, `finding`, `link` |
| `tool`, `target`, `url`, `method` | what ran, against which host |
| `scope` | scope snapshot at capture (decision, matched rule, rules list) |
| `status` | `ok`, `blocked`, `require_approval`, `error`, `time_budget_blocked`, severity |
| `timing.elapsed_s` | dispatcher clock |
| `observation` | bounded tool result, not the model narrative |
| `request` / `response` | present only when the caller has them |
| `finding_id`, `parent_id` | provenance links |
| `prev_hash`, `digest` | integrity |

`request` / `response` stay empty for subprocess scanners. The dispatcher does not invent HTTP bodies it never saw. Replay says so.

## Capture boundary

The desktop path is:

```text
run_agent_hunt()
  → EvidenceStore(session_dir)
  → ToolDispatcher.dispatch()
       → AutopilotGuard.check_request()
       → EvidenceStore.capture()     # before the tool runs on block/approval,
                                      # after it returns on success/error
  → AgentTracer.tool_result(..., evidence_id=...)
```

Every network-tool outcome (allow, scope block, approval required, time-budget block, sqlmap file host block, error) writes a record when a store is attached. `run_agent_hunt` always attaches one. Unit tests that construct a dispatcher without a store keep the old behavior.

Trace events stay the activity timeline. `tool_result.evidence_id` points at the evidence record. The trace is not replaced.

Findings minted in `_classify_obs` get a stable `fnd-` id and an append-only `link` record back to the action evidence. `link_finding` raises `EvidenceError` if the evidence id does not exist.

## Redaction

One redactor: `memory.redaction.redact_obj`. MCP `redact.py` delegates to it.

Order is always:

```text
captured data → redact_obj() → durable write
```

Applied before write on:

- `evidence.jsonl` (content fields)
- `agent_trace.jsonl` (whole event)
- `agent_session.json` (a redacted copy; in-memory notes stay usable for the running agent)
- stdout tool-argument prints and the observation preview
- Evidence Bundle export (a second pass, so a secret injected into the log after capture is still stripped)

Rules are deterministic and idempotent: sensitive key names (including `cookies`, `authorization`, `x-auth-token`, `email`, `phone`, `ssn`) and known secret shapes (bearer, basic, cookie headers, URL userinfo, secret query params, JWT, PEM, AWS/GitHub/Slack/Stripe/OpenAI-style keys, quoted JSON `password`/`token` values).

Benign URLs and ordinary sentences are left alone. A free-text email inside a finding is **not** blanket-scrubbed, because that address is often the finding. An object key named `email` is scrubbed.

## Provenance

```text
action evidence (ev-…)
    ← link record (parent_id = ev-…, finding_id = fnd-…)
    ← finding record (finding_id = fnd-…)
```

`provenance_for(finding_id)` returns those records in log order. `export_bundle(..., finding_id=)` uses that set. A `validation.json` is attached only when its `finding_id` matches. A missing link sets `provenance_ok` false and lists `errors`. `strict=True` raises `EvidenceError`.

Validation and report files produced by the older CLI (`tools/validate.py`, `brain.py`) do not yet write `evidence_ids` themselves. The bundle is the place that joins them. A report manifest inside the report writer is later work (validation/report phase), not this foundation.

## Integrity

Each record's SHA-256 digest covers every field except `digest`, including `prev_hash`, over canonical JSON (`sort_keys`, compact separators). Append holds one file lock across "read tail → digest → full write → atomic head replace".

`verify_chain()` fails on:

- a changed field (`digest_mismatch`)
- reordered or deleted interior records (`prev_hash_mismatch`)
- a deleted tail while the head anchor remains (`head_anchor_mismatch`)
- a missing head anchor when records exist (`missing_head_anchor`)
- malformed JSON, non-objects, and duplicate keys (`malformed_record`)

A corrupt tail raises on the next append. It does not start a new chain at genesis.

### Trust assumption

This is **tamper evidence**, not tamper-proof storage. Someone who can rewrite both `evidence.jsonl` and `evidence_head.json` can produce a new consistent chain. There is no out-of-band key. A local user who controls the session directory is inside the trust boundary. What verification catches is partial edits, reordering, interior deletion, and tail truncation that forgets the anchor.

## Evidence Bundle

`export_bundle(session_dir, finding_id=..., out_path=...)` writes JSON containing:

- the linked evidence records (redacted)
- scope snapshots embedded in those records
- integrity verdict
- validation object when the finding id matches
- redacted replay text
- `provenance_ok` and `errors`

## Replay

`build_replay` reads only the stored (already redacted) record. The HTTP method must be a short uppercase word or it is replaced with `GET`. Values are JSON-quoted. It is a readable reconstruction, not a command that should be pasted into a shell with live credentials.

## Scope snapshot

The `scope` object stored on a record is a copy taken at capture: decision, matched rule, and the allow/exclude lists then in force. Mutating the live `ScopeChecker` afterward does not change the record.

## Tests

- `tests/test_redaction.py` — secrets, tokens, cookies, JSON passwords, URL userinfo, PEM, determinism, benign text, email-key vs prose
- `tests/test_evidence_provenance.py` — chain reopen, scope snapshot, link/missing id, modify/reorder/delete/malformed/duplicate keys, corrupt-tail refusal, export redaction, wrong-finding validation, post-capture injection, trace evidence id, session-file redaction, dispatcher block (no tool execution) and allow (finding link)
- Existing cookie-trace tests still pass against the shared redactor

Full repository suite: **883 passed**, 0 failures.

## Known limitations

- Subprocess scanners (nuclei, sqlmap, httpx) do not return raw HTTP request/response into the dispatcher. Evidence records the tool, target URL, scope decision, timing, and observation text. Full bodies are a later capture job, not something this phase fabricates.
- Raw scanner files under `recon/` and `findings/` are the tools' own output. They are not passed through `redact_obj`. The desktop should treat them as sensitive local artifacts.
- `brain.py` report markdown and `tools/lead_board.py` / hunt journal are not yet on the redactor. They are outside the desktop session write path.
- `AuditLog.log_request` is still not called from the guard. The evidence record is the structured scope+action log for the desktop path. Wiring the older audit schema as a second write would duplicate it.
- A novel high-entropy secret with no recognizable prefix and no sensitive key name is not guaranteed to be caught. A blanket entropy scrub would destroy legitimate ids and hashes.
- Free-text emails and phone numbers inside observations are preserved on purpose.
- Rewriting both the log and the head anchor is undetectable. See the trust assumption above.

## Independent review

A fresh `security-review` pass on a different model (it did not write this code) inspected capture, redaction, persistence, provenance, scope snapshots, integrity, export, replay, trace linkage, and error paths.

Verdict: **APPROVED**. No secret reaches the durable desktop sinks, scope blocks are captured before any tool runs, and a tampered chain does not verify as intact. The co-located log+anchor rewrite limit matches the code.

One audit gap it noted — `run_sqlmap_on_file` returning "request file not found" without a record — was closed after the review by recording that error the same way as other network-tool errors. It was not a secret leak or an integrity failure.
