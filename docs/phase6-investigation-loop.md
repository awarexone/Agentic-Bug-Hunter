# Phase 6 — Investigation Loop

The desktop remains a thin client. This phase connects the investigation
records the engine already writes so a hunter can leave and come back to the
same session without asking a model what happened.

## Research

The engine already persists the investigation. `agent_session.json` stores
`completed_steps`, `step_count`, `saved_at`, and `findings_log` (id, parent
evidence id, tool, severity, text, timestamp). It does not store a validation
status, a killed-lead flag, or a next action. `agent_trace.jsonl` is the
activity log. `evidence.jsonl` is the Phase 3 chain, with `verify_chain()`.
`validation.json` is written by `tools/validate.py` when someone runs that
tool. It is not produced by the hunt loop itself. The lead board
(`memory/leads/<target>.jsonl`) records killed and parked leads, and it is not
reachable from the control service. Reports are files elsewhere. None of those
were added to the desktop in this phase, because the hunt the desktop starts
does not write them.

Before this phase the desktop showed status, a flat event list, and finding
text. It did not show what had been tested, whether the evidence chain was
intact, whether a validator had recorded anything, or how an event related to
an evidence record.

Product references were used only as principles, the same ones as Phase 5:
a run is an explicit id (Replit), configured is not verified (Vanta, Retool),
disconnect is a normal state (Firezone), secrets are referenced rather than
shown (Infisical), findings are a queue tied to a target (Escape). Atlas,
MindFort, Casco, OpenHack, Tolmo, Veria Labs, Variance, Superlog, and Sentient
OS had no usable public detail and did not change the design.

## What was added

Three read-only control operations, still on the existing Unix socket:

| Op | Reads | Returns |
|---|---|---|
| `session_context` | `agent_session.json` in the owned session | `saved_at`, `step_count`, `completed_steps`, `findings_recorded`. Not working memory. Not observation text. |
| `evidence_verify` | existing `EvidenceStore.verify_chain()` | `ok`, `count`, error codes. No hashes. No writes. |
| `validation_status` | `validation.json` in that session only, if present | `status`, `finding_id`, gate pass/fail, `rejection_count`. Not the proof-of-concept, not gate notes, not the reason text. |

`events()` now includes a short `detail` for an operator note, a finding line,
or a finish marker. Tool output previews stay out of the timeline.

The desktop adds:

- A state sentence for each real engine state. An unrecognized state stays `unknown`.
- A "where this investigation stands" list built only from those records. It does not contain a recommended next step.
- Resume is described as available only when this session is not starting, running, or stopping, and no other investigation is running.
- Activity labels (`Called recon`, `Operator note`, `Finding recorded`). An evidence id on a row opens the stored record.
- Findings and an evidence list open the same record. The view shows id, kind, tool, status, finding link, parent link, and observation text. It does not show request or response bodies, and it cannot edit the record.
- Missing validation is "not yet available". Missing evidence is "unavailable". An empty chain is "none recorded", not "intact".

Session directories and the files these operations read are refused when they are symlinks, so a link cannot point the read at another path.

## What was reused

Scope validation, start, stop, steer, resume, and the single-investigation lock are unchanged Phase 4 behavior. Evidence capture and the hash chain are unchanged Phase 3 behavior. The desktop still does not import the engine.

## Tests

`tests/test_investigation_loop.py` covers the connected path on a local fixture, not a live target:

- scope validate, start, activity, finding, evidence record, chain check, validation status
- a secret in a request header is redacted in the evidence record
- a proof-of-concept string in validation is not returned
- a malformed trace line is skipped
- a missing evidence id, a missing validation file, and an unreadable session file stay explicit errors
- a tampered evidence line fails verification
- completion and failure leave the same session id inspectable, and resume keeps that id
- a second resume while a run is active is rejected
- a symlinked validation file and a symlinked session directory are refused
- the resume summary has no next-step field, and it does not offer resume while another run is active

Full suite after the review fixes: **923 passed**.

There is no automated click-through of the webview. The journey is proven at the control boundary the UI calls.

## Review

An independent review rejected three issues. All three were fixed:

- a symlink could make a session path resolve outside the recon tree
- free-form rejection text could carry a proof of concept into the UI
- the resume line could say resume was available while another target's investigation was running

## Limitations

The hunt loop does not write `validation.json`. Until someone runs the existing validator, the workspace correctly says validation is not yet available. Killed leads and report files are still not on this screen. `completed_steps` is the record of what was tested. There is no generated narrative and no suggested next action. No code signing, and no webview driver.

## Next

Phase 7 in the plan is Trust UX: activity cards that answer what, why, in-scope, result, and evidence, using the links this phase now exposes. Not long-term memory, not collaboration, not cloud sync.
