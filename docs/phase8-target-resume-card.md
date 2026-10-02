# Phase 8 — Target Resume Card

Returning to a target reads the files that investigation already left behind. There is no model summary and no new store.

## What the card is allowed to say

Facts that already exist:

- The target record has a name, a domain, and scope patterns.
- `sessions()` returns session ids for that domain, sorted by name. Ids are time-prefixed, so the last id is the newest name. It is not a ranking of importance.
- `status()` is the engine's single run record: state, target, and session id. Other sessions do not have their own stored state. The card says "unknown" rather than guessing.
- `session_context` has completed steps, a finding count, and `saved_at`.
- Events, findings, evidence references, `validation_status`, and `evidence_verify` describe one session.

Facts that do not exist, and stay off the card: a target-wide finding rollup, a saved scope verdict, a next action, a risk score, and a statement that the target is safe or finished unless that session's state is `completed`.

A scope explanation exists only after Validate in this visit. Patterns are durable. The explanation is not. Changing patterns makes the previous explanation stale, which the card repeats from the Phase 7 wording.

## Meaningful activity

The last meaningful event is the last trace row whose type is `tool_call`, `tool_result`, `finding`, `bump`, or `finish`. `loop_warn` and `loop_break` are skipped. The card shows the label and timestamp, not the note or tool output.

## Resume

Resume stays off until the user has selected that session, the engine run state is known, and nothing is `starting`, `running`, or `stopping`. A completed or failed run can be resumed, because the control layer allows it. The card names the session id. Reopening the app does not resume. "Show this session" only selects the id so the activity and findings below load. It does not start work.

## Tests

A fixture writes a session saved on an earlier date, with an older session beside it. The control interface returns that save time, the completed steps, and the finding count, and it does not return the working-memory secret. The view-model tests cover no history, two sessions, an unselected newest session, another target running, a validation record for a different finding, a missing integrity result, and the meaningful-activity rule.

Full suite: **925 passed**. No webview click-through.

## Review

An independent review approved the card: no safe or verified claim, no automatic resume, no invented state for sessions outside the run record, and no observation text on the card.

## Limitations

History is per session. The card does not add up findings across every session. It shows the selected session, or the newest id if nothing is selected, and it says which. Killed leads and reports are still not on this card.

## Next

The plan's next build is compounding memory: leads, patterns, and notes fed back on resume. That is not started.
