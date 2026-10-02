# Phase 7 — Trust UX

Trust here means the screen says what the engine recorded, and it says when it does not know. No new control operation was added. The desktop still cannot decide scope, approve an action, or edit evidence.

## What a hunter can now read

**Before start.** The scope panel says the engine has not explained the target, or it quotes the explanation and the time that reply arrived. Saving patterns clears that explanation. The checklist says "engine: in scope" only when the explanation's `in_scope` field is true. "Configured, not verified" is not a green provider. Only a local provider the control interface reports as available is marked verified. A configured API key is not treated as a connection.

**While running.** The state word is the engine's, including `stopping`. The sentence under it says stop does not finish at the click. Closing the window is described as leaving that session id in place, not as starting or resuming another one.

**Actions.** Evidence rows use the stored kind and status. A `scope_decision` with `blocked` reads "Blocked by scope. Not executed." `require_approval` reads as not executed. An action with status `ok` reads "Completed." It is not labeled allowed. Trace rows are tagged You only for `bump`. Known agent events are tagged Agent. Any other event type is Unattributed.

**Findings and evidence.** A finding is "Observed", then either evidence-backed, evidence unavailable, or no link recorded. Validation is "not yet available", "recorded", or "for a different finding". A failed chain adds "Provenance incomplete". None of these become the word verified. An intact chain says a change can be detected, and that someone with access to the files can still change them.

**Failures.** The screen uses a fixed sentence per error code: what happened, what is still true, what is safe to do. It does not append the engine's message string. Notes, finding text, and observations are passed through a display scrub for bearer tokens and common key shapes before they are shown.

**Resume.** The resume control stays disabled until this session is idle enough and no other investigation is running. The line names the session id. It does not resume by itself on reconnect.

## Review

An independent review rejected five wording bugs: the checklist said "in scope" from validation alone, activity text was shown without a display scrub, the chain sentence used the word immutable, unknown events were attributed to the agent, and the resume button ignored the availability flag. Those are fixed. The same review accepted configured-versus-verified, missing-evidence wording, and "Completed" rather than "allowed".

## Tests

The view-model tests cover an unvalidated scope, a stale explanation, a blocked evidence row, a finding with no evidence and no validation, operator versus agent versus unattributed events, a scrubbed bearer token, and resume blocked by another run. Full suite: **923 passed**. There is still no webview click-through.

## Limitations

The activity trace does not itself carry the scope decision. Blocked actions appear on the evidence list, which is where the engine writes them. The display scrub is a second pass over text the engine already redacts. It is not a new redaction policy. Validation still appears only when `validation.json` exists. No trust score was added.

## Next

The plan's next build is the target resume card: last investigation, open leads, and ruled-out work, still without a model call. That is not started.
