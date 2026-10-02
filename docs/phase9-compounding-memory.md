# Phase 9 — Compounding Memory

Memory is rebuilt from the session files each time it is read. It is not a diary, and it is not fed to the agent.

## What can accumulate

From each session file, when the field is actually present:

- A completed step name, with the sessions it appeared in.
- A finding, identified only by its finding id. The same summary text with a different id stays a separate finding. A repeated-summary item points at those ids and does not merge them.
- An observed URL, only when that session's evidence chain verifies, and only after userinfo and the query string are removed.
- A change between the previous session and the newest one: a completed step that showed up, or one that was not repeated. The "not repeated" item cites only the session that recorded the step.

A session that never wrote these fields contributes nothing. A tool being installed does not count as tested. No finding does not count as ruled out. The lead board is not read, because this hunt path does not write it and its target key is not the desktop target id.

## What stays out

Working memory, observation text, and request bodies are not copied. Scope verdicts are not copied. Memory has `authorization: none`. The desktop line says this history does not authorize scope, tools, or a current vulnerability. Nothing is added to the agent prompt.

## Lifecycle

- `active` — seen in the newest session, or a current comparison.
- `stale` — last seen in an older session. Kept.
- `unsupported` — a finding whose evidence chain does not verify. Its URL is omitted, not shown as known.
- `disputed` — the same finding id has two different summary texts. Both are kept.

There is no expiry and no automatic deletion.

## Isolation

Sessions are read through the target's domain directory, with the same symlink checks as the other session reads. A second target on a different domain gets an empty memory list.

## Tests

**935 passed.** They cover one session, repeated derivation, repeated text without a merge, a disputed finding id, a stale step, a failed chain, a credentialed URL dropped, a redacted bearer token, an empty history, and two targets that do not share sessions.

## Review

An independent review rejected two items. A "not repeated" change cited a completed-step record in the newest session that does not exist. The ruled-out line did not look at the memory items. The change now cites only the session that recorded the step. The screen says none are recorded only when the item list has no ruled-out rows.

## Limitations

There is no endpoint inventory beyond URLs that were stored on evidence records with a valid chain. There is no explicit ruled-out store on this path. Memory is not searched semantically and is not sent to the model.

## Next

The plan's next build is the validation and report workflow. That is not started.
