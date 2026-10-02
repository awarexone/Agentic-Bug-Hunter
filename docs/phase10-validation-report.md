# Phase 10 — Validation and Report Workflow

A finding stays an observation until the existing validator writes `validation.json`. A report is a local Markdown file built from those records. Export is not submission.

## What already existed

`tools/validate.py` is an interactive validator. It writes `validation.json` with a status (`validated_finding` only when its four gates passed, otherwise `scanner_hit`), the gates `is_real`, `in_scope`, `exploitable`, and `not_duplicate`, a finding id, and optional reproduction and impact text. It also has a report skeleton that fills placeholder CVSS and impact lines. The desktop does not call that skeleton, because those placeholders would look like recorded facts.

Findings already carry an id, summary text, severity label, and an optional parent evidence id. Evidence and the hash chain are unchanged.

## What the desktop does

Opening a finding calls `finding_detail` and `report_draft`. The screen shows, separately:

- observed
- evidence-backed, or not
- provenance state
- whether the session's validation file matches this finding, names a different finding, or is absent
- the recorded validation status, without treating a partial result as a decision that the finding is valid

`validation_history` lists every session of this target whose validation file names this finding. If the statuses disagree, both stay and the screen says they disagree. The current session does not borrow another session's file.

Operator title, summary, reproduction, impact, and remediation are stored in `report-drafts/<finding id>/operator.json`. Saving them does not write the finding log, the evidence log, or `validation.json`. Empty operator fields stay as `[Operator input required]` in the Markdown. They are not filled by a model.

Export writes `report.md` in that same directory after a redaction pass and a residual secret scan. A remaining bearer token, private key, userinfo URL, or query string refuses the export. The file says it was not submitted. Warnings cover a missing summary, incomplete provenance, a failed chain, missing validation, and a validation file for another finding. Warnings do not block export, and the draft is never marked ready to submit.

## Tests

**945 passed.** They cover the finding-to-report path, a different finding's validation left unattached, disagreeing validation records, secret refusal, no submit operation, another target blocked from this session, and a symlinked draft directory that cannot redirect the write.

## Review

An independent review approved the workflow: validation is tied to the finding id, operator text stays in the draft directory, export says it was not submitted, and a failed evidence chain is a warning.

## Limitations

The hunt loop still does not run the validator. Until someone does, the screen says validation is not yet available. Reproduction text is included only when `validation.json` or the operator note already has it, and only after redaction. There is no platform submission.

## Next

The plan's next items are user testing, a release security review, and macOS signing. None of those are started.
