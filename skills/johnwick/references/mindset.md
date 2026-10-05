# Phase 1 — Mindset & Threat Model (understand the target)

Hunting is not "find a bug" — it is "prove an attack scenario." Think like an attacker with a goal,
not a scanner matching patterns. Write the output of this phase to `notes.md`; it shapes every later phase.

## Define → Select → Execute
1. **Define:** "On [feature/domain] I will achieve [impact]."
2. **Select:** pick 1–2 impact goals + likely bug classes for that surface.
3. **Execute:** focus only on that. No wandering. (Coverage across assets is enforced by the ledger,
   not by scattering attention within an asset.)

## 5 impact goals (name one per asset)
Confidentiality (steal data) · Integrity (modify data) · Availability (app-level DoS) ·
Account Takeover · RCE. Every finding must chain to one of these — ceiling impact, no single primitives.

## Build the threat model (write to notes.md)
Fetch and read, per target:
- Disclosed reports (HackerOne/Bugcrowd/Intigriti, last 24 months) — what already paid here.
- Status page incidents (90d), engineering blog (12m), careers page → real stack, migrations, cloud.
- GitHub org: `gh search repos "org:<target>" --limit 100`; scan commit history for leaked `.env`/config.
- Wayback/gau: old API docs, removed endpoints, deprecated `/v1` still mounted, old admin panels.

Extract:
- **Business model** — B2B / B2C / multi-tenant / marketplace.
- **Actors** — end user, org admin, super admin, support agent, partner, API consumer.
- **Trust boundaries** — tenant↔tenant, org↔org, role↔role, service↔service, frontend↔backend, staging↔prod.
- **Where money moves** — payments, billing, payouts, referral/credits.
- **Where PII concentrates** — profiles, KYC, tickets, CRM, analytics, exports.
- **Shipping velocity + acquisitions** — fast shipping and integration seams = auth/model mismatch = bugs.

## 4 thinking domains (apply everywhere)
1. **Question trust boundaries.** Frontend disabled a control? Send the request directly. `role=user`
   cookie? Try `admin`. Client-side price? Set your own.
2. **Developer psychology.** Auth added late = one surface forgot it (per-verb/API-vs-UI gaps).
   Copy-pasted resolver = same missing check repeated. New feature = thinner review.
3. **Anomaly detection.** A response that differs from its sibling (status-code diff, byte-size diff,
   extra field, slower timing) is the tell. Chase the diff.
4. **What-If experiments.** "What if I send this step out of order? / two requests at once? / a foreign
   id? / a negative quantity? / the same token twice?"

**Output:** a one-page threat model with the trust-boundary list and a chosen impact goal per major
asset, before any Phase-2 testing is analysed for exploitation.
