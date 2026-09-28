---
description: The report gate — independently re-derive a finding from its PoC bundle and decide if it may be reported. PROVEN → reportable; REFUTED/UNPROVEN/INCONCLUSIVE → suppressed. Usage: /verify check <bundle-dir> [--marker "signal"] | /verify sweep [root]
---

# /verify

The anti-hallucination gate. An agent or a noisy scanner can *claim* a bug that
isn't real; `/verify` refuses to let anything be reported that it can't
independently prove. It re-derives a finding from its `/poc` evidence bundle and
returns a reportability verdict, writing a `verification.json` record the report
step consumes.

## Where it sits (the Verification Spine)

```
/poc      produces PROOF     — the reproducible evidence bundle
/verify   the GATE (this)    — re-derives it; PROVEN → reportable, else SUPPRESSED
/bench    MEASURES the gate  — proves its false-accept rate is ~0
/report   ENFORCES it        — nothing unproven ships (wiring step)
```

## Usage

```
/verify check findings/target.com-idor/evidence/F-12 --marker "victim@corp.com"
/verify sweep                       # verify every bundle under findings/
/verify check <dir> --require-proof # exit 1 unless reportable (for gating)
```

Run directly:

```bash
tools/verifier.py check <bundle-dir> --marker "signal-that-proves-the-bug"
tools/verifier.py sweep [root] --require-proof
```

## Verdicts

| | | reportable |
|---|---|---|
| ✅ `PROVEN` | marker was in the **original** response AND is still present in the fresh one | **yes** |
| ❌ `REFUTED` | marker was in the original but is gone now / endpoint safe | no |
| 🚫 `UNPROVEN` | no bundle, no marker, or the marker isn't in the original response (so its presence now isn't proof of this finding) | no |
| ⏸ `INCONCLUSIVE` | unreachable / missing secret / mutating method not re-fired / initial host blocked | no |

**Only `PROVEN` is reportable.** "Can't confirm" is deliberately not "probably
fine" — the burden of proof is on the finding. That policy is what keeps false
accepts near zero, and it's exactly what `/bench` can measure.

To avoid **false PROVEN**, the marker must be present in the *original* recorded
response before its presence in a fresh response counts as proof — so a server
banner or attacker input reflected on an error page can't be mistaken for the bug.

## Where the marker is matched

The marker is searched across the response **headers and body**, so header-based
classes work too — open-redirect (`Location`), CORS (`Access-Control-Allow-Origin`),
`Set-Cookie`, cache poisoning — not just body content.

## Safety

- Re-derivation uses the SSRF-guarded opener (`tools/safe_http.py`), **and the
  initial host is validated** against the same metadata/private/loopback blocklist
  before the first request — a tampered bundle URL can't make verification hit
  `169.254.169.254`/localhost (it holds as `INCONCLUSIVE`).
- **`PUT`/`DELETE`/`PATCH` are not re-fired** without `--confirm-unsafe` — a
  verification must never re-trigger a destructive action; it holds as
  INCONCLUSIVE instead.
- Secrets are read from env vars (like the bundle's `repro.sh`) and **never
  written** into `verification.json`. The record stores the re-fetched response's
  SHA-256 + status (`rederived_sha256`/`rederived_status`) so it binds to what was
  actually re-fetched.
- `sweep --require-proof` exits `1` if **any** bundle isn't reportable — an
  intentional all-or-nothing gate; leave it out for a plain report.

## The marker

A marker is the string that proves the bug (a leaked value, a reflected payload,
an error message). Pass `--marker` once; it's saved as `marker.txt` in the bundle
(the same sidecar `/replay` uses) and reused on every future verification.
