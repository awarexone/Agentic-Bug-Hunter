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
| ✅ `PROVEN` | bundle exists AND re-derivation confirms the marker | **yes** |
| ❌ `REFUTED` | re-derived, but the marker is gone / endpoint safe | no |
| 🚫 `UNPROVEN` | no bundle, or no confirmable marker at all | no |
| ⏸ `INCONCLUSIVE` | unreachable / missing secret / mutating method not re-fired | no |

**Only `PROVEN` is reportable.** "Can't confirm" is deliberately not "probably
fine" — the burden of proof is on the finding. That policy is what keeps false
accepts near zero, and it's exactly what `/bench` can measure.

## Safety

- Re-derivation uses the SSRF-guarded opener (`tools/safe_http.py`).
- **`PUT`/`DELETE`/`PATCH` are not re-fired** without `--confirm-unsafe` — a
  verification must never re-trigger a destructive action; it holds as
  INCONCLUSIVE instead.
- Secrets are read from env vars (like the bundle's `repro.sh`) and **never
  written** into `verification.json`.

## The marker

A marker is the string that proves the bug (a leaked value, a reflected payload,
an error message). Pass `--marker` once; it's saved as `marker.txt` in the bundle
(the same sidecar `/replay` uses) and reused on every future verification.
