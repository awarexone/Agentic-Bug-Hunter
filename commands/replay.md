---
description: Re-verify a past finding against its PoC evidence bundle — is it still vulnerable, fixed, or changed? Replays the exact captured request (SSRF-guarded) and compares to the recorded evidence. Usage: /replay run <bundle-dir> [--marker "signal"] | /replay all [root]
---

# /replay

Turn a `/poc` evidence bundle into a **regression check**. Retests pay again and
programs increasingly reward regression reports — this replays the exact request
stored in a bundle and tells you whether the bug is still live.

## Usage

```
/replay run findings/target.com-idor/evidence/F-12 --marker "victim@corp.com"
/replay all                     # sweep every bundle under findings/ (retest day)
```

Run directly:

```bash
tools/replay.py run <bundle-dir> --marker "signal-that-proves-the-bug"
tools/replay.py all [root]      # default root: findings/
```

## Verdicts

| Verdict | Meaning |
|---|---|
| 🔴 `STILL_VULNERABLE` | the bug's signal is still present |
| 🟢 `FIXED` | the signal is gone |
| 🟡 `CHANGED` | response differs from the PoC — a human should look |
| ⚫ `UNREACHABLE` | the host/endpoint no longer answers |
| ⚪ `INDETERMINATE` | can't judge (no marker + no baseline, or a missing secret) |
| ⏭ `SKIPPED_UNSAFE` | a mutating method (PUT/DELETE/PATCH) — needs `--confirm-unsafe` |

## How the verdict is decided

- **Marker (reliable, `confidence: confirmed`)** — a string that proves the bug:
  the leaked email, the reflected payload, an error message. Present → still
  vulnerable; absent → fixed. Pass it with `--marker`; it's saved as `marker.txt`
  in the bundle so later `all` sweeps reuse it automatically.
- **Heuristic (`confidence: heuristic`)** — with no marker, replay compares the
  fresh response to the recorded one (status + SHA-256). Byte-identical → still
  vulnerable (unchanged); different → `CHANGED`. It never claims `FIXED` from a
  hash alone, since dynamic content also changes.

## Safety

- Replays through the repo's SSRF-guarded opener (`tools/safe_http.py`).
- **`PUT`/`DELETE`/`PATCH` are skipped unless you pass `--confirm-unsafe`** —
  replaying a mutating request could re-trigger the action.
- Redacted bundles reference secrets via env vars; replay reads them from the
  environment (like `repro.sh`) and **never writes secret values or full response
  bodies** into `replay.json` / the sweep report.

## Output

- `run` writes `replay.json` into the bundle and prints the verdict.
- `all` writes `regression-report.md` + `regression.json` at the root and prints a
  ranked table (most-severe first).
- `--fail-if-vulnerable` exits `3` when anything is still vulnerable — handy for
  scheduled monitoring / CI.
