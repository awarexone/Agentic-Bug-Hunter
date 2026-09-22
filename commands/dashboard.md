---
description: Launch the local Hunt Dashboard — one live view of leads, recon surface, findings, reports, screenshot galleries, and the memory flywheel. Usage: /dashboard [--port 8777] | /dashboard --export dashboard.html
---

# /dashboard

Spin up a single live view of the current hunt. A hunt's state is normally
scattered across `memory/leads/<target>.jsonl`, `recon/<target>/`, `findings/`,
`reports/`, screenshot `gallery.html` files, and `hunt-memory/*.jsonl` — the
dashboard reads all of it and shows it in one place, so stale high-priority
leads (Critical Rule 6) and the memory flywheel stop being invisible.

Pure stdlib, zero dependencies. Binds to `127.0.0.1` only.

## Usage

```
/dashboard                      # serve at http://127.0.0.1:8777
/dashboard --port 9000          # custom port
/dashboard --export report.html # write a shareable self-contained snapshot
```

Run directly:

```bash
tools/hunt_dashboard.py serve --port 8777
tools/hunt_dashboard.py export -o dashboard.html
```

> Not to be confused with `tools/dashboard.py`, the in-terminal ANSI progress
> bar shown *while* a recon/hunt runs. This is the persistent **web view** of
> everything a hunt has accumulated.

## What it shows

- **Stat tiles** — targets, total leads, untouched, in-progress, findings, and a
  red **stale HIGH leads** alert (HIGH-priority `new` leads untouched ≥2 days).
- **Lead board** — per target, grouped by status (new → investigating → reported
  → parked → killed), untouched-first, with priority chips and per-lead age.
- **Recon surface** — subdomains / live hosts / URLs / nuclei counts per target.
- **Findings & Reports** — every `.md`/`.txt` under `findings/` and `reports/`,
  newest first, clickable (served safely from within the repo root).
- **Screenshot galleries** — links to any `gallery.html` from `/screenshot`.
- **Memory flywheel** — journal / pattern / audit counts and recent activity.

## Endpoints (serve mode)

| Path | Returns |
|---|---|
| `/` | the dashboard (auto-refreshes every 30s) |
| `/api/state` | the same data as JSON — for scripting or other tools |
| `/file?path=<rel>` | a finding/report/gallery, restricted to the repo root |

## Safety

- Binds to `127.0.0.1` — never exposed to the network.
- `/file` resolves paths under the repo root only; traversal (`../`) is refused
  and only viewable extensions (`.md`/`.txt`/`.json`/`.html`/images) are served.
- All recon-derived text (URLs, tech banners, evidence) is HTML-escaped, so a
  malicious value captured during recon cannot execute in the dashboard.
