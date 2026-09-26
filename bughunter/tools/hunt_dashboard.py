#!/usr/bin/env python3
"""
hunt_dashboard.py — the local Hunt Dashboard (web view).

Note: distinct from tools/dashboard.py, which is the in-terminal ANSI progress
TUI for a running recon/hunt. This is the persistent web view of accumulated
hunt state across every target.

The problem this solves: a live hunt scatters its state across a dozen files —
leads in `memory/leads/<target>.jsonl`, recon under `recon/<target>/`, findings
and reports in `findings/` and `reports/`, screenshots in a `gallery.html`, and
the memory flywheel in `hunt-memory/*.jsonl`. Nothing shows it all at once, so
stale high-priority leads rot (Critical Rule 6) and the memory flywheel stays
invisible (see TODO-6). This turns that scattered state into one live view.

Two modes, both pure-stdlib (zero dependencies — same tech as demo/app.py):

  hunt_dashboard.py serve  [--host 127.0.0.1] [--port 8777] [--root DIR]
      Live local server. Re-reads state on every load, auto-refreshes.
      /            → the dashboard
      /api/state   → the same data as JSON (for scripting / other tools)
      /file?path=  → safely view a finding/report/gallery (within --root only)

  hunt_dashboard.py export -o dashboard.html [--root DIR]
      Write a single self-contained HTML snapshot (shareable, e.g. as report
      evidence). No server, no external assets.

Design: `collect_state()` reads the repo's real output files into a plain dict,
and `render_dashboard()` turns that dict into HTML. Both are pure given a root
dir, so they're unit-tested without a running server. Every value that comes
from recon (URLs, tech banners, evidence) is HTML-escaped — recon data is
attacker-controlled, so the dashboard must not become a stored-XSS sink.
"""

from __future__ import annotations

import argparse
import glob
import html
import json
import mimetypes
import os
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT_DEFAULT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Mirror lead_board.py's vocabulary so the board reads the same everywhere.
PRIO_RANK = {"high": 0, "med": 1, "low": 2}
HIGH_VALUE = {"hunt-idor", "hunt-graphql", "hunt-ssrf", "hunt-llm-ai",
              "hunt-source-leak", "hunt-oauth", "hunt-ato", "hunt-auth-bypass"}
STATUS_ICON = {"new": "•", "investigating": "🔬", "killed": "☠",
               "reported": "📤", "parked": "⏸"}
STATUS_ORDER = ["new", "investigating", "reported", "parked", "killed"]
STALE_DAYS = 2  # a HIGH lead untouched this long is "stale" (matches lead_board)

# ---------------------------------------------------------------------------
# Collection — read the repo's real output files into a plain dict.
# Every function is pure given `root`; missing dirs degrade to empty, never raise.
# ---------------------------------------------------------------------------


def _read_lines(path: str) -> list[str]:
    try:
        with open(path, errors="replace") as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def _read_jsonl(path: str) -> list[dict]:
    out = []
    for line in _read_lines(path):
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                out.append(obj)
        except ValueError:
            pass
    return out


def _rank_key(lead: dict):
    return (PRIO_RANK.get(lead.get("priority"), 3),
            0 if lead.get("skill") in HIGH_VALUE else 1,
            lead.get("created", ""))


def lead_age_days(lead: dict, _now=None) -> int:
    """Whole days since a lead was created; 0 if the timestamp is unparseable."""
    now = _now or datetime.now(timezone.utc)
    try:
        created = datetime.fromisoformat(lead.get("created", "").replace("Z", "+00:00"))
        return max(0, (now - created).days)
    except (ValueError, AttributeError):
        return 0


def is_stale(lead: dict, _now=None) -> bool:
    return (lead.get("status") == "new"
            and lead.get("priority") == "high"
            and lead_age_days(lead, _now) >= STALE_DAYS)


def collect_leads(root: str) -> dict:
    """{target: {"leads": [...sorted...], "counts": {status: n}, "stale": n}}."""
    boards = {}
    for path in sorted(glob.glob(os.path.join(root, "memory", "leads", "*.jsonl"))):
        target = os.path.splitext(os.path.basename(path))[0]
        leads = _read_jsonl(path)
        if not leads:
            continue
        counts = {}
        for l in leads:
            counts[l.get("status", "new")] = counts.get(l.get("status", "new"), 0) + 1
        leads.sort(key=lambda l: (STATUS_ORDER.index(l.get("status", "new"))
                                  if l.get("status", "new") in STATUS_ORDER else 99,
                                  _rank_key(l)))
        boards[target] = {
            "leads": leads,
            "counts": counts,
            "stale": sum(1 for l in leads if is_stale(l)),
        }
    return boards


def collect_recon(root: str) -> dict:
    """{target: {subdomains, live_hosts, urls, nuclei}} counted from recon/<target>/."""
    out = {}
    recon_root = os.path.join(root, "recon")
    if not os.path.isdir(recon_root):
        return out
    for target in sorted(os.listdir(recon_root)):
        tdir = os.path.join(recon_root, target)
        if not os.path.isdir(tdir):
            continue

        def count(*globs):
            seen = set()
            for gpat in globs:
                for f in glob.glob(os.path.join(tdir, gpat), recursive=True):
                    seen.update(_read_lines(f))
            return len(seen)

        out[target] = {
            "subdomains": count("subdomains.txt", "subdomains/*.txt", "**/subdomains.txt"),
            "live_hosts": count("live-hosts.txt", "live/*.txt", "**/httpx_full.txt"),
            "urls": count("urls.txt", "urls/*.txt", "**/urls.txt"),
            "nuclei": count("nuclei.txt", "nuclei/*.txt", "**/nuclei.txt"),
        }
    return out


def _collect_docs(root: str, subdir: str) -> list[dict]:
    base = os.path.join(root, subdir)
    docs = []
    for f in glob.glob(os.path.join(base, "**", "*"), recursive=True):
        if not os.path.isfile(f):
            continue
        if os.path.splitext(f)[1].lower() not in (".md", ".txt", ".json", ".html"):
            continue
        rel = os.path.relpath(f, root).replace(os.sep, "/")
        parts = rel.split("/")
        docs.append({
            "rel": rel,
            "name": os.path.basename(f),
            "target": parts[1] if len(parts) > 2 else "",
            "mtime": os.path.getmtime(f),
        })
    docs.sort(key=lambda d: d["mtime"], reverse=True)
    return docs


def collect_galleries(root: str) -> list[dict]:
    out = []
    for f in glob.glob(os.path.join(root, "**", "gallery.html"), recursive=True):
        rel = os.path.relpath(f, root).replace(os.sep, "/")
        out.append({"rel": rel, "mtime": os.path.getmtime(f)})
    out.sort(key=lambda d: d["mtime"], reverse=True)
    return out


def collect_memory(root: str) -> dict:
    hm = os.path.join(root, "hunt-memory")
    journal = _read_jsonl(os.path.join(hm, "journal.jsonl"))
    patterns = _read_jsonl(os.path.join(hm, "patterns.jsonl"))
    audit = _read_jsonl(os.path.join(hm, "audit.jsonl"))
    recent = sorted(journal, key=lambda e: e.get("ts", ""), reverse=True)[:8]
    return {
        "journal": len(journal),
        "patterns": len(patterns),
        "audit": len(audit),
        "recent": recent,
    }


def collect_state(root: str) -> dict:
    """The whole dashboard's data. Pure given `root`; safe on a fresh checkout."""
    boards = collect_leads(root)
    all_leads = [l for b in boards.values() for l in b["leads"]]
    status_totals = {}
    for l in all_leads:
        status_totals[l.get("status", "new")] = status_totals.get(l.get("status", "new"), 0) + 1
    findings = _collect_docs(root, "findings")
    reports = _collect_docs(root, "reports")
    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "root": root,
        "boards": boards,
        "recon": collect_recon(root),
        "findings": findings,
        "reports": reports,
        "galleries": collect_galleries(root),
        "memory": collect_memory(root),
        "totals": {
            "targets": len(set(list(boards) + list(collect_recon(root)))),
            "leads": len(all_leads),
            "untouched": status_totals.get("new", 0),
            "investigating": status_totals.get("investigating", 0),
            "reported": status_totals.get("reported", 0),
            "findings": len(findings),
            "reports": len(reports),
            "stale": sum(b["stale"] for b in boards.values()),
        },
    }


# ---------------------------------------------------------------------------
# Rendering — pure: state dict in, self-contained HTML string out.
# ---------------------------------------------------------------------------

_STYLE = """
:root{--bg:#0b0e14;--panel:#141a24;--panel2:#0f141d;--border:#232a36;
--text:#c8d3f5;--muted:#7f8ba3;--blue:#6cb6ff;--green:#4ade80;--amber:#ffb454;
--red:#ff5c7a;--violet:#a78bfa}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif;margin:0;padding:24px}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:20px}
h1{font-size:20px;margin:0}h2{font-size:15px;margin:26px 0 10px;color:var(--muted);
text-transform:uppercase;letter-spacing:.06em;font-weight:600}
.sub{color:var(--muted);font-size:12px}
.live{background:var(--green);color:#04120a;font-size:11px;font-weight:700;
padding:2px 8px;border-radius:999px}
.tiles{display:grid;gap:14px;grid-template-columns:repeat(auto-fill,minmax(150px,1fr))}
.tile{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.tile .n{font-size:26px;font-weight:700}.tile .l{color:var(--muted);font-size:12px;margin-top:2px}
.tile.alert{border-color:var(--red)}.tile.alert .n{color:var(--red)}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;
padding:4px 0;overflow:hidden}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 14px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
tr:last-child td{border-bottom:none}
td.ev{word-break:break-all;color:var(--muted);max-width:520px}
.chip{display:inline-block;font-size:11px;font-weight:600;padding:1px 8px;border-radius:999px;
border:1px solid var(--border)}
.p-high{color:var(--red);border-color:var(--red)}
.p-med{color:var(--amber);border-color:var(--amber)}
.p-low{color:var(--muted)}
.s-new{color:var(--blue)}.s-investigating{color:var(--amber)}
.s-reported{color:var(--green)}.s-killed{color:var(--muted)}.s-parked{color:var(--violet)}
.stale{color:var(--red);font-weight:600}
.board-hd{display:flex;gap:10px;align-items:baseline;margin:22px 0 8px}
.board-hd .t{font-size:15px;font-weight:600}
.empty{color:var(--muted);padding:16px 14px}
footer{margin-top:32px;color:var(--muted);font-size:12px}
"""


def _esc(s) -> str:
    return html.escape(str(s), quote=True)


def _chip(text: str, cls: str) -> str:
    return f'<span class="chip {cls}">{_esc(text)}</span>'


def _tile(n, label, alert=False) -> str:
    return (f'<div class="tile{" alert" if alert else ""}">'
            f'<div class="n">{_esc(n)}</div><div class="l">{_esc(label)}</div></div>')


def _file_link(rel: str, live: bool, label: str | None = None) -> str:
    text = _esc(label if label is not None else rel)
    if live:
        return f'<a href="/file?path={urllib.parse.quote(rel)}">{text}</a>'
    return f'<a href="{_esc(rel)}">{text}</a>'  # relative link for static export


def _render_board(target: str, board: dict) -> str:
    counts = "  ".join(
        f'<span class="s-{s}">{STATUS_ICON.get(s, "")} {s}:{board["counts"][s]}</span>'
        for s in STATUS_ORDER if s in board["counts"])
    stale_badge = (f'<span class="stale">⏰ {board["stale"]} stale</span>'
                   if board["stale"] else "")
    rows = []
    for l in board["leads"]:
        prio = l.get("priority", "low")
        status = l.get("status", "new")
        age = lead_age_days(l)
        stale = ' <span class="stale">⏰</span>' if is_stale(l) else ""
        rows.append(
            "<tr>"
            f'<td>{_chip(prio, "p-" + prio)}</td>'
            f'<td class="s-{status}">{STATUS_ICON.get(status, "")} {_esc(status)}{stale}</td>'
            f'<td>{_esc(l.get("skill", ""))}</td>'
            f'<td class="ev">{_esc(l.get("evidence", ""))}'
            f'<br><span class="sub">{_esc(l.get("signal", ""))} — {_esc(l.get("why", ""))}</span></td>'
            f'<td class="sub">{age}d</td>'
            "</tr>")
    body = ("".join(rows) if rows else
            '<tr><td colspan="5" class="empty">no leads</td></tr>')
    return (
        f'<div class="board-hd"><span class="t">{_esc(target)}</span>'
        f'<span class="sub">{counts}</span>{stale_badge}</div>'
        '<div class="panel"><table>'
        '<tr><th>prio</th><th>status</th><th>skill</th><th>lead</th><th>age</th></tr>'
        f'{body}</table></div>')


def render_dashboard(state: dict, live: bool = False) -> str:
    t = state["totals"]
    refresh = '<meta http-equiv="refresh" content="30">' if live else ""
    badge = '<span class="live">● LIVE</span>' if live else ""

    tiles = "".join([
        _tile(t["targets"], "targets"),
        _tile(t["leads"], "leads"),
        _tile(t["untouched"], "untouched"),
        _tile(t["investigating"], "in progress"),
        _tile(t["findings"], "findings"),
        _tile(t["stale"], "stale HIGH leads", alert=t["stale"] > 0),
    ])

    # Lead boards
    if state["boards"]:
        boards_html = "".join(_render_board(tg, b) for tg, b in state["boards"].items())
    else:
        boards_html = '<div class="panel"><div class="empty">No leads yet. Run <code>lead_board.py ingest &lt;target&gt;</code> after recon.</div></div>'

    # Recon surface
    recon_rows = "".join(
        "<tr>"
        f"<td>{_esc(tg)}</td><td>{r['subdomains']}</td><td>{r['live_hosts']}</td>"
        f"<td>{r['urls']}</td><td>{r['nuclei']}</td></tr>"
        for tg, r in sorted(state["recon"].items()))
    recon_html = (
        '<div class="panel"><table>'
        '<tr><th>target</th><th>subdomains</th><th>live hosts</th><th>urls</th><th>nuclei</th></tr>'
        f'{recon_rows}</table></div>' if recon_rows else
        '<div class="panel"><div class="empty">No recon output yet.</div></div>')

    # Findings + reports
    def _doc_table(docs, kind):
        if not docs:
            return f'<div class="panel"><div class="empty">No {kind} yet.</div></div>'
        rows = "".join(
            "<tr>"
            f"<td>{_file_link(d['rel'], live, d['name'])}</td>"
            f"<td class='sub'>{_esc(d['target'])}</td>"
            f"<td class='sub'>{_esc(datetime.fromtimestamp(d['mtime']).strftime('%Y-%m-%d %H:%M'))}</td>"
            "</tr>" for d in docs[:50])
        return ('<div class="panel"><table>'
                '<tr><th>file</th><th>target</th><th>modified</th></tr>'
                f'{rows}</table></div>')

    galleries_html = ""
    if state["galleries"]:
        links = "  ·  ".join(_file_link(g["rel"], live) for g in state["galleries"])
        galleries_html = f'<h2>Screenshot galleries</h2><div class="panel"><div class="empty">{links}</div></div>'

    # Memory flywheel
    m = state["memory"]
    mem_recent = "".join(
        "<tr>"
        f"<td class='sub'>{_esc(e.get('ts', '')[:16])}</td>"
        f"<td>{_esc(e.get('target', ''))}</td>"
        f"<td>{_esc(e.get('vuln_class', e.get('action', '')))}</td>"
        f"<td class='sub'>{_esc(e.get('result', ''))}</td></tr>"
        for e in m["recent"])
    mem_html = (
        f'<div class="tiles" style="margin-bottom:12px">'
        f'{_tile(m["journal"], "journal entries")}{_tile(m["patterns"], "learned patterns")}'
        f'{_tile(m["audit"], "audited requests")}</div>')
    if mem_recent:
        mem_html += ('<div class="panel"><table>'
                     '<tr><th>when</th><th>target</th><th>class/action</th><th>result</th></tr>'
                     f'{mem_recent}</table></div>')

    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        f"{refresh}<title>Hunt Dashboard</title><style>{_STYLE}</style></head><body>"
        f'<header><h1>🎯 Hunt Dashboard</h1>{badge}'
        f'<span class="sub">generated {_esc(state["generated"])} · {_esc(state["root"])}</span></header>'
        f'<div class="tiles">{tiles}</div>'
        f'<h2>Lead board</h2>{boards_html}'
        f'<h2>Recon surface</h2>{recon_html}'
        f'<h2>Findings</h2>{_doc_table(state["findings"], "findings")}'
        f'<h2>Reports</h2>{_doc_table(state["reports"], "reports")}'
        f'{galleries_html}'
        f'<h2>Memory flywheel</h2>{mem_html}'
        '<footer>Agentic Bug Hunter · local dashboard · '
        'data read from memory/leads, recon/, findings/, reports/, hunt-memory/</footer>'
        "</body></html>")


# ---------------------------------------------------------------------------
# Safe file serving (serve mode only) — never escape the root.
# ---------------------------------------------------------------------------

_VIEWABLE = {".md", ".txt", ".json", ".html", ".png", ".jpg", ".jpeg", ".gif",
             ".svg", ".webp"}


def safe_path(root: str, rel: str) -> str | None:
    """Resolve `rel` under `root`, refusing anything that escapes it."""
    real_root = os.path.realpath(root)
    full = os.path.realpath(os.path.join(real_root, rel))
    try:
        if os.path.commonpath([full, real_root]) != real_root:
            return None
    except ValueError:  # different drives on Windows
        return None
    if not os.path.isfile(full):
        return None
    if os.path.splitext(full)[1].lower() not in _VIEWABLE:
        return None
    return full


def _wrap_text(rel: str, body: str) -> bytes:
    return (
        "<!doctype html><meta charset=utf-8>"
        f"<title>{_esc(rel)}</title>"
        f"<style>body{{background:#0b0e14;color:#c8d3f5;font:13px/1.6 ui-monospace,"
        "monospace;margin:0;padding:24px}a{color:#6cb6ff}pre{white-space:pre-wrap;"
        "word-break:break-word}</style>"
        f'<p><a href="/">← dashboard</a> · {_esc(rel)}</p><pre>{_esc(body)}</pre>'
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------


def make_handler(root: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):  # quiet
            pass

        def _send(self, code, body, ctype="text/html; charset=utf-8"):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/":
                self._send(200, render_dashboard(collect_state(root), live=True))
            elif parsed.path == "/api/state":
                self._send(200, json.dumps(collect_state(root), indent=2),
                           "application/json; charset=utf-8")
            elif parsed.path == "/file":
                rel = urllib.parse.parse_qs(parsed.query).get("path", [""])[0]
                full = safe_path(root, rel)
                if not full:
                    self._send(404, "not found or not allowed")
                    return
                ext = os.path.splitext(full)[1].lower()
                with open(full, "rb") as fh:
                    data = fh.read()
                if ext in (".md", ".txt", ".json"):
                    self._send(200, _wrap_text(rel, data.decode("utf-8", "replace")))
                elif ext == ".html":
                    self._send(200, data)
                else:
                    ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
                    self._send(200, data, ctype)
            else:
                self._send(404, "not found")

    return Handler


def serve(root: str, host: str, port: int):
    httpd = ThreadingHTTPServer((host, port), make_handler(root))
    url = f"http://{host}:{port}"
    print(f"[+] Hunt Dashboard live at {url}")
    print(f"[+] Serving state from: {root}")
    print("[+] Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] dashboard stopped.")
    finally:
        httpd.server_close()


def export(root: str, out: str):
    html_str = render_dashboard(collect_state(root), live=False)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html_str)
    print(f"[+] wrote self-contained dashboard: {out}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Local Hunt Dashboard — one live view of a hunt.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("serve", help="run the live local dashboard server")
    ps.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    ps.add_argument("--port", type=int, default=8777, help="bind port (default: 8777)")
    ps.add_argument("--root", default=ROOT_DEFAULT, help="repo root to read state from")

    pe = sub.add_parser("export", help="write a self-contained HTML snapshot")
    pe.add_argument("-o", "--out", required=True, help="output .html file")
    pe.add_argument("--root", default=ROOT_DEFAULT, help="repo root to read state from")

    args = ap.parse_args(argv)
    if args.cmd == "serve":
        serve(os.path.abspath(args.root), args.host, args.port)
    elif args.cmd == "export":
        export(os.path.abspath(args.root), args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
