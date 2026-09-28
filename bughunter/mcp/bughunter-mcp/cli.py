"""CLI helpers: bughunter mcp serve | doctor | tools."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_DIR = Path(__file__).resolve().parent
_REPO = _DIR.parents[1]


def cmd_tools() -> int:
    sys.path.insert(0, str(_DIR))
    from policy.tool_meta import list_tool_catalog

    rows = list_tool_catalog()
    print(f"{'TOOL':<28} {'SCOPE':<6} {'APPROVAL':<10} {'ACTIVE':<7} {'RO'}")
    print("-" * 70)
    for r in rows:
        print(
            f"{r['tool']:<28} "
            f"{'yes' if r['requires_scope'] else 'no':<6} "
            f"{r['approval_level']:<10} "
            f"{'yes' if r['active_testing'] else 'no':<7} "
            f"{'yes' if r['read_only'] else 'no'}"
        )
    return 0


def cmd_doctor() -> int:
    print("Agentic-Bug-Hunter MCP doctor")
    print(f"repo: {_REPO}")
    if str(_REPO) not in sys.path:
        sys.path.insert(0, str(_REPO))
    ok = True

    # SDK
    try:
        from mcp.server.mcpserver import MCPServer  # noqa: F401
        print("[+] mcp SDK (MCPServer) import OK")
    except Exception as exc:
        print(f"[!] mcp SDK missing: {exc}")
        print("    pip install 'mcp>=2.2.0'")
        ok = False

    # server file
    server = _DIR / "server.py"
    print(f"[+] server: {server}" if server.exists() else "[!] server.py missing")
    ok = ok and server.exists()

    # core deps
    for mod in ("tools.scope_checker", "tools.lead_board", "memory.audit_log"):
        try:
            __import__(mod)
            print(f"[+] {mod}")
        except Exception as e:
            print(f"[!] {mod}: {e}")
            ok = False

    # memory / config
    mem = Path(os.environ.get("BBHUNT_MEMORY_DIR", "hunt-memory"))
    print(f"[*] BBHUNT_MEMORY_DIR={mem} exists={mem.exists()}")
    cfg = Path.home() / ".bughunter" / "config.json"
    print(f"[*] provider config {cfg} exists={cfg.exists()}")

    # sibling integrations
    for name in ("burp-mcp-client", "caido-mcp-client", "hackerone-mcp"):
        p = _REPO / "mcp" / name
        print(f"[*] sibling {name}: {'ok' if p.exists() else 'missing'}")

    print("[+] approve env BBHUNT_MCP_APPROVE=" + os.environ.get("BBHUNT_MCP_APPROVE", "(unset)"))
    print("OK" if ok else "ISSUES FOUND")
    return 0 if ok else 1


def cmd_serve() -> int:
    server = _DIR / "server.py"
    # Re-exec as the server module for clean stdio
    os.execv(sys.executable, [sys.executable, str(server)])
    return 0  # pragma: no cover


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    if not argv or argv[0] in {"-h", "--help", "help"}:
        print("Usage: bughunter mcp [serve|doctor|tools]")
        return 0
    cmd = argv[0]
    if cmd == "serve":
        return cmd_serve()
    if cmd == "doctor":
        return cmd_doctor()
    if cmd == "tools":
        return cmd_tools()
    print(f"Unknown mcp subcommand: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
