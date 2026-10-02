# Agentic-Bug-Hunter MCP

Native MCP **server** that exposes the existing BugHunter research engine to AI agents.

This does **not** replace:

- `burp-mcp-client/`
- `caido-mcp-client/`
- `hackerone-mcp/`

## Install (any MCP client)

```bash
pip install agentic-bug-hunter
```

That installs the `bughunter` command. The MCP server runs as `bughunter mcp serve`,
so the same config works from any directory in any MCP-compatible agent.

```bash
bughunter mcp doctor   # verify SDK, tools, and paths
bughunter mcp tools    # list the exposed tool catalog
```

## Clients

Add this to your client's MCP config (works after `pip install`, no repo checkout needed):

```json
{
  "mcpServers": {
    "bughunter": {
      "command": "bughunter",
      "args": ["mcp", "serve"],
      "env": { "BBHUNT_MCP_APPROVE": "0" }
    }
  }
}
```

- **Claude Desktop / Claude Code**: merge `claude-config.json` into `mcpServers`
- **Cursor / Cline / Windsurf / Zed**: same `command` + `args` in their MCP settings
- **OpenCode**: see `opencode-config.json`

Running from a cloned repo instead of pip? Use `python3 mcp/bughunter-mcp/server.py`.

## Safety

- Scope must be set (`scope_domains`) before active tools
- Active tools need `approve=true` or `BBHUNT_MCP_APPROVE=1`
- Discovered hosts are not automatically authorized
- Reports are never auto-submitted
- Target content is untrusted data (not instructions)

## Primary tool

`bughunter_research` — modes `RECON|HUNT|VALIDATE|REPORT|FULL`

See `docs/mcp.md` and `docs/mcp-research.md`.
