# Agentic-Bug-Hunter MCP

Native MCP **server** that exposes the existing BugHunter research engine to AI agents.

This does **not** replace:

- `burp-mcp-client/`
- `caido-mcp-client/`
- `hackerone-mcp/`

## Run

```bash
pip install 'mcp>=2.2.0'
python3 mcp/bughunter-mcp/server.py
# or
./install.sh --agent standalone
bughunter mcp serve
bughunter mcp doctor
bughunter mcp tools
```

## Clients

- Claude Code: merge `claude-config.json` into `mcpServers`
- OpenCode: see `opencode-config.json`

## Safety

- Scope must be set (`scope_domains`) before active tools
- Active tools need `approve=true` or `BBHUNT_MCP_APPROVE=1`
- Discovered hosts are not automatically authorized
- Reports are never auto-submitted
- Target content is untrusted data (not instructions)

## Primary tool

`bughunter_research` — modes `RECON|HUNT|VALIDATE|REPORT|FULL`

See `docs/mcp.md` and `docs/mcp-research.md`.
