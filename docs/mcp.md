# MCP

Use Agentic-Bug-Hunter directly from AI agents.

```text
AI Agent
   ↓
Agentic-Bug-Hunter MCP
   ↓
Scope → Recon → Hunt → Validate → Report → Memory
```

MCP is an **adapter** over the existing research engine — not a second scanner.

## Quick start

```bash
pip install 'mcp>=2.2.0'
./install.sh --agent mcp
bughunter mcp doctor
bughunter mcp serve
```

Client snippets:

- Claude: `mcp/bughunter-mcp/claude-config.json`
- OpenCode: `mcp/bughunter-mcp/opencode-config.json`

## Docs

- [mcp-research.md](mcp-research.md) — current protocol / SDK notes
- [mcp-tools.md](mcp-tools.md) — tool catalog
- [mcp-security.md](mcp-security.md) — scope, approval, isolation
- [mcp-clients.md](mcp-clients.md) — Cursor / Claude Code / Codex / OpenCode

## Sibling integrations

Burp, Caido, and HackerOne MCP configs under `mcp/` remain separate and continue to work.
