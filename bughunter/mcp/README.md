# MCP

MCP (Model Context Protocol) integrations.

| Integration | Purpose |
|:---|:---|
| `bughunter-mcp/` | **Native server** — AI agents run scope → recon → hunt → validate → report via existing engines |
| `burp-mcp-client/` | Burp Suite proxy integration |
| `caido-mcp-client/` | Caido proxy integration |
| `hackerone-mcp/` | HackerOne public API helpers (CLI/library) |

```bash
./install.sh --agent mcp
bughunter mcp doctor
bughunter mcp serve
```

See `docs/mcp.md`. Configure Claude/OpenCode using snippets inside each folder.

