# MCP Tools

| Tool | Risk | Scope | Approval |
|---|---|---|---|
| `bughunter_research` | active | yes | yes |
| `bughunter_scope_check` | read-only | — | — |
| `bughunter_get_scope` | read-only | — | — |
| `bughunter_recon` | active | yes | yes |
| `bughunter_attack_surface` | read-only | — | — |
| `bughunter_subdomains` | read-only | — | — |
| `bughunter_endpoints` | read-only | — | — |
| `bughunter_parameters` | read-only | — | — |
| `bughunter_hunt` | active | yes | yes |
| `bughunter_hunt_class` | active | yes | yes |
| `bughunter_list_findings` | read-only | — | — |
| `bughunter_get_finding` | read-only | — | — |
| `bughunter_validate` | gated | yes | yes |
| `bughunter_get_validation` | read-only | — | — |
| `bughunter_generate_report` | read-only | — | — |
| `bughunter_get_report` | read-only | — | — |
| `bughunter_get_evidence` | read-only | — | — |
| `bughunter_memory_*` | read-only | target filter | — |
| `bughunter_leads` / `next` / `update` | local | — | — |
| `bughunter_program*` | external read | — | — |

List at runtime: `bughunter mcp tools`.

Backed by existing `bughunter/tools/recon_engine.sh`, `bughunter/tools/hunt.py`, `bughunter/tools/validate.py`, `bughunter/tools/lead_board.py`, `memory/*`, and `mcp/hackerone-mcp/`.
