"""Per-tool security metadata (hints + server-side policy inputs)."""

from __future__ import annotations

from dataclasses import dataclass

from .decisions import ApprovalLevel


@dataclass(frozen=True)
class ToolSecurity:
    read_only: bool = False
    active_testing: bool = False
    network_access: bool = False
    external_action: bool = False
    destructive: bool = False
    idempotent: bool = True
    requires_scope: bool = False
    requires_approval: bool = False
    approval_level: ApprovalLevel = ApprovalLevel.AUTO


TOOL_META: dict[str, ToolSecurity] = {
    "bughunter_research": ToolSecurity(
        active_testing=True, network_access=True, requires_scope=True,
        requires_approval=True, approval_level=ApprovalLevel.APPROVAL_REQUIRED,
        idempotent=False,
    ),
    "bughunter_scope_check": ToolSecurity(read_only=True),
    "bughunter_get_scope": ToolSecurity(read_only=True),
    "bughunter_recon": ToolSecurity(
        active_testing=True, network_access=True, requires_scope=True,
        requires_approval=True, approval_level=ApprovalLevel.APPROVAL_REQUIRED,
        idempotent=False,
    ),
    "bughunter_attack_surface": ToolSecurity(read_only=True),
    "bughunter_subdomains": ToolSecurity(read_only=True),
    "bughunter_endpoints": ToolSecurity(read_only=True),
    "bughunter_parameters": ToolSecurity(read_only=True),
    "bughunter_hunt": ToolSecurity(
        active_testing=True, network_access=True, requires_scope=True,
        requires_approval=True, approval_level=ApprovalLevel.APPROVAL_REQUIRED,
        idempotent=False,
    ),
    "bughunter_hunt_class": ToolSecurity(
        active_testing=True, network_access=True, requires_scope=True,
        requires_approval=True, approval_level=ApprovalLevel.APPROVAL_REQUIRED,
        idempotent=False,
    ),
    "bughunter_list_findings": ToolSecurity(read_only=True),
    "bughunter_get_finding": ToolSecurity(read_only=True),
    "bughunter_validate": ToolSecurity(
        network_access=True, requires_scope=True,
        requires_approval=True, approval_level=ApprovalLevel.APPROVAL_REQUIRED,
    ),
    "bughunter_get_validation": ToolSecurity(read_only=True),
    "bughunter_generate_report": ToolSecurity(read_only=True),
    "bughunter_get_report": ToolSecurity(read_only=True),
    "bughunter_get_evidence": ToolSecurity(read_only=True),
    "bughunter_memory_search": ToolSecurity(read_only=True),
    "bughunter_memory_get": ToolSecurity(read_only=True),
    "bughunter_memory_patterns": ToolSecurity(read_only=True),
    "bughunter_leads": ToolSecurity(read_only=True),
    "bughunter_next_lead": ToolSecurity(read_only=True),
    "bughunter_update_lead": ToolSecurity(idempotent=False),
    "bughunter_program": ToolSecurity(read_only=True, network_access=True),
    "bughunter_program_policy": ToolSecurity(read_only=True, network_access=True),
}


def get_tool_meta(name: str) -> ToolSecurity:
    return TOOL_META.get(
        name,
        ToolSecurity(
            requires_approval=True,
            approval_level=ApprovalLevel.APPROVAL_REQUIRED,
        ),
    )


def list_tool_catalog() -> list[dict]:
    """Flat catalog for `bughunter mcp tools`."""
    rows = []
    for name, meta in sorted(TOOL_META.items()):
        rows.append({
            "tool": name,
            "read_only": meta.read_only,
            "active_testing": meta.active_testing,
            "network_access": meta.network_access,
            "external_action": meta.external_action,
            "requires_scope": meta.requires_scope,
            "requires_approval": meta.requires_approval,
            "approval_level": meta.approval_level.value,
        })
    return rows
