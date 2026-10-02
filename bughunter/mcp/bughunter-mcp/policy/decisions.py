"""Policy decisions for MCP tool calls."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ApprovalLevel(str, Enum):
    AUTO = "AUTO"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    HIGH_RISK = "HIGH_RISK"


class DecisionKind(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    HIGH_RISK = "high_risk"


@dataclass
class Decision:
    kind: DecisionKind
    reason: str = ""
    error_code: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.kind == DecisionKind.ALLOW


# Canonical MCP error codes (agent-actionable)
SCOPE_REQUIRED = "SCOPE_REQUIRED"
OUT_OF_SCOPE = "OUT_OF_SCOPE"
TARGET_REQUIRED = "TARGET_REQUIRED"
AUTHORIZATION_REQUIRED = "AUTHORIZATION_REQUIRED"
VALIDATION_REQUIRED = "VALIDATION_REQUIRED"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
ACTIVE_TEST_APPROVAL_REQUIRED = "ACTIVE_TEST_APPROVAL_REQUIRED"
REPORT_APPROVAL_REQUIRED = "REPORT_APPROVAL_REQUIRED"
RESOURCE_LIMIT = "RESOURCE_LIMIT"
RESEARCH_FAILED = "RESEARCH_FAILED"
CANCELLED = "CANCELLED"
