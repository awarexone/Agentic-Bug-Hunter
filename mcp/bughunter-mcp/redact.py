"""Secret redaction for MCP outputs.

Delegates to memory.redaction — the one project redactor. MCP must not keep
a second, weaker rule set.
"""

from __future__ import annotations

from memory.redaction import redact_obj, redact_text

__all__ = ["redact_obj", "redact_text"]
