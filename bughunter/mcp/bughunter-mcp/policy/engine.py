"""Server-side policy: scope + approval before active MCP tools."""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

from .decisions import (
    ACTIVE_TEST_APPROVAL_REQUIRED,
    AUTHORIZATION_REQUIRED,
    Decision,
    DecisionKind,
    OUT_OF_SCOPE,
    REPORT_APPROVAL_REQUIRED,
    SCOPE_REQUIRED,
    TARGET_REQUIRED,
    ApprovalLevel,
)
from .tool_meta import get_tool_meta


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _ensure_path() -> None:
    import sys
    root = _repo_root()
    if root not in sys.path:
        sys.path.insert(0, root)


def _host_of(target: str) -> str:
    raw = target if "://" in target else f"https://{target}"
    try:
        return (urlparse(raw).hostname or target).lower()
    except Exception:
        return target.lower()


class PolicyEngine:
    """Wrap existing ScopeChecker; enforce approval for active tools."""

    def __init__(
        self,
        domains: list[str] | None = None,
        excluded_domains: list[str] | None = None,
        excluded_classes: list[str] | None = None,
        *,
        auto_approve: bool | None = None,
    ):
        self._domains: list[str] = [d.lower() for d in (domains or [])]
        self._excluded = excluded_domains
        self._excluded_classes = excluded_classes
        self._checker = None
        if self._domains:
            self.set_scope(self._domains, excluded_domains)
        if auto_approve is None:
            auto_approve = os.environ.get("BBHUNT_MCP_APPROVE", "").strip().lower() in {
                "1", "true", "yes",
            }
        self.auto_approve = auto_approve
        self.discovered: set[str] = set()
        self.authorized: set[str] = {d.lstrip("*.").lower() for d in self._domains if d}

    def set_scope(self, domains: list[str], excluded_domains: list[str] | None = None) -> None:
        _ensure_path()
        from tools.scope_checker import ScopeChecker, ScopeError

        self._domains = [d.lower() for d in domains]
        try:
            self._checker = ScopeChecker(
                domains=self._domains,
                excluded_domains=excluded_domains or self._excluded,
                excluded_classes=self._excluded_classes,
            )
        except ScopeError as exc:
            # Dangerous scope config (e.g. a public-suffix wildcard). Leave the
            # checker unset so promote_asset() fails closed (BLOCK) rather than
            # widening scope. Surface the reason on stderr.
            import sys as _sys
            print(f"WARNING: rejected unsafe scope configuration: {exc}", file=_sys.stderr)
            self._checker = None
            self.authorized = set()
            return
        self.authorized = {d.lstrip("*.").lower() for d in self._domains if d}

    def note_discovered(self, host: str) -> None:
        h = host.lower().strip()
        if h and h not in self.authorized:
            self.discovered.add(h)

    def promote_asset(self, host: str) -> Decision:
        h = host.lower().strip()
        if not self._checker:
            return Decision(DecisionKind.BLOCK, "No scope configured", SCOPE_REQUIRED)
        if not self._checker.is_in_scope(h):
            return Decision(DecisionKind.BLOCK, f"{h} is out of scope", OUT_OF_SCOPE)
        self.authorized.add(h)
        self.discovered.discard(h)
        return Decision(DecisionKind.ALLOW, f"{h} authorized")

    def _approval_ok(self, args: dict[str, Any]) -> bool:
        if self.auto_approve:
            return True
        if args.get("approve") is True:
            return True
        token = str(args.get("approval_token") or "").strip()
        expected = os.environ.get("BBHUNT_MCP_APPROVAL_TOKEN", "").strip()
        return bool(expected and token and token == expected)

    def authorize_tool(self, tool: str, args: dict[str, Any]) -> Decision:
        meta = get_tool_meta(tool)
        target = str(args.get("target") or args.get("host") or "").strip()

        scope_domains = args.get("scope_domains") or args.get("domains")
        if scope_domains and isinstance(scope_domains, list) and scope_domains:
            self.set_scope([str(d) for d in scope_domains])

        if meta.requires_scope:
            if not self._domains or not self._checker:
                return Decision(
                    DecisionKind.BLOCK,
                    "Configure scope domains before active research",
                    SCOPE_REQUIRED,
                )
            if not target:
                return Decision(DecisionKind.BLOCK, "target is required", TARGET_REQUIRED)
            if not self._checker.is_in_scope(target):
                return Decision(DecisionKind.BLOCK, f"Target out of scope: {target}", OUT_OF_SCOPE)
            host = _host_of(target)
            if host in self.discovered and host not in self.authorized:
                if not self._checker.is_in_scope(host):
                    return Decision(
                        DecisionKind.BLOCK,
                        f"Host {host} is discovered but not authorized",
                        AUTHORIZATION_REQUIRED,
                        {"host": host, "state": "discovered"},
                    )
            self.authorized.add(host)

        if meta.external_action or meta.approval_level == ApprovalLevel.HIGH_RISK:
            if not self._approval_ok(args):
                return Decision(
                    DecisionKind.HIGH_RISK,
                    "External action requires explicit approval",
                    REPORT_APPROVAL_REQUIRED,
                )

        if meta.requires_approval or meta.active_testing:
            if not self._approval_ok(args):
                return Decision(
                    DecisionKind.REQUIRE_APPROVAL,
                    "Active testing requires approval "
                    "(pass approve=true or set BBHUNT_MCP_APPROVE=1)",
                    ACTIVE_TEST_APPROVAL_REQUIRED,
                    {"tool": tool, "target": target, "level": meta.approval_level.value},
                )

        return Decision(DecisionKind.ALLOW, "ok")

    def authorize_url(self, method: str, url: str) -> Decision:
        if not self._checker:
            return Decision(DecisionKind.BLOCK, "No scope configured", SCOPE_REQUIRED)
        if not self._checker.is_in_scope(url):
            return Decision(DecisionKind.BLOCK, f"URL out of scope: {url}", OUT_OF_SCOPE)
        try:
            from memory.audit_log import AutopilotGuard

            # scope_checker is a keyword arg (first positional is circuit_threshold);
            # check_request returns a dict whose "decision" key holds the verdict.
            guard = AutopilotGuard(scope_checker=self._checker, fail_closed=True)
            result = guard.check_request(method.upper(), url)
            decision = result.get("decision")
            if decision == "block":
                return Decision(
                    DecisionKind.BLOCK,
                    f"AutopilotGuard blocked request: {result.get('reason', '')}",
                    OUT_OF_SCOPE,
                )
            if decision == "require_approval":
                return Decision(
                    DecisionKind.REQUIRE_APPROVAL,
                    f"Method {method} requires approval",
                    ACTIVE_TEST_APPROVAL_REQUIRED,
                )
        except Exception as exc:  # noqa: BLE001
            return Decision(DecisionKind.BLOCK, f"Guard error: {exc}", AUTHORIZATION_REQUIRED)
        return Decision(DecisionKind.ALLOW, "ok")


def denied_payload(decision: Decision) -> dict[str, Any]:
    return {
        "status": "denied",
        "error": decision.error_code or "AUTHORIZATION_REQUIRED",
        "reason": decision.reason,
        "details": decision.details,
        "next_action": {
            SCOPE_REQUIRED: "Pass scope_domains or configure scope first",
            OUT_OF_SCOPE: "Choose an in-scope target",
            TARGET_REQUIRED: "Provide target",
            ACTIVE_TEST_APPROVAL_REQUIRED: "Pass approve=true after researcher confirmation",
            REPORT_APPROVAL_REQUIRED: "Preview then approve submission separately",
            AUTHORIZATION_REQUIRED: "Promote discovered host only if scope allows",
        }.get(decision.error_code or "", "Fix the error and retry"),
    }
