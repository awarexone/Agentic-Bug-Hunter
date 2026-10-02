"""
Deterministic scope checker — code check, not LLM judgment.

Validates URLs against an allowlist of patterns before any outbound request.
This is safety-critical trust infrastructure: the guarantee it exists to keep
is "out-of-scope traffic executed = 0". Every decision is deterministic and
fails closed — anything empty, malformed, ambiguous, or unrecognized is
treated as OUT OF SCOPE, never as in scope.

Supported allow/deny pattern forms:
  - "target.com"            exact host
  - "*.target.com"          any subdomain (NOT the apex, NOT evil-target.com)
  - "api.target.com:8443"   host + optional port constraint (narrows scope)
  - "target.com/api/"       host + optional path-prefix constraint (narrows)
  - "10.0.0.0/24"           IPv4 CIDR range
  - "10.0.0.5"              single IPv4 (treated as /32)
  - "2001:db8::/32"         IPv6 CIDR range
  - "2001:db8::1"           single IPv6

Anchored suffix matching (not raw fnmatch) prevents subdomain confusion:
  - "*.target.com" matches "sub.target.com" but NOT "evil-target.com"
  - "target.com" matches exactly "target.com", never a subdomain

Hardening (see docs/phase2-scope-hardening.md):
  - single canonical parser for every check (no parser divergence)
  - rejects backslash / whitespace / control-character URL tricks
  - rejects non-http(s) schemes
  - rejects unicode/non-ASCII and otherwise malformed hostnames
  - normalizes a single trailing FQDN dot ("target.com." == "target.com")
  - rejects ambiguous / alternate IP encodings (decimal/hex/octal/short-form)
  - refuses wildcards over public suffixes ("*.com") — accidental widening
  - IP/CIDR membership via the stdlib ipaddress module (canonical only)
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import sys
import argparse
import ipaddress
import json
import re
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Dangerous or unusable scope configuration — raised at construction so a
    misconfigured scope fails loudly at config time instead of silently
    widening (or silently blocking everything) at request time.

    Subclasses ValueError so existing ``except ValueError`` sites still catch it.
    """


# Public suffixes we refuse to wildcard over. Not the full Public Suffix List —
# a pragmatic guard against the common "*.com" / "*.co.uk" footguns that would
# put the entire TLD in scope.
_PUBLIC_SUFFIXES = {
    "com", "net", "org", "io", "co", "dev", "app", "xyz", "info", "biz", "me",
    "ai", "gov", "edu", "mil", "int", "eu", "us", "uk", "de", "fr", "nl", "ru",
    "cn", "jp", "in", "br", "au", "ca", "es", "it", "se", "no", "fi", "pl",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.nz", "com.br", "co.in", "com.cn", "com.mx", "com.tr",
    "co.za", "com.sg", "com.hk", "com.tw",
}

# Post-lowercasing ASCII DNS label charset. Anything outside this (unicode
# homoglyphs, %, spaces, etc.) means "not a hostname we can reason about" and
# is rejected -> fail closed.
_HOSTNAME_CHARS = re.compile(r"^[a-z0-9._-]+$")

# Control chars (incl. NUL/CR/LF/TAB), space, DEL/C1 range, and backslash.
# Backslash matters because browsers/curl treat "\" as "/" while urlparse does
# not — "https://target.com\\@evil.com" would otherwise parse as host
# target.com here but connect to evil.com. Reject the whole URL if present.
_FORBIDDEN_URL_CHARS = re.compile(r"[\x00-\x20\x7f-\x9f\\]")

_ALLOWED_SCHEMES = {"http", "https"}

_PORT_RE = re.compile(r"^[0-9]{1,5}$")


def _warn(msg: str) -> None:
    print(f"WARNING: scope checker {msg}", file=sys.stderr)


def _try_ip_network(text: str):
    """Return an ip_network for an IP or CIDR literal, else None.

    ipaddress rejects anything containing letters, so a domain like
    "target.com" correctly returns None. Wildcards are never IPs.
    """
    if not text or "*" in text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def _is_public_suffix(base: str) -> bool:
    return base in _PUBLIC_SUFFIXES


def _normalize_and_parse(url: str):
    """Canonicalize a URL/host string into a target tuple, or None (fail closed).

    Returns (kind, host, port, path, scheme) where:
      - kind is "ip" (host is an ipaddress object) or "domain" (host is str)
      - port is an int or None (no explicit port)
      - path is the URL path (defaults to "/")
      - scheme is "http" or "https"

    Returns None for anything empty, malformed, ambiguous, or unsupported.
    This is the ONE parser every scope decision goes through.
    """
    if not url or not isinstance(url, str):
        return None

    # Reject URL-level tricks before parsing: backslash, whitespace, controls.
    if _FORBIDDEN_URL_CHARS.search(url):
        return None

    candidate = url if "://" in url else f"https://{url}"

    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None

    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        return None

    try:
        hostname = parsed.hostname
        port = parsed.port  # raises ValueError on a bad/out-of-range port
    except ValueError:
        return None

    if not hostname:
        return None

    host = hostname.lower()

    # Normalize a single trailing FQDN root dot: "target.com." == "target.com".
    if host.endswith("."):
        host = host[:-1]
    if not host:
        return None

    # IPv6 literals contain ":" (urlparse already stripped the [] brackets).
    if ":" in host:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return None
        return ("ip", ip, port, parsed.path or "/", scheme)

    # ASCII-only hostname charset gate (defeats unicode homoglyph lookalikes).
    if not _HOSTNAME_CHARS.match(host):
        return None

    labels = host.split(".")
    if any(label == "" for label in labels):
        return None  # empty label: leading/trailing/double dot

    # Canonical dotted-quad IPv4.
    try:
        ip = ipaddress.ip_address(host)
        return ("ip", ip, port, parsed.path or "/", scheme)
    except ValueError:
        pass

    # Alternate / ambiguous IP encodings: a valid domain never has an
    # all-numeric or 0x-prefixed rightmost label. Decimal (2130706433),
    # hex (0x7f000001), octal, and short-form IPs land here. Refuse them
    # rather than risk any canonicalization confusion -> fail closed.
    last = labels[-1]
    if re.fullmatch(r"[0-9]+", last) or last.startswith("0x"):
        return None

    return ("domain", host, port, parsed.path or "/", scheme)


def _domain_matches(hostname: str, pattern: str) -> bool:
    """Anchored domain matching — prevents subdomain confusion.

    *.target.com  -> matches sub.target.com, a.b.target.com
                  -> does NOT match target.com, evil-target.com
    target.com    -> matches target.com exactly
    """
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".target.com"
        # Must be a proper subdomain: ends with ".target.com" and is not the
        # apex itself. endswith on the dotted suffix is what blocks
        # "evil-target.com" (ends with "-target.com", not ".target.com").
        return hostname.endswith(suffix) and hostname != suffix[1:]
    return hostname == pattern


def _exclusion_matches(hostname: str, pattern: str) -> bool:
    """Exclusions deny broadly: an exact exclusion covers the host AND its
    subdomains, so excluding "blog.target.com" also blocks
    "cdn.blog.target.com" (which a "*.target.com" allow would otherwise let
    back in). A wildcard exclusion keeps the anchored *.target.com semantics.
    """
    if pattern.startswith("*."):
        return _domain_matches(hostname, pattern)
    return hostname == pattern or hostname.endswith("." + pattern)


def _path_matches(url_path: str, pattern_path: str | None) -> bool:
    """Prefix match with a path-segment boundary (so /api does not match
    /apixyz). A pattern with no path (None or "/") matches any path."""
    if not pattern_path or pattern_path == "/":
        return True
    up = url_path or "/"
    if pattern_path.endswith("/"):
        return up == pattern_path[:-1] or up.startswith(pattern_path)
    return up == pattern_path or up.startswith(pattern_path + "/")


def _parse_pattern(raw: str) -> dict | None:
    """Parse one scope pattern into a structured rule.

    Returns a rule dict, or None for an unusable pattern (skipped with a
    warning — an unusable allow pattern simply never matches, which fails
    closed). Raises ScopeError for a dangerous pattern (e.g. a wildcard over
    a public suffix) so the misconfiguration surfaces immediately.
    """
    if raw is None:
        return None
    p = raw.strip().lower()
    if not p:
        return None

    # Strip scheme if the user pasted a full URL as a pattern.
    if "://" in p:
        p = p.split("://", 1)[1]

    # IP or CIDR (covers single IPs and ranges, v4/v6) — check before treating
    # "/" as a path separator, since CIDR uses "/".
    net = _try_ip_network(p)
    if net is not None:
        return {"kind": "ip", "raw": raw, "network": net}

    # domain[:port][/path]
    host_port, sep, rest = p.partition("/")
    path = ("/" + rest) if sep else None

    host = host_port
    port: int | None = None
    if ":" in host_port:
        host, _, port_s = host_port.rpartition(":")
        if not _PORT_RE.match(port_s) or int(port_s) > 65535:
            _warn(f"ignoring pattern with invalid port: {raw!r}")
            return None
        port = int(port_s)

    if host.endswith("."):
        host = host[:-1]

    # A bare IP that arrived with a port or path (ip_network above would have
    # rejected "10.0.0.5:8080"): route it back to an IP rule, dropping the
    # unsupported port/path rather than silently storing an inert domain rule.
    ip_from_host = _try_ip_network(host)
    if ip_from_host is not None:
        if port is not None or path is not None:
            _warn(f"port/path not supported on IP scope patterns; using host only: {raw!r}")
        return {"kind": "ip", "raw": raw, "network": ip_from_host}

    if host.startswith("*."):
        base = host[2:]
        if not base or "*" in base:
            raise ScopeError(f"invalid wildcard pattern: {raw!r}")
        if not _HOSTNAME_CHARS.match(base) or "" in base.split("."):
            _warn(f"ignoring unparseable wildcard pattern: {raw!r}")
            return None
        if "." not in base:
            raise ScopeError(
                f"refusing overly broad wildcard {raw!r} — a single-label base "
                f"would match an entire TLD"
            )
        if _is_public_suffix(base):
            raise ScopeError(
                f"refusing wildcard over public suffix {base!r} in {raw!r} — "
                f"this would put the entire suffix in scope"
            )
    else:
        if "*" in host:
            raise ScopeError(f"unsupported wildcard placement in {raw!r}")
        if not host or not _HOSTNAME_CHARS.match(host) or "" in host.split("."):
            _warn(f"ignoring unparseable pattern: {raw!r}")
            return None

    return {"kind": "domain", "raw": raw, "host": host, "port": port, "path": path}


def extract_host_port(url: str) -> str:
    """Canonical "host" or "host:port" for a URL, or "" if unparseable.

    Shared so callers that key on host (e.g. the circuit breaker) use the same
    parser as the scope decision instead of a divergent hand-rolled one.
    """
    parsed = _normalize_and_parse(url)
    if parsed is None:
        return ""
    _, host, port, _, _ = parsed
    host_str = str(host)
    return f"{host_str}:{port}" if port is not None else host_str


class ScopeChecker:
    """Deterministic scope validator for bug bounty targets."""

    def __init__(
        self,
        domains: list[str],
        excluded_domains: list[str] | None = None,
        excluded_classes: list[str] | None = None,
    ):
        """
        Args:
            domains: Allowlist patterns like ["*.target.com", "api.target.com"]
            excluded_domains: Blocklist patterns like ["blog.target.com"]
            excluded_classes: Vuln classes excluded by program (e.g., ["dos"])

        Raises:
            ScopeError: if any pattern is dangerous (e.g. a public-suffix wildcard).
        """
        self._allow_domain_rules: list[dict] = []
        self._allow_ip_rules: list[dict] = []
        for raw in domains or []:
            rule = _parse_pattern(raw)
            if rule is None:
                continue
            if rule["kind"] == "ip":
                self._allow_ip_rules.append(rule)
            else:
                self._allow_domain_rules.append(rule)

        self._exclude_domain_rules: list[dict] = []
        self._exclude_ip_rules: list[dict] = []
        for raw in excluded_domains or []:
            rule = _parse_pattern(raw)
            if rule is None:
                continue
            if rule["kind"] == "ip":
                self._exclude_ip_rules.append(rule)
            else:
                self._exclude_domain_rules.append(rule)

        # Backward-compatible attributes some callers read directly.
        self.domains = [d.lower() for d in (domains or [])]
        self.excluded_domains = [d.lower() for d in (excluded_domains or [])]
        self.excluded_classes = [c.lower() for c in (excluded_classes or [])]

    def explain(self, url: str) -> dict:
        """Deterministic scope decision with attribution.

        Returns a dict:
            {
              "in_scope": bool,
              "host": str | None,
              "kind": "domain" | "ip" | "invalid",
              "matched_rule": str | None,   # the pattern that decided it
              "reason": str,                 # human-readable "why"
            }

        This is the single source of truth; is_in_scope() is a thin wrapper.
        The structured output is what the desktop layer will later render as
        "why allowed / why blocked / which rule matched" — but enforcement is
        correct here regardless of any UI.
        """
        parsed = _normalize_and_parse(url)
        if parsed is None:
            return {
                "in_scope": False,
                "host": None,
                "kind": "invalid",
                "matched_rule": None,
                "reason": (
                    "URL is empty, malformed, or uses an ambiguous/unsupported "
                    "form (bad scheme, encoding trick, or alternate IP encoding) "
                    "— failing closed"
                ),
            }

        kind, host, _port, path, scheme = parsed

        if kind == "ip":
            host_str = str(host)
            for rule in self._exclude_ip_rules:
                if host in rule["network"]:
                    return {
                        "in_scope": False, "host": host_str, "kind": "ip",
                        "matched_rule": rule["raw"],
                        "reason": f"{host_str} is inside excluded range {rule['raw']}",
                    }
            for rule in self._allow_ip_rules:
                if host in rule["network"]:
                    return {
                        "in_scope": True, "host": host_str, "kind": "ip",
                        "matched_rule": rule["raw"],
                        "reason": f"{host_str} is inside in-scope range {rule['raw']}",
                    }
            return {
                "in_scope": False, "host": host_str, "kind": "ip",
                "matched_rule": None,
                "reason": f"{host_str} matches no in-scope IP/CIDR rule",
            }

        # domain
        for rule in self._exclude_domain_rules:
            if _exclusion_matches(host, rule["host"]):
                return {
                    "in_scope": False, "host": host, "kind": "domain",
                    "matched_rule": rule["raw"],
                    "reason": f"{host} matches exclusion {rule['raw']}",
                }

        eff_port = _port if _port is not None else (443 if scheme == "https" else 80)
        for rule in self._allow_domain_rules:
            if not _domain_matches(host, rule["host"]):
                continue
            if rule["port"] is not None and rule["port"] != eff_port:
                continue
            if not _path_matches(path, rule["path"]):
                continue
            return {
                "in_scope": True, "host": host, "kind": "domain",
                "matched_rule": rule["raw"],
                "reason": f"{host} matches in-scope rule {rule['raw']}",
            }

        return {
            "in_scope": False, "host": host, "kind": "domain",
            "matched_rule": None,
            "reason": f"{host} matches no in-scope rule",
        }

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL's host is in scope.

        Returns True only if the host matches an allow rule and no exclusion.
        Returns False for everything else, including malformed/ambiguous input.
        """
        return self.explain(url)["in_scope"]

    def is_vuln_class_allowed(self, vuln_class: str) -> bool:
        """Check if a vulnerability class is allowed by the program."""
        return vuln_class.lower() not in self.excluded_classes

    def filter_urls(self, urls: list[str]) -> tuple[list[str], list[str]]:
        """Split a list of URLs into (in_scope, out_of_scope)."""
        in_scope = []
        out_of_scope = []
        for url in urls:
            if self.is_in_scope(url):
                in_scope.append(url)
            else:
                out_of_scope.append(url)
        return in_scope, out_of_scope

    def filter_file(self, input_path: str, output_path: str | None = None) -> tuple[int, int]:
        """Filter a file of URLs (one per line) through scope check.

        Args:
            input_path: Path to file with URLs, one per line.
            output_path: If provided, write in-scope URLs here. If None, filter in-place.

        Returns:
            (in_scope_count, out_of_scope_count)
        """
        with open(input_path, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        in_scope, out_of_scope = self.filter_urls(lines)

        dest = output_path or input_path
        with open(dest, "w") as f:
            for url in in_scope:
                f.write(url + "\n")

        if out_of_scope:
            print(
                f"WARNING: filtered {len(out_of_scope)} out-of-scope URLs from {input_path}",
                file=sys.stderr,
            )

        return len(in_scope), len(out_of_scope)


def _split_patterns(values: list[str]) -> list[str]:
    """Expand comma-separated CLI pattern args while preserving order."""
    patterns: list[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if part:
                patterns.append(part)
    return patterns


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deterministically check assets against bug bounty scope."
    )
    parser.add_argument("asset", nargs="?", help="URL or hostname to check")
    parser.add_argument(
        "--domain",
        "-d",
        action="append",
        default=[],
        help="Allowed domain pattern. Repeat or comma-separate, e.g. target.com,*.target.com",
    )
    parser.add_argument(
        "--exclude-domain",
        "-x",
        action="append",
        default=[],
        help="Excluded domain pattern. Repeat or comma-separate.",
    )
    parser.add_argument(
        "--exclude-class",
        action="append",
        default=[],
        help="Excluded vulnerability class. Repeat or comma-separate.",
    )
    parser.add_argument("--vuln-class", help="Optional vulnerability class to check")
    parser.add_argument("--input-file", help="Filter URLs from a file, one per line")
    parser.add_argument("--output", help="Output path for filtered in-scope URLs")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument("--explain", action="store_true", help="Print the matched rule + reason")
    args = parser.parse_args(argv)

    domains = _split_patterns(args.domain)
    excluded_domains = _split_patterns(args.exclude_domain)
    excluded_classes = _split_patterns(args.exclude_class)

    if not domains:
        parser.error("at least one --domain pattern is required")
    if not args.asset and not args.input_file and not args.vuln_class:
        parser.error("provide an asset, --input-file, or --vuln-class")

    try:
        checker = ScopeChecker(domains, excluded_domains, excluded_classes)
    except ScopeError as exc:
        parser.error(str(exc))

    result: dict[str, object] = {
        "domains": domains,
        "excluded_domains": excluded_domains,
        "excluded_classes": excluded_classes,
    }
    exit_code = 0

    if args.asset:
        verdict = checker.explain(args.asset)
        in_scope = verdict["in_scope"]
        result["asset"] = args.asset
        result["in_scope"] = in_scope
        result["matched_rule"] = verdict["matched_rule"]
        result["reason"] = verdict["reason"]
        if not in_scope:
            exit_code = 2

    if args.vuln_class:
        allowed = checker.is_vuln_class_allowed(args.vuln_class)
        result["vuln_class"] = args.vuln_class
        result["vuln_class_allowed"] = allowed
        if not allowed:
            exit_code = 2

    if args.input_file:
        try:
            in_count, out_count = checker.filter_file(args.input_file, args.output)
        except OSError as exc:
            parser.error(str(exc))
        result["input_file"] = args.input_file
        result["output"] = args.output or args.input_file
        result["in_scope_count"] = in_count
        result["out_of_scope_count"] = out_count

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if "asset" in result:
            verdict_str = "IN SCOPE" if result["in_scope"] else "OUT OF SCOPE"
            print(f"{verdict_str}: {result['asset']}")
            if args.explain:
                print(f"  rule:   {result.get('matched_rule')}")
                print(f"  reason: {result.get('reason')}")
        if "vuln_class" in result:
            verdict_str = "ALLOWED" if result["vuln_class_allowed"] else "EXCLUDED"
            print(f"{verdict_str}: vulnerability class {result['vuln_class']}")
        if "input_file" in result:
            print(
                "Filtered URLs: "
                f"{result['in_scope_count']} in scope, "
                f"{result['out_of_scope_count']} out of scope -> {result['output']}"
            )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
