"""Phase 2 adversarial scope-hardening matrix.

The guarantee under test: "out-of-scope traffic executed = 0". These tests try
to BREAK the scope checker rather than confirm it. Every case is categorized:

  Allowed    -> must be in scope
  Blocked    -> well-formed but out of scope, must be refused
  Ambiguous  -> weird-but-not-obviously-broken, must FAIL CLOSED
  Malformed  -> empty/garbage/encoding tricks, must FAIL CLOSED

Plus IP/CIDR, port/path narrowing, wildcard-widening config guards, explain()
attribution, AutopilotGuard integration, redirect scope, and parser unification.
"""

import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

import pytest

from scope_checker import (
    ScopeChecker,
    ScopeError,
    extract_host_port,
)
from memory.audit_log import AutopilotGuard
from tools.safe_http import safe_urlopen


# --- Fixtures --------------------------------------------------------------

@pytest.fixture
def sc():
    """Broad program scope: wildcard + apex + exclusions."""
    return ScopeChecker(
        domains=["target.com", "*.target.com"],
        excluded_domains=["blog.target.com"],
    )


@pytest.fixture
def sc_ip():
    return ScopeChecker(
        domains=["10.0.0.0/24", "192.168.1.5", "2001:db8::/32"],
        excluded_domains=["10.0.0.5"],
    )


@pytest.fixture
def sc_portpath():
    """No wildcard — so port/path narrowing is actually observable."""
    return ScopeChecker(
        domains=["api.example.com:8443", "cdn.example.com/assets/"],
    )


# --- ALLOWED (must pass) ---------------------------------------------------

class TestAllowed:
    @pytest.mark.parametrize("url", [
        "https://target.com",
        "https://target.com/",
        "https://target.com./",              # trailing FQDN dot normalized
        "http://target.com",                 # http scheme allowed
        "https://sub.target.com/path",
        "https://a.b.c.target.com",
        "https://API.TARGET.COM/v2",         # case-insensitive
        "https://Sub.Target.Com",
        "api.target.com",                    # bare host, no scheme
        "https://api.target.com:8443/x",     # any port ok when rule has none
        "https://evil.com@target.com",       # real host is target.com (in scope)
        "https://user:pass@sub.target.com/x",
    ])
    def test_in_scope(self, sc, url):
        assert sc.is_in_scope(url) is True, url


# --- BLOCKED (well-formed, out of scope) -----------------------------------

class TestBlocked:
    @pytest.mark.parametrize("url", [
        "https://evil.com",
        "https://other.com/attack",
        "https://nottarget.com",
        "https://blog.target.com",           # excluded exact
        "https://cdn.blog.target.com",       # excluded subtree (would-be *.target.com leak)
        "https://target.com.evil.com",       # suffix-append trick
        "https://evil.com/target.com",       # target.com only in path
        "https://192.168.1.1/admin",         # IP, no IP rules configured
        "https://[::1]/admin",               # IPv6, no IP rules
    ])
    def test_out_of_scope(self, sc, url):
        assert sc.is_in_scope(url) is False, url


# --- HOSTNAME BOUNDARY (the headline attack) --------------------------------

class TestHostnameBoundary:
    @pytest.mark.parametrize("url", [
        "https://evil-target.com",           # contains target.com but is NOT a subdomain
        "https://xtarget.com",
        "https://targetXcom.com",
        "https://nottarget.com",
        "https://target.com.attacker.net",
        "https://faketarget.com",
    ])
    def test_lookalike_blocked(self, sc, url):
        assert sc.is_in_scope(url) is False, url

    def test_wildcard_excludes_apex_when_only_wildcard(self):
        sc = ScopeChecker(["*.target.com"])
        assert sc.is_in_scope("https://target.com") is False
        assert sc.is_in_scope("https://sub.target.com") is True


# --- AMBIGUOUS (must fail closed) ------------------------------------------

class TestAmbiguousFailClosed:
    @pytest.mark.parametrize("url", [
        "https://2130706433/",               # decimal IP for 127.0.0.1
        "https://0x7f000001/",               # hex IP
        "https://0177.0.0.1/",               # octal-ish IP
        "https://1.2.3",                     # short-form / incomplete IP
        "https://999.999.999.999/",          # invalid dotted quad
        "https://target.com:99999/",         # out-of-range port
        "https://target.com:abc/",           # non-numeric port
        "https://sub..target.com/",          # empty label
        "https://[:::1]/",                    # malformed IPv6
    ])
    def test_ambiguous_blocked(self, sc, url):
        assert sc.is_in_scope(url) is False, url
        assert sc.explain(url)["in_scope"] is False


# --- MALFORMED (must fail closed) ------------------------------------------

class TestMalformedFailClosed:
    @pytest.mark.parametrize("url", [
        "",
        None,
        "   ",
        "://broken",
        "https://",                          # no host
        "/just/a/path",
        "ftp://target.com",                  # disallowed scheme
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://target.com\\@evil.com",     # backslash host trick
        "https://target.com\t.evil.com",     # tab
        "https://target.com\n.evil.com",     # newline
        "https:// target.com",               # space in authority
        "https://exa mple.com",
        "https://tаrget.com",                # cyrillic 'а' homoglyph
        123,                                  # non-string
    ])
    def test_malformed_blocked(self, sc, url):
        assert sc.is_in_scope(url) is False, repr(url)


# --- IP / CIDR -------------------------------------------------------------

class TestIpCidr:
    @pytest.mark.parametrize("url,expected", [
        ("http://10.0.0.1/", True),
        ("https://10.0.0.254/", True),
        ("https://10.0.0.5/", False),        # excluded /32
        ("https://10.0.1.1/", False),        # outside /24
        ("https://192.168.1.5/", True),      # single-IP allow
        ("https://192.168.1.6/", False),
        ("https://[2001:db8::1]/", True),    # inside v6 CIDR
        ("https://[2001:db8::1]:8080/", True),
        ("https://[2001:db9::1]/", False),   # outside v6 CIDR
        ("https://11.0.0.1/", False),
    ])
    def test_membership(self, sc_ip, url, expected):
        assert sc_ip.is_in_scope(url) is expected, url

    def test_domain_url_never_matches_ip_rule(self, sc_ip):
        assert sc_ip.is_in_scope("https://target.com") is False

    def test_ip_url_never_matches_domain_rule(self, sc):
        assert sc.is_in_scope("https://10.0.0.1") is False


# --- PORT / PATH narrowing --------------------------------------------------

class TestPortPathNarrowing:
    def test_port_must_match(self, sc_portpath):
        assert sc_portpath.is_in_scope("https://api.example.com:8443/x") is True
        assert sc_portpath.is_in_scope("https://api.example.com/x") is False        # 443 != 8443
        assert sc_portpath.is_in_scope("https://api.example.com:9000/x") is False

    def test_path_prefix_with_boundary(self, sc_portpath):
        assert sc_portpath.is_in_scope("https://cdn.example.com/assets/app.js") is True
        assert sc_portpath.is_in_scope("https://cdn.example.com/assets") is True     # the dir itself
        assert sc_portpath.is_in_scope("https://cdn.example.com/assetsxyz") is False # boundary
        assert sc_portpath.is_in_scope("https://cdn.example.com/other") is False

    def test_narrowing_never_widens(self, sc_portpath):
        # A host that matches neither host rule is still blocked.
        assert sc_portpath.is_in_scope("https://www.example.com/assets/x") is False


# --- WILDCARD WIDENING config guards ---------------------------------------

class TestWildcardWideningRejected:
    @pytest.mark.parametrize("pattern", [
        "*.com", "*.co.uk", "*.io", "*.net", "*.org",
        "*", "*.*", "*.internal", "https://*.com",
    ])
    def test_dangerous_wildcard_raises(self, pattern):
        with pytest.raises(ScopeError):
            ScopeChecker([pattern])

    @pytest.mark.parametrize("pattern", [
        "*.target.com", "target.com", "api.target.com", "*.internal.target.com",
    ])
    def test_safe_pattern_accepted(self, pattern):
        ScopeChecker([pattern])  # must not raise


# --- explain() attribution --------------------------------------------------

class TestExplainAttribution:
    def test_allowed_names_rule(self, sc):
        v = sc.explain("https://sub.target.com")
        assert v["in_scope"] is True
        assert v["matched_rule"] == "*.target.com"
        assert v["kind"] == "domain"
        assert "sub.target.com" in v["reason"]

    def test_exclusion_names_rule(self, sc):
        v = sc.explain("https://blog.target.com")
        assert v["in_scope"] is False
        assert v["matched_rule"] == "blog.target.com"
        assert "exclusion" in v["reason"].lower()

    def test_out_of_scope_no_rule(self, sc):
        v = sc.explain("https://evil.com")
        assert v["in_scope"] is False
        assert v["matched_rule"] is None

    def test_invalid_kind(self, sc):
        v = sc.explain("https://target.com\\@evil.com")
        assert v["in_scope"] is False
        assert v["kind"] == "invalid"

    def test_ip_rule_named(self, sc_ip):
        v = sc_ip.explain("https://10.0.0.9")
        assert v["in_scope"] is True
        assert v["matched_rule"] == "10.0.0.0/24"
        assert v["kind"] == "ip"


# --- AutopilotGuard integration (below-the-UI enforcement) -----------------

class TestGuardIntegration:
    def _scoped(self, **kw):
        return AutopilotGuard(scope_checker=ScopeChecker(["target.com", "*.target.com"]), **kw)

    def test_in_scope_allowed(self):
        g = self._scoped()
        assert g.check_request("GET", "https://api.target.com/x")["decision"] == "allow"

    def test_lookalike_blocked_with_scope_reason(self):
        g = self._scoped()
        r = g.check_request("GET", "https://evil-target.com/")
        assert r["decision"] == "block"
        assert "scope" in r["reason"].lower()

    def test_backslash_trick_blocked(self):
        g = self._scoped()
        r = g.check_request("GET", "https://target.com\\@evil.com/")
        assert r["decision"] == "block"

    def test_block_result_carries_scope_rule_field(self):
        g = self._scoped()
        r = g.check_request("GET", "https://blog2.example.org/")
        assert r["decision"] == "block"
        assert "scope_rule" in r

    def test_scope_first_even_for_unsafe_method(self):
        g = self._scoped()
        r = g.check_request("DELETE", "https://evil.com/x")
        assert r["decision"] == "block"
        assert "scope" in r["reason"].lower()

    def test_fail_closed_with_no_scope(self):
        g = AutopilotGuard()  # fail_closed default True
        assert g.check_request("GET", "https://anything.com/")["decision"] == "block"


# --- Redirect scope enforcement (our own HTTP client) ----------------------

class TestRedirectScope:
    def test_redirect_to_out_of_scope_public_host_blocked(self):
        sc = ScopeChecker(["target.example", "*.target.example"])
        req = urllib.request.Request("https://target.example/start")
        with patch("tools.safe_http._one_hop") as hop:
            resp = MagicMock()
            resp.status = 302
            resp.headers = {"Location": "https://evil.com/pwn"}
            hop.return_value = resp
            with pytest.raises(urllib.error.URLError) as exc:
                safe_urlopen(req, scope_checker=sc)
            assert "scope" in str(exc.value).lower()

    def test_redirect_to_in_scope_host_followed(self):
        sc = ScopeChecker(["target.example", "*.target.example"])
        req = urllib.request.Request("https://target.example/start")
        final = MagicMock()
        final.status = 200
        with patch("tools.safe_http._one_hop") as hop:
            redirect = MagicMock()
            redirect.status = 302
            redirect.headers = {"Location": "https://api.target.example/final"}
            hop.side_effect = [redirect, final]
            assert safe_urlopen(req, scope_checker=sc) is final

    def test_no_scope_checker_preserves_old_behavior(self):
        req = urllib.request.Request("https://target.example/start")
        final = MagicMock()
        final.status = 200
        with patch("tools.safe_http._one_hop") as hop:
            redirect = MagicMock()
            redirect.status = 302
            redirect.headers = {"Location": "https://somewhere-else.com/final"}
            hop.side_effect = [redirect, final]
            # No scope_checker => only SSRF guard applies; public host followed.
            assert safe_urlopen(req) is final


# --- Unified host parser ----------------------------------------------------

class TestUnifiedHostParser:
    @pytest.mark.parametrize("url,expected", [
        ("https://target.com:8443/x", "target.com:8443"),
        ("https://target.com/x", "target.com"),
        ("https://API.TARGET.COM", "api.target.com"),
        ("https://[2001:db8::1]:80/x", "2001:db8::1:80"),
        ("garbage \\ bad", ""),
        ("", ""),
    ])
    def test_extract_host_port(self, url, expected):
        assert extract_host_port(url) == expected

    def test_guard_uses_same_parser(self):
        assert AutopilotGuard._extract_host("https://target.com:8443/x") == "target.com:8443"
        # Backslash trick yields no usable host (fail closed at parse).
        assert AutopilotGuard._extract_host("https://target.com\\@evil.com") == ""
