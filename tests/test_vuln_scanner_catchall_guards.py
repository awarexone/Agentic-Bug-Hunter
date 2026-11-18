"""Regression checks for the catch-all / SAML / auth-propagation fixes in
bughunter/tools/vuln_scanner.sh.

Each of the three defects these cover was silent: the scanner emitted or
suppressed findings with nothing in its output to say coverage had changed. A
regression would therefore be invisible in a manual run, which is why they are
pinned here.

Style follows tests/test_vuln_scanner_review_fixes.py — source-level assertions
against the script text, no subprocess, no network.
"""

import re
from pathlib import Path


SCANNER_PATH = Path(__file__).resolve().parents[1] / "bughunter" / "tools" / "vuln_scanner.sh"
AUTH_SPLAT = '${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"}'


def _scanner() -> str:
    return SCANNER_PATH.read_text()


def _joined_lines(text: str) -> list[str]:
    """Logical lines: backslash-continuations collapsed into one entry, so a
    multi-line `curl` reads as a single command."""
    return re.sub(r"\\\n\s*", " ", text).splitlines()


def test_catchall_detection_runs_in_the_current_shell():
    """`head -N file | while read` puts the loop in a subshell, so the
    CATCHALL_HOSTS it builds is discarded on exit and the skip that consumes it
    can never fire. Process substitution keeps the loop in the current shell.
    """
    scanner = _scanner()

    assert 'done < <(head -10 "$ORDERED_SCAN")' in scanner
    assert 'done < <(head -30 "$ORDERED_SCAN")' in scanner

    # Scoped to the two loops that accumulate state across iterations. Other
    # `... | while read` loops in this file (the SQLi and CMS phases) only set
    # per-iteration variables, so their subshells are harmless and must not
    # fail this test.
    assert 'head -10 "$ORDERED_SCAN" | while' not in scanner
    assert 'head -30 "$ORDERED_SCAN" | while' not in scanner


def test_catchall_match_is_comma_anchored():
    """An unanchored `*"$host"*` match is substring, not host equality, so a
    recorded "https://api.t.com:8443" would suppress a probed
    "https://api.t.com" — a host never detected as catch-all. Entries are
    stored ",host," and matched with anchors on both sides.
    """
    scanner = _scanner()

    assert 'CATCHALL_HOSTS="${CATCHALL_HOSTS},${host},"' in scanner
    assert 'case "$CATCHALL_HOSTS" in *",${host},"*) continue ;; esac' in scanner

    assert '[[ "$CATCHALL_HOSTS" == *"$host"* ]]' not in scanner, (
        "unanchored substring match reintroduced; use the comma-anchored case"
    )



def test_saml_endpoint_discovery_has_a_control_probe():
    """A random-path control must be checked before SAML path discovery."""
    scanner = _scanner()

    assert "CONTROL=$(curl" in scanner
    assert '"${host%/}/saml-control-$RANDOM-$$"' in scanner
    control_at = scanner.index("CONTROL=$(curl")
    loop_at = scanner.index("for path in /saml/login")
    assert control_at < loop_at
    assert 'case "$CONTROL" in' in scanner
    assert '[INFORMATIONAL] [SAML-CATCHALL]' in scanner


def test_saml_endpoint_consumers_read_the_url_field():
    """SAML metadata processing must extract the URL, not the label."""
    scanner = _scanner()

    assert 'echo "[INFORMATIONAL] [SAML-ENDPOINT] $url | HTTP $code"' in scanner
    assert 'awk \'{print $3}\' "$SAML_ENDPOINTS_FILE"' in scanner
    assert 'awk \'{print $2}\' "$SAML_ENDPOINTS_FILE"' not in scanner
    assert '[SAML-METADATA-EXPOSED]' in scanner


def test_auth_propagates_to_catchall_and_upload_probes():
    """Authenticated discovery and metadata requests must reuse BB_AUTH_ARGS."""
    joined = _joined_lines(_scanner())

    def command_with(needle):
        matches = [ln for ln in joined if needle in ln]
        assert matches, f"anchor vanished from scanner: {needle!r}"
        return matches[0]

    assert AUTH_SPLAT in command_with('"${host}/non_existent_$(date +%s)"')
    assert AUTH_SPLAT in command_with('"$U")" -eq 200')
    assert AUTH_SPLAT in command_with('"$url" 2>/dev/null || echo 000')
    assert AUTH_SPLAT in command_with('"${host%/}/saml-control-$RANDOM-$$"')
    assert AUTH_SPLAT in command_with("body=$(curl -sk --max-time 8")


def test_deliberately_anonymous_probes_stay_anonymous():
    """Protected-route reachability checks must remain unauthenticated."""
    scanner = _scanner()
    lines = scanner.splitlines()

    matches = [ln for ln in lines if '"$HOST/$path" 2>/dev/null' in ln]
    assert matches, "anonymous protected-route probe is missing"
    assert AUTH_SPLAT not in matches[0]

    # SAML signature-stripping/login-forgery probes must not be present.
    assert 'SAMLResponse=${STRIPPED_SAML}' not in scanner
    assert 'SAML-SIG-STRIP' not in scanner
