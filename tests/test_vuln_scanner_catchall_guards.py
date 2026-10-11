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
    """Accepting 200/301/302/403 as "SAML endpoint found" with no baseline makes
    every catch-all host report the whole path list. A control probe against a
    random path establishes what the host says about paths that do not exist.
    """
    scanner = _scanner()

    assert "SAML_CONTROL=$(curl" in scanner
    assert '"${host}/saml-control-$RANDOM$$"' in scanner
    # The control probe must be consulted before the path loop runs.
    control_at = scanner.index("SAML_CONTROL=$(curl")
    loop_at = scanner.index('for SAML_PATH in "/saml/login"')
    assert control_at < loop_at, "control probe must precede the SAML path loop"


def test_saml_endpoint_consumers_read_the_url_field():
    """endpoints.txt rows are:

        [INFORMATIONAL] [SAML-ENDPOINT] <url> | HTTP <code>

    so the URL is field 3. Reading field 2 yields the literal tag
    "[SAML-ENDPOINT]", which curl rejects at URL-parse time — the metadata leg
    and the ACS_URL feeding the signature-stripping probe then never reach the
    network, silently.
    """
    scanner = _scanner()

    assert "[INFORMATIONAL] [SAML-ENDPOINT] ${host}${SAML_PATH}" in scanner
    assert scanner.count("awk '{print $3}'") >= 2
    assert "awk '{print $2}'" not in scanner, (
        "field 2 is the [SAML-ENDPOINT] tag, not the URL"
    )


def test_auth_propagates_to_catchall_and_upload_probes():
    """These four ran anonymously while every neighbouring call carried the
    session. Behind a login the upload probes all got 401, found nothing, and
    the run reported no findings — indistinguishable from "no upload surface".
    """
    # These curl calls span line continuations, so compare against a version
    # with backslash-newlines joined — a per-line check cannot see a splat that
    # sits on the preceding physical line.
    joined = _joined_lines(_scanner())

    def command_with(needle: str) -> str:
        matches = [ln for ln in joined if needle in ln]
        assert matches, f"anchor vanished from the scanner: {needle!r}"
        return matches[0]

    # catch-all baseline must use the same session as the probes it baselines
    assert AUTH_SPLAT in command_with('"${host}/non_existent_$(date +%s)"')
    # upload-surface probe loop
    assert AUTH_SPLAT in command_with('"$U")" -eq 200')
    # SAML endpoint discovery
    assert AUTH_SPLAT in command_with('"${host}${SAML_PATH}" 2>/dev/null')
    # SAML control probe
    assert AUTH_SPLAT in command_with('"${host}/saml-control-$RANDOM$$"')
    # SAML metadata retrieval
    assert AUTH_SPLAT in command_with("RESP=$(curl -sk --max-time 8")


def test_deliberately_anonymous_probes_stay_anonymous():
    """Two probes must NOT carry the session, and both look like bugs to anyone
    auditing for missing auth:

    - MFA workflow-skip asks whether a page is reachable *without* auth, so
      supplying the session makes it pass trivially.
    - SAML signature-stripping forges a login; replaying it with a valid
      session returns 200/302 regardless, producing a false CRITICAL on every
      authenticated run.

    This test exists so a future "add the missing auth array" sweep fails here
    instead of silently destroying both checks.
    """
    scanner = _scanner()
    lines = scanner.splitlines()

    def line_with(needle: str) -> str:
        matches = [ln for ln in lines if needle in ln]
        assert matches, f"anchor vanished from the scanner: {needle!r}"
        return matches[0]

    assert AUTH_SPLAT not in line_with('"$HOST/$PROTECTED" 2>/dev/null')
    assert AUTH_SPLAT not in line_with('-d "SAMLResponse=${STRIPPED_SAML}"')
