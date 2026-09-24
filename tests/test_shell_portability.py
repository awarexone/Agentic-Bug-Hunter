"""Guard against macOS(BSD)/Linux(GNU) shell portability regressions.

These constructs silently misbehave on macOS (BSD userland, bash 3.2):
grep -P, `date +%s%N`, bare `mktemp`, and bash-4 `${var^^}`. They had crept
into the recon/scanner scripts; these checks keep them out and confirm the
portable replacements actually work.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = [
    REPO / "bughunter" / "tools" / "recon_engine.sh",
    REPO / "bughunter" / "tools" / "cicd_scanner.sh",
    REPO / "bughunter" / "tools" / "vuln_scanner.sh",
    REPO / "bughunter" / "tools" / "bypass_403.sh",
    REPO / "scripts" / "full_hunt.sh",
]


def code_lines(path: Path) -> list[str]:
    """Lines with comments/blank stripped, so matches are real commands."""
    out = []
    for ln in path.read_text().splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        out.append(ln.split(" #", 1)[0])
    return out


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_no_grep_perl_flag(path):
    for ln in code_lines(path):
        assert not re.search(r"grep\s+-\S*P", ln), f"grep -P in {path.name}: {ln.strip()}"


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_no_bare_mktemp(path):
    for ln in code_lines(path):
        assert "$(mktemp)" not in ln, f"bare mktemp in {path.name}: {ln.strip()}"


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_no_bash4_upper_expansion(path):
    for ln in code_lines(path):
        assert not re.search(r"\$\{[A-Za-z_][A-Za-z0-9_]*\^\^", ln), f"${{x^^}} in {path.name}: {ln.strip()}"


def test_no_date_nanoseconds_usage_form():
    """The `$(date +%s%N)` usage form must be gone (BSD date has no %N).
    The one remaining `date +%s%N` is inside the guarded _now_ns fallback."""
    txt = (REPO / "bughunter" / "tools" / "vuln_scanner.sh").read_text()
    assert "$(date +%s%N)" not in txt
    assert "_now_ns()" in txt  # the portable helper exists


def test_now_ns_helper_returns_positive_integer():
    script = REPO / "bughunter" / "tools" / "vuln_scanner.sh"
    # source the helper in isolation and call it
    out = subprocess.run(
        ["bash", "-c", f'. "{script}" 2>/dev/null || true; _now_ns'],
        capture_output=True, text=True, timeout=30,
    )
    # _now_ns may run after the script's arg parsing errors; call it directly
    # via a minimal extraction instead if needed.
    val = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else ""
    if not val.isdigit():
        # Fallback: extract and eval just the function.
        text = script.read_text()
        start = text.index("_now_ns()")
        end = text.index("\n}\n", start) + 3
        func = text[start:end]
        out = subprocess.run(["bash", "-c", func + "\n_now_ns"],
                             capture_output=True, text=True, timeout=30)
        val = out.stdout.strip()
    assert val.isdigit() and int(val) > 0, f"_now_ns returned {val!r}"
