"""Regression tests for install.sh's source-path resolution.

The repo layout is mixed: skills/, commands/, rules/, scripts/ and hooks/ sit at
the root, but agents/, tools/ and mcp/ live under bughunter/. install.sh used
root-relative globs, so the `agents/*.md` call matched nothing on any harness.

Bash passes an unmatched glob through as a literal string rather than erroring,
so the copy loop silently skipped it and the script still exited 0 — nine agents
missing with no warning. The same applied to the mcp/ and tools/ references, and
because every source path was cwd-relative, running the script by absolute path
from an unrelated directory copied nothing at all.

These tests drive the real script end to end from an unrelated cwd, and assert
the empty-glob guard now fails loudly instead of reporting success.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "install.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash not available")

# install_opencode honours OPENCODE_CONFIG_DIR, so the real script can target a
# throwaway directory instead of the developer's ~/.config/opencode.
AGENTS_SRC = REPO / ("bughunter/agents" if (REPO / "bughunter/agents").is_dir() else "agents")


def run_install(args, cwd, env=None):
    return subprocess.run(
        [BASH, str(INSTALL), *args],
        cwd=str(cwd),
        env={**os.environ, "BBHUNT_SKIP_DEPS": "1", **(env or {})},
        capture_output=True,
        text=True,
        timeout=180,
    )


def extract_function(name: str) -> str:
    """Pull a single shell function out of install.sh so it can be unit-tested.

    Trailing newline is stripped: callers append a statement, and `}\\n; cmd`
    is a bash syntax error (a lone `;` line).
    """
    text = INSTALL.read_text()
    start = text.index(f"{name}()")
    end = text.index("\n}\n", start) + 3
    return text[start:end].rstrip()


# ── the reported bug: agents went missing silently ──────────────────────────

def test_agents_install_when_run_from_unrelated_cwd(tmp_path):
    """The core regression: agents must land even when cwd != repo root."""
    cfg = tmp_path / "cfg"
    proc = run_install(["--agent", "opencode"], cwd=tmp_path, env={"OPENCODE_CONFIG_DIR": str(cfg)})

    assert proc.returncode == 0, proc.stderr
    expected = sorted(p.name for p in AGENTS_SRC.glob("*.md"))
    assert expected, "no agent .md files found in the source tree"
    installed = sorted(p.name for p in (cfg / "agents").glob("*.md"))
    assert installed == expected, f"agents mismatch: {installed} != {expected}"


def test_skills_and_commands_install_from_unrelated_cwd(tmp_path):
    """Same cwd-independence, for the two directories that always worked."""
    cfg = tmp_path / "cfg"
    proc = run_install(["--agent", "opencode"], cwd=tmp_path, env={"OPENCODE_CONFIG_DIR": str(cfg)})

    assert proc.returncode == 0, proc.stderr
    assert len(list((cfg / "skills").iterdir())) == len(list((REPO / "skills").iterdir()))
    assert len(list((cfg / "commands").glob("*.md"))) == len(list((REPO / "commands").glob("*.md")))


def test_install_is_idempotent(tmp_path):
    """Re-running must not error or duplicate anything."""
    cfg = tmp_path / "cfg"
    env = {"OPENCODE_CONFIG_DIR": str(cfg)}
    first = run_install(["--agent", "opencode"], cwd=tmp_path, env=env)
    second = run_install(["--agent", "opencode"], cwd=tmp_path, env=env)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    expected = sorted(p.name for p in AGENTS_SRC.glob("*.md"))
    assert sorted(p.name for p in (cfg / "agents").glob("*.md")) == expected


# ── the guard that stops this class of bug from hiding again ───────────────

def test_empty_source_dir_fails_loudly(tmp_path):
    """A glob that matches nothing must exit non-zero, not report success.

    Reproduces the original failure mode: a repo whose agents/ directory exists
    but holds no .md files. Before the fix this printed "Done" and exited 0.
    """
    fake = tmp_path / "repo"
    (fake / "bughunter/agents").mkdir(parents=True)
    for name in ("skills", "commands"):
        (fake / name).symlink_to(REPO / name)
    shutil.copy2(INSTALL, fake / INSTALL.name)

    cfg = tmp_path / "cfg"
    proc = subprocess.run(
        [BASH, str(fake / "install.sh"), "--agent", "opencode"],
        cwd=str(tmp_path), env={**os.environ, "OPENCODE_CONFIG_DIR": str(cfg)},
        capture_output=True, text=True, timeout=180,
    )

    assert proc.returncode != 0, f"empty agents/ should fail, got 0:\n{proc.stdout}"
    assert "No agent found" in proc.stderr, proc.stderr


@pytest.mark.parametrize("fn", ["copy_files", "copy_tree_items"])
def test_copy_helpers_warn_on_empty_glob(fn, tmp_path):
    """The helpers themselves must reject a glob that matched zero files."""
    dest = tmp_path / fn
    proc = subprocess.run(
        [BASH, "-c", f'set -euo pipefail\n{extract_function(fn)}\n{fn} "definitely/not/here/*.md" "{dest}" "widget"'],
        cwd=str(tmp_path), capture_output=True, text=True, timeout=30,
    )

    assert proc.returncode != 0, f"{fn} returned 0 for an unmatched glob"
    assert "No widget found" in proc.stderr, proc.stderr


# ── resolve_src: the mixed layout declared in exactly one place ────────────

def test_resolve_src_prefers_first_existing_candidate(tmp_path):
    root = tmp_path / "root"
    nested = root / "bughunter/agents"
    nested.mkdir(parents=True)
    fn = extract_function("resolve_src")

    out = subprocess.run(
        [BASH, "-c", f'set -euo pipefail\n{fn}\nresolve_src "agents" "agents" "bughunter/agents"'],
        cwd=str(root), capture_output=True, text=True, timeout=30,
    )
    assert out.stdout.strip() == "bughunter/agents", out.stdout

    (root / "agents").mkdir()
    out2 = subprocess.run(
        [BASH, "-c", f'set -euo pipefail\n{fn}\nresolve_src "agents" "agents" "bughunter/agents"'],
        cwd=str(root), capture_output=True, text=True, timeout=30,
    )
    assert out2.stdout.strip() == "agents", out2.stdout


def test_resolve_src_falls_back_when_nothing_exists(tmp_path):
    """Nothing found → legacy path echoed on stdout, non-zero status."""
    fn = extract_function("resolve_src")
    out = subprocess.run(
        [BASH, "-c", f'{fn}\nresolve_src "agents" "agents" "bughunter/agents" || true'],
        cwd=str(tmp_path), capture_output=True, text=True, timeout=30,
    )
    assert out.stdout.strip() == "agents", out.stdout


# ── static guards against reintroducing hardcoded root-relative paths ──────

def test_no_bare_root_relative_agents_glob():
    """The literal `agents/*.md` must not come back.

    It only worked by accident on a flat checkout; on this split layout it
    silently installed nothing.
    """
    for line in INSTALL.read_text().splitlines():
        code = line.split(" #", 1)[0]
        if not code.strip() or code.strip().startswith("#"):
            continue
        assert '"agents/*.md"' not in code, f"root-relative agents glob reintroduced: {line.strip()}"


def test_every_resolved_src_is_used():
    """AGENTS_SRC / MCP_SRC must be defined and actually referenced.

    A resolved-but-unused variable is dead code: it looks like the layout is
    handled while nothing consumes it. `tools/` is intentionally absent here —
    install.sh only mentions it in comments.
    """
    text = INSTALL.read_text()
    for var in ("AGENTS_SRC", "MCP_SRC"):
        assert f'{var}="$(resolve_src' in text, f"{var} is never resolved"
        assert text.count(var) >= 2, f"{var} resolved but never used"
    assert "TOOLS_SRC" not in text, "TOOLS_SRC is dead code — install.sh never reads tools/"


def test_script_anchors_to_its_own_directory():
    """The cwd anchor must run at top level, before any copying.

    A substring check alone is not enough: the pre-fix script already contained
    BASH_SOURCE[0] inside install_standalone, so the anchor existed but only
    covered the standalone path. Require the cd itself, and require it to be
    declared before the `--agent` dispatch.
    """
    text = INSTALL.read_text()
    anchor = text.index('cd "$SCRIPT_DIR"') if 'cd "$SCRIPT_DIR"' in text else -1
    assert anchor != -1, "install.sh never cds to its own directory"

    dispatch = text.index('case "$AGENT" in')
    assert anchor < dispatch, "the cwd anchor runs after --agent dispatch, so most paths stay cwd-relative"
