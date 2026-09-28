"""Guard against commands in the docs that cannot be run.

Documentation here is full of copy-paste shell snippets — a user who hits a
missing-tool message is expected to paste one straight into a terminal. When
the referenced script sits somewhere other than the path shown, the snippet
fails with "No such file or directory" at exactly the moment the user needs
help.

The repo layout is split: `install_tools.sh` lives at the root while most
tooling lives under `bughunter/tools/`, and the docs shorten that to `tools/`
as a convention. These tests check the *invocable command* — a `bash foo.sh`
or `./foo.sh` line must resolve to a real file under the documented prefix
convention or at the repo root.

Runtime-created directories (e.g. `bughunter/memory/leads/`, which
lead_board.py creates on first ingest) are deliberately not covered: a missing
directory there is correct, not a bug.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

DOCS = [
    "AGENTS.md", "CLAUDE.md", "README.md", "OPENCODE.md", "FAQ.md", "ADOPTERS.md",
    *sorted(str(p.relative_to(REPO)) for p in (REPO / "commands").glob("*.md")),
]

# `bash foo.sh`, `./foo.sh`, `sh foo.sh`, with optional leading path.
CMD = re.compile(r'(?:^|[`$\s(])(?:ba)?sh\s+(?P<p>[A-Za-z0-9_./-]+\.(?:sh|py))(?P<flags>\s+-{1,2}[A-Za-z-]+)*')
BARE = re.compile(r'(?:^|[`$\s(])\./(?P<p>[A-Za-z0-9_./-]+\.(?:sh|py))')

# Path prefixes the docs use, and the on-disk locations they may map to.
PREFIX_ROOTS = [Path(""), Path("bughunter")]


def _code_lines(path: Path):
    """Yield (lineno, text) for lines inside fenced blocks and inline code."""
    for i, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
        yield i, line


def _resolves(rel: str) -> bool:
    """Does this documented script path exist under the prefix convention?"""
    rel = rel.lstrip("./")
    # Absolute path already produced by a script at runtime (e.g. the
    # _dep_hint fix) — trust it only if it is inside this repo.
    if rel.startswith("/"):
        try:
            rel = str(Path(rel).relative_to(REPO))
        except ValueError:
            return True  # outside the repo, not our problem to assert
    for root in PREFIX_ROOTS:
        if (REPO / root / rel).is_file():
            return True
    return False


@pytest.mark.parametrize("doc", DOCS, ids=lambda d: Path(d).name)
def test_documented_shell_commands_resolve(doc: str):
    path = REPO / doc
    if not path.is_file():
        pytest.skip(f"{doc} not present")

    broken: list[str] = []
    for lineno, line in _code_lines(path):
        for pat in (CMD, BARE):
            for m in pat.finditer(line):
                rel = m.group("p")
                if not _resolves(rel):
                    broken.append(f"{doc}:{lineno}: {line.strip()}")

    assert not broken, "documented command points at a non-existent script:\n" + "\n".join(broken)


def test_install_tools_is_reachable_from_every_command_doc():
    """`install_tools.sh` is at the root, not under tools/.

    Regression: commands/recon.md and commands/hunt.md both told users to run
    `bash tools/install_tools.sh`, which does not exist. The docs shorten
    `bughunter/tools/` to `tools/`, but this script was never in that tree.
    """
    assert (REPO / "install_tools.sh").is_file()
    assert not (REPO / "tools" / "install_tools.sh").exists()

    offenders = []
    for path in sorted((REPO / "commands").glob("*.md")):
        for lineno, line in _code_lines(path):
            if re.search(r'(?:ba)?sh\s+tools/install_tools\.sh', line):
                offenders.append(f"{path.name}:{lineno}")
    assert not offenders, f"still references the non-existent tools/install_tools.sh: {offenders}"
