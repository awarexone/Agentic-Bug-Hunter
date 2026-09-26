# Project knowledge

This file gives Freebuff context about your project: goals, commands, conventions, and gotchas.

This repo is the **skills collection for the Agentic-Bug-Hunter bug-bounty toolkit**: 15
self-contained skill folders (each with a `SKILL.md` + optional reference files) covering
web2/web3/mobile/CI-CD security hunting, methodology, payload arsenal, and report writing.

## Quickstart

- Setup: nothing to install — the repo is pure Markdown plus one bash script.
- Save/install all skills into agent skill directories: `scripts/save-skills.sh`
  - `--force` — recopy every file regardless of mtime
  - `--dry-run` — print the plan without writing anything
  - `[skill-name...]` — limit the run to specific skill folders
- Test: `bash -n scripts/save-skills.sh` (syntax); `scripts/save-skills.sh --dry-run` (plan);
  run twice in a row — the second run must report every skill `[current]` (idempotency).

## Architecture

- Key directories:
  - `*/` (repo root) — the **source of truth**: one folder per skill, each with `SKILL.md`.
  - `.agents/skills/` — a **synced, committed artifact** produced by `scripts/save-skills.sh`
    (primary install target; generated `INDEX.md` lives here).
  - `.agents/types/` — TypeScript type definitions for agent definitions; unrelated to skills.
  - `scripts/save-skills.sh` — the installer (plain bash + coreutils, fully offline).
- Data flow: skill folders at root → strict validation (frontmatter, `name` == folder name,
  non-empty `description`, ecosystem name/description rules) → per-file newer-source-wins
  sync (rsync-style, deletions propagate) → auto-prune of installed skills removed from root
  → `INDEX.md` regenerated in every synced target.
- Install targets: `.agents/skills/` (always; serves Codex, Cursor, Gemini CLI, OpenCode,
  Cline, Warp, Zed, Copilot, … at project scope) + `.claude/skills/` (project, only if it
  exists — Claude Code does not read `.agents/skills/`) + global agent dirs (only if they
  already exist, never created) — full table in `save-all-skills-spec.md` §6.3.

## Conventions

- Adding a skill: create `<name>/SKILL.md` with YAML frontmatter where `name` **exactly
  equals the folder name** (lowercase/hyphens, `^[a-z0-9]+(-[a-z0-9]+)*$`, ≤64 chars) and
  `description` is non-empty (≤1024 chars). Then run `scripts/save-skills.sh` and commit both
  the source folder and the updated `.agents/skills/`.
- Never edit files under `.agents/skills/` directly — newer-source-wins sync clobbers those
  edits. Edit the root folder, then re-run the script.
- `INDEX.md` is generated ("do not edit by hand") and rewritten wholesale on every run.
- Script style: plain bash, `set -u`, `shopt -s nullglob`, POSIX/coreutils only, no network,
  no prompts (safe to run unattended); check with `bash -n` before committing.

## Gotchas

- Broken-looking internal links (`tools/cors_scanner.py`, `../../commands/takeover.md`,
  `skills/report-writing`) are **intentional** references into the parent Agentic-Bug-Hunter
  toolkit repo — do not "fix" them.
- mtime-based sync: files with equal mtimes are treated as current (no recopy churn);
  copies preserve the source mtime (`cp -p`). Editing a file without changing its mtime
  (e.g. `touch` tricks) can make drift invisible until `--force`.
- A skill with invalid frontmatter is `[skip]`-ed with a reason and never partially installed;
  the run still exits 0 for the remaining skills.
- Deleting a skill folder from the root removes it from all install targets on the next run
  (auto-prune) — deletion is intentional and propagated, not an error.
