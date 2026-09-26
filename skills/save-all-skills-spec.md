# Spec: Save All Skills (`/save all skill`)

**Status:** Draft — no code changes yet
**Date:** 2026-09-26
**Repo:** `Awarexone/Agentic-Bug-Hunter` (skills collection)

---

## 1. Summary

Implement a reusable, dependency-free bash script (`scripts/save-skills.sh`) that **saves all skills** from this repo into the skill directories that AI agents read from:

- **Primary target:** `.agents/skills/` inside this project (the location the Freebuff/Codebuff `skill` tool loads from, and the convention used by the `npx skills` ecosystem).
- **Secondary targets (auto-detect):** any other agent skill directories that already exist on the machine (e.g. `~/.claude/skills`, Codex, Cursor, Gemini, Windsurf, opencode) — synced only if present.

The script is **add-or-update**: it copies skill folders from the repo root, updates installed files whose source is newer, prunes installed skills deleted from the repo, validates skills strictly, and regenerates an `INDEX.md` in each target after every run. The result is committed to git so fresh clones come pre-installed.

---

## 2. Background & Current State

- This repo currently contains **only skills** — 15 top-level folders, each with a `SKILL.md` (two have extra files). Git history shows it was originally a full toolkit (tools/, commands/, README.md) that has since been reduced to the skills collection; the parent "Agentic-Bug-Hunter" toolkit repo holds the companion `tools/` and `commands/` trees.
- Skills **reference companion files that do not exist in this repo** (e.g. `argus/SKILL.md` → `tools/cors_scanner.py`, `../../commands/takeover.md`; `bug-bounty/SKILL.md` → `skills/report-writing`). These are intentional links into the parent toolkit.
- `.agents/` exists but is **untracked** and contains only `types/` (TypeScript type definitions for agent definitions — not skills).
- `AGENTS.md` is a stub template with no real project knowledge.
- Today the skills are **not loadable** by the agent `skill` tool because they live at the repo root, not in `.agents/skills/`.

### Skill inventory (source of truth: repo root)

| # | Skill | Extra files beyond SKILL.md |
|---|---|---|
| 1 | `argus` | — |
| 2 | `bb-methodology` | — |
| 3 | `bug-bounty` | — |
| 4 | `cicd-security` | — |
| 5 | `client-reverse` | `references/browser-js-signing.md` |
| 6 | `credential-attack` | — |
| 7 | `graphql-audit` | — |
| 8 | `meme-coin-audit` | — |
| 9 | `mobile-pentest` | — |
| 10 | `report-writing` | — |
| 11 | `security-arsenal` | `REFERENCES.md`, `METHODOLOGY_CHEATSHEET.md` |
| 12 | `triage-validation` | — |
| 13 | `web2-recon` | — |
| 14 | `web2-vuln-classes` | — |
| 15 | `web3-audit` | — |

All 15 currently pass the strict validation rules defined below (frontmatter present, `name:` matches folder name, non-empty `description:`).

---

## 3. Goals

1. All 15 skills loadable by agents via the standard `skill` mechanism (`.agents/skills/<name>/SKILL.md`).
2. One-command, re-runnable save: `scripts/save-skills.sh`.
3. New skills dropped at the repo root get saved automatically on the next run.
4. Edits to existing skills propagate to installed copies **per-file, newer-source-wins** (rsync-style).
5. Orphans (skills deleted from the repo root) are auto-pruned from install targets.
6. Clear per-run feedback: console summary + generated `INDEX.md` per target.
7. Installed skills are committed to git so clones and collaborators get them "for free".
8. The convention is documented in `AGENTS.md`.

## 4. Non-Goals

- **No rewriting of skill content.** Internal references to `tools/…` and `../../commands/…` are copied verbatim (they document the parent toolkit; agents should note missing files, not be misled by rewritten links).
- **No publishing** of this repo as an `npx skills add Awarexone/Agentic-Bug-Hunter` source (possible future work; see §12).
- **No packaging into an archive** (no tarball/zip bundle).
- **No network access** of any kind; the script is fully offline.
- No package.json/Node runtime, no Python dependency — plain bash only.

---

## 5. Interview Decisions (recorded)

| Decision | Choice |
|---|---|
| Primary outcome | Install skills locally so agents can load them |
| Destination | `.agents/skills/` (project-local), plus auto-detected other agent dirs |
| Scope | All 15 skills, whole folders (including `argus` and multi-file skills) |
| Copy vs link | **Copy** (never symlinks) |
| Repeatability | Reusable script; run now and any time later |
| Re-run policy | **Newer-source wins** (per-file mtime comparison) |
| Copy granularity | **Per file, rsync-style** — only changed files are recopied; unchanged installed files are left untouched |
| Conflict handling | Newer source file overwrites older installed file; no prompts, no backups |
| Orphans | **Auto-prune** — installed skill folders missing from the repo root are deleted |
| Validation | **Strict** — valid YAML frontmatter, `name` == folder name, non-empty `description`; invalid skills are skipped with a warning, never partially installed |
| Index | **Yes** — `INDEX.md` written to every target dir after each run |
| Other agent targets | **Broad auto-detect** — sync into global agent skill dirs that already exist; exact paths resolved and confirmed (see §6.3) |
| Script location/language | `scripts/save-skills.sh`, plain bash |
| Git handling | **Commit** `.agents/skills/` to the repo |
| Broken internal links | **Leave as-is** |
| Documentation | Update **AGENTS.md** (currently a stub) with the convention |

---

## 6. Detailed Behavior

### 6.1 Skill Discovery

- Scan **top-level directories of the repo root only** (no recursion into unrelated trees).
- A directory is a **skill candidate** iff it contains `SKILL.md` at its first level.
- Excluded from discovery: `.git`, `.agents`, any dot-directory, and any plain files at root (`AGENTS.md`, spec files, etc.).
- Subdirectories *inside* a skill folder are part of the skill and copied recursively (e.g. `client-reverse/references/`).
- Anything at root that is not a directory, or a directory without `SKILL.md`, is ignored (not warned about).

### 6.2 Strict Validation (per skill, before any copy)

A skill is installable only if **all** hold:

1. `SKILL.md` exists in the folder root.
2. `SKILL.md` begins with YAML frontmatter: a `---` line, then key/value lines, closed by a second `---`.
3. Frontmatter contains `name:` whose trimmed value **exactly equals** the directory name.
4. Frontmatter contains `description:` with a non-empty value (single-line or quoted multi-line YAML scalar).

Frontmatter parsing in bash: read only the region between the first two `^---$` lines and match `^name:` / `^description:` with leading/trailing whitespace and surrounding quotes stripped. No full YAML parser required.

Additionally enforce the **ecosystem-standard constraints** (confirmed from OpenCode's Agent Skills spec, the strictest of the consumer agents):

5. `name` matches `^[a-z0-9]+(-[a-z0-9]+)*$` (lowercase alphanumerics, single hyphen separators, no leading/trailing/consecutive hyphens, 1–64 chars).
6. `description` is 1–1024 characters.

All 15 current skills pass both (longest description: `mobile-pentest` at 900 chars). Enforcing these here keeps installs valid for every agent that reads the target directories.

**On failure:** print a warning naming the skill and the violated rule, skip the skill entirely (no partial folder writes), and continue with the remaining skills. Validation failures never abort the whole run and are reported in the summary.

### 6.3 Targets

Paths below are **confirmed** from primary sources: the `vercel-labs/skills` CLI supported-agents table, plus official docs for OpenCode (opencode.ai/docs/skills) and Gemini CLI (geminicli.com/docs/cli/skills).

### Primary target (always)

`<repo-root>/.agents/skills/` — created on first run if missing.

**Key insight:** this single project-level path already serves, at project scope, every agent that reads the shared `.agents/skills/` convention — confirmed for **Codex, Cursor, Gemini CLI, OpenCode, Amp, Replit, Cline, Warp, Zed, GitHub Copilot, Droid, Kilo Code** and others. No per-agent copies are needed for those in project scope. Gemini CLI additionally documents `.agents/skills/` as its *higher-precedence alias* for workspace skills, and OpenCode as an alias alongside `.opencode/skills/`.

### Project-level auto-detect (only if the directory already exists in the repo)

| Path | Serves | Why it's separate |
|---|---|---|
| `<repo-root>/.claude/skills/` | Claude Code (project scope) | Claude Code does **not** read `.agents/skills/` at project scope — it uses `.claude/skills/` |

### Global auto-detect (only if the directory already exists on this machine)

| Path | Agent | Notes |
|---|---|---|
| `~/.claude/skills/` | Claude Code (personal scope) | Also read by OpenCode as a global alias |
| `~/.codex/skills/` | Codex (global) | |
| `~/.cursor/skills/` | Cursor (global) | |
| `~/.gemini/skills/` | Gemini CLI (user scope) | `~/.agents/skills/` is its higher-precedence alias — also checked (see extras) |
| `~/.codeium/windsurf/skills/` | Windsurf (global) | Note: not `~/.windsurf/` |
| `~/.config/opencode/skills/` | OpenCode (global config) | Note: not `~/.opencode/` |

Optional extension rows (same "only if it already exists" rule), lower priority — include in the script's table but they rarely exist:

| Path | Agent |
|---|---|
| `~/.agents/skills/` | Universal global (Cline, Zed, Warp, Gemini CLI alias, Kimi Code, Dexto…) |
| `~/.config/agents/skills/` | Amp / Replit / Universal global |

Rules (unchanged from the interview decisions):

- Auto-detect list is a table inside the script (candidate paths, one per line) so it's easy to extend.
- A global target is synced **only if it already exists**; the script never creates directories under `$HOME`.
- If no secondary targets exist, the run still succeeds with just the primary.
- `INDEX.md` is regenerated in **every** target that received a sync.

### 6.4 Sync Algorithm (per skill, per target)

For each valid skill and each target:

1. If target lacks the skill folder → **install**: copy the whole folder recursively.
2. Else → **update, rsync-style, file by file**:
   - For every file in the source folder (recursive): if the installed counterpart is missing, or the source file's mtime is newer than the installed file's mtime → copy it.
   - **Preserve the source mtime on the copied file** (`touch -r <src> <dst>`) so the comparison remains stable on subsequent runs.
   - Every file that exists in the installed folder but **not** in the source folder is **deleted** (mirrors `rsync --delete` within a skill folder; keeps stale payload/wordlist files from lingering inside a skill).
3. Whole-folder copies use `cp -a` (or `cp -R` + mtime fix-up) so directory structure and mtimes carry over.

mtime comparison must be **portable**: prefer `find -newer` / `[ file1 -nt file2 ]` over raw `stat -c`/`stat -f` (which differ between GNU and BSD). Must work correctly on Linux (this machine); macOS compatibility is desirable but secondary.

### 6.5 Prune (orphans)

After the per-skill pass, for each target:

- Any skill folder in the target that has **no corresponding folder at the repo root** is deleted recursively.
- Pruned skills are listed in the console summary and marked in `INDEX.md` as `pruned` for that run (the *next* run's index won't mention them).

### 6.6 Index Generation

After every run, write `INDEX.md` at the root of **each synced target**:

```
# Installed Skills
_Generated by scripts/save-skills.sh on 2026-09-26T… — do not edit by hand._

| Skill | Description |
|---|---|
| argus | Argus — the all-seeing scanner suite. Six automated scanners … (first sentence) |
| … | … |
```

- Descriptions come from each skill's frontmatter, truncated to the first sentence / ~160 chars.
- Sorted alphabetically.
- `INDEX.md` is regenerated (overwritten) wholesale on each run — it is never diff-merged.

### 6.7 Console Summary (every run)

One line per skill, per target set, e.g.:

```
[install] argus
[update]  security-arsenal  (2 files refreshed, 1 file removed)
[current] report-writing
[skip]    some-skill — invalid frontmatter: 'name' does not match folder name
[prune]   legacy-skill  (removed from .agents/skills)
Targets: .agents/skills (15 skills), ~/.claude/skills (15 skills)
```

- `install` = new, `update` = ≥1 file changed, `current` = no changes, `skip` = validation failure, `prune` = orphan removed.
- Exit code `0` if all valid skills synced; non-zero only if a target is unwritable.

### 6.8 CLI Interface

```
scripts/save-skills.sh            # default: sync all skills to all targets
scripts/save-skills.sh <name>...  # sync only the named skill folders (still validates strictly)
scripts/save-skills.sh --force    # recopy every file regardless of mtime
scripts/save-skills.sh --dry-run  # print the plan (install/update/delete/prune) without writing
scripts/save-skills.sh --help
```

`--dry-run` and `--force` are nice-to-have but strongly recommended; they make the first run and future debugging safe.

### 6.9 Git Handling

- `.agents/skills/` (including generated `INDEX.md`) is **tracked and committed**.
- Run once at the end of implementation so the first commit includes all 15 skills + indexes.
- Secondary user-home targets are never committed (outside the repo).
- `.agents/types/` and `AGENTS.md` are unrelated to this feature and left alone by the script.

---

## 7. Edge Cases (must handle)

1. **Skill folder named like an existing reserved dir** (e.g. a root folder called `types`): still discovered normally if it has a valid `SKILL.md`; no special-casing.
2. **Root folder without `SKILL.md`**: ignored silently.
3. **`SKILL.md` with frontmatter but no `description:`** → strict-skip with warning.
4. **`name:` mismatching folder name** (e.g. renamed folder): strict-skip with warning — never silently install under a different name.
5. **Skill deleted from root but present in target** → auto-pruned (§6.5).
6. **File deleted inside a skill's source** → corresponding installed file deleted (§6.4 step 2).
7. **Same-mtime files** (git checkouts often normalize mtimes): when mtimes are equal, treat installed as current — do **not** recopy (prevents perpetual "update" churn).
8. **Targets that are read-only or missing** → secondary targets silently skipped; primary unwritable → error, non-zero exit.
9. **A global target exists but is the wrong shape** (e.g. a file, not a directory; or a symlink into an unrelated tree) → skip with a warning, never delete or overwrite the odd path itself.
10. **Skill name collisions between targets are impossible by construction** — every target receives the same validated names, so no cross-target dedup logic is needed.
11. **Script run from a different cwd** → must always resolve the repo root relative to the script location (`cd "$(dirname "$0")/.."`), not the caller's cwd.
12. **Spaces/special chars in paths**: all paths quoted; no word-splitting bugs.
13. **Concurrent/interleaved edits**: acceptable to be last-run-wins; no locking required (document this).
14. **INDEX.md accidentally hand-edited** → overwritten on next run (by design; banner text says "do not edit").
15. **Empty repo-root scan** (no valid skills at all): targets are left with only prune + index regeneration; summary explains zero skills found.
16. **Long descriptions / YAML special chars in descriptions** (the 15 skills contain colons, em-dashes, quotes): index table must escape pipes (`|`) so the Markdown table stays valid.

---

## 8. Safety Constraints

- Script touches **only**: repo-root skill folders (read), target skill dirs (write), target `INDEX.md` (write). Never `AGENTS.md`, never `.agents/types/`, never `.git`.
- No network, no external binaries beyond POSIX/coreutils + bash.
- No prompts — fully unattended-safe (matching the "add `-y` flags" project convention for commands).
- Pruning is the only destructive operation; it is confined to skill-named folders inside targets and is listed in the summary.

---

## 9. Documentation Changes (`AGENTS.md`)

Replace the stub `AGENTS.md` with real project knowledge while keeping its role as agent context:

- **Quickstart:** what this repo is (the skills collection for the Agentic-Bug-Hunter bug-bounty toolkit); how to save/install all skills (`scripts/save-skills.sh`); optional flags.
- **Architecture / layout:** repo-root skill folders are the **source of truth**; `.agents/skills/` is a synced, committed artifact; `.agents/types/` holds agent-definition TypeScript types (unrelated); skills may reference `tools/` and `commands/` that live in the **parent Agentic-Bug-Hunter toolkit repo**.
- **Conventions:** to add a skill — create `<name>/SKILL.md` with frontmatter where `name` equals the folder name and `description` is non-empty, then run `scripts/save-skills.sh` and commit; never edit files under `.agents/skills/` directly (edits get clobbered by newer-source wins).
- **Gotchas:** broken-looking internal links (`../../commands/...`, `tools/...`) are intentional references into the parent toolkit, not bugs to fix.

---

## 10. Acceptance Criteria / Test Checklist

- [ ] Fresh run on a clean checkout creates `.agents/skills/` with all 15 skills, byte-for-byte folder contents identical to root (minus nothing).
- [ ] Each installed skill has `SKILL.md` with frontmatter `name` == folder name.
- [ ] `INDEX.md` exists in `.agents/skills/` listing 15 rows, alphabetical, valid Markdown table.
- [ ] Editing one file at root (e.g. `web2-recon/SKILL.md`) and re-running shows `[update] web2-recon (1 file refreshed)`; other skills report `[current]`.
- [ ] Adding a new skill folder + re-running installs it; removing it + re-running prunes it.
- [ ] Deleting a file inside an existing skill + re-running removes the installed copy.
- [ ] A skill with deliberately broken frontmatter (renamed `name`) is `[skip]`-ed with a clear warning and **no** partial install.
- [ ] `--dry-run` makes zero filesystem writes (verify via `find -newer` snapshot before/after).
- [ ] `--force` recopies all files even when mtimes are unchanged.
- [ ] Secondary auto-detect: with `~/.claude/skills/` existing, it is synced; with it absent, nothing outside the project is touched or created. Same for the other confirmed globals (`~/.codex/skills/`, `~/.cursor/skills/`, `~/.gemini/skills/`, `~/.codeium/windsurf/skills/`, `~/.config/opencode/skills/`) and the project-level `.claude/skills/`.
- [ ] A skill violating the ecosystem name regex (e.g. folder `My_Skill`) or a >1024-char description is `[skip]`-ed with a clear warning.
- [ ] Running from a subdirectory (`cd web2-recon && ../scripts/save-skills.sh`) works.
- [ ] `bash -n scripts/save-skills.sh` passes; `shellcheck` clean or documented exceptions.
- [ ] `.agents/skills/` + `INDEX.md` are committed; `.agents/types/` and `AGENTS.md` remain untracked-by-this-feature (status unchanged unless AGENTS.md doc work lands).

---

## 11. Open Questions (resolve during implementation)

1. ~~Exact secondary-target paths~~ — **Resolved.** Confirmed from `vercel-labs/skills` CLI table + official OpenCode and Gemini CLI docs; final table captured in §6.3.
2. **Should `--dry-run` also be the default for the very first run on a machine** (safety), or always write immediately? Default per spec: writes immediately; dry-run is opt-in.
3. Whether future skill *updates* should be announced anywhere beyond the console summary (e.g. a `CHANGELOG` under `.agents/skills/`). Default: no.
4. *(new, minor)* Whether to keep the optional extension rows (`~/.agents/skills/`, `~/.config/agents/skills/`) in the auto-detect table from day one, or add them only if a user reports having one. Default per spec: include them — they cost one `[-d]` check each and are inert if absent.

---

## 12. Future Enhancements (explicitly out of scope now)

- Publish the skills so anyone can install via `npx skills add Awarexone/Agentic-Bug-Hunter` (would need README + layout validation + possibly a top-level `skills` manifest).
- A `/save` slash-command wrapper inside the parent toolkit that invokes this script.
- Content-hash comparison (sha256) instead of mtime for drift detection, if mtime proves unreliable (e.g. git checkouts).
- Per-target include/exclude lists (e.g. skip heavy `security-arsenal` for lightweight agents).

---

## 13. Implementation Sketch (reference only — not code)

```
scripts/save-skills.sh
├── resolve REPO_ROOT from script location
├── parse flags (--force --dry-run --help) + optional skill-name args
├── discover: top-level dirs with SKILL.md  → candidates[]
├── validate each candidate (frontmatter/name/description) → valid[] | skipped[]
├── build targets: $REPO_ROOT/.agents/skills  + auto-detected existing dirs
├── for target in targets:
│     ├── mkdir -p (primary only)
│     ├── for skill in valid:
│     │     ├── absent?      → cp -a  → [install]
│     │     ├── present?    → per-file: newer?/missing? copy (preserve mtime);
│     │     │                 installed-extra files → delete  → update/current
│     │     └── (--force: treat every file as newer)
│     ├── prune: target skill dirs with no root counterpart → rm -rf
│     └── regenerate INDEX.md from valid[] (+ prune note for this run)
└── print summary; exit 0
```
