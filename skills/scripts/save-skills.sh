#!/usr/bin/env bash
#
# save-skills.sh — save all skills from the repo root into agent skill
# directories (".agents/skills" plus auto-detected agent/global dirs).
#
# Spec: ./save-all-skills-spec.md
#   - strict validation (frontmatter, name == folder, ecosystem name/desc rules)
#   - per-file, newer-source-wins sync (rsync-style; deletions propagate)
#   - auto-prune of installed skills removed from the repo root
#   - INDEX.md regenerated in every synced target after each run
#   - offline, unattended-safe, plain bash + coreutils only
#
# Usage: scripts/save-skills.sh [--force] [--dry-run] [--help] [skill-name...]

set -u
shopt -s nullglob

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_NAME="scripts/save-skills.sh"
INDEX_NAME="INDEX.md"
PRIMARY="$REPO_ROOT/.agents/skills"

# Project-level extras (only synced if already present).
# Claude Code does NOT read .agents/skills/ at project scope (see spec §6.3).
PROJECT_EXTRAS=(
  "$REPO_ROOT/.claude/skills"
)

# Global agent skill dirs (only synced if already present; never created).
# Confirmed against the vercel-labs/skills CLI supported-agents table and
# official agent docs (spec §6.3).
GLOBAL_TARGETS=(
  "$HOME/.claude/skills"
  "$HOME/.codex/skills"
  "$HOME/.cursor/skills"
  "$HOME/.gemini/skills"
  "$HOME/.codeium/windsurf/skills"     # Windsurf global — NOT ~/.windsurf
  "$HOME/.config/opencode/skills"      # OpenCode global — NOT ~/.opencode
  "$HOME/.agents/skills"               # universal global (Cline/Zed/Warp/Gemini alias)
  "$HOME/.config/agents/skills"        # Amp / Replit / Universal global
)

FORCE=0
DRY_RUN=0
REQUESTED=()

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options] [skill-name...]

Save all skills from the repo root into agent skill directories.

Options:
  --force     recopy every file regardless of mtime
  --dry-run   print the plan (install/update/delete/prune) without writing
  -h, --help  show this help

skill-name...  limit the run to specific skill folder names
EOF
}

for arg in "$@"; do
  case "$arg" in
    --force)   FORCE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "error: unknown option: $arg" >&2; usage >&2; exit 2 ;;
    *)  REQUESTED+=("$arg") ;;
  esac
done

# act CMD... — execute, or just print the plan when --dry-run
act() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '    [dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

line() { # STATUS NAME [DETAIL] — e.g. "[update]  security-arsenal  (2 files refreshed)"
  local pad=$((8 - ${#1})); [ "$pad" -lt 1 ] && pad=1
  printf '[%s]%*s %s%s\n' "$1" "$pad" '' "$2" "${3:+  ($3)}"
}

plural() { # COUNT WORD — "1 file" / "3 files"
  if [ "$1" -eq 1 ]; then printf '%s %s' "$1" "$2"; else printf '%s %ss' "$1" "$2"; fi
}

# ---------------------------------------------------------------- validation

# fm_field FILE KEY — print the value of KEY from the YAML frontmatter.
# Handles plain/quoted scalars and block scalars (> or |, with optional
# chomping/indent indicators); block lines are folded with single spaces.
fm_field() {
  awk -v key="$2" '
    NR == 1 && $0 == "---" { infm = 1; next }
    infm && $0 == "---"    { exit }
    infm && $0 ~ "^"key":" {
      val = $0
      sub("^"key":[[:space:]]*", "", val)
      if (val == "" || val ~ /^[>|][+-]?[0-9]*$/) {
        block = ""
        while ((getline nxt) > 0) {
          if (nxt == "---") break
          if (nxt ~ /^[[:space:]]*$/) { block = block " "; continue }
          if (nxt !~ /^[[:space:]]/) break
          line = nxt; sub(/^[[:space:]]+/, "", line)
          gsub(/[[:space:]]+$/, "", line)
          block = block (block == "" ? "" : " ") line
        }
        sub(/[[:space:]]+$/, "", block)
        print block
        exit
      }
      print val
      exit
    }
  ' "$1"
}

# unquote STRING — trim whitespace, strip one layer of matching ' or " quotes
unquote() {
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  if [ "${#v}" -ge 2 ]; then
    local first="${v:0:1}" last="${v: -1}"
    if [ "$first" = '"' ] && [ "$last" = '"' ]; then
      v="${v:1:${#v}-2}"
      v="${v//\\\"/\"}"   # "esc\"aped" -> "escaped"
      v="${v//\\\\/\\}"   # a\\b -> a\b
    elif [ "$first" = "'" ] && [ "$last" = "'" ]; then
      v="${v:1:${#v}-2}"
      v="${v//\'\'/\'}"   # It''s -> It's (YAML single-quote escape)
    fi
  fi
  printf '%s' "$v"
}

declare -A DESCS=()   # skill name -> full description (valid skills only)

# validate DIR — sets NAME, DESC on success; REASON on failure
validate() {
  local dir="$1" md="$1/SKILL.md" rawname rawdesc folder
  folder="$(basename "$dir")"
  if [ ! -f "$md" ]; then REASON="missing SKILL.md"; return 1; fi
  if [ "$(head -n 1 "$md")" != "---" ]; then REASON="no YAML frontmatter"; return 1; fi
  if ! awk 'NR == 1 && $0 == "---" { infm = 1; next }
           infm && $0 == "---"    { found = 1; exit }
           END { exit !found }' "$md"; then
    REASON="frontmatter not closed (missing second '---')"; return 1
  fi
  rawname="$(fm_field "$md" name)"
  rawdesc="$(fm_field "$md" description)"
  NAME="$(unquote "$rawname")"
  DESC="$(unquote "$rawdesc")"
  if [ -z "$NAME" ]; then REASON="empty 'name'"; return 1; fi
  if [ "$NAME" != "$folder" ]; then
    REASON="'name' ($NAME) does not match folder name ($folder)"; return 1
  fi
  if ! [[ "$NAME" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
    REASON="'name' ($NAME) violates ^[a-z0-9]+(-[a-z0-9]+)*\$"; return 1
  fi
  if [ "${#NAME}" -gt 64 ]; then REASON="'name' longer than 64 chars"; return 1; fi
  if [ -z "$DESC" ]; then REASON="empty 'description'"; return 1; fi
  if [ "${#DESC}" -gt 1024 ]; then
    REASON="'description' longer than 1024 chars (${#DESC})"; return 1
  fi
  return 0
}

# short_desc STRING — first sentence if long enough, capped ~160 chars, pipes escaped
short_desc() {
  local s="$1" sent
  sent="${s%%. *}"
  if [ "${#sent}" -ge 40 ]; then
    case "$sent" in
      *[.!?]) s="$sent" ;;
      *)      s="$sent." ;;
    esac
  fi
  if [ "${#s}" -gt 160 ]; then s="${s:0:157}…"; fi
  printf '%s' "${s//|/\\|}"
}

# -------------------------------------------------------------- file syncing

CHANGED=0
REMOVED=0
DIRS_MADE=0

# sync_files SRC DST — rsync-style per-file sync, newer-source-wins
sync_files() {
  local src="$1" dst="$2" rel srcfile dstfile srcdir reldir dstdir
  CHANGED=0
  REMOVED=0
  DIRS_MADE=0
  # source-side dirs (including empty ones) get mirrored into dst
  while IFS= read -r -d '' srcdir; do
    reldir="${srcdir#"$src"}"
    reldir="${reldir#/}"
    [ -n "$reldir" ] || continue          # skip the skill root itself
    dstdir="$dst/$reldir"
    if [ ! -d "$dstdir" ]; then
      act mkdir -p "$dstdir"
      DIRS_MADE=$((DIRS_MADE + 1))
    fi
  done < <(find "$src" -type d -print0 | sort -z)
  while IFS= read -r -d '' srcfile; do
    rel="${srcfile#"$src"/}"
    dstfile="$dst/$rel"
    if [ "$FORCE" -eq 1 ] || [ ! -e "$dstfile" ] || [ "$srcfile" -nt "$dstfile" ]; then
      act mkdir -p "$(dirname "$dstfile")"
      act cp -p "$srcfile" "$dstfile"
      CHANGED=$((CHANGED + 1))
    fi
  done < <(find "$src" -type f -print0 | sort -z)
  while IFS= read -r -d '' dstfile; do
    rel="${dstfile#"$dst"/}"
    srcfile="$src/$rel"
    if [ ! -e "$srcfile" ]; then
      act rm -f "$dstfile"
      REMOVED=$((REMOVED + 1))
    fi
  done < <(find "$dst" -type f -print0 | sort -z)
  # mirror directory structure (rsync --delete semantics): after the file
  # pass, any dst dir with no src counterpart holds only removed files, so
  # it is empty — remove it deepest-first. Source-side dirs (even empty
  # ones) are never touched. Spec §6.4 step 2.
  while IFS= read -r -d '' dstdir; do
    [ "$dstdir" = "$dst" ] && continue    # never rmdir the skill root
    reldir="${dstdir#"$dst"}"
    reldir="${reldir#/}"
    srcdir="$src/$reldir"
    [ -d "$srcdir" ] || act rmdir "$dstdir" 2>/dev/null || true
  done < <(find "$dst" -type d -print0 | sort -rz)
}

# ----------------------------------------------------------------- discovery

declare -a ALL_DIRS=() CANON=() SYNC_LIST=()
declare -A IS_VALID=() SKIP_REASON=()

for d in "$REPO_ROOT"/*/; do
  [ -f "$d/SKILL.md" ] || continue
  ALL_DIRS+=("$(basename "${d%/}")")
done

if [ "${#ALL_DIRS[@]}" -eq 0 ]; then
  echo "warn: no skill folders found at repo root ($REPO_ROOT)" >&2
fi

for name in "${ALL_DIRS[@]}"; do
  if validate "$REPO_ROOT/$name"; then
    IS_VALID[$name]=1
    DESCS[$name]=$DESC
    CANON+=("$name")
  else
    SKIP_REASON[$name]=$REASON
  fi
done

if [ "${#REQUESTED[@]}" -gt 0 ]; then
  for r in "${REQUESTED[@]}"; do
    if [ ! -d "$REPO_ROOT/$r" ]; then
      echo "error: no skill folder '$r' at repo root" >&2
      exit 2
    fi
    if [ -n "${IS_VALID[$r]:-}" ]; then
      SYNC_LIST+=("$r")
    else
      line skip "$r" "${SKIP_REASON[$r]}"
    fi
  done
else
  SYNC_LIST=("${CANON[@]}")
fi

# Skip warnings for non-requested invalid skills (target-independent; print once).
for name in "${ALL_DIRS[@]}"; do
  if [ -z "${IS_VALID[$name]:-}" ]; then
    if [ "${#REQUESTED[@]}" -eq 0 ]; then
      line skip "$name" "${SKIP_REASON[$name]}"
    else
      case " ${REQUESTED[*]} " in
        *" $name "*) line skip "$name" "${SKIP_REASON[$name]}" ;;
      esac
    fi
  fi
done

if [ "${#SYNC_LIST[@]}" -eq 0 ]; then
  echo "warn: no valid skills to sync" >&2
fi

# ------------------------------------------------------------------- targets

TARGETS=()
TARGET_CREATED_PRIMARY=0
if [ ! -d "$PRIMARY" ]; then
  act mkdir -p "$PRIMARY" || { echo "error: cannot create $PRIMARY" >&2; exit 1; }
  TARGET_CREATED_PRIMARY=1
fi
TARGETS+=("$PRIMARY")

for t in "${PROJECT_EXTRAS[@]}" "${GLOBAL_TARGETS[@]}"; do
  if [ -e "$t" ] && [ ! -d "$t" ]; then
    echo "warn: skipping skill target (exists but is not a directory): $t" >&2
  elif [ -d "$t" ]; then
    TARGETS+=("$t")
  fi
done

# ----------------------------------------------------------------- sync runs

declare -a PRUNED_PRIMARY=()
PRIMARY_STATS=""

for target in "${TARGETS[@]}"; do
  is_primary=0
  [ "$target" = "$PRIMARY" ] && is_primary=1

  updated_total=0
  current_total=0
  install_total=0
  pruned_in_target=()

  for skill in "${SYNC_LIST[@]}"; do
    src="$REPO_ROOT/$skill"
    dst="$target/$skill"
    if [ ! -d "$dst" ]; then
      act cp -pR "$src" "$dst"
      install_total=$((install_total + 1))
      [ "$is_primary" -eq 1 ] && line install "$skill"
    else
      sync_files "$src" "$dst"
      if [ "$CHANGED" -gt 0 ] || [ "$REMOVED" -gt 0 ] || [ "$DIRS_MADE" -gt 0 ]; then
        updated_total=$((updated_total + 1))
        detail=""
        [ "$CHANGED" -gt 0 ] && detail="$(plural "$CHANGED" "file") refreshed"
        [ "$DIRS_MADE" -gt 0 ] && detail="${detail:+$detail, }$(plural "$DIRS_MADE" "dir") added"
        if [ "$REMOVED" -gt 0 ]; then
          [ -n "$detail" ] && detail="$detail, "
          detail="$detail$(plural "$REMOVED" "file") removed"
        fi
        [ "$is_primary" -eq 1 ] && line update "$skill" "$detail"
      else
        current_total=$((current_total + 1))
        [ "$is_primary" -eq 1 ] && line current "$skill"
      fi
    fi
  done

  # prune: installed skill folders with no corresponding folder at repo root
  if [ -d "$target" ]; then
    while IFS= read -r -d '' dir; do
      name="$(basename "$dir")"
      if [ ! -d "$REPO_ROOT/$name" ]; then
        act rm -rf "$dir"
        pruned_in_target+=("$name")
        if [ "$is_primary" -eq 1 ]; then
          line prune "$name" "removed from .agents/skills"
          PRUNED_PRIMARY+=("$name")
        fi
      fi
    done < <(find "$target" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
  fi

  # INDEX.md — always reflects the canonical valid-skill set (never a subset
  # run), so subset runs cannot erase rows. Spec §6.6.
  index_out="$target/$INDEX_NAME"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '    [dry-run] would write %s\n' "$index_out"
  else
    {
      echo "# Installed Skills"
      echo
      echo "_Generated by $SCRIPT_NAME on $(date '+%Y-%m-%dT%H:%M:%S%z') — do not edit by hand._"
      echo
      echo "| Skill | Description |"
      echo "|---|---|"
      while IFS= read -r name; do
        [ -n "$name" ] || continue
        printf '| %s | %s |\n' "$name" "$(short_desc "${DESCS[$name]}")"
      done < <(printf '%s\n' "${CANON[@]}" | LC_ALL=C sort)
      if [ "${#pruned_in_target[@]}" -gt 0 ]; then
        echo
        echo "_Pruned this run: ${pruned_in_target[*]}_"
      fi
    } >"$index_out" || { echo "error: cannot write $index_out" >&2; exit 1; }
  fi

  if [ "$is_primary" -eq 1 ]; then
    stats="$(plural "$install_total" "skill") installed, $(plural "$updated_total" "skill") updated, $(plural "$current_total" "skill") current"
    if [ "$TARGET_CREATED_PRIMARY" -eq 1 ]; then
      stats="$stats (target created)"
    fi
    if [ "${#PRUNED_PRIMARY[@]}" -gt 0 ]; then
      stats="$stats, $(plural "${#PRUNED_PRIMARY[@]}" "skill") pruned"
    fi
    PRIMARY_STATS="$stats"
  else
    disp="${target/#$HOME/~}"
    line target "$disp" "$(plural "$install_total" "skill") installed, $(plural "$updated_total" "skill") updated, $(plural "${#pruned_in_target[@]}" "skill") pruned"
  fi
done

# ------------------------------------------------------------------ summary

disp="${PRIMARY/#$REPO_ROOT\//}"
[ -n "$disp" ] || disp="$PRIMARY"
summary="Targets: $disp ($PRIMARY_STATS)"
for target in "${TARGETS[@]}"; do
  [ "$target" = "$PRIMARY" ] && continue
  summary="$summary, ${target/#$HOME/~}"
done
echo "$summary"

exit 0
