#!/usr/bin/env bash
# shellcheck shell=bash
# =============================================================================
# _dep_hint.sh — OS-specific install hints for missing external tools.
#
# Sourced by recon_engine.sh (and usable by other scripts). When a scanner is
# not on PATH the pipeline should say exactly how to install it on the host's
# OS instead of a bare "not installed — skipping". Provides:
#
#   dep_install_hint <tool>          # prints indented macOS/Linux commands
#   warn_missing <tool> [what]       # log_warn + the hint (needs log_warn)
#
# Prefers the OS the script is actually running on (via `uname`) but always
# prints both so a hint copied into a ticket is useful anywhere.
# =============================================================================

# Detect once; used to put the host's own OS first.
_DEP_OS="$(uname -s 2>/dev/null || echo unknown)"

dep_install_hint() {
    local tool="$1" mac="" lin="" note=""
    case "$tool" in
        nmap)
            mac="brew install nmap"
            lin="sudo apt install -y nmap    # rpm: sudo dnf install -y nmap" ;;
        ffuf)
            mac="brew install ffuf"
            lin="sudo apt install -y ffuf    # or: GOBIN=\$HOME/go/bin go install github.com/ffuf/ffuf/v2@latest" ;;
        subfinder)
            mac="brew install subfinder"
            lin="GOBIN=\$HOME/go/bin go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
        httpx)
            # Homebrew's `httpx` is the unrelated Python CLI — always use the Go build.
            mac="GOBIN=\$HOME/go/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
            lin="GOBIN=\$HOME/go/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
            note="'brew install httpx' installs a different (Python) tool — use the Go build above" ;;
        nuclei)
            mac="brew install nuclei"
            lin="GOBIN=\$HOME/go/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
        gau)
            mac="GOBIN=\$HOME/go/bin go install github.com/lc/gau/v2/cmd/gau@latest"
            lin="GOBIN=\$HOME/go/bin go install github.com/lc/gau/v2/cmd/gau@latest" ;;
        katana)
            mac="brew install katana"
            lin="GOBIN=\$HOME/go/bin go install github.com/projectdiscovery/katana/cmd/katana@latest" ;;
        amass)
            mac="brew install amass"
            lin="GOBIN=\$HOME/go/bin go install github.com/owasp-amass/amass/v4/...@master" ;;
        *)
            echo "      See: ./tools/external_arsenal.sh --install-hint $tool"
            return ;;
    esac
    # Print the running OS first for copy-paste convenience.
    if [ "$_DEP_OS" = "Linux" ]; then
        echo "      Linux:  $lin"
        echo "      macOS:  $mac"
    else
        echo "      macOS:  $mac"
        echo "      Linux:  $lin"
    fi
    [ -n "$note" ] && echo "      note:   $note"
    return 0
}

# warn_missing <tool> [what-is-skipped]. Relies on log_warn from the caller;
# falls back to a plain prefix if it isn't defined.
warn_missing() {
    local tool="$1" what="${2:-this step}"
    if command -v log_warn >/dev/null 2>&1 || declare -F log_warn >/dev/null 2>&1; then
        log_warn "$tool not installed — skipping $what. Install it:"
    else
        echo "[!] $tool not installed — skipping $what. Install it:" >&2
    fi
    dep_install_hint "$tool"
}
