#!/bin/bash
# =============================================================================
# External Arsenal — detect installed bug-bounty tools and surface install hints
#
# Curated from high-signal repos in the project owner's GitHub stars list.
# Run `./external_arsenal.sh` to see which tools are wired and which are missing.
# Other scripts source this file via `_have <tool>` to gate optional code paths.
#
# Usage:
#   ./tools/external_arsenal.sh                # status table
#   ./tools/external_arsenal.sh --install-hint <tool>
#   . ./tools/external_arsenal.sh && _have nuclei && nuclei ...
# =============================================================================

set -uo pipefail

export PATH="$HOME/go/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

# tool|category|install-hint|upstream-url
#
# SUPPLY-CHAIN RULE — read before adding or editing a hint.
# A `pip/pipx install <name>` hint is only valid when <name> is a PyPI package
# published BY the upstream project. Several tools here have no PyPI presence at
# all; pointing `pip install` at their unclaimed names hands code execution to
# whoever registers the name first. Verified 2026-09-19: graphw00f and gqlmap
# were already sitting on PyPI as third-party placeholder stubs, and `knockpy`
# on PyPI is an unrelated statistics package, not the subdomain scanner.
# So: prefer `pipx install git+<upstream>` (works when the repo ships
# setup.py/pyproject.toml), else `git clone`. Never guess a PyPI name.
ARSENAL_TOOLS=(
  # ── Recon / discovery ───────────────────────────────────────────────────
  "subfinder|recon|GOBIN=\$HOME/go/bin go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest|github.com/projectdiscovery/subfinder"
  "amass|recon|GOBIN=\$HOME/go/bin go install github.com/owasp-amass/amass/v4/...@master|github.com/owasp-amass/amass"
  "assetfinder|recon|GOBIN=\$HOME/go/bin go install github.com/tomnomnom/assetfinder@latest|github.com/tomnomnom/assetfinder"
  "bbot|recon|pipx install bbot  # needs a Rust toolchain: brew install rust|github.com/blacklanternsecurity/bbot"
  "theHarvester|recon|brew install theharvester|github.com/laramies/theHarvester"
  "dnsrecon|recon|pipx install dnsrecon  # NB: PyPI 'dnsrecon' is cr0hn's repackage, not darkoperator upstream|github.com/darkoperator/dnsrecon"
  "massdns|recon|brew install massdns|github.com/blechschmidt/massdns"
  "puredns|recon|GOBIN=\$HOME/go/bin go install github.com/d3mondev/puredns/v2@latest|github.com/d3mondev/puredns"
  "shuffledns|recon|GOBIN=\$HOME/go/bin go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest|github.com/projectdiscovery/shuffledns"
  "knockpy|recon|pipx install knock-subdomains  # NOT 'knockpy' — that PyPI name is an unrelated stats package|github.com/guelfoweb/knockpy"
  # ── Live host probing ───────────────────────────────────────────────────
  "httpx|probe|GOBIN=\$HOME/go/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest|github.com/projectdiscovery/httpx"
  "dnsx|probe|GOBIN=\$HOME/go/bin go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest|github.com/projectdiscovery/dnsx"
  "naabu|probe|GOBIN=\$HOME/go/bin go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest|github.com/projectdiscovery/naabu"
  "smap|probe|GOBIN=\$HOME/go/bin go install github.com/s0md3v/smap/cmd/smap@latest|github.com/s0md3v/Smap"
  "aquatone|probe|ARCHIVED upstream — use gowitness: GOBIN=\$HOME/go/bin go install github.com/sensepost/gowitness@latest|github.com/michenriksen/aquatone"
  "eyewitness|probe|git clone https://github.com/RedSiege/EyeWitness && cd EyeWitness/Python/setup && ./setup.sh  # no brew formula|github.com/RedSiege/EyeWitness"
  # ── URL / endpoint collection ───────────────────────────────────────────
  "katana|crawl|GOBIN=\$HOME/go/bin go install github.com/projectdiscovery/katana/cmd/katana@latest|github.com/projectdiscovery/katana"
  "gau|crawl|GOBIN=\$HOME/go/bin go install github.com/lc/gau/v2/cmd/gau@latest|github.com/lc/gau"
  "waybackurls|crawl|GOBIN=\$HOME/go/bin go install github.com/tomnomnom/waybackurls@latest|github.com/tomnomnom/waybackurls"
  "waymore|crawl|pipx install waymore|github.com/xnl-h4ck3r/waymore"
  "hakrawler|crawl|GOBIN=\$HOME/go/bin go install github.com/hakluke/hakrawler@latest|github.com/hakluke/hakrawler"
  "gospider|crawl|GOBIN=\$HOME/go/bin go install github.com/jaeles-project/gospider@latest|github.com/jaeles-project/gospider"
  "cariddi|crawl|GOBIN=\$HOME/go/bin go install github.com/edoardottt/cariddi/cmd/cariddi@latest|github.com/edoardottt/cariddi"
  # ── Content / param discovery ───────────────────────────────────────────
  "ffuf|fuzz|GOBIN=\$HOME/go/bin go install github.com/ffuf/ffuf/v2@latest|github.com/ffuf/ffuf"
  "feroxbuster|fuzz|brew install feroxbuster|github.com/epi052/feroxbuster"
  "gobuster|fuzz|GOBIN=\$HOME/go/bin go install github.com/OJ/gobuster/v3@latest|github.com/OJ/gobuster"
  "arjun|param|pipx install arjun|github.com/s0md3v/Arjun"
  "x8|param|cargo install x8  # needs a Rust toolchain: brew install rust|github.com/Sh1Yo/x8"
  # ── Vuln scanning ───────────────────────────────────────────────────────
  "nuclei|scan|GOBIN=\$HOME/go/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest|github.com/projectdiscovery/nuclei"
  "dalfox|xss|GOBIN=\$HOME/go/bin go install github.com/hahwul/dalfox/v2@latest|github.com/hahwul/dalfox"
  "xsstrike|xss|git clone https://github.com/s0md3v/XSStrike  # PyPI 'xsstrike' is a third-party fork, not upstream|github.com/s0md3v/XSStrike"
  "ghauri|sqli|pipx install git+https://github.com/r0oth3x49/ghauri.git  # not on PyPI|github.com/r0oth3x49/ghauri"
  "sqlmap|sqli|brew install sqlmap|github.com/sqlmapproject/sqlmap"
  "fuxploider|upload|git clone https://github.com/almandin/fuxploider|github.com/almandin/fuxploider"
  "log4j-scan|cve|git clone https://github.com/fullhunt/log4j-scan|github.com/fullhunt/log4j-scan"
  "linkfinder|js|git clone https://github.com/GerbenJavado/LinkFinder && cd LinkFinder && pip install -r requirements.txt  # 'linkfinder' is UNCLAIMED on PyPI|github.com/GerbenJavado/LinkFinder"
  # ── Secrets / credential discovery ──────────────────────────────────────
  "trufflehog|secrets|brew install trufflehog|github.com/trufflesecurity/trufflehog"
  "noseyparker|secrets|brew install noseyparker|github.com/praetorian-inc/noseyparker"
  "gitleaks|secrets|brew install gitleaks|github.com/gitleaks/gitleaks"
  "shhgit|secrets|GOBIN=\$HOME/go/bin go install github.com/eth0izzle/shhgit@latest|github.com/eth0izzle/shhgit"
  "git-hound|secrets|GOBIN=\$HOME/go/bin go install github.com/tillson/git-hound@latest|github.com/tillson/git-hound"
  # ── Cloud / S3 ──────────────────────────────────────────────────────────
  "s3scanner|cloud|GOBIN=\$HOME/go/bin go install github.com/sa7mon/s3scanner@latest|github.com/sa7mon/S3Scanner"
  "cloud_enum|cloud|pipx install git+https://github.com/initstring/cloud_enum.git  # 'cloud-enum' is UNCLAIMED on PyPI|github.com/initstring/cloud_enum"
  "cloudfail|cloud|git clone https://github.com/m0rtem/CloudFail|github.com/m0rtem/CloudFail"
  "scout|cloud|pipx install scoutsuite  # package is 'scoutsuite', binary is 'scout'|github.com/nccgroup/ScoutSuite"
  # ── Subdomain takeover ──────────────────────────────────────────────────
  "dnsreaper|takeover|docker run punksecurity/dnsreaper  # or git clone; 'dnsreaper' is UNCLAIMED on PyPI|github.com/punk-security/dnsReaper"
  "subjack|takeover|GOBIN=\$HOME/go/bin go install github.com/haccer/subjack@latest|github.com/haccer/subjack"
  # ── 403 / WAF bypass ────────────────────────────────────────────────────
  "byp4xx|bypass|GOBIN=\$HOME/go/bin go install github.com/lobuhi/byp4xx@latest|github.com/lobuhi/byp4xx"
  "whatwaf|bypass|git clone https://github.com/Ekultek/WhatWaf && cd WhatWaf && pip install -r requirements.txt  # UNCLAIMED on PyPI; git+ build fails|github.com/Ekultek/WhatWaf"
  "unwaf|bypass|GOBIN=\$HOME/go/bin go install github.com/mmarting/unwaf@latest|github.com/mmarting/unwaf"
  # ── Credential attack / password spray ──────────────────────────────────
  "hashcat|cred|brew install hashcat|hashcat.net/hashcat"
  "cewler|cred|pipx install cewler|github.com/roys/cewler"
  "cupp|cred|git clone https://github.com/Mebus/cupp  # PyPI 'cupp' is a third-party fork, not Mebus upstream|github.com/Mebus/cupp"
  "trevorspray|cred|pipx install trevorspray|github.com/blacklanternsecurity/TREVORspray"
  "kerbrute|cred|GOBIN=\$HOME/go/bin go install github.com/ropnop/kerbrute@latest|github.com/ropnop/kerbrute"
  # ── GraphQL ─────────────────────────────────────────────────────────────
  "graphw00f|graphql|git clone https://github.com/dolevf/graphw00f  # PyPI 'graphw00f' is a third-party placeholder, NOT the tool|github.com/dolevf/graphw00f"
  "clairvoyance|graphql|pipx install clairvoyance  # genuine, published by upstream|github.com/nikitastupin/clairvoyance"
  "gqlmap|graphql|git clone https://github.com/swisskyrepo/GraphQLmap  # old hint pointed at a DEAD repo; PyPI 'gqlmap' is a placeholder|github.com/swisskyrepo/GraphQLmap"
  "graphql-cop|graphql|git clone https://github.com/dolevf/graphql-cop && cd graphql-cop && pip install -r requirements.txt  # UNCLAIMED on PyPI|github.com/dolevf/graphql-cop"
  # ── JWT / auth ──────────────────────────────────────────────────────────
  "jwt_tool|jwt|git clone https://github.com/ticarpi/jwt_tool && cd jwt_tool && pip install -r requirements.txt  # 'jwt-tool' is UNCLAIMED on PyPI|github.com/ticarpi/jwt_tool"
  # ── Bug bounty scope tooling ────────────────────────────────────────────
  "bbscope|scope|GOBIN=\$HOME/go/bin go install github.com/sw33tLie/bbscope@latest|github.com/sw33tLie/bbscope"
  # ── Mobile ──────────────────────────────────────────────────────────────
  "mobsf|mobile|pipx install --python python3.11 mobsf  # fails to build on 3.12+|github.com/MobSF/Mobile-Security-Framework-MobSF"
  "apkleaks|mobile|pipx install apkleaks|github.com/dwisiswant0/apkleaks"
  "objection|mobile|pipx install objection|github.com/sensepost/objection"
  "jadx|mobile|brew install jadx|github.com/skylot/jadx"
  # ── Static analysis ─────────────────────────────────────────────────────
  "semgrep|sast|brew install semgrep|github.com/semgrep/semgrep"
  # ── Headless browser (client-side confirmation) ─────────────────────────
  "playwright|browser|pip install playwright && playwright install chromium|github.com/microsoft/playwright-python"
  # ── OSINT ───────────────────────────────────────────────────────────────
  "maigret|osint|pipx install maigret|github.com/soxoj/maigret"
  "pywhat|osint|pipx install pywhat|github.com/bee-san/pyWhat"
  # ── DNS history / origin IP ─────────────────────────────────────────────
  "sublert|recon|git clone https://github.com/yassineaboukir/sublert && cd sublert && pip install -r requirements.txt  # UNCLAIMED on PyPI; git+ build fails|github.com/yassineaboukir/sublert"
  # ── Misc ────────────────────────────────────────────────────────────────
  "gf|filter|GOBIN=\$HOME/go/bin go install github.com/tomnomnom/gf@latest|github.com/tomnomnom/gf"
  "qsreplace|filter|GOBIN=\$HOME/go/bin go install github.com/tomnomnom/qsreplace@latest|github.com/tomnomnom/qsreplace"
  "anew|filter|GOBIN=\$HOME/go/bin go install github.com/tomnomnom/anew@latest|github.com/tomnomnom/anew"
  "interactsh-client|oob|GOBIN=\$HOME/go/bin go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest|github.com/projectdiscovery/interactsh"
  # ── AI Coding Assistants ────────────────────────────────────────────────
  "kimchi|ai|curl -fsSL https://kimchi.dev/install.sh -o kimchi_install.sh && sh kimchi_install.sh|kimchi.dev"
  "freebuff|ai|npm install -g freebuff|freebuff.com"
)

# `_have <tool>` — true when the binary is on PATH. Source this file from other
# scripts to use it; safe under `set -e` because it returns 1 (no exit).
_have() { command -v "$1" >/dev/null 2>&1; }
export -f _have 2>/dev/null || true

_print_status() {
  local installed=0 missing=0 total=${#ARSENAL_TOOLS[@]}
  printf "\n%-18s %-10s %-8s %s\n" "TOOL" "CATEGORY" "STATUS" "UPSTREAM"
  printf "%-18s %-10s %-8s %s\n" "----" "--------" "------" "--------"
  local sorted
  sorted=$(printf '%s\n' "${ARSENAL_TOOLS[@]}" | sort -t'|' -k2,2 -k1,1)
  while IFS='|' read -r name cat hint url; do
    if _have "$name"; then
      printf "\033[0;32m%-18s\033[0m %-10s \033[0;32m%-8s\033[0m %s\n" "$name" "$cat" "OK" "$url"
      installed=$((installed + 1))
    else
      printf "\033[0;31m%-18s\033[0m %-10s \033[0;31m%-8s\033[0m %s\n" "$name" "$cat" "MISSING" "$url"
      missing=$((missing + 1))
    fi
  done <<< "$sorted"
  printf "\nInstalled: %d / %d   Missing: %d\n" "$installed" "$total" "$missing"
  printf "Run \`%s --install-hint <tool>\` to see how to install one.\n" "$0"
}

_install_hint() {
  local target="$1"
  for entry in "${ARSENAL_TOOLS[@]}"; do
    IFS='|' read -r name cat hint url <<< "$entry"
    if [ "$name" = "$target" ]; then
      printf "Install %s (%s):\n  %s\nUpstream: https://%s\n" "$name" "$cat" "$hint" "$url"
      return 0
    fi
  done
  printf "Unknown tool: %s\n" "$target" >&2
  return 1
}

# Only run main when executed directly, not when sourced.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  # shellcheck source=banner.sh
  . "$(dirname "$0")/banner.sh"
  print_banner "Arsenal · External Tool Registry" "" \
      "Categories|recon · probe · crawl · fuzz · vuln · etc." \
      "Status|green = installed, red = missing" \
      "Install hint|run with --install-hint <tool>"
  case "${1:-}" in
    --install-hint) shift; _install_hint "${1:?tool name required}" ;;
    --have) shift; _have "${1:?tool name required}" && echo yes || { echo no; exit 1; } ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) _print_status ;;
  esac
fi
