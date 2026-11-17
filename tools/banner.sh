#!/bin/bash
# banner.sh — print_banner for scripts/full_hunt.sh.
#
# Usage:
#   print_banner "<title>" "<target>" "<label>|<description>" [...]
#
# Prints a boxed header with the title and target, then one line per
# "label|description" pair. This file was missing from the installed skill
# (the upstream repo never shipped it), which made full_hunt.sh die at the
# source line. It is a local fix, written to match the call full_hunt.sh
# makes. It prints only; it sends nothing anywhere and touches no files.

print_banner() {
    local _title="$1"; shift
    local _target="$1"; shift
    local _line="════════════════════════════════════════════════════════════════"
    echo "$_line"
    echo "  $_title"
    echo "  Target: $_target"
    echo "$_line"
    local _item _label _desc
    for _item in "$@"; do
        _label="${_item%%|*}"
        _desc="${_item#*|}"
        printf "  • %-20s %s\n" "$_label" "$_desc"
    done
    echo "$_line"
}
