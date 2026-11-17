#!/bin/bash
# _auth_helper.sh — compute BB_AUTH_ARGS + BBHUNT_SESSION_ID from BBHUNT_AUTH_HEADERS.
#
# Sourced by scripts/full_hunt.sh (and any other hunt script that needs auth).
# Input:  BBHUNT_AUTH_HEADERS — newline-separated "Name: value" header lines,
#         e.g. "Authorization: Bearer <token>" and/or "Cookie: <cookie>".
# Output: BB_AUTH_ARGS       — array of `-H "Name: value"` pairs, splattable into
#         curl / httpx / nuclei / katana / ffuf (all of them take -H for headers).
#         BBHUNT_SESSION_ID — short stable id for the auth session ("anon" when
#         no headers are set), usable as a label for the run's output.
#
# This file was missing from the installed skill (the upstream repo never
# shipped it), which made full_hunt.sh die at the source line. It is a local
# fix, written to match the contract full_hunt.sh expects. It sends nothing
# anywhere and reads no credential files; it only reformats headers the user
# already passed on the command line.

BB_AUTH_ARGS=()
if [ -n "${BBHUNT_AUTH_HEADERS:-}" ]; then
    while IFS= read -r _bb_line; do
        [ -z "$_bb_line" ] && continue
        BB_AUTH_ARGS+=(-H "$_bb_line")
    done <<< "$BBHUNT_AUTH_HEADERS"
fi

if [ -n "${BBHUNT_AUTH_HEADERS:-}" ]; then
    if command -v sha256sum &>/dev/null; then
        BBHUNT_SESSION_ID="auth-$(printf '%s' "$BBHUNT_AUTH_HEADERS" | sha256sum | cut -c1-12)"
    elif command -v shasum &>/dev/null; then
        BBHUNT_SESSION_ID="auth-$(printf '%s' "$BBHUNT_AUTH_HEADERS" | shasum -a 256 | cut -c1-12)"
    else
        BBHUNT_SESSION_ID="auth-$(date +%s)"
    fi
else
    BBHUNT_SESSION_ID="anon"
fi
unset _bb_line
