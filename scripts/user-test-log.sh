#!/bin/sh
# Local user-test log. Nothing is uploaded. Do not put secrets or finding text here.
set -eu
if [ "$#" -ne 2 ]; then
  echo "usage: user-test-log.sh <scenario-id> <completed|failed|abandoned>" >&2
  exit 1
fi
case "$2" in
  completed|failed|abandoned) ;;
  *) echo "outcome must be completed, failed, or abandoned" >&2; exit 1 ;;
esac
DIR="${HOME}/Library/Application Support/bughunter"
mkdir -p "$DIR"
chmod 700 "$DIR"
printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" >> "$DIR/user-test.log"
chmod 600 "$DIR/user-test.log"
echo "Appended to $DIR/user-test.log"
