#!/usr/bin/env bash
# Scripted playthrough for the MIJHAR terminal demo.
# Drives the interactive menu: Supported Platforms -> Start Assessment ->
# macOS -> CIS framework -> run -> exit.
set -euo pipefail
cd "$(dirname "$0")"

# Use a throwaway data directory so the recording never touches real scan data.
export MIJHAR_HOME="/tmp/mijhar-demo-gif/mijhar"
rm -rf "$MIJHAR_HOME"

BIN=".venv/bin/mijhar"
[ -x "$BIN" ] || BIN="mijhar"

inputs=(
  "2"    # Supported Platforms & Scan Types
  "1"    # Start Security Assessment
  "1"    # macOS (local)
  "cis"  # assess CIS only
  "y"    # confirm scan
  "8"    # exit
)

for c in "${inputs[@]}"; do
  # Give the scan time to finish (and its results time on screen) before exiting.
  if [ "$c" = "8" ]; then
    sleep 8
  else
    sleep 1.6
  fi
  printf '%s\n' "$c"
done | env -u NO_COLOR "$BIN"
