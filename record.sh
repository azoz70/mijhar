#!/usr/bin/env bash
# Record the MIJHAR demo as a cast file, then convert it to an animated GIF.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v asciinema >/dev/null 2>&1; then
  echo "Install asciinema first: brew install asciinema" >&2
  exit 1
fi

echo "[*] Recording demo.cast ..."
asciinema rec demo.cast -c ./demo.sh --overwrite \
  --window-size 120x40 --idle-time-limit 2

if command -v agg >/dev/null 2>&1; then
  echo "[*] Converting to demo.gif ..."
  agg demo.cast demo.gif --theme asciinema --idle-time-limit 2 --last-frame-duration 2
  echo "[+] Wrote demo.gif — reference it in README.md"
else
  echo "Install agg for GIF conversion: brew install agg" >&2
  exit 1
fi
