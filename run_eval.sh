#!/bin/sh
# Real-model evaluation in Docker. Reads the OpenRouter key from the macOS
# Keychain (service "openrouter") so it never appears in the shell history.
# One-time setup:  security add-generic-password -a "$USER" -s openrouter -w
set -eu
cd "$(dirname "$0")"
MODEL="${MODEL:-anthropic/claude-haiku-5.5}"
OPENROUTER_API_KEY="$(security find-generic-password -a "$USER" -s openrouter -w 2>/dev/null || true)"
if [ -z "$OPENROUTER_API_KEY" ]; then
  echo "No key found in the Keychain (service 'openrouter')." >&2
  echo "Add it with: security add-generic-password -a \"\$USER\" -s openrouter -w" >&2
  exit 1
fi
export OPENROUTER_API_KEY
docker build -q -t crash-triage-agent . >/dev/null
TTY=""; [ -t 1 ] && TTY="-t"   # a real terminal gets the live progress bar
docker run --rm $TTY -e OPENROUTER_API_KEY -v "$PWD/eval:/app/eval" crash-triage-agent \
  sh -lc "triage eval --model $MODEL --security --max-cost-usd ${MAX_COST:-1} && triage report -o eval/report.md"
