#!/usr/bin/env bash
#!/usr/bin/env bash
set -euo pipefail

INPUT_HTTPX="$1"
TMPDIR=$(dirname "$INPUT_HTTPX")
log(){ echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"; }

if [ ! -f "$INPUT_HTTPX" ]; then
  log "No httpx input found at $INPUT_HTTPX; exiting."
  exit 0
fi

# ensure nuclei in PATH (go install should have put it in $HOME/go/bin)
export PATH="$HOME/go/bin:$PATH"

log "Updating nuclei templates..."
nuclei -update || true
nuclei -ut || true

# Ensure a templates http folder exists (nuclei stores templates by default in ~/.nuclei-templates or ~/.config/nuclei)
# We'll run using the default templates; the -t option can accept 'templates/http' pattern if present.
# Run the scan; capture verbose output to a file

OUTFILE="$TMPDIR/nuclei_results.txt"
nuclei -t ~/nuclei-templates/http/ -l "$INPUT_HTTPX" -es info -mhe 5 -stats -H "X-Forwarded-For: 127.0.0.1" -H "X-Forwarded-Host: 127.0.0.1" -H "X-Forwarded: 127.0.0.1" -H "Forwarded-For: 127.0.0.1" -o "$OUTFILE" || true

# If that template path doesn't exist or produced no results, run default http templates:
if [ ! -s "$OUTFILE" ]; then
  log "No results or templates missing at ~/nuclei-templates/http/. Falling back to built-in http templates."
  nuclei -t http/ -l "$INPUT_HTTPX" -es info -mhe 5 -stats -H "X-Forwarded-For: 127.0.0.1" -H "X-Forwarded-Host: 127.0.0.1" -H "X-Forwarded: 127.0.0.1" -H "Forwarded-For: 127.0.0.1" -o "$OUTFILE" || true
fi

# Post results to Discord (trim large output)
SUMMARY="$(head -n 300 "$OUTFILE" || true)"
if [ -n "${DISCORD_WEBHOOK_SPECTROCLOUD:-}" ]; then
  if [ -s "$OUTFILE" ]; then
    payload="{\"content\":\"Nuclei scan finished. Results (first lines):\n\`\`\`\n${SUMMARY}\n\`\`\`\"}"
  else
    payload="{\"content\":\"Nuclei scan finished. No findings.\"}"
  fi
  curl -s -H "Content-Type: application/json" -d "$payload" "$DISCORD_WEBHOOK_SPECTROCLOUD" || true
fi

# Archive webhook: minimal summary
if [ -n "${DISCORD_WEBHOOK_ARCHIVE:-}" ]; then
  count=$(grep -c "" "$OUTFILE" || true)
  payload="{\"content\":\"[ARCHIVE] Nuclei scan completed. Output lines: ${count}\"}"
  curl -s -H "Content-Type: application/json" -d "$payload" "$DISCORD_WEBHOOK_ARCHIVE" || true
fi

log "Nuclei job finished. Output at $OUTFILE"

