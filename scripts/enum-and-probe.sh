#!/usr/bin/env bash
#!/usr/bin/env bash
set -euo pipefail

WILD_FILE="$1"
WORKDIR=$(pwd)
TMPDIR="$WORKDIR/tmp"
mkdir -p "$TMPDIR"

# Helper to log
log(){ echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"; }

# Install go tools (installed into $GOPATH/bin -> $HOME/go/bin)
export PATH="$HOME/go/bin:$PATH"

log "Installing go tools..."
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest || true
go install -v github.com/tomnomnom/anew@latest || true

# Install httpx-pd
log "Installing httpx (ProjectDiscovery) ..."
set +e
# attempt use pip httpx for fallback but prefer PD binary
python3 -m pip install --user 'httpx[cli]' >/dev/null 2>&1 || true
set -e
HOMEBIN="$HOME/.local/bin"
mkdir -p "$HOMEBIN"
export PATH="$HOMEBIN:$PATH"

# Download httpx PD binary
if ! command -v httpx-pd >/dev/null 2>&1; then
  tmpzip="$TMPDIR/httpx_latest.zip"
  URL=$(curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest \
    | grep "browser_download_url.*linux_amd64.zip" | cut -d '"' -f 4)
  if [ -n "$URL" ]; then
    wget -q "$URL" -O "$tmpzip"
    unzip -o "$tmpzip" -d "$TMPDIR"
    chmod +x "$TMPDIR/httpx"
    mv "$TMPDIR/httpx" "$HOMEBIN/httpx-pd"
  fi
fi

# Download findomain
if ! command -v findomain >/dev/null 2>&1; then
  curl -sL https://github.com/findomain/findomain/releases/latest/download/findomain-linux-i386.zip -o "$TMPDIR/findomain.zip"
  unzip -o "$TMPDIR/findomain.zip" -d "$TMPDIR"
  chmod +x "$TMPDIR/findomain"
  sudo mv "$TMPDIR/findomain" /usr/local/bin/findomain || mv "$TMPDIR/findomain" "$HOMEBIN/findomain"
fi

# Ensure subfinder config (provider-config.yaml)
mkdir -p "$HOME/.config/subfinder"
cat > "$HOME/.config/subfinder/provider-config.yaml" <<'EOF'
bevigil:
  - ${BEVIGIL_API_KEY}
bufferover: []
builtwith: []
c99: []
censys: []
certspotter: []
chaos:
  - ${PDCP_API_KEY}
chinaz: []
digitalyama: []
dnsdb: []
dnsdumpster: []
dnsrepo: []
facebook: []
fofa:
  - ${FOFA_API_KEY}
fullhunt: []
github: []
hunter: []
intelx:
  - ${INTELX_API_KEY}
leakix: []
netlas: []
pugrecon: []
quake: []
redhuntlabs: []
robtex: []
rsecloud: []
securitytrails:
  - ${SECURITYTRAILS_API_KEY}
shodan:
  - ${SHODAN_API_KEY}
threatbook: []
virustotal:
  - ${VIRUSTOTAL_API_KEY}
whoisxmlapi: []
zoomeyeapi:
  - ${ZOOMEYE_API_KEY}
EOF

log "Starting enumerations from wildcards: $WILD_FILE"

# run commands for each wildcard (append results)
all_out="$TMPDIR/all_enumeration_merged.txt"
> "$all_out"

while read -r wildcard; do
  wildcard="${wildcard// /}"
  [ -z "$wildcard" ] && continue
  echo "$wildcard" >> "$TMPDIR/input-wildcards.txt"

  log "Running subfinder on $wildcard"
  # -dL can accept a single domain; to use -d we pass domain from wildcard trimming '*.'
  dom="${wildcard#*.}"
  subfinder -d "$dom" -all -silent -recursive -t 200 -o "$TMPDIR/subfinder_${dom}.txt" || true

  log "Running findomain on $dom"
  findomain -t "$dom" -q -o "$TMPDIR/findomain_${dom}.txt" || true

  log "Running assetfinder on $dom"
  assetfinder --subs-only "$dom" 2>/dev/null | tee "$TMPDIR/assetfinder_${dom}.txt" >/dev/null || true

  # chaos client if available (may require PDCP API key)
  if command -v chaos >/dev/null 2>&1; then
    chaos resolve "$dom" -silent 2>/dev/null | tee "$TMPDIR/chaos_${dom}.txt" >/dev/null || true
  fi

done < "$WILD_FILE"

# Merge everything
grep -h . "$TMPDIR"/subfinder_*.txt 2>/dev/null || true
for f in "$TMPDIR"/subfinder_*.txt "$TMPDIR"/findomain_*.txt "$TMPDIR"/assetfinder_*.txt "$TMPDIR"/chaos_*.txt; do
  [ -f "$f" ] && cat "$f" >> "$all_out"
done

# run any other custom enumerator (if you have Subenum/subenum.sh in repo)
if [ -x "./Subenum/subenum.sh" ]; then
  ./Subenum/subenum.sh -l "$WILD_FILE" -u wayback,crt,abuseipdb,Amass -o "$TMPDIR/subenum_out.txt" || true
  [ -f "$TMPDIR/subenum_out.txt" ] && cat "$TMPDIR/subenum_out.txt" >> "$all_out"
fi

# normalize and dedupe
cat "$all_out" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/^www\.//' | sort -u > "$TMPDIR/all_sorted.txt" || true
mv "$TMPDIR/all_sorted.txt" "$all_out"

log "Total enumerated entries: $(wc -l < "$all_out" || true)"

# Save to scope.txt (unique)
cp "$all_out" "$TMPDIR/scope.txt"

# Probe live with httpx-pd (ports specified)
log "Probing live hosts with httpx-pd..."
if [ -f "$HOMEBIN/httpx-pd" ] || command -v httpx-pd >/dev/null 2>&1; then
  cat "$all_out" | httpx-pd -ports 80,443,8080,8000,8888,8443,9443 -threads 200 -silent -o "$TMPDIR/httpx_raw.txt" || true
else
  # fallback to `httpx` if only 'httpx' is available
  cat "$all_out" | httpx -ports 80,443,8080,8000,8888,8443,9443 -threads 200 -silent -o "$TMPDIR/httpx_raw.txt" || true
fi

# httpx returns URLs (scheme://host:port/path). We normalize to host + port and prefer https if both 80 and 443 are open.
# Extract host and port
awk -F/ '{print $1"//"$3}' "$TMPDIR/httpx_raw.txt" | sed 's#^##' > "$TMPDIR/httpx_urls.txt" || true

# Normalize to host and scheme: get scheme and host:port if port present
# We'll prefer https entries when duplicates exist.
declare -A best
while IFS= read -r url; do
  scheme=$(echo "$url" | awk -F:// '{print $1}')
  hostport=$(echo "$url" | awk -F:// '{print $2}')
  # remove path if any (shouldn't happen)
  hostport=${hostport%%/*}
  host=$(echo "$hostport" | sed -E 's/:.*$//')
  port=$(echo "$hostport" | sed -n 's/.*:\([0-9]\+\)$/\1/p' || true)

  key="$host"
  if [[ -z "${best[$key]+x}" ]]; then
    best[$key]="$scheme://$host${port:+:$port}"
  else
    # prefer https
    if [[ "$scheme" == "https" ]]; then
      best[$key]="$scheme://$host${port:+:$port}"
    fi
  fi
done < "$TMPDIR/httpx_urls.txt"

# write final httpx.txt list (one URL per line)
: > "$TMPDIR/httpx.txt"
for k in "${!best[@]}"; do
  echo "${best[$k]}" >> "$TMPDIR/httpx.txt"
done
sort -u "$TMPDIR/httpx.txt" -o "$TMPDIR/httpx.txt"

# create scope.txt (just hostnames)
cut -d/ -f3 "$TMPDIR/httpx.txt" | sed 's/:.*$//' | sort -u > "$TMPDIR/scope.txt"

log "Live hosts: $(wc -l < "$TMPDIR/httpx.txt" || true)"

# compare with repo known_subdomains.txt (store known list in repo root)
KNOWN_FILE="known_subdomains.txt"
if [ ! -f "$KNOWN_FILE" ]; then
  touch "$KNOWN_FILE"
fi

# New entries = those in scope.txt but not in known
comm -23 <(sort "$TMPDIR/scope.txt") <(sort "$KNOWN_FILE") > "$TMPDIR/new_subs.txt" || true

if [ -s "$TMPDIR/new_subs.txt" ]; then
  log "New subdomains found: $(wc -l < "$TMPDIR/new_subs.txt")"
  # append to known file
  cat "$TMPDIR/new_subs.txt" >> "$KNOWN_FILE"
  sort -u "$KNOWN_FILE" -o "$KNOWN_FILE"

  # Commit changes using GITHUB_TOKEN (provided automatically in actions)
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    git config user.email "actions@github.com"
    git config user.name "github-actions[bot]"
    git add "$KNOWN_FILE"
    git commit -m "chore: update known_subdomains (new discoveries)" || true
    git push || true
    echo "committed=true" > "$TMPDIR/commit_flag"
  fi

  # Send each new subdomain to Discord webhook (one message summary)
  if [ -n "${DISCORD_WEBHOOK_SPECTROCLOUD:-}" ]; then
    summary=$(awk '{printf "- %s\n", $0}' "$TMPDIR/new_subs.txt")
    payload="{\"content\":\"New subdomains discovered:\n${summary}\"}"
    curl -s -H "Content-Type: application/json" -d "$payload" "$DISCORD_WEBHOOK_SPECTROCLOUD" || true
  fi

  # Also send archive summary
  if [ -n "${DISCORD_WEBHOOK_ARCHIVE:-}" ]; then
    payload="{\"content\":\"[ARCHIVE] New subdomains discovered: $(wc -l < "$TMPDIR/new_subs.txt")\"}"
    curl -s -H "Content-Type: application/json" -d "$payload" "$DISCORD_WEBHOOK_ARCHIVE" || true
  fi
else
  log "No new subdomains."
fi

# Save outputs for workflow artifact
cp "$TMPDIR/httpx.txt" "$WORKDIR/tmp/httpx.txt"
cp "$TMPDIR/scope.txt" "$WORKDIR/tmp/scope.txt"
cp "$TMPDIR/all_enumeration_merged.txt" "$WORKDIR/tmp/all_enumeration_merged.txt" || true

# set output for workflow
if [ -f "$TMPDIR/commit_flag" ]; then
  echo "::set-output name=committed::true"
else
  echo "::set-output name=committed::false"
fi

log "Enumeration step finished."

