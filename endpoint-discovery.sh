#!/usr/bin/env bash
# endpoint-discovery.sh
#
# Finds as many endpoints as possible for a domain you own or are authorised to test.
# Works with plain bash + curl. Uses gau, katana, httpx, ffuf, subfinder if installed.
#
# Usage:
#   ./endpoint-discovery.sh yourdomain.com
#   TARGET=yourdomain.com ./endpoint-discovery.sh
#
# Options (environment variables):
#   TARGET         Domain (or URL) to map
#   OUT_DIR        Output folder (default: ./discovery/<domain>-<timestamp>)
#   SUBS           1 = include subdomains (default: 1)
#   BRUTE          1 = wordlist guessing of paths (default: 1)
#   WORDLIST       Custom wordlist file for path guessing (default: built in list)
#   RATE           Requests per second for active steps (default: 10)
#   MAX_ARCHIVE    Max archived URLs to keep per host (default: 20000)
#   MAX_CHECK      Max URLs to check for liveness (default: 500)
#   RUN_BLACKBOX   1 = run blackbox-scan.sh against every live host found (default: 0)

set -uo pipefail

TARGET="${1:-${TARGET:-}}"
if [[ -z "$TARGET" ]]; then
  echo "Usage: ./endpoint-discovery.sh yourdomain.com"
  exit 1
fi
DOMAIN="$(echo "$TARGET" | sed -E 's#^https?://##; s#/.*$##; s#:.*$##' | tr 'A-Z' 'a-z')"
SUBS="${SUBS:-1}"
BRUTE="${BRUTE:-1}"
RATE="${RATE:-10}"
MAX_ARCHIVE="${MAX_ARCHIVE:-20000}"
MAX_CHECK="${MAX_CHECK:-500}"
RUN_BLACKBOX="${RUN_BLACKBOX:-0}"
UA="${USER_AGENT:-endpoint-discovery/1.0}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-./discovery/${DOMAIN}-${STAMP}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT_DIR"
SLEEP="$(awk -v r="$RATE" 'BEGIN{ if (r<=0) r=10; printf "%.3f", 1/r }')"

if [[ -t 1 ]]; then B=$'\e[34m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[0m'; else B=""; G=""; Y=""; R=""; fi
step() { echo ""; echo "${B}==== $* ====${R}"; }
say()  { echo "  $*"; }
have() { command -v "$1" >/dev/null 2>&1; }
c()    { curl -s -k -L --max-time 20 -A "$UA" "$@"; }

# Keep only URLs on the target domain or its subdomains
in_scope() {
  local d="${DOMAIN//./\\.}"
  grep -Ei "^https?://([a-z0-9-]+\.)*${d}(:[0-9]+)?(/|$|\?)"
}

echo "Endpoint discovery for: $DOMAIN"
echo "Output: $OUT_DIR"
echo "Tools found: $(for t in gau waybackurls katana httpx ffuf subfinder; do have $t && printf '%s ' $t; done)"

# ---------------------------------------------------------------------------
step "1. Subdomains"
# ---------------------------------------------------------------------------
echo "$DOMAIN" > "$OUT_DIR/subdomains.txt"
if [[ "$SUBS" == "1" ]]; then
  say "Certificate transparency logs (crt.sh)..."
  c "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
    | grep -oE '"(name_value|common_name)":"[^"]*"' \
    | cut -d'"' -f4 | sed 's/\\n/\n/g' | sed 's/^\*\.//' \
    | tr 'A-Z' 'a-z' | grep -E "(^|\.)${DOMAIN//./\\.}$" >> "$OUT_DIR/subdomains.txt"
  if have subfinder; then
    say "subfinder..."
    subfinder -d "$DOMAIN" -silent 2>/dev/null >> "$OUT_DIR/subdomains.txt"
  fi
  sort -u "$OUT_DIR/subdomains.txt" -o "$OUT_DIR/subdomains.txt"
fi
say "Subdomains found: $(wc -l < "$OUT_DIR/subdomains.txt")"

# Which hosts actually serve web pages
step "2. Live hosts"
: > "$OUT_DIR/live_hosts.txt"
if have httpx; then
  httpx -l "$OUT_DIR/subdomains.txt" -silent -rl "$RATE" 2>/dev/null > "$OUT_DIR/live_hosts.txt"
else
  while read -r h; do
    for s in https http; do
      code="$(curl -s -k -o /dev/null --max-time 8 -A "$UA" -w '%{http_code}' "$s://$h/")"
      if [[ "$code" != "000" ]]; then echo "$s://$h" >> "$OUT_DIR/live_hosts.txt"; break; fi
    done
    sleep "$SLEEP"
  done < "$OUT_DIR/subdomains.txt"
fi
say "Live hosts: $(wc -l < "$OUT_DIR/live_hosts.txt")"
sed 's/^/    /' "$OUT_DIR/live_hosts.txt" | head -30

# ---------------------------------------------------------------------------
step "3. Archived URLs (passive)"
# ---------------------------------------------------------------------------
: > "$OUT_DIR/archive.txt"
if have gau; then
  say "gau..."
  if [[ "$SUBS" == "1" ]]; then echo "$DOMAIN" | gau --subs 2>/dev/null >> "$OUT_DIR/archive.txt"
  else echo "$DOMAIN" | gau 2>/dev/null >> "$OUT_DIR/archive.txt"; fi
elif have waybackurls; then
  say "waybackurls..."
  echo "$DOMAIN" | waybackurls 2>/dev/null >> "$OUT_DIR/archive.txt"
else
  say "Wayback Machine API (install gau for more sources)..."
  pfx=""; [[ "$SUBS" == "1" ]] && pfx="*."
  c "https://web.archive.org/cdx/search/cdx?url=${pfx}${DOMAIN}/*&fl=original&collapse=urlkey&limit=${MAX_ARCHIVE}" >> "$OUT_DIR/archive.txt"
  say "AlienVault OTX..."
  for page in 1 2 3 4 5; do
    r="$(c "https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/url_list?limit=500&page=${page}")"
    echo "$r" | grep -oE '"url": ?"[^"]*"' | cut -d'"' -f4 >> "$OUT_DIR/archive.txt"
    echo "$r" | grep -q '"has_next": *true' || break
  done
fi
in_scope < "$OUT_DIR/archive.txt" | sort -u | head -n "$MAX_ARCHIVE" > "$OUT_DIR/archive_inscope.txt"
say "Archived URLs (in scope): $(wc -l < "$OUT_DIR/archive_inscope.txt")"

# ---------------------------------------------------------------------------
step "4. Crawl and JavaScript mining (active)"
# ---------------------------------------------------------------------------
: > "$OUT_DIR/crawl.txt"
if have katana; then
  say "katana..."
  katana -list "$OUT_DIR/live_hosts.txt" -jc -d 3 -silent -rl "$RATE" -kf all 2>/dev/null >> "$OUT_DIR/crawl.txt"
else
  say "Built in crawler (install katana for deeper results)..."
  mkdir -p "$OUT_DIR/.pages"
  while read -r base; do
    host="${base#*://}"
    queue=("$base/" "$base/robots.txt" "$base/sitemap.xml")
    declare -A seen=()
    n=0
    while (( ${#queue[@]} > 0 && n < 60 )); do
      u="${queue[0]}"; queue=("${queue[@]:1}")
      [[ -n "${seen[$u]:-}" ]] && continue
      seen[$u]=1; n=$((n+1))
      body="$(c "$u")"
      echo "$u" >> "$OUT_DIR/crawl.txt"
      # href/src/action attributes, sitemap <loc>, robots paths, and quoted paths in JS
      links="$( { echo "$body" | grep -oiE '(href|src|action)=["'"'"'][^"'"'"' >]+' | sed -E 's/^[a-z]+=["'"'"']//I'
                  echo "$body" | grep -oiE '<loc>[^<]+' | sed 's/<loc>//I'
                  echo "$body" | grep -iE '^(dis)?allow:' | awk '{print $2}'
                  echo "$body" | grep -oE '["'"'"'`](/[A-Za-z0-9_./?=&%-]{2,})["'"'"'`]' | tr -d '"'"'"'`'
                  echo "$body" | grep -oE 'https?://[A-Za-z0-9._-]+[A-Za-z0-9_./?=&%:-]*'
                } | sort -u )"
      while IFS= read -r l; do
        [[ -z "$l" || "$l" =~ ^(#|mailto:|tel:|javascript:|data:) ]] && continue
        if [[ "$l" =~ ^// ]]; then l="https:$l"
        elif [[ "$l" =~ ^/ ]]; then l="$base$l"
        elif [[ ! "$l" =~ ^https?:// ]]; then l="$base/${l#./}"; fi
        l="${l%%#*}"
        echo "$l" >> "$OUT_DIR/crawl.txt"
        # only follow same host pages and scripts
        if [[ "$l" == *"://$host"* ]] && [[ ! "$l" =~ \.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|pdf|mp4|webp|zip)(\?|$) ]]; then
          queue+=("$l")
        fi
      done <<< "$links"
      sleep "$SLEEP"
    done
    unset seen
  done < "$OUT_DIR/live_hosts.txt"
  rm -rf "$OUT_DIR/.pages"
fi
in_scope < "$OUT_DIR/crawl.txt" | sort -u > "$OUT_DIR/crawl_inscope.txt"
say "Crawled URLs (in scope): $(wc -l < "$OUT_DIR/crawl_inscope.txt")"

# ---------------------------------------------------------------------------
step "5. Path guessing (active, noisy)"
# ---------------------------------------------------------------------------
: > "$OUT_DIR/brute.txt"
if [[ "$BRUTE" == "1" ]]; then
  WL="${WORDLIST:-}"
  if [[ -z "$WL" ]]; then
    WL="$OUT_DIR/.wordlist"
    cat > "$WL" <<'WORDS'
admin
administrator
admin.php
admin/login.php
login
login.php
logout
register
signup
dashboard
panel
cp
cpanel
manage
manager
console
portal
user
users
account
profile
api
api/v1
api/v2
api/users
rest
graphql
v1
v2
upload
uploads
upload.php
files
file
download
download.php
export
import
backup
backups
bak
old
new
test
tests
testing
dev
staging
beta
demo
tmp
temp
debug
info.php
phpinfo.php
test.php
config
config.php
settings
setup
install
install.php
installer
cron
cron.php
ajax
ajax.php
includes
inc
lib
vendor
src
app
application
core
system
private
internal
secret
hidden
log
logs
report
reports
stats
status
health
metrics
search
search.php
index.php
index.html
home
main
mail
email
webmail
db
database
sql
phpmyadmin
pma
adminer.php
cgi-bin
server-status
wp-admin
wp-login.php
xmlrpc.php
.git/HEAD
.env
.htaccess
composer.json
package.json
swagger
swagger.json
api-docs
docs
documentation
WORDS
  fi
  first_host="$(head -1 "$OUT_DIR/live_hosts.txt")"
  if [[ -z "$first_host" ]]; then
    say "No live hosts, skipping"
  elif have ffuf; then
    while read -r base; do
      say "ffuf on $base ..."
      ffuf -u "$base/FUZZ" -w "$WL" -rate "$RATE" -mc 200,204,301,302,307,401,403,405,500 -ac -s 2>/dev/null \
        | sed "s#^#$base/#" >> "$OUT_DIR/brute.txt"
    done < "$OUT_DIR/live_hosts.txt"
  else
    while read -r base; do
      say "Guessing paths on $base (install ffuf for speed)..."
      junk="$(curl -s -k -o /dev/null --max-time 10 -A "$UA" -w '%{http_code}:%{size_download}' "$base/zz-not-real-$RANDOM")"
      while read -r w; do
        [[ -z "$w" ]] && continue
        r="$(curl -s -k -o /dev/null --max-time 10 -A "$UA" -w '%{http_code}:%{size_download}' "$base/$w")"
        code="${r%%:*}"
        if [[ "$code" =~ ^(200|204|301|302|307|401|403|405|500)$ && "$r" != "$junk" ]]; then
          echo "$base/$w" >> "$OUT_DIR/brute.txt"
        fi
        sleep "$SLEEP"
      done < "$WL"
    done < "$OUT_DIR/live_hosts.txt"
  fi
  rm -f "$OUT_DIR/.wordlist"
else
  say "Skipped (BRUTE=0)"
fi
say "Guessed paths that responded: $(wc -l < "$OUT_DIR/brute.txt")"

# ---------------------------------------------------------------------------
step "6. Merge and check which URLs are live"
# ---------------------------------------------------------------------------
cat "$OUT_DIR/archive_inscope.txt" "$OUT_DIR/crawl_inscope.txt" "$OUT_DIR/brute.txt" \
  | sed -E 's#(https?://[^/]+):(80|443)/#\1/#' | sort -u > "$OUT_DIR/all_urls.txt"
say "Unique URLs: $(wc -l < "$OUT_DIR/all_urls.txt")"

# Check status of the non static URLs (cap to keep it reasonable on a phone)
grep -viE '\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|mp4|webp|mp3)(\?|$)' "$OUT_DIR/all_urls.txt" \
  | head -n "$MAX_CHECK" > "$OUT_DIR/.tocheck"
: > "$OUT_DIR/live_urls.txt"
if have httpx; then
  httpx -l "$OUT_DIR/.tocheck" -silent -sc -cl -rl "$RATE" -nc 2>/dev/null \
    | awk '{gsub(/[\[\]]/,""); print $2, $3, $1}' > "$OUT_DIR/live_urls.txt"
else
  total="$(wc -l < "$OUT_DIR/.tocheck")"; i=0
  while read -r u; do
    i=$((i+1)); (( i % 50 == 0 )) && say "checked $i / $total"
    r="$(curl -s -k -o /dev/null --max-time 10 -A "$UA" -w '%{http_code} %{size_download}' "$u")"
    [[ "${r%% *}" != "000" && "${r%% *}" != "404" ]] && echo "$r $u" >> "$OUT_DIR/live_urls.txt"
    sleep "$SLEEP"
  done < "$OUT_DIR/.tocheck"
fi
rm -f "$OUT_DIR/.tocheck"
grep -vE '^404 ' "$OUT_DIR/live_urls.txt" > "$OUT_DIR/.l" && mv "$OUT_DIR/.l" "$OUT_DIR/live_urls.txt"
say "Live URLs (not 404): $(wc -l < "$OUT_DIR/live_urls.txt")"

# ---------------------------------------------------------------------------
step "7. Interesting endpoints"
# ---------------------------------------------------------------------------
flag() {
  local label="$1"
  local pattern="$2"
  local file="$OUT_DIR/interesting_${label}.txt"
  grep -Ei "$pattern" "$OUT_DIR/live_urls.txt" | sort -u > "$file"
  local n; n="$(wc -l < "$file")"
  if (( n > 0 )); then
    echo "${Y}[$label] $n${R}"
    head -10 "$file" | sed 's/^/    /'
    (( n > 10 )) && echo "    ... see $file"
  else
    rm -f "$file"
  fi
}
flag admin        '/(admin|administrator|dashboard|panel|manage|manager|console|cpanel|phpmyadmin|pma|adminer)'
flag auth         '/(login|logout|signin|signup|register|reset|forgot|password|auth|oauth|sso|token)'
flag api          '/(api|graphql|rest|v[0-9]+/|swagger|openapi|api-docs)'
flag backup_files '\.(bak|old|orig|backup|swp|save|sql|zip|tar|gz|tgz|7z|rar|log|conf|cfg|ini|env|yml|yaml)(\?|$)'
flag php          '\.php(\?|$|/)'
flag upload       '/(upload|uploads|file|files|import|attachment)'
flag dev_test     '/(test|tests|dev|debug|staging|beta|demo|tmp|temp|phpinfo|info\.php)'
flag params       '\?[^ ]+='
flag redirects    '[?&](url|redirect|redirect_uri|next|return|returnurl|goto|dest|destination|continue)='
flag file_params  '[?&](file|path|page|include|template|doc|folder|dir|download)='
flag id_params    '[?&]([a-z_]*id|uid|user|account|order|invoice)=[0-9]'
flag server_errors '^5[0-9][0-9] '
flag forbidden    '^(401|403) '

# Unique parameter names (handy for testing)
grep -oE '[?&][][A-Za-z0-9_-]+=' "$OUT_DIR/all_urls.txt" | tr -d '?&=' | sort | uniq -c | sort -rn > "$OUT_DIR/parameters.txt"
say "Unique parameter names: $(wc -l < "$OUT_DIR/parameters.txt") (see parameters.txt)"

# ---------------------------------------------------------------------------
step "8. Hand off to blackbox-scan.sh"
# ---------------------------------------------------------------------------
if [[ "$RUN_BLACKBOX" == "1" ]]; then
  BBX=""
  for p in "$SCRIPT_DIR/blackbox-scan.sh" "$HOME/blackbox-scan.sh" "./blackbox-scan.sh"; do
    [[ -x "$p" ]] && BBX="$p" && break
  done
  if [[ -z "$BBX" ]]; then
    say "blackbox-scan.sh not found next to this script or in ~"
  else
    while read -r h; do
      say "Running blackbox-scan.sh on $h"
      OUT_DIR="$OUT_DIR/blackbox/$(echo "$h" | sed -E 's#^https?://##; s#[/:]#_#g')" "$BBX" "$h" | grep -E '\[(HIGH|MED)\]|High:'
    done < "$OUT_DIR/live_hosts.txt"
  fi
else
  say "Skipped. Re-run with RUN_BLACKBOX=1 to scan every live host with blackbox-scan.sh"
fi

step "Done"
echo "  ${G}All URLs:${R}        $OUT_DIR/all_urls.txt"
echo "  ${G}Live URLs:${R}       $OUT_DIR/live_urls.txt   (status size url)"
echo "  ${G}Interesting:${R}     $OUT_DIR/interesting_*.txt"
echo "  ${G}Live hosts:${R}      $OUT_DIR/live_hosts.txt"
echo "  ${G}Parameters:${R}      $OUT_DIR/parameters.txt"
