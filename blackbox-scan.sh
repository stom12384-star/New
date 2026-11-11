#!/usr/bin/env bash
# blackbox-scan.sh
#
# Non-destructive black box security check for a web application.
# Only run this against systems you own or are explicitly authorised to test.
#
# Usage:
#   TARGET_URL="https://staging.example.com" ./blackbox-scan.sh
#   ./blackbox-scan.sh https://staging.example.com
#
# Optional environment variables:
#   TARGET_URL     Base URL to test (or pass as first argument)
#   OUT_DIR        Where reports go (default: ./reports/<host>-<timestamp>)
#   DELAY          Seconds between path probes (default: 0.2)
#   TIMEOUT        Per request timeout in seconds (default: 10)
#   USER_AGENT     User agent string (default: blackbox-scan/1.0)
#   RUN_EXTERNAL   Set to 1 to run nmap/nikto/nuclei/testssl if installed (default: 0)
#   AUTH_HEADER    Optional header for authenticated checks, e.g. "Authorization: Bearer xyz"

set -uo pipefail

TARGET_URL="${1:-${TARGET_URL:-}}"
if [[ -z "$TARGET_URL" ]]; then
  echo "Usage: TARGET_URL=https://your.site ./blackbox-scan.sh   (or pass the URL as an argument)"
  exit 1
fi

TARGET_URL="${TARGET_URL%/}"
if [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
  TARGET_URL="https://$TARGET_URL"
fi

HOST="$(echo "$TARGET_URL" | sed -E 's#^https?://##; s#/.*$##; s#:.*$##')"
SCHEME="$(echo "$TARGET_URL" | sed -E 's#://.*$##')"
DELAY="${DELAY:-0.2}"
TIMEOUT="${TIMEOUT:-10}"
USER_AGENT="${USER_AGENT:-blackbox-scan/1.0}"
RUN_EXTERNAL="${RUN_EXTERNAL:-0}"
AUTH_HEADER="${AUTH_HEADER:-}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-./reports/${HOST}-${STAMP}}"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/report.txt"

# Colours (disabled when not a terminal)
if [[ -t 1 ]]; then
  RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; BLU=$'\e[34m'; RST=$'\e[0m'
else
  RED=""; YEL=""; GRN=""; BLU=""; RST=""
fi

HIGH=0; MED=0; LOW=0; INFO=0

log()     { echo "$*" | tee -a "$REPORT"; }
section() { log ""; log "${BLU}==== $* ====${RST}"; }
high()    { HIGH=$((HIGH+1)); log "${RED}[HIGH]${RST} $*"; }
med()     { MED=$((MED+1));   log "${YEL}[MED] ${RST} $*"; }
low()     { LOW=$((LOW+1));   log "${YEL}[LOW] ${RST} $*"; }
info()    { INFO=$((INFO+1)); log "[INFO] $*"; }
ok()      { log "${GRN}[OK]  ${RST} $*"; }

have() { command -v "$1" >/dev/null 2>&1; }

CURL_BASE=(curl -s -k --max-time "$TIMEOUT" -A "$USER_AGENT")
if [[ -n "$AUTH_HEADER" ]]; then
  CURL_BASE+=(-H "$AUTH_HEADER")
fi

req() { "${CURL_BASE[@]}" "$@"; }

log "Black box scan of: $TARGET_URL"
log "Host: $HOST"
log "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Output: $OUT_DIR"

# ---------------------------------------------------------------------------
section "1. Reachability and DNS"
# ---------------------------------------------------------------------------
if have dig; then
  dig +short A "$HOST"    > "$OUT_DIR/dns_a.txt"
  dig +short AAAA "$HOST" > "$OUT_DIR/dns_aaaa.txt"
  dig +short CNAME "$HOST" > "$OUT_DIR/dns_cname.txt"
  dig +short TXT "$(echo "$HOST" | awk -F. '{print $(NF-1)"."$NF}')" > "$OUT_DIR/dns_txt.txt"
  info "A records: $(tr '\n' ' ' < "$OUT_DIR/dns_a.txt")"
  [[ -s "$OUT_DIR/dns_cname.txt" ]] && info "CNAME: $(tr '\n' ' ' < "$OUT_DIR/dns_cname.txt") (check for dangling CNAME / subdomain takeover)"
  APEX="$(echo "$HOST" | awk -F. '{print $(NF-1)"."$NF}')"
  if ! dig +short TXT "_dmarc.$APEX" | grep -qi "v=DMARC1"; then
    low "No DMARC record found on $APEX"
  fi
  if ! grep -qi "v=spf1" "$OUT_DIR/dns_txt.txt"; then
    low "No SPF record found on $APEX"
  fi
else
  info "dig not installed, skipping DNS checks"
fi

HTTP_CODE="$(req -o /dev/null -w '%{http_code}' "$TARGET_URL/")"
if [[ "$HTTP_CODE" == "000" ]]; then
  high "Target unreachable ($TARGET_URL). Aborting."
  exit 2
fi
ok "Target responded with HTTP $HTTP_CODE"

# ---------------------------------------------------------------------------
section "2. HTTP to HTTPS redirect"
# ---------------------------------------------------------------------------
REDIR="$(req -o /dev/null -w '%{http_code} %{redirect_url}' "http://$HOST/")"
if [[ "$REDIR" =~ ^30[1278]\ https:// ]]; then
  ok "HTTP redirects to HTTPS ($REDIR)"
else
  med "HTTP does not redirect to HTTPS (got: $REDIR)"
fi

# ---------------------------------------------------------------------------
section "3. TLS configuration"
# ---------------------------------------------------------------------------
if [[ "$SCHEME" == "https" ]] && have openssl; then
  CERT="$(echo | openssl s_client -servername "$HOST" -connect "$HOST:443" 2>/dev/null | openssl x509 -noout -subject -issuer -enddate 2>/dev/null)"
  echo "$CERT" > "$OUT_DIR/cert.txt"
  info "Certificate: $(echo "$CERT" | tr '\n' ' | ')"
  END="$(echo "$CERT" | grep notAfter | cut -d= -f2)"
  if [[ -n "$END" ]]; then
    END_TS="$(date -d "$END" +%s 2>/dev/null || date -j -f '%b %d %T %Y %Z' "$END" +%s 2>/dev/null)"
    if [[ -n "$END_TS" ]]; then
      DAYS=$(( (END_TS - $(date +%s)) / 86400 ))
      if (( DAYS < 0 )); then high "Certificate expired"; elif (( DAYS < 21 )); then med "Certificate expires in $DAYS days"; else ok "Certificate valid for $DAYS more days"; fi
    fi
  fi
  for proto in tls1 tls1_1; do
    if echo | openssl s_client -"$proto" -servername "$HOST" -connect "$HOST:443" >/dev/null 2>&1; then
      med "Legacy protocol accepted: $proto"
    else
      ok "Legacy protocol rejected: $proto"
    fi
  done
  if echo | openssl s_client -tls1_3 -servername "$HOST" -connect "$HOST:443" >/dev/null 2>&1; then
    ok "TLS 1.3 supported"
  else
    low "TLS 1.3 not supported"
  fi
else
  info "Skipping TLS checks (not https or openssl missing)"
fi

# ---------------------------------------------------------------------------
section "4. Security headers"
# ---------------------------------------------------------------------------
req -D "$OUT_DIR/headers.txt" -o "$OUT_DIR/index.html" "$TARGET_URL/"
H="$(tr -d '\r' < "$OUT_DIR/headers.txt")"

check_header() {
  local name="$1" sev="$2" note="$3"
  if echo "$H" | grep -qi "^$name:"; then
    ok "$name: $(echo "$H" | grep -i "^$name:" | head -1 | cut -d: -f2- | sed 's/^ //' | cut -c1-120)"
  else
    "$sev" "Missing header $name. $note"
  fi
}
check_header "Strict-Transport-Security" med  "Enables HSTS."
check_header "Content-Security-Policy"   med  "Mitigates XSS and injection."
check_header "X-Content-Type-Options"    low  "Should be nosniff."
check_header "X-Frame-Options"           low  "Or use CSP frame-ancestors to prevent clickjacking."
check_header "Referrer-Policy"           low  "Limits referrer leakage."
check_header "Permissions-Policy"        low  "Restricts browser features."

if echo "$H" | grep -qi "^content-security-policy:.*unsafe-inline"; then low "CSP allows 'unsafe-inline'"; fi
if echo "$H" | grep -qi "^content-security-policy:.*unsafe-eval";   then low "CSP allows 'unsafe-eval'"; fi
HSTS="$(echo "$H" | grep -i '^strict-transport-security:' | head -1)"
if [[ -n "$HSTS" ]]; then
  MAXAGE="$(echo "$HSTS" | grep -oi 'max-age=[0-9]*' | cut -d= -f2)"
  [[ -n "$MAXAGE" && "$MAXAGE" -lt 15552000 ]] && low "HSTS max-age is short ($MAXAGE)"
fi

# Information disclosure headers
for hd in Server X-Powered-By X-AspNet-Version X-AspNetMvc-Version X-Generator X-Drupal-Cache X-Runtime X-Debug-Token; do
  v="$(echo "$H" | grep -i "^$hd:" | head -1 | cut -d: -f2- | sed 's/^ //')"
  if [[ -n "$v" ]]; then
    if [[ "$v" =~ [0-9]+\.[0-9]+ ]]; then low "Version disclosure in $hd: $v"; else info "$hd: $v"; fi
  fi
done

# ---------------------------------------------------------------------------
section "5. Cookies"
# ---------------------------------------------------------------------------
COOKIES="$(echo "$H" | grep -i '^set-cookie:')"
if [[ -z "$COOKIES" ]]; then
  info "No cookies set on landing page"
else
  while IFS= read -r c; do
    name="$(echo "$c" | cut -d: -f2- | sed 's/^ //' | cut -d= -f1)"
    flags=""
    echo "$c" | grep -qi 'secure'   || flags+=" no-Secure"
    echo "$c" | grep -qi 'httponly' || flags+=" no-HttpOnly"
    echo "$c" | grep -qi 'samesite' || flags+=" no-SameSite"
    if [[ -n "$flags" ]]; then low "Cookie '$name' missing flags:$flags"; else ok "Cookie '$name' has Secure, HttpOnly, SameSite"; fi
  done <<< "$COOKIES"
fi

# ---------------------------------------------------------------------------
section "6. HTTP methods"
# ---------------------------------------------------------------------------
ALLOW="$(req -X OPTIONS -D - -o /dev/null "$TARGET_URL/" | tr -d '\r' | grep -i '^allow:' | cut -d: -f2-)"
[[ -n "$ALLOW" ]] && info "OPTIONS Allow:$ALLOW"
TRACE_CODE="$(req -X TRACE -o /dev/null -w '%{http_code}' "$TARGET_URL/")"
if [[ "$TRACE_CODE" == "200" ]]; then med "TRACE method enabled (HTTP 200)"; else ok "TRACE not enabled ($TRACE_CODE)"; fi
for m in PUT DELETE PATCH; do
  code="$(req -X "$m" -o /dev/null -w '%{http_code}' "$TARGET_URL/blackbox-scan-nonexistent-$$")"
  [[ "$code" =~ ^2 ]] && med "$m on a random path returned $code (verify it is not writable)"
done

# ---------------------------------------------------------------------------
section "7. CORS"
# ---------------------------------------------------------------------------
EVIL="https://evil-blackbox-test.example"
CORS="$(req -H "Origin: $EVIL" -D - -o /dev/null "$TARGET_URL/" | tr -d '\r')"
ACAO="$(echo "$CORS" | grep -i '^access-control-allow-origin:' | cut -d: -f2- | sed 's/^ //')"
ACAC="$(echo "$CORS" | grep -i '^access-control-allow-credentials:' | cut -d: -f2- | sed 's/^ //')"
if [[ "$ACAO" == "$EVIL" && "$ACAC" =~ [Tt]rue ]]; then
  high "CORS reflects arbitrary Origin WITH credentials"
elif [[ "$ACAO" == "$EVIL" ]]; then
  med "CORS reflects arbitrary Origin"
elif [[ "$ACAO" == "*" ]]; then
  low "CORS allows any origin (*)"
else
  ok "CORS does not reflect arbitrary origin"
fi
NULLO="$(req -H "Origin: null" -D - -o /dev/null "$TARGET_URL/" | tr -d '\r' | grep -i '^access-control-allow-origin:' | cut -d: -f2- | sed 's/^ //')"
[[ "$NULLO" == "null" ]] && med "CORS trusts the 'null' origin"

# ---------------------------------------------------------------------------
section "8. Sensitive file and path exposure"
# ---------------------------------------------------------------------------
# Baseline for soft 404 detection
RAND="blackbox-$(date +%s)-$RANDOM"
BASE_LEN="$(req -o /dev/null -w '%{size_download}' "$TARGET_URL/$RAND")"
BASE_CODE="$(req -o /dev/null -w '%{http_code}' "$TARGET_URL/$RAND")"
info "Soft 404 baseline: HTTP $BASE_CODE, $BASE_LEN bytes"

# path|severity|content regex that confirms a real hit (optional)
PATHS=(
  ".git/HEAD|high|ref: refs"
  ".git/config|high|\\[core\\]"
  ".svn/entries|high|"
  ".hg/requires|high|"
  ".env|high|[A-Z_]+="
  ".env.local|high|[A-Z_]+="
  ".env.production|high|[A-Z_]+="
  ".env.backup|high|[A-Z_]+="
  "config.json|med|\\{"
  "config.php.bak|high|"
  "wp-config.php.bak|high|DB_"
  ".DS_Store|low|Bud1"
  ".htaccess|med|"
  ".htpasswd|high|:"
  "web.config|med|<configuration"
  "composer.json|low|require"
  "composer.lock|low|packages"
  "package.json|low|dependencies"
  "package-lock.json|low|lockfileVersion"
  "yarn.lock|low|"
  "Dockerfile|low|FROM"
  "docker-compose.yml|med|services"
  "backup.zip|high|"
  "backup.sql|high|"
  "dump.sql|high|"
  "db.sql|high|"
  "database.sql|high|"
  "phpinfo.php|high|phpinfo"
  "info.php|high|phpinfo"
  "server-status|med|Apache"
  "server-info|med|Apache"
  "actuator|med|_links"
  "actuator/env|high|propertySources"
  "actuator/heapdump|high|"
  "debug|low|"
  "_debugbar/open|med|"
  "telescope|med|"
  "horizon|med|"
  "elmah.axd|high|"
  "trace.axd|high|"
  "swagger.json|info|swagger|openapi"
  "swagger-ui.html|info|"
  "openapi.json|info|openapi"
  "api-docs|info|"
  "v2/api-docs|info|"
  "graphql|info|"
  "admin|info|"
  "administrator|info|"
  "wp-admin/|info|"
  "wp-login.php|info|"
  "wp-json/wp/v2/users|med|\"slug\""
  "xmlrpc.php|low|XML-RPC"
  "phpmyadmin/|med|"
  "adminer.php|med|"
  "crossdomain.xml|low|allow-access-from domain=\"\\*\""
  "clientaccesspolicy.xml|low|"
  "robots.txt|info|"
  "sitemap.xml|info|"
  ".well-known/security.txt|info|Contact"
  "security.txt|info|Contact"
  "storage/logs/laravel.log|high|"
  "logs/error.log|high|"
  "error_log|high|"
  "npm-debug.log|med|"
  ".vscode/settings.json|low|"
  ".idea/workspace.xml|low|"
  "id_rsa|high|PRIVATE KEY"
  ".ssh/id_rsa|high|PRIVATE KEY"
  ".aws/credentials|high|aws_access_key_id"
  "main.js.map|low|sources"
  "app.js.map|low|sources"
)

: > "$OUT_DIR/paths.txt"
for entry in "${PATHS[@]}"; do
  IFS='|' read -r path sev pattern <<< "$entry"
  body_file="$OUT_DIR/.probe"
  res="$(req -o "$body_file" -w '%{http_code} %{size_download}' "$TARGET_URL/$path")"
  code="${res%% *}"; size="${res##* }"
  echo "$code $size /$path" >> "$OUT_DIR/paths.txt"

  if [[ "$code" == "200" ]]; then
    # Skip if it looks like the soft 404 page
    if [[ "$BASE_CODE" == "200" && "$size" == "$BASE_LEN" ]]; then
      continue
    fi
    if [[ -n "$pattern" ]]; then
      if grep -Eqi "$pattern" "$body_file" 2>/dev/null; then
        case "$sev" in
          high) high "Exposed: /$path (HTTP 200, $size bytes, content matched)";;
          med)  med  "Exposed: /$path (HTTP 200, $size bytes, content matched)";;
          low)  low  "Exposed: /$path (HTTP 200, $size bytes, content matched)";;
          *)    info "Found: /$path (HTTP 200, $size bytes)";;
        esac
      fi
    else
      case "$sev" in
        high|med) med "Possible exposure: /$path (HTTP 200, $size bytes, verify manually)";;
        *)        info "Found: /$path (HTTP 200, $size bytes)";;
      esac
    fi
  elif [[ "$code" == "401" || "$code" == "403" ]] && [[ "$sev" != "info" ]]; then
    info "/$path exists but is protected (HTTP $code)"
  fi
  sleep "$DELAY"
done
rm -f "$OUT_DIR/.probe"

if [[ -s "$OUT_DIR/index.html" ]]; then
  # robots.txt disallowed paths are often interesting
  req "$TARGET_URL/robots.txt" -o "$OUT_DIR/robots.txt"
  if grep -qi '^disallow' "$OUT_DIR/robots.txt" 2>/dev/null; then
    info "robots.txt Disallow entries: $(grep -i '^disallow' "$OUT_DIR/robots.txt" | awk '{print $2}' | tr '\n' ' ' | cut -c1-300)"
  fi
fi

# ---------------------------------------------------------------------------
section "9. Directory listing and error handling"
# ---------------------------------------------------------------------------
for d in "" "images/" "img/" "uploads/" "static/" "assets/" "files/" "backup/" "js/" "css/"; do
  if req "$TARGET_URL/$d" | grep -qiE '<title>Index of|Directory listing for|\[To Parent Directory\]'; then
    med "Directory listing enabled at /$d"
  fi
  sleep "$DELAY"
done

ERR="$(req "$TARGET_URL/%ff%fe%00'\"<>" ; req "$TARGET_URL/?id='" ; req "$TARGET_URL/index.php?page[]=x")"
if echo "$ERR" | grep -qiE 'stack trace|traceback \(most recent|exception in thread|at [a-z]+\.[a-z]+\(.*\.java:[0-9]+\)|SQLSTATE|mysql_fetch|ORA-[0-9]{5}|pg_query|Warning:.*on line [0-9]+|Fatal error:|Whoops!|DEBUG = True|Microsoft OLE DB'; then
  med "Verbose error / stack trace leaked for malformed input"
else
  ok "No obvious stack traces on malformed input"
fi

# ---------------------------------------------------------------------------
section "10. Reflected input and host header"
# ---------------------------------------------------------------------------
CANARY="bbx$RANDOM\"'<zq>"
ENC="$(printf '%s' "$CANARY" | od -An -tx1 | tr -d ' \n' | sed 's/../%&/g')"
for p in q search s query id page redirect url next return returnUrl; do
  body="$(req "$TARGET_URL/?$p=$ENC")"
  if echo "$body" | grep -qF "$CANARY"; then
    med "Parameter '$p' reflects input unencoded (possible XSS, verify manually)"
  fi
  sleep "$DELAY"
done

# Open redirect
for p in redirect url next return returnUrl redirect_uri continue dest destination goto; do
  loc="$(req -o /dev/null -w '%{redirect_url}' "$TARGET_URL/?$p=https://evil-blackbox-test.example/")"
  if [[ "$loc" == https://evil-blackbox-test.example* ]]; then
    med "Possible open redirect via '$p' parameter"
  fi
  sleep "$DELAY"
done

# Host header injection
HH="$(req -H "Host: evil-blackbox-test.example" "$TARGET_URL/" -D - | tr -d '\r')"
if echo "$HH" | grep -qi 'evil-blackbox-test.example'; then
  med "Host header is reflected in response (cache poisoning / reset link poisoning risk)"
fi
XFH="$(req -H "X-Forwarded-Host: evil-blackbox-test.example" "$TARGET_URL/" -D - | tr -d '\r')"
if echo "$XFH" | grep -qi 'evil-blackbox-test.example'; then
  med "X-Forwarded-Host is reflected in response"
fi

# ---------------------------------------------------------------------------
section "11. Front end and third party"
# ---------------------------------------------------------------------------
if [[ -s "$OUT_DIR/index.html" ]]; then
  grep -oiE '<script[^>]+src="[^"]+"' "$OUT_DIR/index.html" | sed -E 's/.*src="([^"]+)"/\1/' | sort -u > "$OUT_DIR/scripts.txt"
  info "External/inline script sources found: $(wc -l < "$OUT_DIR/scripts.txt")"
  while IFS= read -r s; do
    if [[ "$s" =~ ^http:// ]]; then med "Mixed content script: $s"; fi
  done < "$OUT_DIR/scripts.txt"
  NOSRI="$(grep -oiE '<script[^>]+src="https?://[^"]+"[^>]*>' "$OUT_DIR/index.html" | grep -vi "$HOST" | grep -vic integrity)"
  [[ "$NOSRI" -gt 0 ]] && low "$NOSRI third party script(s) loaded without Subresource Integrity"
  for lib in 'jquery[.-]1\.' 'jquery[.-]2\.' 'angular(\.min)?\.js.*1\.[0-5]' 'bootstrap[.-]3\.'; do
    grep -qiE "$lib" "$OUT_DIR/index.html" && low "Possibly outdated library referenced (pattern: $lib)"
  done
  if grep -qiE '(api[_-]?key|secret|token|password)["'"'"' ]*[:=]["'"'"' ]*[A-Za-z0-9_\-]{16,}' "$OUT_DIR/index.html"; then
    med "Possible secret/API key in page source, review index.html"
  fi
  grep -qiE 'AKIA[0-9A-Z]{16}' "$OUT_DIR/index.html" && high "AWS access key pattern found in page source"
  grep -qiE '<form[^>]+action="http://' "$OUT_DIR/index.html" && med "Form posts over plain HTTP"
fi

# ---------------------------------------------------------------------------
section "12. Rate limiting on login (light touch)"
# ---------------------------------------------------------------------------
# Only sends 15 requests; tweak LOGIN_PATH if your login lives elsewhere.
LOGIN_PATH="${LOGIN_PATH:-login}"
lcode="$(req -o /dev/null -w '%{http_code}' "$TARGET_URL/$LOGIN_PATH")"
if [[ "$lcode" =~ ^(200|302|405)$ ]]; then
  limited=0
  for i in $(seq 1 15); do
    c="$(req -o /dev/null -w '%{http_code}' -X POST -d "email=blackbox-test@example.invalid&password=wrong$i" "$TARGET_URL/$LOGIN_PATH")"
    if [[ "$c" == "429" ]]; then limited=1; break; fi
  done
  if (( limited )); then ok "Login endpoint rate limits (429 seen)"; else low "No 429 after 15 failed logins at /$LOGIN_PATH (check lockout / captcha)"; fi
else
  info "No login at /$LOGIN_PATH (HTTP $lcode). Set LOGIN_PATH to test."
fi

# ---------------------------------------------------------------------------
section "13. External tools (optional)"
# ---------------------------------------------------------------------------
if [[ "$RUN_EXTERNAL" == "1" ]]; then
  if have nmap; then
    info "Running nmap top 1000 TCP ports with service detection..."
    nmap -Pn -sV --top-ports 1000 -T3 -oN "$OUT_DIR/nmap.txt" "$HOST" >/dev/null 2>&1
    grep -E '^[0-9]+/tcp\s+open' "$OUT_DIR/nmap.txt" | while read -r l; do info "nmap: $l"; done
  else info "nmap not installed"; fi

  if have testssl.sh || have testssl; then
    T="$(command -v testssl.sh || command -v testssl)"
    info "Running testssl..."
    "$T" --quiet --color 0 --severity LOW "$HOST" > "$OUT_DIR/testssl.txt" 2>&1
  else info "testssl not installed"; fi

  if have nikto; then
    info "Running nikto (this can take a while)..."
    nikto -h "$TARGET_URL" -ask no -nointeractive -output "$OUT_DIR/nikto.txt" >/dev/null 2>&1
  else info "nikto not installed"; fi

  if have nuclei; then
    info "Running nuclei (excluding intrusive/dos templates)..."
    nuclei -u "$TARGET_URL" -silent -etags dos,intrusive,fuzz -o "$OUT_DIR/nuclei.txt" >/dev/null 2>&1
    [[ -s "$OUT_DIR/nuclei.txt" ]] && while read -r l; do info "nuclei: $l"; done < "$OUT_DIR/nuclei.txt"
  else info "nuclei not installed"; fi
else
  info "Skipped. Re-run with RUN_EXTERNAL=1 to use nmap, testssl, nikto, nuclei if installed."
fi

# ---------------------------------------------------------------------------
section "Summary"
# ---------------------------------------------------------------------------
log "High: $HIGH   Medium: $MED   Low: $LOW   Info: $INFO"
log "Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Full report: $REPORT"

(( HIGH > 0 )) && exit 3
exit 0
