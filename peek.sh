#!/usr/bin/env bash
# peek.sh
#
# Shows the response a page sends BEFORE/underneath a redirect.
# Many PHP pages print HTML and then redirect; the browser never shows it,
# but the body is still sent. This fetches without following the redirect
# and dumps the headers, the body, and a tags-stripped text view.
#
# Only use against sites you own or are authorised to test.
#
# Usage:
#   ./peek.sh https://develop.example.com/signin.php
#   ./peek.sh https://develop.example.com/signin.php text   # text only
#   ./peek.sh https://develop.example.com/properties/ chain   # follow redirects, show each hop
#
# Options (environment variables):
#   OUT_DIR    Where to save output (default: ./peek)
#   COOKIE     Optional cookie header, e.g. "PHPSESSID=abc"
#   TIMEOUT    Request timeout seconds (default: 15)

set -uo pipefail

URL="${1:-}"
MODE="${2:-all}"            # all | text | raw | chain
if [[ -z "$URL" ]]; then
  echo "Usage: ./peek.sh <url> [text|raw]"
  exit 1
fi
TIMEOUT="${TIMEOUT:-15}"
OUT_DIR="${OUT_DIR:-./peek}"
UA="${USER_AGENT:-peek/1.0}"
mkdir -p "$OUT_DIR"
NAME="$(echo "$URL" | sed -E 's#^https?://##; s#[/:?&=]#_#g' | cut -c1-80)"
HDR="$OUT_DIR/${NAME}.headers"
BODY="$OUT_DIR/${NAME}.body.html"
TXT="$OUT_DIR/${NAME}.text"

CURL=(curl -s -k --max-time "$TIMEOUT" -A "$UA" --max-redirs 0)
[[ -n "${COOKIE:-}" ]] && CURL+=(-H "Cookie: ${COOKIE}")

if [[ -t 1 ]]; then B=$'\e[34m'; Y=$'\e[33m'; G=$'\e[32m'; R=$'\e[0m'; else B=""; Y=""; G=""; R=""; fi

# chain mode: walk every redirect, show status + body size at each hop
if [[ "$MODE" == "chain" ]]; then
  cur="$URL"; hop=0
  while :; do
    hop=$((hop+1))
    "${CURL[@]}" -D "$OUT_DIR/.h" -o "$OUT_DIR/.b" "$cur"
    code="$(awk 'NR==1{print $2}' "$OUT_DIR/.h")"
    loc="$(tr -d '\r' < "$OUT_DIR/.h" | grep -i '^location:' | head -1 | cut -d: -f2- | sed 's/^ //')"
    sz="$(wc -c < "$OUT_DIR/.b" | tr -d ' ')"
    echo "${B}[hop $hop]${R} $code  ${sz}b  $cur"
    if (( sz > 0 )); then
      echo "    ${Y}body:${R} $(sed -E 's/<[^>]+>//g' "$OUT_DIR/.b" | tr -s ' \n' ' ' | sed 's/^ //' | cut -c1-200)"
    fi
    if [[ -n "$loc" && $hop -lt 10 ]]; then
      case "$loc" in
        http*) cur="$loc" ;;
        /*)    cur="$(echo "$cur" | sed -E 's#(https?://[^/]+).*#\1#')$loc" ;;
        *)     cur="$(dirname "$cur")/$loc" ;;
      esac
    else
      echo "${G}Final page reached at hop $hop.${R}"
      break
    fi
  done
  rm -f "$OUT_DIR/.h" "$OUT_DIR/.b"
  exit 0
fi

# Fetch once, keep headers and body separately, do NOT follow the redirect
"${CURL[@]}" -D "$HDR" -o "$BODY" "$URL"
CODE="$(awk 'NR==1{print $2}' "$HDR" 2>/dev/null)"
LOC="$(tr -d '\r' < "$HDR" | grep -i '^location:' | head -1 | cut -d: -f2- | sed 's/^ //')"
SIZE="$(wc -c < "$BODY" | tr -d ' ')"

echo "${B}URL:${R}      $URL"
echo "${B}Status:${R}   $CODE"
[[ -n "$LOC" ]] && echo "${B}Redirect to:${R} ${Y}$LOC${R}"
echo "${B}Body size:${R} $SIZE bytes"
echo ""

# Strip tags, scripts and styles to plain text
strip_text() {
  sed -E ':a;N;$!ba; s#<script[^>]*>.*?</script>##gI; s#<style[^>]*>.*?</style>##gI' "$BODY" \
    | sed -E 's/<[^>]+>//g' \
    | sed -E 's/&nbsp;/ /g; s/&amp;/\&/g; s/&lt;/</g; s/&gt;/>/g; s/&#39;/'"'"'/g; s/&quot;/"/g' \
    | grep -vE '^[[:space:]]*$' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}

if [[ "$SIZE" == "0" ]]; then
  echo "${Y}The page sent no body with the redirect (nothing leaked here).${R}"
else
  strip_text > "$TXT"
  case "$MODE" in
    raw)  echo "${B}---- raw body ----${R}"; cat "$BODY" ;;
    text) echo "${B}---- text (tags stripped) ----${R}"; cat "$TXT" ;;
    *)
      echo "${B}---- text (tags stripped) ----${R}"
      cat "$TXT"
      echo ""
      echo "${G}Saved:${R}"
      echo "  raw body : $BODY"
      echo "  text     : $TXT"
      echo "  headers  : $HDR"
      ;;
  esac

  # Flag things worth a look in the hidden body
  echo ""
  echo "${B}---- notable content in the hidden body ----${R}"
  grep -ioE '(error|warning|exception|fatal|stack trace|sql|mysql|undefined|notice:|deprecated|debug)[^<]{0,80}' "$BODY" | sort -u | head -20
  grep -ioE '(csrf|token|api[_-]?key|secret|password|session)["'"'"' :=>]{1,4}[A-Za-z0-9_\-]{8,}' "$BODY" | sort -u | head -20
  grep -ioE '<input[^>]+name=["'"'"'][^"'"'"']+["'"'"'][^>]*>' "$BODY" | sed -E 's/.*name=["'"'"']([^"'"'"']+).*/form field: \1/' | sort -u | head -30
  grep -ioE '<!--.*-->' "$BODY" | head -10
  grep -ioE '(/[a-z0-9_./-]+\.php|/api/[a-z0-9_./-]+)' "$BODY" | sort -u | head -20
fi
