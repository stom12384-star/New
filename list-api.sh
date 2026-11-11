#!/usr/bin/env bash
# list-api.sh
#
# Lists the endpoints declared in an OpenAPI/Swagger JSON spec
# (such as Restler's /storage/api-docs/complete.json).
# Shows method + path, and flags paths that look like leaked helper methods.
#
# Only use against specs for apps you own or are authorised to test.
#
# Usage:
#   ./list-api.sh https://develop.example.com/storage/api-docs/complete.json
#   ./list-api.sh ./complete.json            # a file you already downloaded

set -uo pipefail
SRC="${1:-}"
[[ -z "$SRC" ]] && { echo "Usage: ./list-api.sh <url-or-file-to-openapi.json>"; exit 1; }

TMP="$(mktemp)"
if [[ "$SRC" =~ ^https?:// ]]; then
  curl -s -k --max-time 30 -A "list-api/1.0" "$SRC" -o "$TMP"
else
  cp "$SRC" "$TMP"
fi

if [[ -t 1 ]]; then Y=$'\e[33m'; G=$'\e[32m'; R=$'\e[0m'; else Y=""; G=""; R=""; fi

if command -v jq >/dev/null 2>&1; then
  echo "${G}Endpoints:${R}"
  jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[] | "\(.key|ascii_upcase)\t\($p)"' "$TMP" \
    | sort -u | tee /tmp/.eps | sed 's/^/  /'
  echo ""
  echo "Total: $(wc -l < /tmp/.eps) method+path combinations"
  echo ""
  echo "${Y}Paths that look like leaked helper/factory methods:${R}"
  grep -iE 'create|from|global|internal|helper|__|build|make|set[A-Z]|load|init|factory|raw|debug|test' /tmp/.eps | sed 's/^/  /' || echo "  (none obvious)"
else
  echo "jq not installed; showing raw paths with grep:"
  grep -oE '"/[^"]+"' "$TMP" | sort -u | sed 's/^/  /'
  echo ""
  echo "Install jq for method+path output:  pkg install jq   (Termux)  /  apt install jq"
fi
rm -f "$TMP"
