# blackbox-scan

A non-destructive black box security check for web apps. Only run it against sites you own or are authorised to test.

## Usage

```bash
# URL as an argument
./blackbox-scan.sh https://staging.example.com

# or as a variable
TARGET_URL=https://app.example.com ./blackbox-scan.sh

# loop over several domains
for d in https://app.example.com https://staging.example.com https://www.example.com; do
  TARGET_URL="$d" ./blackbox-scan.sh
done
```

## Options (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `TARGET_URL` | (required) | Base URL to test |
| `OUT_DIR` | `./reports/<host>-<timestamp>` | Output folder |
| `DELAY` | `0.2` | Seconds between path probes |
| `TIMEOUT` | `10` | Per request timeout |
| `LOGIN_PATH` | `login` | Path used for the light rate limit check |
| `AUTH_HEADER` | empty | e.g. `"Authorization: Bearer ..."` for authenticated checks |
| `RUN_EXTERNAL` | `0` | `1` runs nmap, testssl, nikto, nuclei if installed |

## What it checks

1. DNS, CNAME (takeover hint), SPF, DMARC
2. HTTP to HTTPS redirect
3. TLS certificate expiry, legacy TLS 1.0/1.1, TLS 1.3
4. Security headers (HSTS, CSP, XFO, etc.) and version disclosure
5. Cookie flags (Secure, HttpOnly, SameSite)
6. HTTP methods (TRACE, PUT, DELETE)
7. CORS misconfiguration (reflected origin, null origin)
8. ~75 sensitive files and paths (.git, .env, backups, actuator, logs, keys, API docs), with soft 404 detection
9. Directory listing and verbose error pages
10. Reflected input, open redirects, Host header injection
11. Mixed content, missing SRI, old libraries, secrets in page source
12. Login rate limiting (15 requests only)
13. Optional external tools

Exit code is `3` if any HIGH finding is reported, so it can gate a CI job.

Requirements: `bash`, `curl`, `openssl`, `dig` (optional). Results are saved in `reports/`, which is git ignored.
