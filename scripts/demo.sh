#!/usr/bin/env bash
# Local demo: runs rotor plus a "whoami" target on loopback and shows
# rotation, sticky sessions, geo-targeting, SOCKS5 and metrics.
#
# Linux: works as is (all of 127.0.0.0/8 is on the loopback interface).
# macOS: add the exit addresses first:
#   sudo ifconfig lo0 alias 127.0.0.2 && sudo ifconfig lo0 alias 127.0.0.3 && sudo ifconfig lo0 alias 127.0.0.4
set -euo pipefail
cd "$(dirname "$0")/.."

go build -o bin/ ./cmd/...
./bin/whoami -listen 127.0.0.1:8000 2>/dev/null & W=$!
./bin/rotor -config config.example.json -log-level warn & R=$!
trap 'kill $W $R 2>/dev/null' EXIT
sleep 0.5

# --noproxy "" stops curl from bypassing the proxy if NO_PROXY covers localhost.
P=http://127.0.0.1:8080
T=http://127.0.0.1:8000

echo "== rotating (new exit IP per request)"
for i in 1 2 3 4; do curl -s --noproxy "" -x $P -U alice:change-me $T; done

echo "== sticky session (same IP while the session lives)"
for i in 1 2 3; do curl -s --noproxy "" -x $P -U alice-session-job42:change-me $T; done

echo "== geo-targeting: country us"
for i in 1 2; do curl -s --noproxy "" -x $P -U alice-country-us:change-me $T; done

echo "== SOCKS5 (proxy resolves the name: socks5h)"
curl -s --noproxy "" --socks5-hostname 127.0.0.1:8080 -U alice-country-de:change-me http://localhost:8000

echo "== wrong password"
curl -s --noproxy "" -o /dev/null -w "HTTP %{http_code}\n" -x $P -U alice:wrong $T

echo "== metrics (excerpt)"
curl -s --noproxy "" http://127.0.0.1:9090/metrics | grep -E '^rotor_(user_bytes|exit_connections_total|sticky)'
