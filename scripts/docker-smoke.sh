#!/usr/bin/env bash
# Lab smoke test for the myOwnCA Docker MVP stack.
# Proves: image builds, compose config is valid, the first-run setup server is
# reachable on the published port, and the nginx proxy terminates TLS.
# It does NOT finalize the wizard (that is a browser step) — so the CA service
# stays in setup mode and the proxy returns 502 until you finish setup.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> [1/6] Ensuring lab TLS material exists in ./tls"
if [[ ! -s tls/tls.crt || ! -s tls/tls.key ]]; then
  ./scripts/gen-lab-cert.sh
fi

echo "==> [2/6] Validating compose file"
docker compose config -q

echo "==> [3/6] Building images"
docker compose build

# WARNING: cleanup runs `docker compose down -v`, which DESTROYS the named
# state volume. That is correct for this throwaway lab smoke — never run this
# script against a stack that holds real CA state.
cleanup() { echo "==> Tearing down"; docker compose down -v; }
trap cleanup EXIT

echo "==> [4/6] Starting the stack"
docker compose up -d

echo "==> [5/6] Waiting for the first-run setup server on 127.0.0.1:8765"
ok=""
for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null "http://127.0.0.1:8765/setup"; then ok=1; break; fi
  sleep 1
done
if [[ -z "$ok" ]]; then
  echo "FAIL: setup server never became reachable on :8765"
  docker compose logs ca
  exit 1
fi
echo "    OK: setup wizard reachable (MYOWNCA_SETUP_HOST=0.0.0.0 verified)"

echo "==> [6/6] Checking the nginx proxy terminates TLS on :443"
# Before finalize the upstream is down, so expect an HTTP status (e.g. 502),
# which proves the TLS handshake + proxy path work end-to-end.
code="$(curl -k -s -o /dev/null -w '%{http_code}' "https://127.0.0.1/" || true)"
if [[ -z "$code" || "$code" == "000" ]]; then
  echo "FAIL: TLS handshake to the proxy did not complete (curl code: '$code')"
  docker compose logs proxy
  exit 1
fi
echo "    OK: proxy answered over HTTPS with status $code (502 before finalize is expected)"

echo
echo "SMOKE PASS. To finish a lab install, browse the printed setup URL:"
docker compose logs ca | grep -A3 "first-run setup" | tail -n 4 || true
echo "(token is in the logs above). Finalize the wizard, then https://127.0.0.1/ serves the CA."
