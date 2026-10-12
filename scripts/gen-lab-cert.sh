#!/usr/bin/env bash
# Generate a self-signed lab TLS cert/key for the nginx proxy into ./tls/.
# Lab / evaluation only — for real use, drop an operator-issued cert+key in
# ./tls/tls.crt and ./tls/tls.key instead of running this.
#
# Usage: ./scripts/gen-lab-cert.sh [--force]
#   --force  overwrite an existing non-empty tls.crt / tls.key
set -euo pipefail

cd "$(dirname "$0")/.."

crt="tls/tls.crt"
key="tls/tls.key"
force="${1:-}"

mkdir -p tls

# A missing bind mount makes Docker auto-create an empty dir (or empty file) at
# ./tls/tls.crt. Treat any non-regular or empty stub as "no cert" and clear it
# so openssl can write — that stub is what produces nginx's PEM "no start line".
for f in "$crt" "$key"; do
  if [[ -d "$f" ]] || { [[ -e "$f" ]] && [[ ! -s "$f" ]]; }; then
    rm -rf "$f"
  fi
done

if { [[ -s "$crt" ]] || [[ -s "$key" ]]; } && [[ "$force" != "--force" ]]; then
  echo "Refusing to overwrite existing $crt / $key — pass --force to replace." >&2
  openssl x509 -in "$crt" -noout -subject -enddate 2>/dev/null | sed 's/^/  current cert: /' >&2 || true
  exit 1
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$key" -out "$crt" -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 "$key"

echo "Wrote $crt and $key (self-signed, CN=localhost, valid 365 days)."
echo "NOTE: lab/eval only — replace with an operator-issued cert for production."
