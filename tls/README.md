# TLS material for the nginx proxy

The `proxy` service mounts `tls.crt` and `tls.key` from this folder (read-only).
Drop an operator-provided cert/key pair here before `docker compose up`:

- `tls/tls.crt` — PEM certificate (chain leaf-first if you have intermediates)
- `tls/tls.key` — PEM private key

For a lab/eval, generate a self-signed pair with the helper (the smoke script
runs it for you):

    ./scripts/gen-lab-cert.sh

It writes `tls/tls.crt` + `tls/tls.key` (CN=localhost, 365 days); pass `--force`
to replace an existing pair. Under the hood it is just:

    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout tls/tls.key -out tls/tls.crt -days 365 \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

These files are git-ignored — never commit private keys.
