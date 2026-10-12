# Running myOwnCA with Docker

The root Dockerfile and Compose stack described here are **development source
builds**. Production installs use the prebuilt GHCR image and signed Compose
bundle described in [release publishing](release-publishing.md) and
[release verification](release-signing.md). Standalone development uses
`pip install -e .`; production standalone uses the signed installer.
The development stack packages the same application and first-run wizard behind
an nginx TLS proxy on a single host.

> **Docker is not limited to Test/Lab use.** The Test/Lab install type—not
> Docker—creates the automatic, evaluation-only Root + Sub CA hierarchy. The
> supplied Compose configuration is a single-host default using SQLite and the
> software keystore. It does not include MariaDB-as-a-service, per-portal
> network separation, holder mTLS forwarding, local PKCS#11 passthrough,
> high availability, or other organization-specific production controls.

## Prerequisites

- Docker Engine 24+ and the Compose v2 plugin.
- A TLS cert/key pair for the proxy. Drop them in `./tls/tls.crt` and
  `./tls/tls.key` (see `tls/README.md`). For a lab, generate a self-signed pair
  with the helper:

      ./scripts/gen-lab-cert.sh

## Quickstart

1. **Provide the proxy's TLS cert/key first** — without it nginx won't start.
   For a lab, generate a self-signed pair:

       ./scripts/gen-lab-cert.sh

   (or drop an operator-issued `tls/tls.crt` + `tls/tls.key` in `./tls/` yourself —
   see `tls/README.md`). If you skip this, the `proxy` container exits with a
   clear "missing TLS material" message.
2. `docker compose up -d --build`
3. Read the first-run URL + token from the logs:

       docker compose logs ca

   The setup port `8765` is published to the host's loopback only. Browse
   `http://127.0.0.1:8765/setup` on the host, or forward it:

       ssh -L 8765:127.0.0.1:8765 <docker-host>

   (Optionally preset `MYOWNCA_SETUP_TOKEN` in `docker-compose.yml` instead of
   reading it from the logs.)
4. Complete the wizard (install type, governance mode, per-role TOTP policy,
   database, service URLs, issuance endpoints, optionally paste your offline
   Root CA certificate, and create the bootstrap administrator account(s)).
   Test/Lab defaults to Single administrator; its automatic Root + Sub CA is
   for evaluation only. For Production, select Production and complete the
   offline-root ceremony. Dual control requires two distinct admins. Click
   **Finalize**.
5. The same container boots the CA service; the proxy serves it on
   `https://<host>/`. The container's health flips from unhealthy (setup) to
   healthy (serving). Log in as the first admin (forced password change and,
   when enabled for Administrators, TOTP enrollment).
6. Harden: remove the `127.0.0.1:8765:8765` mapping from `docker-compose.yml`
   and `docker compose up -d` again so the setup port is no longer published.

## What lives where

- **All state** is in the `myownca-state` named volume (`/var/lib/myownca`):
  `config.toml`, `secrets/secrets.env` (mode `0600`, in a mode-`0700`
  directory; wizard-generated auth secret, key passphrases, and DB URL), the
  setup latch, software keys, and the SQLite DB.
  **Back up this volume** — it is the whole CA.
- **TLS cert/key** belong to the proxy (`./tls`), not the app. The app runs
  plain HTTP behind nginx; `MYOWNCA_SESSION_COOKIE_SECURE=true` keeps session
  cookies `Secure` because the client is on HTTPS.
- **Bind hosts** (`MYOWNCA_SETUP_HOST` / `MYOWNCA_BIND_HOST=0.0.0.0`) are baked
  into the image, so a bare `docker run -p 8765:8765 myownca:dev` also works for
  a standalone first run; compose only adds the topology-specific
  `MYOWNCA_SESSION_COOKIE_SECURE` and the ports.

## Backup / restore

Create application backups while the service is running from the Admin portal,
under **System → Backups**. One administrator requests the export and supplies
passphrase share A; a different administrator approves it, supplies share B, and
downloads the `.myownca-backup` file. Store the file and the two shares in
separate protected locations.

Restore only while the stack is stopped and only into a newly created,
confirmed-empty `myownca-state` volume. Preserve the failed/old volume separately;
the restore command refuses to delete or overwrite it. Use the exact image release
recorded by `myownca backup verify`.

    docker compose down
    docker volume create myownca-state
    docker compose run --rm -v "$PWD:/recovery:ro" ca \
      backup verify /recovery/myownca-application-backup-....myownca-backup
    docker compose run --rm -v "$PWD:/recovery:ro" ca \
      backup restore /recovery/myownca-application-backup-....myownca-backup \
      --state-dir /var/lib/myownca --sqlite
    docker compose up -d

Both commands prompt for the requester and approver shares without placing them
on the command line. Omit `--sqlite` when restoring to the archived MariaDB URL,
or pass `--database-url` to target a new empty MariaDB schema. See
[backup and disaster recovery](backup-and-disaster-recovery.md) for exclusions,
verification, and the isolated restore-test procedure.

## Caveats

- Private/internal hostnames cannot qualify for certificates from a public ACME
  CA. Supply an operator-managed proxy certificate unless the proxy hostname is
  publicly valid and you deliberately obtain a certificate for it.
- Keep the **offline root** off-box — paste only its public cert into the wizard;
  the root private key never belongs in the container.
- Local PKCS#11 passthrough is not supported in this Compose stack. The software
  keystore works with the default image. AWS KMS/Azure Key Vault are included in
  that same image; no rebuild or extra selection is needed, and no USB/token
  passthrough is required for cloud signing.

## Automatic external certificates (ACME HTTP-01)

External (service) certificates can be issued and renewed automatically with
Let's Encrypt's HTTP-01 challenge. The stack already serves the challenge — the
proxy listens on port 80 and forwards `/.well-known/acme-challenge/` to the CA,
redirecting everything else to HTTPS. To use it:

1. Publish a public DNS `A`/`AAAA` record for the certificate's domain pointing at
   this host, and make sure inbound TCP **port 80** reaches the `proxy` container.
2. In the Certificate Operator portal, add an account for an external ACME CA
   and request a certificate with the **HTTP-01** challenge. Issuance and renewal
   then need no manual steps.

HTTP-01 cannot issue wildcards (`*.example.com`) — those need DNS-01 (below).
Renewal runs automatically inside the service (daily by default; set
`MYOWNCA_ACME_AUTORENEW=false` to disable, `MYOWNCA_ACME_RENEW_INTERVAL_SECONDS`
to retune).

The port-80 server also proxies `/crl/` to the app, so the issuing CA's CRL is
fetchable at `http://<host>/crl/<issuer>.crl` (DER). Set the **CRL base URL** in
the admin portal (CA management → Service URLs) to publish it and embed it in
newly-issued certificates.

With OCSP enabled (admin → CA management → OCSP responder), the port-80 server also answers
OCSP at `http://<host>/ocsp` (GET and POST). Responses are pre-produced and signed by a delegated
responder certificate; the HSM is only used to mint/renew that short-lived certificate.
When enabled, OCSP responses refresh automatically: a cert's response is re-signed the moment it
is issued or revoked, and a daily background pass refreshes all responses and renews the responder
certificate (while the HSM is unlocked). Set `MYOWNCA_OCSP_AUTO=false` to disable the daily pass.

### Wildcards / DNS-01 (automated)

For wildcard certs (`*.example.com`) or domains not reachable on port 80, configure a
**DNS provider** on the ACME account (Certificate Operator portal → External Certs → ACME
account): pick the provider (LuaDNS, etc.) and enter its API username/token. The
DNS-01 integration is included in the base image and host install. DNS-01 then publishes
the `_acme-challenge` TXT, waits for it to propagate, finalizes, and removes the
record — issuance and renewal are hands-off. DNS-01 has no manual fallback (it
requires a configured provider).

## Smoke test

`./scripts/docker-smoke.sh` builds, brings the stack up, asserts the wizard is
reachable on the published port and the proxy terminates TLS, then tears down.

### Troubleshooting ACME issuance

If creating an ACME account, configuring a DNS provider, or requesting/renewing a
certificate fails, the error message (including the DNS provider's own message) is
shown in the Certificate Operator portal under **External Certs → Recent ACME errors**.

For the full traceback, read the server logs:

```bash
docker compose logs -f ca          # Docker stack
journalctl -u myownca              # systemd install
```
