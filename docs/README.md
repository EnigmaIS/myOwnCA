# myOwnCA

**A private, self-hosted Certificate Authority you run yourself — browser-driven,
offline-root-capable, and built for small businesses and home labs.**

myOwnCA replaces error-prone manual PKI (OpenSSL scripts, spreadsheets of expiry
dates, ad-hoc key handling) with a guided web application, while keeping a
production-grade operating model: an air-gapped offline root, online issuing
sub-CAs, role separation, configurable certificate-approval quorum, and
CRL/OCSP revocation status. Run it on a single box in minutes, or behind your
own TLS proxy for real use.

> **Free for genuine noncommercial use within the 10-active-identity allowance.**
> Every commercial use, including commercial evaluation, requires paid terms.
> Source is available for inspection under the [licence](../LICENSE); modifications
> and derivative versions are prohibited. See [licensing](#licensing).

![myOwnCA feature map](../diags/feautures.png)

---

## Contents

- [Highlights](#highlights)
- [Architecture](#architecture)
- [Modules](#modules)
- [Quick start](#quick-start)
  - [Option A — Docker](#option-a--docker)
  - [Option B — Standalone (bare metal)](#option-b--standalone-bare-metal)
  - [Finish in the browser: the setup wizard](#finish-in-the-browser-the-setup-wizard)
  - [First login & next steps](#first-login--next-steps)
- [Configuration & data](#configuration--data)
- [Security & operating model](#security--operating-model)
- [Licensing](#licensing)
- [Roadmap](#roadmap)
- [Manual & advanced](#manual--advanced)

---

## Highlights

- **Certificate authority** — TLS, S/MIME, and user-auth profiles; templates with
  key-usage policy; CSR upload or server-generated keys; quorum approval that
  auto-issues; revoke, renew, and CRLs.
- **Approval separation** — first issuance from a new CSR defaults to two
  distinct Certificate Operator approvals, with a configurable threshold per
  template. Setup bootstraps one (optionally two) administrators in Single
  administrator mode or two distinct administrators in Dual control mode. Administrators — not
  Certificate Operators — manage the templates that set issuance policy.
- **Lifecycle automation** — **automatic certificate-expiry reminders** by email
  (also Slack / webhook) and a self-service **renewal** flow: holders get a secure
  link to renew before expiry, and ACME-obtained external certs auto-renew. A
  application-managed sweep drives reminders and expiry alerts when enabled in
  Admin or Superuser settings, with a live configurable cadence. The manual
  `myownca-notify-run` command remains available.
- **Offline-root trust hierarchy** — an air-gapped offline root signs a copied
  PEM CSR for the online issuing Sub CA; setup verifies the pasted certificate
  against the Root and local key; a single-host **Lab mode** is available for
  evaluation.
- **Hardware key protection** — software keystore by default, or PKCS#11 HSMs /
  smart cards (SmartCard-HSM, NitroKey HSM) via OpenSC, with non-extractable
  token signing and session-scoped PIN unlock. The backend selected during
  setup remains fixed for the running service.
- **External & public CAs** — built-in outbound **ACME client** (Let's Encrypt
  and other ACME CAs) with HTTP-01 / DNS-01 challenges and auto-renew, plus
  CSR-for-external and PEM/PKCS#12 import for certs you didn't issue yourself.
- **Automatic external certs:** HTTP-01 issuance + renewal are hands-off when the
  service is reachable on port 80 at the certificate's domain. The app serves
  `/.well-known/acme-challenge/` itself (in the Docker stack the nginx proxy
  forwards port 80 to it; bare-metal on port 80 needs no extra config). Renewal is
  scheduled in-process. Wildcards need DNS-01.
- **Wildcards / DNS-01:** configure a DNS provider (LuaDNS and ~90 others via
  `dns-lexicon`) on the ACME account; myOwnCA publishes, polls
  the authoritative nameservers, finalizes, and removes the `_acme-challenge` TXT
  automatically for both issuance and renewal — no manual step.
- **Many export formats & secure delivery** — PEM, DER, PKCS#7, and PKCS#12 (PFX)
  bundles that include the PKCS#8 private key, plus signature-verified full-chain
  bundles; delivered via secure claim links with email OTP, mTLS proof, QR codes,
  and receipts.
- **Strong auth & governance** — four RBAC roles (Administrator, Certificate
  Operator, User, and Auditor) on separate portals; the Certificate Operator
  retains the internal `superuser` wire value for compatibility. Argon2id
  passwords; **role-based TOTP MFA** (recommended and enabled by default for
  Administrators and Certificate Operators, optional for every role) with
  email-OTP and recovery-code account recovery; install-level Single administrator or Dual
  control policy for privileged role grants and credential resets; a
  tamper-evident audit log with optional remote syslog; and email / Slack /
  webhook notification channels.
- **Self-service & people/devices** — model certificate holders as **people** and
  **devices**; an optional, admin-gated public "request a certificate" flow with
  an email-domain allow-list.
- **Runs anywhere small** — single console script or a one-command Docker stack;
  SQLite by default or MariaDB/MySQL, with both drivers bundled; a friendly
  **first-run web wizard** does the rest.

## Architecture

Web clients talk to a FastAPI app (`online/app.py`) that orchestrates two issuance
lanes — an **internal CA** lane (lifecycle → policy/quorum → X.509/CRL build →
HSM signing) and an **external** lane (ACME / import). Issued material is exported,
delivered, and persisted; the issuing sub-CA is provisioned from the air-gapped
offline root through a copy/paste CSR and signed-certificate handoff. Auth,
audit, notifications, comms, and licensing are cross-cutting.

![myOwnCA architecture](../diags/architecture.png)

## Modules

The application is shipped as one `myownca` distribution. Every runtime module
and integration is installed by `pip install .`; there is no feature-selection
build flag. The selected signing backend is still an installation setting, so
an operator chooses software, PKCS#11, AWS KMS, or Azure Key Vault for a given
issuer rather than activating multiple issuer backends at once.

| Module | Responsibility |
|---|---|
| `ca_main` | Certificate issuance, templates, identities, exports, CRL, AIA, and OCSP. |
| `ca_hsm` | Software keys, PKCS#11/smart cards, DKEK recovery, AWS KMS, and Azure Key Vault. |
| `ca_auth` | Accounts, sessions, passwords, TOTP MFA, recovery, and RBAC. |
| `online` | FastAPI service, Admin/Certificate Operator/holder portals, and schedulers. |
| `offline` | Air-gapped root and Sub CA ceremony CLI. |
| `setup` | First-run wizard, install governance, preflight, and provisioning. |
| `service_certs` | Outbound ACME, HTTP-01/DNS-01, external certificates, and service TLS. |
| `cloud` | Durable cloud-key inventory and signing-job queue/worker. |
| `storage` | Application database compatibility layer, migrations, and repositories. |
| `key_lifecycle` | Key rotation, cleanup, and lifecycle policy. |
| `notifications` | Templates, expiry reminders, renewal notices, and scheduled sweeps. |
| `comms` | Email, Slack, SMS, and webhook delivery channels. |
| `audit` | Tamper-evident audit records and optional syslog forwarding. |
| `holder` | People/devices, access requests, secure links, and certificate delivery. |
| `licensing` | Installation-bound licensing and issuance authorization. |
| `config`, `domain`, `keygen`, `people_sync` | Shared settings, domain models, key generation, and people synchronization. |

The shared `myownca_core` sources under `core/` are bundled into the main
`myownca` wheel, so the application and Docker image need only one install.
`core/pyproject.toml` remains available to build a standalone `myownca-core`
wheel from the same sources for DeviceCA. Both distributions use the same
repository tag and must be released from the same revision. They contain the
same `myownca_core` namespace and should not be installed side-by-side.

---

## Quick start

Both paths install the same application and finish in the same browser-based
**setup wizard**. The commands below are source-development workflows. Published
production releases currently support only Docker on Linux amd64 and ARM64; use
the [signed release workflow](release-publishing.md) for deployment. Standalone
publication is deferred. Docker supports both production and Test/Lab installations.
The **Test/Lab** install type—not Docker—is the evaluation-only choice: it
creates an automatic local Root + Sub CA hierarchy. The supplied Compose
configuration is a single-host default using SQLite and the software keystore;
adapt its proxy, database, network, and recovery controls for production.
Host-attached PKCS#11 deployments require a separately validated integration.

### Option A — Docker

A single-host Compose stack: the CA container plus an nginx TLS proxy. All state
lives in a named volume. The supplied configuration uses SQLite and the
software keystore and does not provide independent portal isolation, high
availability, or local PKCS#11 passthrough.

**Prerequisites:** Docker Engine 24+ and the Compose v2 plugin, plus a TLS
cert/key for the proxy.

```bash
# From a checkout of this repository:

# 1. Provide the proxy's TLS material first (nginx won't start without it).
#    For a lab, generate a self-signed pair:
./scripts/gen-lab-cert.sh                 # writes ./tls/tls.crt and ./tls/tls.key
#    (or drop your own operator-issued tls/tls.crt + tls/tls.key in ./tls/)

# 2. Build and start the stack:
docker compose up -d --build

# 3. Read the one-time setup URL + token from the logs:
docker compose logs ca
```

The setup port `8765` is published to the host's **loopback only**. Browse
`http://127.0.0.1:8765/setup` on the host (or `ssh -L 8765:127.0.0.1:8765
<docker-host>` to reach it remotely), paste the token, and complete the wizard.

After you finalize, the same container boots the CA and the proxy serves it at
`https://<host>/`. Then **harden**: remove the `127.0.0.1:8765:8765` mapping from
`docker-compose.yml` and `docker compose up -d` again so the setup port is no
longer published.

Full Docker runbook (backup/restore, what lives where, caveats):
[`docker.md`](docker.md).

### Option B — Standalone (bare metal)

Run the app directly on a host. Python 3.12+ is required.

```bash
# From a checkout (no public PyPI package yet):
python -m venv .venv && . .venv/bin/activate
pip install .                 # all runtime modules and integrations included

# Start it — on first run this prints a setup URL + one-time token:
myownca
```

By default the first-run wizard listens on `127.0.0.1:8765`. Open
`http://127.0.0.1:8765/setup`, paste the token, and complete the wizard; the
process then starts serving the CA. **For production, terminate TLS in front of
the app** (a reverse proxy) and set `MYOWNCA_SESSION_COOKIE_SECURE=true` so
session cookies are marked `Secure`. Bind/host and TLS options are configurable
via environment variables (see [Configuration & data](#configuration--data)).

### Finish in the browser: the setup wizard

The wizard walks you top-to-bottom and is self-explaining (each section has a hint
and a "Learn more"). You configure:

- **Install type** — *Test/Lab* (a throwaway CA can be auto-generated; for
  evaluation only) or *Production* (you import your own offline-generated root and
  the full issuing-CA ceremony applies).
- **Administrative governance** — Test/Lab defaults to *Single administrator*.
  Production requires an explicit choice and recommends *Dual control*, where
  one administrator proposes a governed account change and a different
  administrator approves it.
- **Database** — SQLite (a single file, fine for most) or MariaDB; both drivers
  are included in the base install.
- **Service URLs** — the public base URLs your Admin, Certificate Operator, and
  holder portals and emailed links resolve to.
- **Issuance endpoints** — CRL / AIA / OCSP URLs baked into issued certificates
  (optional for Lab).
- **Root CA certificate** — in Production, paste only the **certificate** of your
  offline root (the root private key never touches the server); leave blank for
  Test/Lab.
- **Issuing CA / Sub CA** — before the service can start, create a new key and
  complete the offline-root ceremony, attach an existing PKCS#11/AWS/Azure key,
  import P12/PFX or PEM material, restore a native SmartCard-HSM `.bin` with DKEK, or
  generate the automatic Test/Lab Root + Sub CA.
- **Initial administrators** — Single administrator mode requires one account
  and optionally accepts a second; either can act independently. Dual control
  requires two distinct accounts. Each gets a temporary password to record.
- **TOTP authentication policy** — choose independently for Administrator,
  Certificate Operator, Auditor, and User. Administrator and Certificate
  Operator start enabled as the recommended defaults.

**Finish setup** remains disabled until exactly one active Sub CA has been
validated against the selected Root CA and its private key is accessible. The
issuer step is resumable after a restart. See
[`issuer-setup.md`](issuer-setup.md) for the complete procedures and reset
semantics.

### First login & next steps

After setup completes (the wizard also shows this):

1. Sign in as the first admin at your login URL using the temporary password.
2. When prompted, set a new password. If the Administrator role requires TOTP,
   **enroll TOTP** with an authenticator app.
3. In the Admin portal, create your **Certificate Operator** account(s) and
   review CA policy (certificate templates, etc.).
4. Review the immutable Root/Sub CA fingerprints and validity in **CA
   management**, then configure or verify CRL, AIA, OCSP, and service URLs.
5. Certificate Operators can issue certificates to people and devices; there is
   no post-install issuer provisioning surface.

---

## Configuration & data

- **State.** Configuration and secrets live under the state directory
  (`/var/lib/myownca` in Docker, set by `MYOWNCA_STATE_DIR` on bare metal):
  `config.toml`, `secrets/secrets.env` (mode `0600` in a mode-`0700` directory;
  auth secret, key passphrases, and DB URL), the setup latch, software keys, and
  — for SQLite — the database file. **This is the whole CA; back it up**
  (Docker: back up the `myownca-state` volume).
- **Database.** SQLite by default (single file). Choose MariaDB/MySQL during setup;
  its driver is included in the base installation.
- **Key protection.** Software keystore by default; select a PKCS#11 token
  (SmartCard-HSM / NitroKey HSM via OpenSC) to keep issuer keys
  non-extractable on hardware. Host-attached PKCS#11 signing is supported on
  bare metal; the supplied Compose configuration uses the software keystore.
  Token initialization, N-of-N DKEK backup, and replacement-device recovery are covered by the
  [HSM DKEK recovery runbook](hsm-dkek-recovery.md). Every PKCS#11 operation runs
  in a fresh worker process, so token reinitialization, replacement, and key
  changes are visible without restarting myOwnCA. SmartCard-HSM administration
  remains isolated in short-lived `sc-hsm-tool` processes.
- **Cloud key providers.** AWS KMS and Azure Key Vault can hold non-exportable
  Issuing Sub CA and service-certificate signing keys. The
  [cloud signing-key runbook](cloud-key-providers.md) covers the AWS IAM policy
  templates, Azure app registration and RBAC steps, credentials, lifecycle, and
  failure handling.
- **Service URLs** (admin → CA management): the CRL base URL (serves
  `/crl/<issuer>.crl` and is embedded in new certs as a CRL distribution point),
  plus AIA / OCSP / Admin / Certificate Operator base URLs. These are seeded
  from the installer's values on first boot and editable anytime. The frontend (holder)
  portal base URL is set under Holder portal settings.
- **OCSP responder** (admin → CA management): off by default. When enabled, pre-produced responses
  are served at `/ocsp` and new certificates carry an OCSP AIA entry (using the OCSP base URL from
  Service URLs). The delegated responder certificate's validity is configurable; it auto-renews
  while the HSM is unlocked.
  Responses auto-refresh on issue/revoke and on a daily pass; `MYOWNCA_OCSP_AUTO=false` turns the
  daily pass off (the manual "Generate OCSP responses" button still works).
- **Immutable trust chain.** The Root CA and the single active issuing Sub CA
  are provisioned only by the one-time, token-gated setup application. After the
  completion latch is written, CA management shows their status, fingerprints,
  validity, key backend, and profiles but cannot replace or add an issuer.
- **Environment overrides** (selected): `MYOWNCA_SETUP_HOST` / `MYOWNCA_BIND_HOST`
  (bind addresses), `MYOWNCA_SETUP_TOKEN` (preset the one-time token),
  `MYOWNCA_SESSION_COOKIE_SECURE` (mark cookies `Secure` behind a TLS proxy),
  `MYOWNCA_STATE_DIR`. `MYOWNCA_GOVERNANCE_MODE` seeds a fresh installation;
  runtime governance changes are then stored in the database so a restart cannot
  undo an approved change. The wizard writes these values into
  `config.toml` and `secrets/secrets.env`.

## Security & operating model

- **Offline root.** The root CA is generated and kept air-gapped; only its public
  certificate is imported. The online instance runs an **issuing sub-CA**, signed
  by the root from a copied CSR. Setup accepts the resulting PEM certificate only
  after verifying its Root signature and matching it to the local private key.
- **Role separation & configurable admin governance.** Four roles use separate
  portals. Single administrator mode applies governed privileged-account changes
  immediately. Dual control requires a proposal and approval by a different
  administrator. Enabling Dual control requires two active admins; requesting a
  downgrade leaves Dual control active until another admin approves it with
  recent authentication, a reason, and typed confirmation. TOTP policy changes
  use the same governance workflow. If a legacy Dual control install
  has fewer than two active admins, governed proposal creation pauses and Admin
  reports the recovery condition until a second existing admin is reactivated.
  Separately, first issuance from a new CSR defaults to approval by two distinct
  Certificate Operators,
  configurable per template. Certificate **templates** are admin-managed, so the
  role that operates the CA cannot unilaterally weaken its own issuance policy.
- **Authentication.** Argon2id password hashing; TOTP requirements configured
  independently per role (Admin and Certificate Operator are the recommended
  defaults); account recovery via recovery codes or email OTP; sessions with
  CSRF protection. Sensitive admin operations require recent TOTP when enabled
  for Administrators, otherwise explicit password reauthentication.
- **Auditability.** A tamper-evident audit log records every operation, with
  optional forwarding to a remote syslog collector.

## Licensing

myOwnCA is source-available under the [EnigmaIS Source-Available Licence 1.0](../LICENSE)
from EnigmaIS sp. z o. o. Source inspection is allowed; modifications and derivative
versions are prohibited. Normal configuration and supported integrations are allowed.
Genuine noncommercial use is free within the 10-active-certificate-lineage allowance.
Every commercial use requires paid terms, including evaluation for a commercial
deployment and use below the capacity limit. Internal deployment and backup copies
are permitted; redistribution requires written permission. Link others to official
downloads. Third-party components remain under their own licences.

Installation-bound RSA-4096 PSS/SHA-256 licence tokens verify offline and raise
certificate capacity. Capacity is the technical restriction, not the definition of
permitted use. Genuine renewals remain in their lineage; lifecycle monitoring,
notifications, renewal links, ACME automation, revocation, CRL/OCSP, export, recovery,
and the offline ceremony are not gated by paid capacity. See
[`licensing.md`](licensing.md) for the operational model.

## Roadmap

myOwnCA is focused on being the simplest trustworthy **private, self-hosted CA**
for SMB and home use. Built and shipping today: PKCS#11 / smart cards, an
**outbound ACME client** for obtaining external certificates, a delegated
**OCSP responder**, notifications (email/Slack/webhook), tamper-evident audit,
holder portal + secure links, and guided web setup. Docker and standalone
deployments support both Production and Test/Lab install types; only the
automatic Test/Lab Root + Sub CA hierarchy is evaluation-only. Not yet built:
an internal RFC 8555 ACME server or a public REST API. Managed SaaS is a
separate future direction, not a mode of the current self-hosted product.

---

## Manual & advanced

The web wizard is the supported path for most installs. The material below is for
operators who want to drive things by hand, run the offline ceremony, or
understand the internals.

### Offline root CA ceremony

For production, create and operate the root **off-box** on an air-gapped machine.
The setup wizard uses a direct copy/paste exchange (Sub CA CSR out → signed PEM
certificate back). The wizard's OpenSSL helpers and the guide below use the
same direct PEM handoff:
[`offline-root.md`](offline-root.md).

Storage backends and Sub CA provisioning choices: [`subca-storage-and-provisioning.md`](subca-storage-and-provisioning.md).

### Command-line tools

Installed as console scripts:

| Command | Purpose |
|---|---|
| `myownca` | Launcher — first-run setup wizard, then serve. |
| `myownca-online` | Run the online service directly. |
| `myownca-offline` | Air-gapped offline-root CLI using direct PEM input/output. |
| `myownca-auth-bootstrap` | Create initial administrator accounts for an empty database. |
| `myownca-acme-renew` | Report ACME certificates that are due; the running service performs renewal. |
| `myownca-notify-run` | Run the notification/expiry sweep. |
| `myownca-key-cleanup` | Preview registered private keys due for cleanup; pass `--execute` to delete them. |
| `myownca-reencrypt-secrets` | Inspect stored-secret re-encryption; pass `--execute` to convert them. |

### Manual configuration (without the wizard)

The `myownca` launcher reads `config.toml` and `secrets/secrets.env` from the
state directory, then applies environment variables. If you run
`myownca-online` directly, provide the required `MYOWNCA_*` values through its
process environment instead. These files may be prepared by hand for advanced
deployments, but the supported bootstrap still runs the one-time setup
application to validate and persist exactly one active issuer before normal
service launch. Keep `secrets/secrets.env` at mode `0600`; its `secrets/`
directory is mode `0700`.

### Backup & restore

Administrators create two-person, split-passphrase encrypted application backups
under **System → Backups**. The archive contains the complete logical database,
portable configuration, required secrets, and local software key material. HSM,
cloud-provider, Offline Root, and external proxy material remain separate.

Restore is deliberately offline: stop the service and run `myownca backup verify`
or `myownca backup restore` with the exact application release. Docker commands
are in [`docker.md`](docker.md#backup--restore); scope, safeguards, and the
restore-test procedure are in
[`backup-and-disaster-recovery.md`](backup-and-disaster-recovery.md).

### Hardening checklist

- Terminate TLS in front of the app; set `MYOWNCA_SESSION_COOKIE_SECURE=true`.
- After setup, stop publishing the setup port (Docker: remove the
  `127.0.0.1:8765:8765` mapping).
- Keep the offline root private key off the server; import only its certificate.
- Prefer HSM/smart-card signing for issuer keys in production (bare metal).
- Isolate the Admin, Certificate Operator, and holder portals behind separate
  paths or vhosts on your proxy.

### Additional operator docs

- [`overview.md`](overview.md) — product overview and operating model.
- [`offline-root.md`](offline-root.md) — offline Root ceremony and direct PEM
  handoff.
- [`licensing.md`](licensing.md) — licensing tiers and token operations.
- [`docker.md`](docker.md) — Docker deployment runbook.
- [`cloud-key-providers.md`](cloud-key-providers.md) — AWS KMS and Azure Key
  Vault setup, permissions, credentials, and key lifecycle.
- [`certificate-lifecycle.md`](certificate-lifecycle.md) — templates, approval,
  delivery, renewal, revocation, and periodic certificate operations.
- [`backup-and-disaster-recovery.md`](backup-and-disaster-recovery.md) — backup
  scope, recovery material, restore tests, and production recovery.
- [`upgrade-and-rollback.md`](upgrade-and-rollback.md) — startup migrations,
  upgrade validation, and supported recovery boundaries.
- [`monitoring-and-operations.md`](monitoring-and-operations.md) — health,
  scheduled work, alert response, and operational records.
- [`security-incident-response.md`](security-incident-response.md) — containment
  and response boundaries for credentials and CA-key incidents.
- [`configuration-reference.md`](configuration-reference.md) — state files,
  configuration precedence, defaults, and `MYOWNCA_*` settings.
- [`reverse-proxy-deployment.md`](reverse-proxy-deployment.md) — TLS proxy,
  portal isolation, public endpoints, and optional holder mTLS forwarding.

### Development & tests

```bash
pip install ".[dev]"
python -m pytest -q
ruff check src/ tests/
```
