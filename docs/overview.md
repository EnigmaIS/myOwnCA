# myOwnCA architecture overview

myOwnCA is a self-hosted private certificate authority for small organizations
and home labs. It combines an offline-root workflow, an online issuing CA,
browser-based operations, certificate lifecycle management, and revocation
services. It is not a publicly trusted CA and does not distribute its trust
anchor for you.

This document describes the implementation that ships in this repository. The
future private-ACME-server and managed-SaaS design documents are proposals, not
current deployment modes.

## Current product boundaries

- **OCSP is implemented.** The online service can issue and renew a delegated
  responder certificate, pre-produce responses, serve OCSP GET and POST requests
  at `/ocsp`, and refresh responses after issuance, revocation, and on a daily
  maintenance pass. CRLs remain available alongside OCSP.
- **ACME is currently outbound only.** A built-in client obtains and renews
  external, publicly trusted service certificates from ACME CAs such as Let's
  Encrypt using HTTP-01 or provider-backed DNS-01. myOwnCA does not currently
  expose an RFC 8555 endpoint for internal clients such as certbot,
  cert-manager, Caddy, or Traefik.
- **Docker is a supported deployment option.** The supplied Compose
  configuration is a convenient single-host default with nginx, SQLite, and
  software-held keys. It does not provide local PKCS#11 passthrough, high
  availability, or independent portal network isolation. Production operators
  must supply the required proxy, database, key-backend, network, and recovery
  controls; use the standalone service when a host-attached PKCS#11 device is
  required.
- **Managed SaaS is a separate future direction.** The current product is
  self-hosted and single-installation. It has no multi-tenant hosted control
  plane, endpoint agent fleet, or SaaS tenant isolation.

## Trust hierarchy

Production mode assumes an air-gapped root CA. Only the root certificate is
imported into the online installation. During setup, the online service displays
a sub-CA CSR for copy/paste; the offline root signs it, and the resulting PEM
Sub CA certificate is pasted back and verified against the configured Root and
the local HSM key.

Test/Lab mode can create a single-host hierarchy for evaluation. It is
deliberately not presented as a production substitute for the offline-root
ceremony.

Issuer keys use the encrypted software keystore by default or a PKCS#11 HSM or
smart card on supported standalone deployments. The root private key never
belongs on the online host.

## Portals and roles

The web application exposes separate experiences for four roles:

- **Administrator** — installation readiness, trust configuration, templates,
  privileged accounts, HSM and issuer operations, audit, and integrations.
- **Certificate Operator** — certificate requests, approvals, issuance,
  revocation, people/devices, delivery, and external service certificates.
- **User** — submits certificate requests and manages their issued material.
- **Auditor** — read-only operational and audit visibility.

`Certificate Operator` is the user-visible name. The internal role value,
configuration keys, asset names, and compatibility paths continue to use
`superuser`.

Administrators and Certificate Operators use distinct portals so reverse
proxies and network controls can restrict them separately. They currently run
in one FastAPI process and share the same database; separate UI paths are a
security boundary only when the operator enforces the corresponding proxy and
network policy.

## Issuance lanes

The application has two certificate lanes:

1. **Private-CA issuance.** A user or Certificate Operator submits a CSR or asks
   the server to generate a protected key. Template policy validates the
   subject, SANs, algorithm, usages, validity, and approval threshold. Once the
   required distinct approvals exist, the online issuer signs the certificate.
2. **External service certificates.** A Certificate Operator can generate a CSR,
   import PEM/PKCS#12 material, or register an account with an external ACME CA
   and request a publicly trusted certificate. The ACME client can renew managed
   certificates automatically.

Issued material is tracked in the SQL repository and can be exported in PEM,
DER, PKCS#7, or PKCS#12 formats. Secure claim links support holder delivery and
renewal workflows.

## Revocation and lifecycle

Revoking an internally issued certificate updates certificate state, the audit
log, CRL data, and enabled OCSP response data. New certificates embed the
configured CRL distribution, issuer AIA, and OCSP URLs; these values therefore
need stable public addresses before production issuance.

Scheduled lifecycle work covers expiry notifications, external ACME renewal,
and OCSP refresh. Notification channels include email, SMS through an HTTPS broker,
Slack, HTTPS/webhooks,
and configurable rules and templates.

## Storage and cross-cutting services

- SQLite is the default database; MariaDB/MySQL is supported for a shared
  database deployment.
- Configuration, secret files, software keys, and SQLite data live under the
  state directory. Administrators can create governed encrypted application
  backups containing the database and local recovery material; off-host storage
  and restore testing remain operator responsibilities.
- Authentication uses Argon2id passwords, role-configurable TOTP (recommended
  by default for Administrators and Certificate Operators), recovery
  codes/email recovery, sessions, and CSRF protection.
- The audit log is hash chained and can be forwarded to remote syslog.
- Licensing enforces configured issuance limits without gating revocation or
  other safety operations.

## Deployment choices

Docker and the standalone application both run myOwnCA for production or
Test/Lab installations. The **Test/Lab** install type is the evaluation-only
choice: it creates the automatic local Root + Sub CA hierarchy. For production,
complete the offline-root ceremony and place either deployment behind the
organization's TLS proxy; use the standalone application when a host-attached
PKCS#11 device is required. In either case, keep the setup listener private,
use stable portal and revocation URLs, protect the state store, and exercise
backup/restore before production issuance.

Future work includes an internal RFC 8555 ACME server, broader automation APIs,
governance coverage for additional trust-affecting settings, verified backup
automation, high availability, and a separate managed-SaaS product direction.
None of those future items should be assumed available in the current
self-hosted release.
