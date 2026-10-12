# Configuration reference

The setup wizard is the supported way to create an installation. This reference
describes the configuration it writes and the launch-time overrides available
to an operator. It is not a substitute for the wizard's issuer validation: a
manually prepared configuration still has to complete the one-time setup
workflow with exactly one valid Issuing Sub CA.

## Files, precedence, and restart behavior

The `myownca` launcher reads these locations below `MYOWNCA_STATE_DIR` (default
`./var`):

- `config.toml` — non-secret settings in an `[env]` table;
- `secrets/secrets.env` — secret values, mode `0600`, in a mode-`0700` directory;
- setup state and completion latch; and
- software keys and the default SQLite database when configured there.

Values have this precedence: process environment, then `secrets/secrets.env`,
then `config.toml`. Only `MYOWNCA_*` environment variables participate. Values
in `config.toml` must be quoted strings, even for booleans and numbers.

`myownca-online` reads its process environment directly; use the `myownca`
launcher when the state-directory files should be loaded automatically. Settings
are read at process start, so restart the service after changing an environment
variable, either file, a provider credential, or a TLS file path unless a guide
explicitly states that the corresponding portal setting is live.

Console scripts also read their process environment directly. `myownca-notify-run`
prefers `MYOWNCA_DATABASE_URL`, falling back to `MYOWNCA_DATABASE_PATH`. The
report-only `myownca-acme-renew` command still uses only `MYOWNCA_DATABASE_PATH`; see
[monitoring and operations](monitoring-and-operations.md#scheduled-work) before
scheduling them for a MariaDB/MySQL installation.

Never place private keys, passwords, tokens, database URLs containing passwords,
or cloud client secrets in `config.toml`, deployment manifests committed to Git,
or logs.

### Live expiry notification settings

Admins configure **Notifications & integrations → Automatic rule checks**;
Superusers configure **Settings → Notification rules → Automatic rule checks**.
Automatic checks default to **off**, with a cadence of **1 day**. Both controls
save shared database settings and take effect immediately without a restart.
There are no environment overrides for these settings.

**Check every** accepts a positive whole-number duration in seconds, minutes,
hours, or days, up to 2,147,483,647 seconds. This controls how often due rules are
checked, not how often a rule may notify. See [scheduled
work](monitoring-and-operations.md#expiry-notification-scheduling) for startup,
catch-up, failure, and cron migration behavior.

`GET /internal/notifications/schedule` returns `enabled` and `interval_seconds`.
`PUT` requires both fields (a boolean and a positive integer number of seconds)
and saves them atomically. Both endpoints require Admin or Superuser access;
updates also require CSRF protection and are audited.

## State, launch, and TLS

| Setting | Default | Meaning |
| --- | --- | --- |
| `MYOWNCA_STATE_DIR` | `./var` | State root selected by the launcher; set it in the process environment or pass `myownca --state-dir`. |
| `MYOWNCA_DATABASE_PATH` | `./var/myownca.sqlite3` | SQLite database path when no database URL is set. |
| `MYOWNCA_DATABASE_URL` | unset | MariaDB/MySQL SQLAlchemy URL; secret when it embeds credentials. |
| `MYOWNCA_BIND_HOST` / `MYOWNCA_BIND_PORT` | `127.0.0.1` / `8000` | Normal online-service listener. Invalid or out-of-range ports fall back to `8000`. |
| `MYOWNCA_SETUP_HOST` / `MYOWNCA_SETUP_PORT` | `127.0.0.1` / `8765` | First-run wizard listener. Keep it loopback-only unless an isolated deployment boundary controls access. |
| `MYOWNCA_SETUP_TOKEN` | generated for a wizard run | Optional one-time setup token. Treat it as a secret and remove it after setup. |
| `MYOWNCA_SESSION_COOKIE_SECURE` | `false` | Marks session cookies `Secure`; set `true` when a TLS proxy serves clients. |
| `MYOWNCA_TLS_CERT` / `MYOWNCA_TLS_KEY` | unset | Certificate and private-key paths for direct HTTPS. Set both or neither; the service refuses a half-configured pair. To serve the portal TLS certificate selected in the operator portal, point these at `<state>/tls/portal.crt` and `<state>/tls/portal.key`; see [serving the portal TLS certificate](#serving-the-portal-tls-certificate). |

### Deployment type in first-run setup

The wizard requires an explicit deployment type. **Bare metal** selects Direct
service and writes `MYOWNCA_BIND_HOST` and `MYOWNCA_BIND_PORT` to `config.toml`;
its defaults are `127.0.0.1:8000`. **Docker + Reverse Proxy Bundle** selects the
supplied Docker Compose/nginx topology, where deployment networking controls the
listener and the wizard writes no bind settings.

For Bare metal, **Serve direct HTTPS** accepts absolute paths to an existing PEM
certificate (leaf followed by any chain) and its matching unencrypted private
key. Setup requires both readable regular files, validates the pair and writes
`MYOWNCA_TLS_CERT`, `MYOWNCA_TLS_KEY`, and
`MYOWNCA_SESSION_COOKIE_SECURE=true`. It does not generate certificates or
reload the service; changing certificate material still requires a restart.

This choice applies only to the online service started after setup. It never
changes the currently running setup listener (`MYOWNCA_SETUP_HOST` / port
`8765`). Process environment values continue to override `config.toml`. In the
supplied Docker deployment, the container and nginx configuration control the
application and public listeners respectively; use the proxy on ports 80/443
rather than exposing the setup listener.

### Serving the portal TLS certificate

A Certificate Operator can select a managed external certificate as the portal
TLS certificate (Certificate Operator portal, External Certs, **Use as portal
TLS**). myOwnCA then writes the pair to stable paths under the state directory:

- `<state>/tls/portal.crt` — leaf certificate followed by its chain;
- `<state>/tls/portal.key` — unencrypted private key, mode `0600`.

Selecting a certificate only writes these files. It never enables HTTPS,
restarts the service, or reloads a proxy; a listener has to be pointed at them.
The files are rewritten when the certificate is renewed and re-materialized on
every start, so the paths stay valid across restarts.

To serve them from myOwnCA itself, add to the `[env]` table of `config.toml`:

```toml
[env]
MYOWNCA_BIND_HOST = "0.0.0.0"
MYOWNCA_BIND_PORT = "8000"
MYOWNCA_TLS_CERT = "<state>/tls/portal.crt"
MYOWNCA_TLS_KEY = "<state>/tls/portal.key"
MYOWNCA_SESSION_COOKIE_SECURE = "true"
```

Restart the service to apply. To terminate TLS at a reverse proxy instead, point
`ssl_certificate` and `ssl_certificate_key` at the same two files, reload the
proxy, and leave `MYOWNCA_BIND_HOST` at `127.0.0.1` so only the proxy can reach
the application; see [reverse proxy
deployment](reverse-proxy-deployment.md). Set
`MYOWNCA_SESSION_COOKIE_SECURE` in both shapes, because clients are on HTTPS
either way.

Select the certificate before pointing a listener at the paths. A listener
configured against files that do not exist yet will not start.

Four failures in this area have no obvious symptom:

- `MYOWNCA_SESSION_COOKIE_SECURE = "true"` while the service still answers over
  plain HTTP stops the browser returning the session cookie, so login fails with
  no error explaining why.
- The certificate has to cover the address operators actually browse to. One
  issued for a hostname does not validate against an IP address unless that
  address is a SAN.
- A certificate issued by this CA is untrusted until the root certificate is
  installed in the client trust store.
- A running process reads its certificate once at start. After a renewal,
  restart the service or reload the proxy; until then the previous certificate
  is still served.

Changing `MYOWNCA_BIND_HOST` from `127.0.0.1` to a network address exposes the
portals to that network. Until TLS is serving, administrator passwords, TOTP
codes, and session cookies cross it in the clear, so make both changes in the
same maintenance window.

## Bootstrap, issuer, and key stores

| Setting | Default | Meaning |
| --- | --- | --- |
| `MYOWNCA_LAB_MODE` | `true` | Enables disposable Test/Lab defaults. Production must use a unique authentication secret. |
| `MYOWNCA_LAB_COMMON_NAME` | `myOwnCA Lab Issuing CA` | Subject for the automatic lab issuer. |
| `MYOWNCA_GOVERNANCE_MODE` | unset | Fresh-install seed: `single_admin` or `dual_control`. Later approved governance changes are stored in the database and are not overwritten on restart. |
| `MYOWNCA_TOTP_REQUIRED_ROLES` | unset | Fresh-install TOTP policy: comma-separated `admin`, `superuser`, `auditor`, and/or `user`; an empty value disables it for all roles. |
| `MYOWNCA_ONLINE_KEY_DIR` | `./var/online-keys` | Software issuer-key directory. |
| `MYOWNCA_ONLINE_KEY_PASSPHRASE` | unset | Software issuer/service-key passphrase; secret. |
| `MYOWNCA_SERVICE_KEY_DIR` | `./var/service-keys` | Software service-certificate key directory. |
| `MYOWNCA_AUTH_ENCRYPTION_SECRET` | development placeholder | High-entropy secret protecting stored credentials, TOTP material, recovery values, and audit-related secrets. The wizard generates it; production startup refuses the placeholder. |
| `MYOWNCA_ENTROPY_SOURCE` | unset | Optional external entropy source mixed into software key generation. |

The Root and Issuing Sub CA are not normal runtime settings. Their trust
material is established in setup and remains read-only after completion; do not
attempt to replace it by editing these files.

## Local HSM and cloud signing

| Setting | Default | Meaning |
| --- | --- | --- |
| `MYOWNCA_HSM_BACKEND` | `software` | Issuer backend: `software`, `pkcs11`, `aws_kms`, or `azure_key_vault`. |
| `MYOWNCA_PKCS11_LIB` | auto-detected | PKCS#11 module path. |
| `MYOWNCA_PKCS11_TOKEN_LABEL` | `myOwnCA` | Token label for local PKCS#11. |
| `MYOWNCA_SC_HSM_TOOL` / `MYOWNCA_SC_HSM_READER` | `sc-hsm-tool` / unset | SmartCard-HSM tool path and optional reader selector. |
| `MYOWNCA_PKCS11_DKEK_SHARE_DIR` | `./var/dkek-shares` | Local directory holding imported SmartCard-HSM DKEK shares. |
| `MYOWNCA_SERVICE_KEY_BACKEND` | `software` | Default service-certificate key backend. It must be `software` or match the issuer backend. |
| `MYOWNCA_AWS_REGION` | unset | AWS KMS region. |
| `MYOWNCA_AWS_ACCESS_KEY_ID`, `MYOWNCA_AWS_SECRET_ACCESS_KEY`, `MYOWNCA_AWS_SESSION_TOKEN` | unset | AWS credentials; all are secrets. |
| `MYOWNCA_AZURE_VAULT_URL`, `MYOWNCA_AZURE_KEY_PROTECTION` | unset / `hsm` | Azure Key Vault URL and `standard` or `hsm` key protection choice. |
| `MYOWNCA_AZURE_TENANT_ID`, `MYOWNCA_AZURE_CLIENT_ID`, `MYOWNCA_AZURE_CLIENT_SECRET` | unset | Azure application credentials; secrets. |

The [cloud signing-key runbook](cloud-key-providers.md) defines provider
permissions, credential rotation, and failure handling. The [DKEK runbook](hsm-dkek-recovery.md)
defines local hardware recovery material.

## Automation and service URLs

| Setting | Default | Meaning |
| --- | --- | --- |
| `MYOWNCA_ACME_AUTORENEW` / `MYOWNCA_ACME_RENEW_INTERVAL_SECONDS` | `true` / `86400` | Enable and schedule in-process external ACME renewal. |
| `MYOWNCA_OCSP_AUTO` / `MYOWNCA_OCSP_REFRESH_INTERVAL_SECONDS` | `true` / `86400` | Enable and schedule OCSP refresh. |
| `MYOWNCA_ADMIN_BASE_URL` | unset | Initial Admin portal base URL; does not control the listener. |
| `MYOWNCA_SUPERUSER_BASE_URL` | unset | Initial Certificate Operator portal base URL; does not control the listener. |
| `MYOWNCA_FRONTEND_BASE_URL` | unset | Initial holder portal base URL; does not control the listener. |
| `MYOWNCA_CRL_URL`, `MYOWNCA_AIA_URL`, `MYOWNCA_OCSP_URL` | unset | Initial public revocation/issuer service URLs. |
| `MYOWNCA_LICENSE_PUBLIC_KEYS` | removed | Forbidden in all configuration sources, including development; any occurrence blocks startup. Licensing keys are embedded in the signed release. |

The six service URL values seed only previously unset database settings on first
boot. Later portal edits take precedence and a restart does not overwrite them.
Use the portal to change a configured public URL and plan the certificate-policy
impact before issuing certificates with a new endpoint.

## Stored-secret compatibility

`myownca-reencrypt-secrets` reads the same database and authentication secret as
the service. It reports only by default. Use `--execute` after a backup to
convert stored secrets to the current domain-separated format. `--execute
--to-legacy` reverses only that format so an older compatible build can read the
secrets again; it is not a database or application rollback. See
[upgrade and rollback](upgrade-and-rollback.md).

`myownca-key-cleanup` is also read-only by default. Passing `--execute` may
delete explicitly registered due private keys; review its output and follow
change control before using it.
