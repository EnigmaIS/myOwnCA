# Set Up myOwnCA

Both Docker and the standalone (bare-metal) application run the same setup
wizard. Use either one for a quick **Test/Lab** installation to see how the app
works, or for a properly prepared **Production** installation with an
externally managed, offline Root CA. The deployment method does not select the
trust model: **Test/Lab** is the evaluation-only workflow because it creates an
automatic local Root + Sub CA hierarchy; **Production** imports the public
certificate from your external Root CA and completes an issuing Sub CA ceremony.

Start one deployment path below, then follow the matching
[Test/Lab workflow](#testlab-workflow) or
[Production workflow](#production-workflow).

## Start with Docker

The supplied Compose stack deploys the same application for either a Test/Lab
or Production installation. The **Test/Lab** install type—not Docker—creates
the automatic, evaluation-only Root + Sub CA hierarchy. The supplied topology
is a single-host default using SQLite and the software keystore; it does not
include local PKCS#11 passthrough, high availability, or independent portal
network isolation. For production, provide the appropriate TLS proxy, database,
network controls, and backup/restore process. Use the standalone service when a
host-attached PKCS#11 device is required.

1. From the repo root:

```bash
cd /path/to/EnigmaIS
```

2. Make sure Docker Engine 24+ and Docker Compose v2 are installed.

3. Provide TLS material for nginx. For a quick Test/Lab installation, create a
   self-signed pair:

```bash
./scripts/gen-lab-cert.sh
```

For Production, provide the certificate and private key managed by your
organization's TLS proxy instead:

```text
tls/tls.crt
tls/tls.key
```

4. Build and start the stack:

```bash
docker compose up -d --build
```

5. Get the setup token:

```bash
docker compose logs ca
```

6. Open the setup wizard:

```text
http://127.0.0.1:8765/setup
```

Paste the token from the logs and continue with the selected workflow below.

## Start with the standalone application

1. Use Python 3.12+.

2. Create and activate a virtualenv:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
```

If `python3.12` is not available, use any `python3` that is version 3.12 or newer.

3. Install the app:

```bash
pip install .
```

For development from a checkout, use an editable install with the development
tools:

```bash
pip install -e ".[dev]"
```

All runtime integrations are included by the base install: PKCS#11, AWS KMS,
Azure Key Vault, DNS-01, and MariaDB/MySQL. The historical extras remain empty
compatibility aliases, so no second install command or build flag is needed.

If an older development virtualenv installed `./core` separately, recreate that
virtualenv before installing the updated application. The main and standalone
core wheels contain the same `myownca_core` namespace and are intended for
different environments, not side-by-side installation.

4. Start first-run setup:

```bash
myownca
```

5. Open the printed setup URL, normally:

```text
http://127.0.0.1:8765/setup
```

6. Complete the same browser wizard using the workflow below. After finalizing,
   the service normally listens on `http://127.0.0.1:8000/`. For Production,
   place it behind HTTPS and set secure cookies through the wizard/config.

## Test/Lab workflow

Use this path to explore myOwnCA without bringing an existing trust hierarchy.
It works with either Docker or the standalone application. It creates a local,
automatic Root CA and issuing Sub CA, so certificates from this hierarchy must
not be used as production trust material.

1. Open the one-time setup URL and enter its token.
2. Choose **Test/Lab** as the install type.
3. Keep **Single administrator** for the fastest evaluation, or choose **Dual
   control** to exercise the two-person administration flow. Review the TOTP
   policy; Administrator and Certificate Operator are enabled and recommended
   by default.
4. Use SQLite and local service URLs such as `https://127.0.0.1/` or
   `https://localhost/` when testing locally. Leave the offline Root CA field
   empty.
5. In the issuing CA step, select **Test/Lab — create local CA**, type
   `CREATE LAB CA`, and confirm. This creates the throwaway Root + Sub CA
   hierarchy.
6. Create the required bootstrap administrator account. Dual control requires a
   second, distinct administrator. Complete the wizard and sign in with the
   temporary password; enroll TOTP when required.

For Docker, open the application at `https://127.0.0.1/`. A browser warning is
expected when using the generated self-signed TLS certificate. For the
standalone application, use the service URL printed or configured for the
normal listener.

The automatic Test/Lab Root + Sub CA is intentionally not a production
substitute. To create a production hierarchy, start a new installation and use
the workflow below.

## Production workflow

Use this path with Docker or the standalone application when certificates will
be relied on outside an evaluation. Production setup uses an external,
offline-managed Root CA: import only its public certificate into myOwnCA and
keep the Root private key off the online host.

1. Prepare the deployment boundary before opening the wizard. Provide TLS,
   limit network access to the administrative portals, keep the setup listener
   private, protect the state store, and decide how backups and an isolated
   restore test will be performed. For Docker, replace the generated lab TLS
   pair with your operator-managed proxy certificate and key. For standalone,
   put the service behind the organization's TLS proxy and set
   `MYOWNCA_SESSION_COOKIE_SECURE=true`.
2. Prepare the external Root CA and its approved ceremony. You may use your
   organization's existing Root CA process or the provided
   [`docs/offline-root.md`](docs/offline-root.md) guide. Transfer only the Root
   certificate and the issuing-CA CSR/certificate between the offline and
   online environments; never transfer the Root private key.
3. Open the one-time setup URL, enter its token, and choose **Production**.
   Select the governance mode deliberately; **Dual control** is recommended and
   requires two distinct bootstrap administrators.
4. Select the database and issuing-key backend. Use MariaDB/MySQL when the
   deployment needs a managed external database. Docker can use the supplied
   software-key default and cloud signing keys; use the standalone application
   for a host-attached PKCS#11 device.
5. Set the stable public URLs for the Admin, Certificate Operator, and holder
   portals, plus the CRL, AIA, and OCSP endpoints. These issuance URLs are
   embedded in subsequently issued certificates, so set them before production
   issuance.
6. Import the public certificate of the external Root CA. Do not select
   **Test/Lab — create local CA**.
7. Provision exactly one issuing Sub CA. Usually, select **Create new key +
   offline ceremony**, copy the CSR, have the external Root sign it on the
   offline host, then import and activate the Root-signed Sub CA certificate.
   Existing Root-signed issuer material can instead be imported after its key
   backend is configured. Follow
   [`docs/issuer-setup.md`](docs/issuer-setup.md) for each supported path and
   its validation requirements.
8. Create the bootstrap administrator account(s), complete the wizard, then
   sign in and change all temporary passwords. Enroll TOTP for every role whose
   policy requires it.
9. Before issuing production certificates, complete the Production readiness
    checks, take a protected backup, and perform an isolated restore test as
    described in [`docs/backup-and-disaster-recovery.md`](docs/backup-and-disaster-recovery.md).

Production setup requires an explicit governance choice. Dual control is
recommended: one administrator proposes a privileged role grant or credential
reset and another approves it. Single administrator remains available for
installations that cannot staff two admins, with an explicit warning about the
missing second-person barrier. A later downgrade from Dual control is itself a
pending two-person change and does not take effect until a different admin
approves it. Dual control also keeps a two-active-administrator floor; if a
legacy install starts below that floor, reactivate its second administrator
before creating governed changes.

## First Production Sign-In

Open the Admin portal dashboard and work through **Production readiness** before
issuing production certificates. It checks the issuer, HSM policy, public
service URLs, CRL/OCSP publication, certificate templates, notification
delivery, audit forwarding, recovery evidence, and an issue/revoke exercise.
Each finding identifies the responsible role and links to the relevant Admin
portal setting; certificate lifecycle work remains in the separate Certificate
Operator portal.

Use **Record backup attestation** and **Record restore-test attestation** only
after completing the relevant operation. These append-only records remain human
attestations. For managed SmartCard-HSM keys, myOwnCA can create and verify a
signed DKEK recovery ZIP and perform a guarded restore; it does not persist the
ZIP or replace database/state backup procedures. Keep the package, restore
output, and ticket evidence in your normal protected operations system. See
`docs/hsm-dkek-recovery.md`.

Configuration screens identify whether values are saved, suggested, or sourced
from the environment. The HSM backend selected during setup is fixed for the
running service. Changing it requires an explicit issuer rotation or migration
workflow and a service restart.

Current protocol scope matters when planning integrations: OCSP is implemented
and served by myOwnCA when enabled. The built-in ACME support is an **outbound
client** for obtaining external certificates; myOwnCA does not yet provide a
private RFC 8555 ACME server for internal workloads. Managed SaaS and
multi-tenancy are a separate future direction, not options in this setup flow.

## Useful Commands

Check Docker logs:

```bash
docker compose logs -f ca
docker compose logs -f proxy
```

Run tests after Python setup:

```bash
python -m pytest -q
```

Run lint after installing dev extras:

```bash
ruff check src tests
```

Run the Docker smoke test only on a disposable stack:

```bash
./scripts/docker-smoke.sh
```

That script destroys the Docker state volume during cleanup.

## Important State Notes

Docker state lives in the named volume:

```text
myownca-state
```

That volume contains `config.toml`, `secrets/secrets.env`, the SQLite DB, setup
latch, and software keys. Back it up before treating the instance as real.

Standalone state defaults to:

```text
./var
```

Keep the [project overview](README.md), [full operator guide](docs/README.md),
and [Docker runbook](docs/docker.md) nearby.
