# myOwnCA

Production releases use signed, prebuilt Docker images for Linux amd64 and ARM64.
Standalone publication is deferred. See
[release signing and integrity verification](docs/release-signing.md) for
authenticated container deployment, startup enforcement, daily external
monitoring, and release-key custody. Editable source installs and the original
Docker Compose stack are development workflows.

**A private, self-hosted Certificate Authority for small businesses and home labs —
browser-driven, offline-root-capable, and free for genuine noncommercial use.**

myOwnCA replaces manual PKI with a guided web app while keeping a production-grade
operating model: an air-gapped offline root, online issuing sub-CAs, four-role
separation, install-level Single administrator or Dual control governance,
configurable certificate-approval quorum, PKCS#11 / smart-card key protection,
AWS KMS and Azure Key Vault signing keys,
an outbound ACME client for external certs, **automatic email expiry
reminders and certificate renewal**, **many export formats** (PEM · DER ·
PKCS#7 · PKCS#12/PFX), a tamper-evident audit log, and CRL/OCSP revocation
status. A first-run web wizard does the configuration for you.

![myOwnCA feature map](diags/feautures.png)

## Quick start

**Docker:**

```bash
./scripts/gen-lab-cert.sh          # lab TLS for the proxy (or supply your own)
docker compose up -d --build
docker compose logs ca             # read the one-time setup URL + token
# browse http://127.0.0.1:8765/setup and complete the wizard
```

**Source development (Python 3.12+):**

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .                   # development checkout; production uses signed releases
myownca                            # prints a setup URL + token on first run
```

Both development workflows finish in the same browser-based setup wizard.
Production uses the [signed release workflow](docs/release-publishing.md),
with a prebuilt Docker image and a signed verification/deployment bundle. Docker
supports production and Test/Lab installations; the **Test/Lab** install type—not
Docker—creates an automatic, evaluation-only Root + Sub CA hierarchy. The
supplied Compose configuration is a single-host default using SQLite and
software-held keys. It does not include local PKCS#11 passthrough, high
availability, or independent portal network isolation; adapt the surrounding
deployment for production. Host-attached PKCS#11 deployments need a separately
validated integration and are not supplied by this Docker release. The wizard
provisions and activates the first issuing Sub CA before it permits **Finish setup**;
Root/Sub CA trust material is
read-only after first launch.
**Full documentation, architecture, security model, configuration, and the
offline-root ceremony:**
[`docs/README.md`](docs/README.md).

Current scope is self-hosted and single-installation. OCSP is implemented; ACME
support is an outbound client for external CAs, not a private ACME server.
Managed SaaS is a separate future product direction.

## Architecture

![myOwnCA architecture](diags/architecture.png)

## Project layout

- `src/myownca/` — the single application distribution: online service, offline
  CLI, CA core, auth, software/PKCS#11/AWS/Azure HSM backends, cloud signing,
  storage, ACME + DNS-01, MariaDB, notifications, audit, licensing, holder
  portal, setup, and lifecycle automation. All runtime modules are installed by
  `pip install .`; no feature extra is required.
- `core/myownca_core/` — shared storage, key-generation, and leaf-building
  primitives. They are bundled in the main `myownca` wheel; `core/pyproject.toml`
  can still build the standalone `myownca-core` wheel for DeviceCA. The two
  distributions target separate environments and should not be co-installed.
- `docs/` — [full operator guide](docs/README.md), the
  [Docker runbook](docs/docker.md), the
  [cloud-key runbook](docs/cloud-key-providers.md), the
  [offline Root ceremony guide](docs/offline-root.md), and
  [licensing operations](docs/licensing.md), plus backup, upgrade, monitoring,
  incident-response, configuration, reverse-proxy, and certificate-lifecycle
  runbooks.
- `diags/` — architecture & feature diagrams.
- `tests/` — the test suite (`python -m pytest -q`).

## License

Source-available under the [EnigmaIS Source-Available Licence 1.0](LICENSE),
copyright EnigmaIS sp. z o. o. Source inspection is permitted; source modifications
and derivative versions are prohibited. Genuine noncommercial use is free within
the 10-active-identity allowance. Every commercial use, including commercial
evaluation, requires paid terms even below that limit. Normal settings, supported
APIs, and deployment configuration remain permitted. Internal deployment and backup
copies are allowed; redistribution requires written permission. Share official
download links instead. Third-party components retain their own licences.
See [Licensing](docs/README.md#licensing) for offline customer licence operation.
