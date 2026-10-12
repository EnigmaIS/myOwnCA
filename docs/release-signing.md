# Signed releases and integrity verification

For the local private-repository → GitHub Releases/GHCR operator workflow, use
[release publishing](release-publishing.md). The protocol and trust model below
also describe its individual signing and verification operations.

Current public releases support Docker on Linux amd64 and ARM64 only. Standalone
publication and its acceptance gate are deferred. The low-level standalone install
and monitoring procedures below are retained for earlier releases and development;
they are not a supported installation path for current Docker release bundles.

Production deployments install a signed application wheel or an authenticated
container digest. Release checks are independent of CA keys, licence keys,
configuration, databases, and the application notification subsystem. A failed
check blocks installation or startup before migrations and issuer access.
Daily external failures alert operators without stopping an already-running CA.

These controls support PCI DSS deployments; they do not certify this product or
an installation. PCI DSS 4.0.1 requirement 11.5.2 requires critical-file change
detection, personnel alerts, and comparisons at least weekly. The supplied daily
jobs cover signed first-party application files. Operators must define and
monitor other critical files and maintain incident-response evidence.

## Trust boundary and initial provisioning

An independently authenticated verifier, release public key, operating system,
Python interpreter, and cryptography library form the verification trust base.
An attacker controlling the host can replace that trust base; application
self-checks do not prevent this. Protect these files with host-level integrity
monitoring, restricted administration, and read-only access for the CA account.

Obtain the initial public-key SHA-256 fingerprint and verifier artifact hash
through an authenticated channel independent of the download. Confirm both with
the release operator before provisioning. A key bundled with a download is not
proof that the download is authentic. No production key is embedded in source.

Install the separately built `myownca-release-tools` wheel and its authenticated
dependencies into a dedicated Python 3.12+ environment at
`/opt/myownca-verifier`. Keep it separate from the monitored application. It
contains only the release tooling and depends on `cryptography`, not the CA.
Its public trust store is `/etc/myownca-integrity/release-trust.json`.
Provision and verify these files under administrative change control.

The release tool uses RSA-4096, PSS with SHA-256/MGF1-SHA-256 and a 32-byte salt.
Signatures cover the exact JSON bytes prefixed with a fixed protocol domain.
Key identifiers are SHA-256 fingerprints of DER SubjectPublicKeyInfo. Detached
signatures are base64 in adjacent `.sig` files. Unsigned wheel RECORD hashes
alone are never treated as authenticity evidence.

## Release operator procedure

Use a dedicated release machine with restricted login and disk encryption.
Create the signing key once using the independently provisioned tools:

```sh
myownca-release keygen --private-key /secure/releases/signing.pem --trust-output /secure/releases/release-trust.json
```

The private key is encrypted PKCS#8 with owner-only permissions; the passphrase
is requested interactively and must not be placed in command arguments, CI,
environment files, or repositories. Keep the passphrase separate from the key.
Store an encrypted recovery backup separately; rehearse recovery with test keys.
Customer systems receive public keys only. Key creation is a release-operator
ceremony, not an installation task.

1. Check out the approved annotated release tag in a clean tree. Versioning
   remains derived from that tag. Review the full commit, run the required tests
   and static checks, and retain results with the release approval.
2. Build the application wheel with `python -m build --wheel`, and the verifier
   wheel with `python -m build --wheel ./release-tools`. Production sealing
   rejects development version strings. Never use version overrides for a real
   release.
3. Seal the application wheel into a new directory, retaining its filename:

   ```sh
   myownca-release seal-wheel --wheel dist/myownca-X.Y.Z-py3-none-any.whl --output bundle/myownca-X.Y.Z-py3-none-any.whl --commit FULL_GIT_COMMIT --license-public-keys /secure/releases/license-public-keys.json --private-key /secure/releases/signing.pem
   ```

   The required licensing input is `{"schema":1,"keys":{"KEY_ID":"BASE64_RSA4096_DER_SPKI"}}`.
   Supply a nonempty producer public-key ring with the existing licence key IDs.
   The sealer validates it and embeds it in the signed inventory; do not put a
   placeholder or private key in the package. Rotation requires a new sealed
   release with overlapping old and new licensing keys.

4. On each supported target platform, download the complete wheel-only runtime
   dependency closure into the bundle (`pip download --only-binary=:all:` with
   the sealed application wheel as input). Add the release-tools wheel to the
   bundle. Run `python scripts/releases/lock-wheelhouse.py bundle` to generate
   exact dependency pins and hashes. Dependencies without wheels must have
   reviewed wheels built ahead of this step; production never builds source
   distributions. Test installation using this exact wheelhouse.
5. For Docker, prepare a build context with `bundle/` and the authenticated
   public `release-trust.json`. Build with `Dockerfile.release`, test the final
   image, and push it to the intended registry. Record its immutable repository
   digest. Building and publishing require normal release approval; signing
   tools do not publish anything. Build the image before adding its digest to
   the release manifest, avoiding a circular dependency.
6. Sign the final bundle:

   ```sh
   myownca-release release --bundle bundle --version X.Y.Z --commit FULL_GIT_COMMIT --image ca=REGISTRY/IMAGE@sha256:IMAGE_DIGEST --private-key /secure/releases/signing.pem
   myownca-verify --json artifact --bundle bundle --version X.Y.Z --trust /secure/releases/release-trust.json
   ```

   Omit `--image` for a standalone-only bundle. The release signer validates the
   sealed wheel's version and commit before signing. Keep the signing output,
   artifact hashes, approver identity, tests, and verification results in the
   release record. Never rebuild or edit signed artifacts. Different platform
   wheelhouses need separate signed bundles.

The seal step inventories both application namespaces, portal assets, SQL
migrations, and release bootstrap code. It rewrites production console launchers
to disable unsigned bytecode before imports and checks integrity before entering
the CA. No private material is put into an artifact.

## Standalone installation and upgrades

Use the trusted external verifier, as an administrator, to install into a fresh
versioned environment. Keep mutable state outside that environment:

```sh
/opt/myownca-verifier/bin/myownca-verify --json install --bundle /srv/releases/X.Y.Z --version X.Y.Z --prefix /opt/myownca/X.Y.Z --trust /etc/myownca-integrity/release-trust.json
```

For an upgrade, additionally pass `--current-prefix /opt/myownca/current`.
The installer verifies the current baseline and rejects downgrades unless
`--allow-rollback` is also supplied. Installation never replaces an existing
prefix or switches a running service. Follow the backup and maintenance-window
procedure in [upgrade and rollback](upgrade-and-rollback.md), then change the
operator-managed `current` link/service path to the verified installation.

The installer stages and reverifies signed artifacts, uses offline hash-pinned
dependencies and `--no-compile`, verifies installed first-party files, and copies
the public trust store to `PREFIX/etc/myownca/release-trust.json`. Run the CA as
a separate unprivileged account with no write access to its environment. Failed
installs may leave an unused partial prefix; do not start or reuse it.

Missing signatures/trust, an unknown signer, modified or missing files, injected
files, symbolic links, or `.pyc`/`.pyo` files fail startup with exit code 78.
Use the sealed console commands. Direct Python invocations require `-B` and
still run the package guard. Do not run compileall against production code.

The producer licensing public-key ring is immutable signed application data.
Remove the obsolete `MYOWNCA_LICENSE_PUBLIC_KEYS` setting from every configuration
source before starting; even identical or empty overrides are rejected, including
in development. See [licensing](licensing.md#vendor-key-operations).

Mutable configuration, databases, operational keys, logs, and caches outside managed code
are excluded from the developer signature. Include relevant configuration,
generated console launchers, Python, third-party dependencies, and verification
tools in host integrity monitoring. Normal application backups do not substitute
for authenticated release artifacts.

## Docker deployment and external inspection

The existing Dockerfile/Compose stack is explicitly a development source build;
production uses `Dockerfile.release`. It runs as UID/GID 10001. Use the host-side
`deploy/integrity/deploy-image.sh BUNDLE VERSION TRUST_FILE STATE_VOLUME` helper
to verify the signed manifest, pull its digest, and create a replacement container
without starting it. Then configure the intended proxy/network and complete the
normal maintenance procedure before starting the replacement. The helper does
not remove a container or state volume and deliberately publishes no ports.

Use a read-only root filesystem and the dedicated state volume; do not mount
over code, executable, or trust-store paths. The supplied CA deployment drops all
Linux capabilities and sets `no-new-privileges` to prevent processes from gaining
additional privileges. These runtime restrictions do not prevent a host
administrator from overriding Docker settings or replacing the software; use the
independent verifier to check authenticity. No filesystem immutable flags are
required, and authenticated trust rotation remains available.
Keep the verified release bundle on the monitoring host. The external `container`
command verifies the image's
repository digest, rejects overlapping mounts, exports the container filesystem,
and checks first-party files without executing target code. This works for
stopped containers, including failed startup. Docker daemon access is privileged.
The inspector currently targets the supplied Python 3.12 production image layout.

## Daily monitoring and alert delivery

Templates in `deploy/integrity/` provide standalone and container systemd jobs.
For standalone monitoring, provision `myownca-monitor`, install the external
verifier, and adjust the root path for the deployed Python minor version. For
containers, configure `/etc/myownca-integrity/container.env` with
`MYOWNCA_CONTAINER`, `MYOWNCA_RELEASE_BUNDLE`, and `MYOWNCA_RELEASE_VERSION`.
Install and enable the corresponding timer, then run its service manually and
confirm an actual test alert before accepting the deployment.

Configure an operator-controlled HTTPS endpoint in an owner-restricted file:

```json
{"url":"https://monitoring.example.com/myownca-integrity"}
```

The endpoint must accept JSON POSTs. Redirects and plaintext HTTP are rejected.
The webhook URL is not written to logs; TLS verification remains enabled.
Failed checks generate an alert on each scheduled run. Delivery failure is
recorded locally and retried on the next failure run. External monitoring must
alert on `delivery_failed`, a failed systemd unit/startup, and a missing or
stale successful check (set a 26-hour threshold for the supplied daily timer).
The `myownca-verify --json freshness --file /var/lib/myownca-integrity/last-check.json`
command returns nonzero for missing, failed, stale, or future-dated checks; call
it from the independent monitoring system. It does not replace monitoring host
availability from outside that host.
Journal collection and the status file are the evidence sources; a local log
alone is not proof personnel were alerted.

JSON records contain UTC check time, operation, status, verified version/signer
when available, and failure details. Authentication failures do not label
untrusted metadata as an authenticated release. Keep logs/status directories
protected from the CA account. Readiness/incident procedures must verify timer
execution and downstream alert receipt, not just timer installation.

To inspect a failed installation without importing the application:

```sh
/opt/myownca-verifier/bin/myownca-verify --json installed --root /opt/myownca/current/lib/python3.12/site-packages --trust /etc/myownca-integrity/release-trust.json
```

Do not automatically stop a running CA after a scheduled failure. Investigate,
preserve evidence, and restore a clean signed release under incident control.
Do not suppress the guard or rebaseline altered files on customer machines.

## Key rotation and compromise recovery

For planned rotation, generate a new key separately. Prepare a new public trust
store with sequence incremented by one, retaining old keys while old supported
releases remain deployed. Authorize it with a currently trusted key:

```sh
myownca-release trust-update --new-trust new-trust.json --output trust-update.json --private-key /secure/releases/signing.pem
myownca-verify --json trust-update --trust /etc/myownca-integrity/release-trust.json --update trust-update.json
```

Apply the authenticated update to both the independent monitor trust store and
each installation's trust store before using the new signer. Replays and skipped
sequence numbers fail. Retire old trust only after confirming required rollback
releases remain verifiable and the rotation has been tested.

If a signing key is compromised, signatures from it cannot authorize recovery.
Stop release signing, identify affected artifacts, notify operators through the
independently authenticated channel, replace trusted keys under administrative
incident control, and reinstall a known-clean release signed with the replacement
key. Preserve evidence and review the release workstation and backup custody.

Operator-selected versions and explicit rollback protect the manual workflow.
This is not an automatic update-discovery system and does not claim TUF-style
freshness or resistance to a privileged operator installing an old release.

## Development and validation

Editable source checkouts remain available for development and emit a clear
development warning. Installed unsigned wheels fail closed. Tests use disposable
keys and isolated directories; no production key generation is performed by CI.

Run `pytest -q tests/test_release_integrity.py`, `ruff check src core tests`, the
application regression suite, and the sealed-wheel integration test before a
release. Verify clean and tampered production Docker images on a Docker host.
Reference: [PCI DSS documents](https://www.pcisecuritystandards.org/document_library/)
and [NIST code-signing guidance](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.01262018.pdf).
