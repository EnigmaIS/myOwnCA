# myOwnCA 0.17.2 — Docker on Linux amd64

This directory contains the signed verification and deployment material for the
prebuilt Docker Hub image. Docker on Linux amd64 and ARM64 are the supported release
targets. Wheels are included as image inputs and to bootstrap the independent
verifier; they are not a supported standalone application distribution.

Read the included `LICENSE` before use. EnigmaIS sp. z o. o. permits source
inspection and genuine noncommercial use within the 10-active-identity allowance.
All commercial use requires paid terms, even below the limit. Source modifications
and derivative versions are prohibited. Third-party components retain their own
licences. See https://enigmais.com/licensing/ for the policy summary and contact.

## Establish trust before running any downloaded code

Obtain the SHA-256 fingerprint of the release public key and the complete
`BOOTSTRAP-SHA256SUMS` file through an authenticated channel independent of this
download. The hashes use paths relative to the version directory (the parent of
this directory). Verify them there before executing anything. Verify the release
Git commit with the independently trusted developer key and confirm the checkout
is clean, as described in the main README. A checksum or public key downloaded
beside the files, by itself, does not authenticate them.

Use a trusted OS and Python 3.12. Keep the clone in an administrator-owned directory.
Provision the independently authenticated release-tools wheel from this directory
in its own environment, separate from the application:

```sh
python3.12 -m venv /opt/myownca-verifier
/opt/myownca-verifier/bin/python -m pip --isolated install --no-index --no-compile \
  --only-binary=:all: --find-links /absolute/path/to/bundle \
  /absolute/path/to/bundle/myownca_release_tools-0.17.2-py3-none-any.whl
```

Install the authenticated public trust file as
`/etc/myownca-integrity/release-trust.json`. Keep the verifier, its dependencies,
and trust anchors administrator-owned and protected from the CA account. Add the
verifier's `bin` directory to PATH. Before installation, run:

```sh
myownca-verify --json artifact --bundle /absolute/path/to/bundle \
  --version 0.17.2 --trust /etc/myownca-integrity/release-trust.json
```

## Docker

Docker Engine and Compose v2 are prerequisites. The Linux image runs on amd64 or
ARM64; use the package matching your Docker host. Do not build an image locally.
The signed Compose file pins the application and proxy by digest. The application
image is `docker.io/enigmais/myownca@sha256:a86092782058f61d38ca06017c2ee6f47b3cc65c37cd2ea8344b711cb0ed749f`.

The CA runs as an unprivileged user with a read-only root filesystem, all Linux
capabilities dropped, and `no-new-privileges` enabled. State stays writable in its
dedicated volume, with temporary files in `/tmp`. Keep these settings when adapting
the deployment. They restrict container processes; a host administrator can still
override them. The installed application and verifier wheels retain their licence
under their respective `.dist-info/licenses/LICENSE` directories.

Provide your proxy certificate and key at `tls/tls.crt` and `tls/tls.key` beside
`compose.yaml`, with restrictive permissions. For a **new installation only**,
create the state volume:

```sh
docker volume create myownca-state
```

Never replace/delete an existing state volume during upgrade. Back up the state
and stop the existing service in a maintenance window before replacement.

```sh
bash deploy-compose.sh /etc/myownca-integrity/release-trust.json
docker compose --project-name myownca --project-directory "$PWD" \
  --env-file /dev/null -f "$PWD/compose.yaml" start
```

Run these commands from the extracted bundle directory. The helper verifies and
creates containers without starting them. The setup listener is on host loopback
port 8765; use SSH forwarding for remote setup. Read the one-time token from
`docker compose --project-name myownca -f compose.yaml logs ca`, then complete
the wizard. The proxy serves HTTPS on 443; port 80 serves public CA endpoints and
the configured ACME challenge route. Setup access remains loopback-only.

Run the supplied external container-integrity service/timer on a Linux Docker
host with an authenticated verifier. Configure its bundle path, exact version,
actual container name, and webhook alert destination. The supplied daily monitor
does not stop an already-running CA on a failed check.

## Licences and monitoring

The application includes the producer's public licensing keys. Upload the signed
installation-bound token through **Admin → License**. Send the installation UUID
to your vendor when requesting a licence; a fresh database has a new UUID.
Without a licence, the free-tier limit applies. Never configure
`MYOWNCA_LICENSE_PUBLIC_KEYS`; any such setting is rejected.

The supplied daily integrity timers require administrator setup and an independent
HTTPS alert endpoint. Test actual alert delivery, and monitor missing/stale results
with `myownca-verify freshness` (26-hour threshold). Include Python, third-party
dependencies, launchers, mutable configuration and the verifier in host-level
integrity monitoring. Preserve signed release bundles for recovery and rollback.
