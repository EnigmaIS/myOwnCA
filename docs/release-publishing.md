# Publishing signed releases from the private repository

The source repository stays private. A separate, independently initialized public
GitHub repository contains only customer documentation and release attachments.
GHCR contains the prebuilt application image. Never push the private repository's
branches, tags or history into the public repository. The two repositories may
use the same version tag name, but their tags point to different commits. The
signed release manifest records the private source commit.

Supported release targets:

| Target | Runtime |
| --- | --- |
| Docker | Linux amd64 and ARM64, Python 3.12 in the image |

Docker Desktop can run the Linux images. Both architecture ZIPs contain Docker
verification and deployment material; neither is a supported standalone application
distribution. The wheels remain image inputs and provide the independent verifier.
Standalone publication and acceptance are deferred. Existing low-level installation
tools remain available for earlier releases and development.

Use the operator script from the same source tag as the release workspace. Do not
process an older three-target workspace with the current Docker-only publisher.
No licence format, database schema or development-checkout behavior changes are
needed for this distribution model.

## Operator prerequisites and custody

Use a trusted Python 3.12+ operator environment containing `build` and the
independently provisioned `myownca-release-tools` package. The operator script is
`python scripts/releases/release.py`; use its `--help` for each command. Docker
with Buildx, Git and authenticated GitHub CLI (`gh`) are required for publication.
Authenticate Docker to GHCR separately. Production keys never go to GitHub, Docker
build contexts, CI, or customer machines. Signing prompts for the release-key
passphrase; licensing uses its separate producer key.

Initialize a **new** public GitHub repository with a customer README and an
independent Git history. Do not clone/push the private repository to initialize
it. The publisher checks that the selected public tree contains only README,
CHANGELOG, SECURITY, LICENSE, `.gitignore`, and Markdown beneath `docs/`.
Give the publishing identity access only to the intended public repository and
GHCR package. Set the GHCR package public and link it to this public repository;
package visibility is separate from repository visibility. Check anonymous pulls.

Obtain immutable, multiarchitecture image references for Python 3.12 (Debian
bookworm) and nginx. Pass
their reviewed `name@sha256:DIGEST` values as `--base-image` and `--proxy-image`.
The script records them; it never silently resolves a floating base tag.

The release operator and acceptance records are trusted inputs. Records document
tests performed by the operator; they are not remote attestation or proof against
an operator fabricating results. Keep the release workstation and evidence secure.

## Validate the commit, then approve the tag

Finish and commit the implementation; validation refuses dirty trees, including
untracked files, shallow history and SCM version overrides. Configure an isolated
MariaDB test service with `MYOWNCA_TEST_MARIADB_ADMIN_URL`, then run:

```sh
python scripts/releases/release.py validate --repo /private/myOwnCA \
  --output /secure/releases/validation
```

This clones the exact commit into temporary storage, installs its test environment,
runs Ruff and the full suite, and preserves logs/JUnit results. Packaging and real
sealed-wheel tests must actually run, not skip. Review all other skips and any
platform-specific checks before approval. Validation never creates a tag.

Use `propose-tag --repo /private/myOwnCA --bump minor --subject
'feat(setup): add signed release publishing'` to print the proposed SemVer
transition, exact tag and release subject without creating a tag. Present this
proposal to the developer. After explicit approval, create the annotated tag on the validated
commit. Release versioning remains exclusively `setuptools-scm`; never edit a
source version or set a `SETUPTOOLS_SCM_PRETEND_*` variable for a real release.
The selected commit must be reachable from current `origin/master`.

## Prepare, seal, and build

Choose a new workspace **outside the source repository**. Examples use `X.Y.Z`
and `OWNER/REPO` placeholders; replace them with approved values.

```sh
python scripts/releases/release.py prepare --repo /private/myOwnCA \
  --tag vX.Y.Z --validation /secure/releases/validation \
  --work /secure/releases/X.Y.Z --public-repo OWNER/REPO \
  --image ghcr.io/owner/myownca \
  --base-image python:3.12-slim-bookworm@sha256:REVIEWED_DIGEST \
  --proxy-image nginx@sha256:REVIEWED_DIGEST

python scripts/releases/release.py seal --work /secure/releases/X.Y.Z \
  --private-key /secure/keys/release.pem --trust /secure/keys/release-trust.json \
  --license-public-keys /secure/keys/license-public-keys.json
```

`prepare` fetches `origin/master` and tags, checks the tag and validation evidence,
then builds application and verifier wheels from an isolated checkout. `seal`
embeds the licensing public ring and verifies the resulting signature against the
explicit trust file. The source checkout remains private in the release workspace.

Run both commands below for **each** architecture (`amd64`, then `arm64`):

```sh
python scripts/releases/release.py wheelhouse --work /secure/releases/X.Y.Z --arch amd64
python scripts/releases/release.py build-image --work /secure/releases/X.Y.Z --arch amd64
```

Wheel download runs inside the pinned target-platform Python image. It permits
only wheels and creates an exact hash lock. If a dependency has no supported wheel,
build and review it on a matching target first, then pass its directory with
`wheelhouse --wheels /secure/reviewed-wheels/amd64`. No source build runs on a
customer machine. Never remove integrations merely to make resolution pass.
Buildx emulation may prepare an image; it does not replace native acceptance.

The minimal Docker context contains only wheels, the dependency lock, public trust
and `Dockerfile.release`. An initial offline, read-only `--help` smoke test must
pass with all Linux capabilities dropped and `no-new-privileges` enabled. The
production CA Compose service and direct deployment helper use the same restrictions.
The image is identified by its recorded local image ID, not just its tag.

The root `LICENSE` is the canonical EnigmaIS Source-Available Licence. Keep
`release-tools/LICENSE` identical for the independently packaged verifier.
Both wheels carry the full text, retained in installed `.dist-info/licenses/LICENSE`
files inside the image. Signing also copies the canonical licence into each
bundle as `LICENSE`, covered by the release signature. Review the licence before
the first public distribution and copy that approved text to the independent
public repository. Preserve third-party licences and notices.

## Push images and sign the final bundles

Review the local image tests before explicitly publishing image candidates:

```sh
python scripts/releases/release.py push-images --work /secure/releases/X.Y.Z
python scripts/releases/release.py sign --work /secure/releases/X.Y.Z \
  --private-key /secure/keys/release.pem
```

This pushes architecture tags and creates `X.Y.Z` as a multiarchitecture image.
Existing registry tags are refused. The final digest is included in each signed
bundle, along with the proxy digest and customer deployment files. The registry
push necessarily precedes final manifest signing; publication across GHCR and
GitHub Releases is **not atomic**. A candidate image may be visible before the
GitHub release is approved. Treat GitHub Releases as the supported-release catalog.

Commands refuse to overwrite completed output. After a partial failure, preserve
the workspace and evidence, inspect which remote writes succeeded, and resolve the
incomplete candidate under operator control. Do not retag a different image over
an existing release or use upload `--clobber`. Never rebuild an accepted artifact.

## Native acceptance and publication gates

Copy the exact signed bundle and authenticated verifier to clean native test hosts.
Test Docker on native Linux amd64 and ARM64 using isolated, disposable CA state
and the exact published image digest. The host-side verifier requires Python 3.12+
and authenticated dependencies. Keep test licence private keys off customer/public
artifacts; an installation-bound acceptance licence is issued separately by the
producer.

For each target, perform and retain evidence for all these checks:

```json
{
  "fresh_install": true,
  "setup": true,
  "restart_preserves_state": true,
  "certificate_issuance": true,
  "valid_license": true,
  "wrong_installation_license_rejected": true,
  "tampered_code_rejected": true,
  "tampered_license_keys_rejected": true,
  "missing_signature_rejected": true,
  "upgrade": true,
  "explicit_rollback": true,
  "external_integrity": true,
  "wrong_image_digest_rejected": true
}
```

Both Docker targets require every check above. There is no standalone record or
`offline_install` field in the current release workflow. These are manual acceptance
results, not switches to skip tests. Collect actual command output, HTTP checks,
licence/certificate results and state-recovery evidence in a flat directory.
Do not include private keys, tokens, production state or credentials in logs.
Test tampering on disposable copies; the release bundle remains unchanged.
Test the Compose proxy, mounted state and external image inspector as well as
direct application startup. The inspector must accept the pinned multiarchitecture
digest on each platform and reject a substituted image or overlapping code mount.

Record results **on the native host** (the command checks OS and architecture):

```sh
python scripts/releases/release.py record-acceptance \
  --target docker-amd64 --bundle /test/bundle --version X.Y.Z \
  --trust /test/release-trust.json --operator 'Release operator' \
  --results /test/results.json --evidence /test/evidence --output /test/acceptance
```

Repeat with `docker-arm64` and its matching bundle. Copy the two resulting target
directories into `/secure/releases/acceptance`. Records bind the checked manifest,
version, commit and evidence hashes. Changed bundles or logs invalidate acceptance.
The operator script and its environment belong on test/operator hosts only.

```sh
python scripts/releases/release.py verify --work /secure/releases/X.Y.Z \
  --acceptance /secure/releases/acceptance
python scripts/releases/release.py stage --work /secure/releases/X.Y.Z \
  --acceptance /secure/releases/acceptance --notes /secure/releases/release-notes.md
```

`stage` creates a draft in the explicitly selected public repository, targeting
its independent documentation commit. It uploads only two architecture ZIPs,
`release-trust.json` and `BOOTSTRAP-SHA256SUMS`; no source archives, standalone core
wheel, issuer or private-repository Git refs are published. The application wheel
naturally contains its runtime Python code. GitHub's generated source downloads
contain only the public documentation repository.

The publisher downloads the draft attachments and compares their bytes with the
accepted bundles. Review the draft notes and attachments, then explicitly publish:

```sh
python scripts/releases/release.py publish --work /secure/releases/X.Y.Z \
  --acceptance /secure/releases/acceptance
```

Publishing repeats acceptance and remote-byte checks, then automatically downloads
the public assets without credentials and pulls both architectures using an empty
Docker credentials directory. It checks the exact accepted bytes and image digest.
If this post-publication check fails, the release is already public; fix visibility
or connectivity and rerun `audit-public --work /secure/releases/X.Y.Z`. It never
silently deletes or unpublishes the release. Independently repeat the customer
verification/installation procedure as the final rollout check.

Supply customers the public-key fingerprint and complete bootstrap checksums
through an independently authenticated channel. The archive hash authenticates the
initial verifier wheel and all its dependencies before they are executed. A key or
checksum merely attached to the same download does not establish initial trust.

## First rollout and recurring operations

Rehearse the complete process with disposable keys and a separate public test
repository/GHCR package before the first customer release. Keep validation and
acceptance evidence, tag approval, signed artifacts, digests and release notes in
the private release record. Rotate release trust using the existing authenticated
trust-update protocol; rotate licence keys through a new sealed application with
overlapping public keys. Test daily integrity timers and real alert delivery.

The private CI continues producing **unsigned build candidates**, never customer
releases. It tests release tooling using disposable keys; it does not receive
production private keys or publish from ordinary branch pushes.
