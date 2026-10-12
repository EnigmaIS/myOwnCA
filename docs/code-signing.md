# Code signature verification

EnigmaIS publishes source snapshots as signed commits on the single `main`
branch. Each new release snapshot is appended to this independent public
history. The signed commit message identifies its private source revision:

```text
Source-Tag: vX.Y.Z
Source-Commit: FULL_PRIVATE_RELEASE_COMMIT
```

The current source snapshot is `v0.12.5`, exported from source commit
`910c9c7f4f7021e0e66b93c956a132ec9d8e3ffb`. The preceding `v0.12.4` snapshot
remains in the public commit history. The snapshot contains the tracked release
source except `archive/`, `AGENTS.md` and `TODO`. Code, licences and executable
modes retain their source Git blobs; customer-facing Markdown may be adapted.

Source inspection is governed by the existing [licence](../LICENSE). Docker
release manifests identify the exact source commit and image digest for each
deployment artifact. Production distributions continue to use the existing
release process.

## Public signing key

The dedicated SSH Ed25519 signing key belongs to the GitHub account
`Walkerovski`. Commits use the verified email `simon@enigmais.com`.
The private key remains with the publisher; Docker manifests use their separate
RSA release key.

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINDcnEPZNQYod/6cfWPfhFlv4RGVUQYBGDwemdOj1YQu
```

Fingerprint:

```text
SHA256:5AUWVXSc/LJNAkdlgPZhrqaLUdWPcEeU76dmtH7fABA
```

Confirm the fingerprint through an independently authenticated EnigmaIS channel
before trusting the downloaded key.

## Verify locally

SSH commit verification requires Git 2.34 or later and OpenSSH with SSH
signature support. GitHub describes its verification model in
[About commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification).

```sh
git clone --single-branch --no-tags --branch main \
  https://github.com/EnigmaIS/myOwnCA.git myOwnCA-sources
cd myOwnCA-sources

printf '%s\n' 'simon@enigmais.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINDcnEPZNQYod/6cfWPfhFlv4RGVUQYBGDwemdOj1YQu' \
  > .git/allowed_signers
git config --local gpg.ssh.allowedSignersFile "$PWD/.git/allowed_signers"

git verify-commit HEAD
git show --no-patch --format=fuller HEAD
```

Successful verification reports a good `git` signature for
`simon@enigmais.com` and the fingerprint above. For an older snapshot, select
its public commit SHA from the release record and run `git verify-commit
COMMIT_SHA`. Its signed message records the corresponding source tag and commit.
