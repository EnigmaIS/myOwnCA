# myOwnCA v0.17.2

This release provides signed Docker installation files for Linux amd64 and ARM64
and matching `docker.io/enigmais/myownca:0.17.2` images. The included Compose files
pin the authenticated multiarchitecture image digest and the proxy digest.

The independent container verifier now recognizes Docker Hub references both
with and without the `docker.io/` prefix. Repository names and SHA-256 digests
must still match. Changed application files, licensing trust, image digests and
mounts that obscure application code remain rejected.

Runtime images use the reviewed Debian Trixie base and exclude pip, ensurepip and
the build wheelhouse. The installation bundles retain the authenticated wheels
needed to bootstrap the independent verifier. They support Docker deployment;
they are not a standalone application distribution.

Before running downloaded code, authenticate the Git commit using an independently
trusted developer signing key and authenticate the bootstrap hashes and release
trust through an independent channel. Follow the architecture-specific INSTALL.md.
Back up existing CA state and plan an explicit rollback before upgrading.

ARM64 acceptance for v0.17.2 is authorized under emulation on a Linux amd64 host.
Native ARM64 testing is deferred until after publication and remains outstanding.
This exception does not waive any required acceptance scenario or apply to future
releases.

The source snapshot retained on public main remains v0.12.5. This publication adds
the v0.17.2 installation release without exporting a new source snapshot.
