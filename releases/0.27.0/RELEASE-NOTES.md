# myOwnCA v0.27.0

Source commit: `9c30747dc65f7de73d0630904a2222c286827ff3`.

## Batch import and certificate pre-generation

Certificate Operators can import People or Devices from CSV, review versioned
sessions, and pre-generate certificates with durable progress and reports. A valid,
installation-matched commercial licence is required. Every revision requires
approval by two distinct Certificate Operators, including in single-admin mode;
the second operator confirms the exact uploaded CSV bytes. Imports support up to
10,000 records and 10 MiB, create new holders, and reject existing-holder conflicts.
Processing supports checkpoint recovery, explicit retry, and audited cancellation.

## Other changes since installation release v0.17.2

- Replace person and device deletion with audited archiving. Archiving a Person
  disables the associated account and revokes its login sessions. Archived
  devices cannot receive certificate downloads or delivery.
- Add persistent bulk inventory operations, table pagination and status filters,
  and improve portal loading, session expiry handling, and import feedback.
- Permit reuse of archived People emails while preserving holder and account
  identity and certificate history.

## Upgrade and rollback

Take a matched state/database backup before upgrade. The release introduces
database migrations and compatibility changes to holder retirement workflows.
Before stopping the running service, run the target image's read-only
`myownca --state-dir /path/to/state upgrade check` against the existing state and
database configuration. Exit 1 reports conflicting active People emails; exit 2
reports an inspection failure. Resolve either before cutover. Active People
emails must be unique ignoring case; ambiguous account-to-Person associations
also prevent migration. Review active accounts already linked to archived People.

Apply migrations with a single service process. After migration, rollback requires
restoring the matched pre-upgrade state and database as well as the previous image;
reinstalling an older image alone is not a supported schema rollback.

## Distribution and verification

Signed installation bundles and prebuilt Docker Hub images support Linux amd64
and ARM64. Follow the public README's independent Git signature and bootstrap
authentication instructions, then the selected architecture's INSTALL.md. Compose
pins the authenticated multiarchitecture index digest. The public source snapshot
remains v0.12.5; it is published independently of installation releases.

Both images undergo installed-signature, dependency, and restricted offline
`--help` checks. No new full-suite validation or manual/native acceptance campaign
is performed as part of this publication; image builds do not establish native
production acceptance.
