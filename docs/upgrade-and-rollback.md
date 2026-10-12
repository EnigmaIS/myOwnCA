# Upgrade and rollback

Production upgrades now use authenticated release bundles and fresh installation
prefixes. Follow [signed releases and integrity verification](release-signing.md)
before the operational steps below. Installed unsigned wheels fail startup;
editable source and the original Compose build are development workflows.

**Pre-launch audit format change:** audit hash format 2 requires a fresh
database; existing development databases need a separate reset. There is no
legacy audit migration for this change. See [audit integrity](audit-integrity.md)
before applying the general upgrade procedure below.

Upgrade one myOwnCA installation at a time and take a verified recovery point
first. The service applies numbered SQL migrations automatically during startup
before serving the application. Migration names are recorded in the database's
`schema_migrations` table.

There is no general schema-downgrade command. The supported rollback for an
unsuccessful upgrade is to restore the matched pre-upgrade state/database backup
and run the previously validated application build. The only narrow exception is
the documented stored-secret compatibility tool; see [configuration reference](configuration-reference.md#stored-secret-compatibility).

## Before upgrading

1. Read the release notes for the target revision and confirm its supported
   Python, database, proxy, and signing-backend requirements.
2. Schedule a maintenance window. Stop parallel application processes and
   background CLI jobs so exactly one process performs startup migrations.
3. Complete the backup procedure in [backup and disaster recovery](backup-and-disaster-recovery.md).
   For an external database, the state and database backups must represent the
   same point in time.
4. Record the current Root and Issuing Sub CA fingerprints, service URLs, health
   result, and application revision. Confirm that HSM or cloud-key access is
   available before beginning.
5. Test the target build against a restore copy when the upgrade includes a new
   database migration, key backend, or proxy change.

## Upgrade procedure

1. Stop the service cleanly. For Compose, stop the `ca` container; for a
   standalone deployment, stop its service manager unit. Keep the state and
   database available to the new process.
2. Install or build the target revision using the same deployment method. Do
   not replace `config.toml`, `secrets/secrets.env`, software-key files, or the
   database with files from a different installation.
3. Start one service process. Startup opens the configured database and applies
   each unapplied SQL migration in lexical filename order. A failed migration
   prevents normal startup; do not start a second instance to retry in parallel.
4. Check service logs for migration, key-backend, and secret-reencryption
   warnings. A stored-secret re-encryption sweep is deliberately non-fatal, but
   its warnings require investigation before treating the upgrade as complete.
5. Verify `GET /health`, login, issuer fingerprint, one CRL fetch, and—when
   enabled—one OCSP response. For a cloud backend, also check the administrative
   cloud-signing queue and provider access. Do not create throwaway certificates
   in the production trust domain merely as an upgrade test.
6. Run the report-only checks in [monitoring and operations](monitoring-and-operations.md)
   and preserve the upgrade record with the target revision and verification
   result. Include the `security permissions` report for existing installations;
   permission repair is explicit and should follow the documented maintenance
   procedure. Review any completed-setup secret-cleanup warnings in startup logs.

## Recover from a failed upgrade

Stop the target process before choosing a recovery path.

- **Startup or migration failure:** preserve the error logs and the failed
  state/database copy for investigation. Restore the matched pre-upgrade backup
  to an empty recovery location, restore the previous build, and validate the
  trust fingerprints and key access before returning traffic.
- **Post-start functional failure:** if the migration completed, do not assume
  that reinstalling an older build is safe. Restore the pre-upgrade state and
  database together, then run the previous build.
- **Provider or HSM access failure:** correct the provider identity, network
  path, or HSM readiness without changing trust material. If the key cannot be
  recovered, follow the relevant key-backend and incident procedures rather
  than attempting an unsupported Issuing Sub CA replacement.

## Stored-secret compatibility

`myownca-reencrypt-secrets` is a controlled compatibility tool, not a general
rollback mechanism. Its default is read-only. After taking a backup, use
`--execute` to convert stored secrets; `--execute --to-legacy` reverses only
that stored-secret format for an older build that supports it. It still requires
the correct `MYOWNCA_AUTH_ENCRYPTION_SECRET` and does not revert schema,
configuration, certificates, or key-backend changes.

See the command details in [configuration reference](configuration-reference.md#stored-secret-compatibility).
