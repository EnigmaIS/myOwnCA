# Backup and disaster recovery

myOwnCA creates a portable encrypted backup of the application database,
configuration, required local secrets, and software crypto material. It does not
store the downloaded archive, verify off-host custody, or claim that a restore
has been exercised. Test this runbook before production issuance.

## Recovery objectives and custody

Set the installation RPO and RTO before choosing a backup schedule. Application
backups are manual in this release. Keep a dated recovery record containing the
archive filename and SHA-256, application release, Root and Issuing Sub CA
fingerprints, database target, storage location, and isolated restore-test result.

Every archive has two passphrase shares. The requesting administrator creates
share A; the approving administrator creates share B and receives the download.
Neither share is recoverable from myOwnCA. Keep the archive and both shares in
separate protected locations and do not put either share in the recovery record.

## Included material

The versioned `.myownca-backup` archive contains:

- every application table and row in a database-neutral logical format;
- application version, migration fingerprint, row counts, file hashes, and CA
  fingerprints;
- effective portable configuration and the secrets required to decrypt database
  fields and software keys;
- the database URL/credentials and configured AWS/Azure connection credentials;
- the software Issuing Sub CA key when the issuer backend is software;
- local software service-certificate keys; and
- managed portal TLS material stored under the application state directory.

SQLite is captured with its online backup API. MariaDB/MySQL is read through one
repeatable-read consistent snapshot. Backup creation needs no `sqlite3`,
`mysqldump`, or container-specific executable.

## Excluded material

The archive never exports:

- SmartCard-HSM private keys, wrapped `.bin` backups, DKEK shares, PINs, or share
  passwords;
- AWS KMS or Azure Key Vault private keys (provider references and credentials
  are retained so the service can reconnect);
- Offline Root private material or its passphrase;
- setup tokens or HSM PIN environment values; or
- proxy/operator-managed TLS files outside the state directory.

For SmartCard-HSM, preserve the complete N-of-N share set and native wrapped-key
backups using the unchanged [DKEK recovery runbook](hsm-dkek-recovery.md). For
cloud keys, preserve provider recovery controls, IAM/RBAC, and the provider key
itself using [cloud key providers](cloud-key-providers.md). The Offline Root and
proxy TLS material retain their own recovery procedures.

## Create a backup

1. Sign in to the Admin portal and open **System → Backups**.
2. Review the live database/backend and the displayed inclusion/exclusion list.
3. Choose **Request application backup**, complete recent authentication, enter
   an operational reason, type `REQUEST APPLICATION BACKUP`, and enter share A
   twice. Retain share A separately; myOwnCA stores only an encrypted derived key
   until the request is resolved.
4. A different administrator opens **System → Backups**, reviews the request,
   completes recent authentication, types `APPROVE APPLICATION BACKUP`, and
   enters share B twice.
5. Wait for generation, then save the delivered archive. Compare its filename,
   size, and SHA-256 with the export-history row.
6. Move the archive and both shares to their separate protected locations.

A pending request expires after 24 hours. A generated encrypted file remains on
the server only until successful delivery or for a 30-minute interrupted-download
retry window. Production readiness is healthy for seven days after delivery,
warns through day 30, and becomes critical afterward.

## Verify an archive

Use the exact myOwnCA release recorded inside the archive:

```text
myownca backup verify /recovery/myownca-application-backup-....myownca-backup
```

The command prompts separately for shares A and B, authenticates every encrypted
chunk, validates all member hashes and paths, and reports the source release,
database backend, issuer backend, and recovery boundaries. A wrong share,
truncation, reordering, or modified byte fails without identifying which share
was incorrect.

The binary layout and fixed cryptographic parameters are documented in
[application backup format v1](application-backup-format.md).

## Restore on bare metal

Stop the service and restore into a new empty state directory and empty database.
Never unpack over a running or unknown installation.

```text
sudo systemctl stop myownca
sudo -u myownca myownca backup restore /recovery/BACKUP.myownca-backup \
  --state-dir /var/lib/myownca-restored --sqlite
```

For MariaDB, omit `--sqlite` to use the archived URL or pass
`--database-url mysql+pymysql://...` for a new empty schema. Update the service's
`MYOWNCA_STATE_DIR` when restoring to a new path, then start it and validate
`GET /health`, the portals, Root/Sub CA fingerprints, CRL, OCSP, and a sample
active certificate.

Restore requires the exact application release and migration fingerprint. It
can restore SQLite to MariaDB or MariaDB to SQLite. It stages and validates all
files before applying them, recreates the schema, imports all rows, verifies the
audit chain and software issuer key, revokes every restored login session, and
preserves unfinished non-backup administrator proposals. The setup-complete
marker is written last.

The Docker sequence is in [Docker backup/restore](docker.md#backup--restore).

## Isolated restore test

Use an isolated host/network that cannot issue to production consumers, contact
production notification channels, or publish duplicate CRL/OCSP endpoints.

1. Verify the archive and record its SHA-256.
2. Restore to an empty state directory/database with the exact recorded release.
3. Provide the excluded HSM/cloud recovery boundary when applicable.
4. Start the recovered service and sign in again; restored sessions are revoked.
5. Compare Root and Issuing Sub CA fingerprints, verify audit integrity, inspect
   certificate inventory, and validate current CRL/OCSP material without issuing
   a production certificate.
6. Record elapsed recovery time, discrepancies, and every external prerequisite.

Treat production recovery as an incident. Prevent the failed instance from
serving or signing before changing proxy, DNS, or load-balancer routing. If the
Issuing Sub CA key may be compromised, restoration is not remediation; follow
[security incident response](security-incident-response.md).
