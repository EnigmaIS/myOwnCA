# Monitoring and operations

For production release authenticity, daily independent checks, failure alerts,
and monitoring when CA startup is blocked, see
[signed releases and integrity verification](release-signing.md). The external
integrity timer is separate from the application notification scheduler.

Monitor the CA as a signing service and a published revocation service. A
successful HTTP response alone is not sufficient evidence that the database,
issuer key, CRL, OCSP, notifications, or external ACME renewal are healthy.

## Health and logs

`GET /health` returns `{"status":"ok"}` when the web application is running.
Use it for process/load-balancer liveness only. It does not verify database
connectivity, HSM/cloud-key access, scheduled work, or the freshness of CRL and
OCSP responses.

Collect the service's standard output/error and application logs. In the
supplied Compose deployment use `docker compose logs ca`; a systemd deployment
commonly uses `journalctl -u myownca`. Protect logs as operational records:
they can reveal internal hostnames, certificate subjects, request metadata, and
failure context even though sensitive request values are sanitized.

Alert on repeated warnings or errors from CRL maintenance, OCSP refresh, ACME,
cloud-signing queues, secret re-encryption, and key cleanup. Retain the
tamper-evident audit log and, where configured, ensure remote syslog forwarding
continues to receive it.

## Scheduled work

The running service starts the following work after normal startup:

| Work | Default cadence | What to check |
| --- | --- | --- |
| CRL maintenance | event-driven, with a 300-second reconciliation | A current CRL is published and `nextUpdate` is not approaching. |
| Private-key lifecycle cleanup | hourly | Investigate errors before keys are deleted or detached. |
| ACME renewal | daily when `MYOWNCA_ACME_AUTORENEW=true` | Managed certificates renew and HTTP-01/DNS-01 prerequisites remain available. |
| OCSP refresh | daily when `MYOWNCA_OCSP_AUTO=true` | Delegated responder and produced responses remain current. |
| Expiry notifications | off by default; daily checks when enabled in either portal | Review failed deliveries and scheduler warnings. |
| Cloud signing/ACME/alert workers | when AWS KMS or Azure Key Vault is the issuer backend | No signing job has remained unsuccessful for 15 minutes. |

### Expiry notification scheduling

Admins can open **Notifications & integrations → Automatic rule checks**;
Superusers can open **Settings → Notification rules → Automatic rule checks**.
Both edit the same saved settings. Select **Enable automatic checks**,
choose **Check every**, and save. The default is off with a
one-day cadence. Enablement and cadence changes take effect without restarting.
The application uses its effective database, including MariaDB, and existing
notification rules, channels, recipients, and renewal links.

Enabling or starting an enabled application requests one background check;
delivery does not block startup or saving settings. Only currently due rules
run. Each rule retains its `period_days`, `last_run_at`, expiry threshold, and
successful-delivery deduplication window. Restarting after downtime evaluates
the current inventory once; missed periods are not replayed.

The interval runs from completion of the preceding pass. Shortening an elapsed
interval requests a check promptly; lengthening it postpones the next check.
Changes made during a pass apply after it finishes. Disabling prevents new
automatic passes but allows an active pass to finish. Shutdown waits up to five
seconds for that worker; an in-flight delivery may outlive that wait, and no new
automatic pass starts. Portal **Run scheduled checks now** and the manual CLI
remain available when automatic checks are off.

Failed deliveries remain in **Recent notification deliveries** and are counted
as `failed`, not `sent`, in run summaries and scheduler logs. Expected delivery
failures retain the rule's normal cadence. Unexpected pass failures produce a
scheduler warning without killing the worker; an unfinished rule remains due
and is reconsidered at the next check. Successful-delivery history still applies.

Before migrating from cron or another external timer:

1. Disable external `myownca-notify-run` jobs and wait for any running invocation
   to finish.
2. Ensure only one application instance serves as the notification scheduler
   for this database. Shared-database multi-instance scheduling is unsupported.
3. Enable automatic checks in either portal and review the first pass's logs.

Scheduler and portal runs within one application share an overlap guard;
competing runs report `already_running`. This guard does not cover another
process. For manual CLI use, disable automatic checks and wait for active work
to finish first. A process crash between external delivery and recording success
can still cause a resend; exactly-once delivery is not guaranteed.

`myownca-notify-run` reads its process environment, preferring
`MYOWNCA_DATABASE_URL` over `MYOWNCA_DATABASE_PATH`; it does not load the
launcher's state-directory files itself. Use `--dry-run` to inspect due work and
`--force` only when deliberately bypassing the rule period gate (successful-send
deduplication still applies).

The separate report-only `myownca-acme-renew` command still opens
`MYOWNCA_DATABASE_PATH`, not `MYOWNCA_DATABASE_URL`. Do not treat that command as
targeting MariaDB/MySQL. In-process ACME renewal uses the application's database.

## Recommended checks

Run these checks from monitoring or an operator host at an interval suited to
your RPO/RTO and certificate validity periods:

- Fetch `/health` through the same proxy path used by clients.
- Fetch the configured CRL URL and, when enabled, make an OCSP request through
  its published URL. Validate freshness and issuer identity, not merely HTTP
  status.
- Review Issuing Sub CA and delegated OCSP responder expiry well before their
  renewal windows.
- Run `myownca-acme-renew`. It is report-only and exits non-zero when an ACME
  certificate is due, so it is suitable as an alert input. The running service,
  not this command, performs renewal.
- Run `myownca-key-cleanup` without `--execute` to review keys due for cleanup.
  Treat `--execute` as a controlled destructive action.
- Review notification delivery failures, recent audit events, failed cloud
  signing jobs, and provider credential expiry. The cloud-key runbook defines a
  15-minute unsuccessful signing job as an operational alert.
- Confirm that the newest backup completed and periodically run an isolated
  restore test as described in [backup and disaster recovery](backup-and-disaster-recovery.md).

## First response to an alert

### Issuer lifetime and issuance cutoffs

The existing **Issuing CA** readiness item warns 30 days before the longest
issuer-allowed certificate template stops fitting within the issuer's validity.
It lists the earliest issuance cutoff and templates approaching or past their
cutoffs. The warning within 30 days of issuer expiry also applies when no
templates are configured. Expiry warnings take precedence over the lab-mode
information message. Expired and not-yet-valid issuers are critical failures.

For example, a 365-day template cannot issue a certificate when the issuing CA
has only one day remaining. Issuance rejects that request; it never silently
reduces the requested lifetime. Review the template lifetime with the CA
administrator. This safeguard does not introduce automatic issuer rollover.

Times are evaluated in UTC at certificate precision (whole seconds). Issuance
is allowed at the issuer's validity start and blocked at its expiry. A leaf may
expire exactly at issuer expiry. The usual five-minute backdating is limited
to the issuer's validity start, without changing expiry or the requested
lifetime from issuance time.

The API reports `issuer_not_yet_valid`, `issuer_expired`, or
`issuer_validity_exceeded` with an actionable message. Approval and holder
assignment responses preserve their successful workflow changes and report the
issuance failure in `auto_issue_error`; claim-renewal responses expose the same
field. The request stays pending and approvals remain recorded. Failed renewal
issuance leaves the original certificate and its keys intact.

Cloud issuance checks validity before enqueueing, when executing, and after
signing before saving the certificate. Queue delay does not shorten the
requested lifetime. A failed completion releases its licensing reservation
and records a permanent job failure with the same code and message, visible
through existing cloud job and operations views. Inspect that error before
retrying. A not-yet-valid issuer requires waiting or correcting the system
clock; an expired issuer requires CA administrator attention. Approval,
licensing, and key access requirements still apply to every retry.

### General response

1. Preserve the alert, timestamps, relevant application/proxy logs, and audit
   records. Do not delete a failed job or key record before recording its state.
2. Decide whether the condition affects issuance, revocation publication, or
   confidentiality. Restrict traffic at the proxy if continuing to serve would
   be unsafe.
3. For an HSM, cloud-key, or credential failure, restore only the required
   backend access and re-check the key's public identity. myOwnCA deliberately
   has no fallback from a cloud issuer key to a software or PKCS#11 key.
4. For suspected key compromise or an unavailable Issuing Sub CA, follow
   [security incident response](security-incident-response.md), not a routine
   restart procedure.

## Operational records

Keep a current, access-controlled record of proxy endpoints, service URLs,
issuer fingerprints, key-backend ownership, backup IDs, notification owners,
and escalation contacts. Review it after every upgrade, recovery test, key
ceremony, or change to public CRL/OCSP URLs.

## Private files and completed setup secrets

New application-private directories are created with POSIX mode `0700`, and
new SQLite databases and software private-key files with `0600`. Run the service
under a dedicated account. These modes grant access to the owner only; Windows
deployments require equivalent filesystem ACLs managed by the operator.

Once setup is complete and an active administrator exists, startup removes
bootstrap passwords from `setup/state.json`. Duplicate database and cloud
credentials are removed only when their values match the canonical credentials
in `secrets/secrets.env`. Required runtime secrets remain in that file. Failed
bootstrap retains its recovery material. Cleanup also runs for older completed
installations, including those whose `pending-admins.json` is already gone.
Cleanup preserves the state file's owner, group and mode; a file owned by another
account or linked elsewhere is left for operator review. Cleanup errors produce
a redacted warning and are retried on the next startup.
Old backups and operator-created copies are not scrubbed.

Existing directory/database permissions are not tightened automatically. Inspect
them using the same working directory and `MYOWNCA_*` environment as the service:

```text
myownca --state-dir /var/lib/myownca security permissions
```

This command reads configuration and filesystem metadata only. It does not start
the application, open or migrate the database, create missing files, or display
secret values. Configuration precedence is environment, then `secrets.env`, then
`config.toml`, as for the service. The report lists UID/GID, current mode, and the
proposed mode for the state/setup/secrets directories, configured software-key
directories and PEM keys, managed portal TLS key, and effective SQLite database
and existing journal/WAL files. External database servers are not modified;
external SQLite files and configured key directories are listed explicitly.
Unrelated files and parent directories are not recursively repaired.

Before applying repairs, review whether backup tools, external notification jobs,
or a TLS proxy rely on group access. Run them under the service account or arrange
an appropriate separate access/copy mechanism first. Stop the service and its
external jobs for the maintenance window, then run **as the service account**:

```text
myownca --state-dir /var/lib/myownca security permissions --execute
```

Repairs change permissions only on targets owned by the executing account; they
never change ownership. Symlinks (including parent components), multiply linked
files, special files, and broad targets such as the home or working directory are
refused. Use the physical path if the installation path contains a symlink, after
reviewing its destination and configured paths. Missing targets are reported and
left absent. A refused target does not roll back successful repairs to other
targets; review the complete report, then rerun after resolving failures.

Exit codes are `0` for no outstanding findings, `1` for proposed permission changes
in report-only mode, and `2` for errors or refused targets. This is a POSIX mode
check, not a full ACL or host-security audit. After repair, restart and verify
login, signing-key access, backup access, scheduled jobs, and managed TLS access.
