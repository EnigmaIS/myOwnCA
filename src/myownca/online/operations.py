"""Administrator operations overview built from observable service state."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Protocol

from cryptography import x509
from myownca_core.leaf import IssuerValidityError, validate_issuer_validity

from myownca.domain import CertificateStatus, GovernanceMode, RequestStatus, Role
from myownca.storage.database import Database

FRESHNESS_SECONDS = 60
CLOUD_SIGNING_ALERT_AFTER = timedelta(minutes=15)
RECENT_BACKUP_DAYS = 7
STALE_BACKUP_DAYS = 30


class _BackupRepository(Protocol):
    def latest_delivered(self) -> dict[str, object] | None: ...


class DashboardAlertMuteRepository:
    """Persist visual alert mutes independently for each portal user."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def list_muted(self, *, user_id: str, portal: str) -> list[str]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT alert_id
                FROM dashboard_alert_mutes
                WHERE user_id = ? AND portal = ?
                ORDER BY alert_id
                """,
                (user_id, portal),
            ).fetchall()
        return [str(row["alert_id"]) for row in rows]

    def set_muted(
        self,
        *,
        user_id: str,
        portal: str,
        alert_id: str,
        muted: bool,
        now: datetime | None = None,
    ) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                DELETE FROM dashboard_alert_mutes
                WHERE user_id = ? AND portal = ? AND alert_id = ?
                """,
                (user_id, portal, alert_id),
            )
            if muted:
                connection.execute(
                    """
                    INSERT INTO dashboard_alert_mutes(
                        user_id, portal, alert_id, muted_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        portal,
                        alert_id,
                        _as_utc(now or datetime.now(timezone.utc)).isoformat(),
                    ),
                )


class _PKIRepository(Protocol):
    def get_setting(self, key: str) -> str | None: ...
    def list_templates(self) -> list[object]: ...
    def list_issued_certificates(self) -> list[object]: ...
    def list_requests(self) -> list[object]: ...
    def list_revocations(self) -> list[object]: ...
    def get_latest_issuer_crl(self, issuer_subject: str) -> object | None: ...
    def get_ocsp_responder(self, issuer_subject: str) -> object | None: ...


class _SigningJobRepository(Protocol):
    def list_all(self, *, limit: int = 100) -> list[object]: ...


class OperationsService:
    """Build a live, actionable administrator view from existing subsystem state."""

    def __init__(
        self,
        *,
        repository: _PKIRepository,
        notification_repository,
        service_cert_repository,
        comms_repository,
        licensing_service,
        audit_service,
        proposal_repository,
        backup_repository: _BackupRepository,
        issuer_provider: Callable[[], object | None],
        hsm_backend_provider: Callable[[], str],
        lab_mode: bool,
        signing_job_repository: _SigningJobRepository | None = None,
    ) -> None:
        self.repository = repository
        self.notification_repository = notification_repository
        self.service_cert_repository = service_cert_repository
        self.comms_repository = comms_repository
        self.licensing_service = licensing_service
        self.audit_service = audit_service
        self.proposal_repository = proposal_repository
        self.backup_repository = backup_repository
        self.issuer_provider = issuer_provider
        self.hsm_backend_provider = hsm_backend_provider
        self.lab_mode = lab_mode
        self.signing_job_repository = signing_job_repository

    def readiness(self, *, now: datetime | None = None) -> dict[str, object]:
        current = _as_utc(now or datetime.now(timezone.utc))
        checked_at = current.isoformat()
        builders: tuple[Callable[[datetime], dict[str, object]], ...] = (
            self._issuer_item,
            self._governance_item,
            self._service_urls_item,
            self._revocation_publication_item,
            self._templates_item,
            self._notifications_item,
            self._notification_test_item,
            self._audit_integrity_item,
            self._audit_forwarding_item,
            self._application_backup_item,
            self._issue_revoke_item,
            self._expiration_item,
            self._renewal_failure_item,
            self._license_item,
        )
        items: list[dict[str, object]] = []
        for builder in builders:
            try:
                item = builder(current)
            except Exception:  # noqa: BLE001 - one failed check must not blank the overview
                item_id, title, owner, href = _fallback_metadata(builder)
                item = _item(
                    item_id,
                    title,
                    "This check could not be completed. Retry or inspect Activity & diagnostics.",
                    status="unknown",
                    severity="warning",
                    owner=owner,
                    action=("Retry from dashboard", href),
                    checked_at=current,
                )
            item["checked_at"] = checked_at
            items.append(item)
        items.extend(self._cloud_signing_alert_items(current))
        completed = sum(item["status"] == "pass" for item in items)
        status = _overall_status(items)
        return {
            "generated_at": checked_at,
            "freshness": _freshness(current, "/internal/admin/readiness"),
            "status": status,
            "completed": completed,
            "total": len(items),
            "items": items,
        }

    def overview(self, *, now: datetime | None = None) -> dict[str, object]:
        current = _as_utc(now or datetime.now(timezone.utc))
        readiness = self.readiness(now=current)
        items = readiness["items"]
        assert isinstance(items, list)
        attention = sorted(
            (item for item in items if item["status"] != "pass"),
            key=lambda item: _severity_rank(str(item["severity"])),
            reverse=True,
        )
        by_id = {str(item["id"]): item for item in items}
        security_ids = (
            "issuer.configured",
            "governance.pending_changes",
            "service_urls.publication",
            "revocation.publication",
            "audit.integrity",
            "audit.forwarding",
            "backup.application",
        )
        risk_summary = self._safe_risk_summary(current)
        license_summary = self._safe_license_summary(current)
        latest_backup = self._safe_latest_backup()
        return {
            "generated_at": current.isoformat(),
            "overall_status": readiness["status"],
            "freshness": _freshness(current, "/internal/admin/operations"),
            "summary": {
                "readiness_completed": readiness["completed"],
                "readiness_total": readiness["total"],
                "attention_count": len(attention),
                "critical_count": sum(item["severity"] == "critical" for item in attention),
            },
            "attention_items": attention,
            "security_posture": [by_id[item_id] for item_id in security_ids],
            "lifecycle": {
                "risk_summary": risk_summary,
                "license": license_summary,
            },
            "readiness": {
                "status": readiness["status"],
                "completed": readiness["completed"],
                "total": readiness["total"],
                "items": items,
            },
            "backup": {
                "latest_delivered": latest_backup,
                "href": "#/backups",
                "off_host_storage_verified": False,
                "restore_verified": False,
            },
            "recent_changes": self._recent_changes(),
        }

    def _cloud_signing_alert_items(self, now: datetime) -> list[dict[str, object]]:
        """Return one non-secret operational alert for each blocked cloud job.

        Signing job payloads can contain certificate material and provider
        references, so this view deliberately reads only the job identifier,
        status, timestamps, and the queue's explicitly safe error fields.
        """

        if self.signing_job_repository is None:
            return []
        current = _as_utc(now)
        try:
            list_alerting = getattr(
                self.signing_job_repository, "list_alerting", None
            )
            if callable(list_alerting):
                jobs = list_alerting(
                    now=current,
                    alert_after=CLOUD_SIGNING_ALERT_AFTER,
                    limit=1_000,
                )
            else:
                jobs = self.signing_job_repository.list_all(limit=1_000)
        except Exception:  # noqa: BLE001 - an optional queue must not blank readiness
            return []

        cutoff = current - CLOUD_SIGNING_ALERT_AFTER
        actionable: list[object] = []
        for job in jobs:
            status = _enum_value(getattr(job, "status", ""))
            retry_started_at = getattr(
                job,
                "retry_window_started_at",
                getattr(job, "created_at", None),
            )
            if status == "failed":
                actionable.append(job)
            elif (
                status in {"queued", "running"}
                and isinstance(retry_started_at, datetime)
                and _as_utc(retry_started_at) <= cutoff
            ):
                actionable.append(job)

        actionable.sort(
            key=lambda job: (
                _as_utc(getattr(job, "created_at", current)),
                str(getattr(job, "id", "")),
            )
        )
        return [self._cloud_signing_alert_item(job, current) for job in actionable]

    @staticmethod
    def _cloud_signing_alert_item(job: object, now: datetime) -> dict[str, object]:
        job_id = str(getattr(job, "id", "unknown"))
        status = _enum_value(getattr(job, "status", ""))
        safe_error = _provider_safe_error(job)
        if status == "failed":
            summary = f"Cloud signing job {job_id} failed."
            item_status, severity = "fail", "critical"
        else:
            summary = (
                f"Cloud signing job {job_id} has remained {status} for at least "
                f"{int(CLOUD_SIGNING_ALERT_AFTER.total_seconds() // 60)} minutes."
            )
            item_status, severity = "warn", "warning"
        if safe_error:
            summary += f" Provider-safe error: {safe_error}."
        return _item(
            f"cloud_signing.job.{job_id}",
            f"Cloud signing job {job_id}",
            summary,
            status=item_status,
            severity=severity,
            owner="administrator",
            action=("Review cloud signing", "#/hsm"),
            checked_at=now,
        )

    def _issuer_item(self, now: datetime) -> dict[str, object]:
        issuer = self.issuer_provider()
        if issuer is None:
            return _item(
                "issuer.configured",
                "Issuing CA",
                "No active issuer is configured; certificate issuance is unavailable.",
                status="fail",
                severity="critical",
                owner="administrator",
                action=("Configure issuer", "#/ca"),
                checked_at=now,
            )
        certificate = issuer.certificate
        expires_at = _certificate_expiry(certificate)
        current = _as_utc(now).replace(microsecond=0)
        remaining = expires_at - current
        try:
            validate_issuer_validity(certificate, now=current)
        except IssuerValidityError as exc:
            status, severity = "fail", "critical"
            summary = str(exc)
        else:
            allowed_profiles = getattr(issuer, "allowed_profiles", None)
            cutoffs = sorted(
                (
                    (expires_at - timedelta(days=template.validity_days), template.name)
                    for template in self.repository.list_templates()
                    if allowed_profiles is None or template.profile in allowed_profiles
                ),
            )
            blocked = [name for cutoff, name in cutoffs if current > cutoff]
            approaching = [
                name for cutoff, name in cutoffs
                if current <= cutoff <= current + timedelta(days=30)
            ]
            if blocked or approaching or remaining <= timedelta(days=30):
                status, severity = "warn", "warning"
                summary = f"The active issuer expires at {expires_at.isoformat()}."
                if cutoffs:
                    summary += f" Earliest template issuance cutoff: {cutoffs[0][0].isoformat()}."
                if blocked:
                    summary += f" Requested lifetimes no longer fit: {', '.join(blocked)}."
                if approaching:
                    summary += f" Issuance cutoff within 30 days: {', '.join(approaching)}."
                summary += " Review issuer expiry and template validity with the CA administrator."
            elif self.lab_mode:
                status, severity = "warn", "info"
                summary = (
                    f"The lab issuer is active through {expires_at.date().isoformat()}; "
                    "replace it with an offline-root-signed issuer before production use."
                )
            else:
                status, severity = "pass", "none"
                summary = f"Active issuer is configured through {expires_at.date().isoformat()}."
        return _item(
            "issuer.configured",
            "Issuing CA",
            summary,
            status=status,
            severity=severity,
            owner="administrator",
            action=("Review issuer", "#/ca"),
            checked_at=now,
        )

    def _hsm_item(self, now: datetime) -> dict[str, object]:
        backend = self.hsm_backend_provider()
        if backend == "pkcs11":
            return _item(
                "hsm.backend",
                "CA key protection",
                "The active CA key backend is PKCS#11.",
                status="pass",
                severity="none",
                owner="administrator",
                action=("Review HSM", "#/hsm"),
                checked_at=now,
            )
        lab_note = " This is suitable for a lab." if self.lab_mode else ""
        return _item(
            "hsm.backend",
            "CA key protection",
            f"CA keys use the software backend.{lab_note} Use PKCS#11 for production.",
            status="warn",
            severity="info" if self.lab_mode else "warning",
            owner="administrator",
            action=("Review HSM", "#/hsm"),
            checked_at=now,
        )

    def _governance_item(self, now: datetime) -> dict[str, object]:
        count = len(self.proposal_repository.list_pending_proposals())
        mode = self.proposal_repository.get_governance_mode()
        active_admin_count = self.proposal_repository.count_active_users_with_role(
            Role.ADMIN
        )
        if mode is GovernanceMode.DUAL_CONTROL and active_admin_count < 2:
            summary = (
                "Dual control is enabled but fewer than two active administrators "
                "are available. Reactivate an existing second administrator. If none "
                "exists, stop and restore a known-good state backup containing at "
                "least two active administrators."
            )
            status = "warn"
            severity = "warning"
        elif count:
            summary = (
                f"{count} governed administrative proposal"
                f"{'s are' if count != 1 else ' is'} "
                "waiting for the approval policy captured when created."
            )
            status = "warn"
            severity = "warning" if not self.lab_mode else "info"
        elif mode is GovernanceMode.SINGLE_ADMIN and self.lab_mode:
            summary = (
                "Single-admin governance is the Test/Lab default; privileged account "
                "grants and credential resets apply immediately."
            )
            status = "pass"
            severity = "none"
        elif mode is GovernanceMode.SINGLE_ADMIN:
            summary = (
                "Production is using single-admin governance. Enable dual control "
                "for independent approval of privileged account grants and credential resets."
            )
            status = "warn"
            severity = "warning"
        else:
            summary = (
                "Dual control is enabled. Privileged role grants, privileged credential "
                "resets, and a downgrade to single-admin require approval by a different "
                "administrator; none are awaiting review."
            )
            status = "pass"
            severity = "none"
        return _item(
            "governance.pending_changes",
            "Privileged-change governance",
            summary,
            status=status,
            severity=severity,
            owner="administrator",
            action=("Review privileged changes", "#/privileged"),
            checked_at=now,
        )

    def _service_urls_item(self, now: datetime) -> dict[str, object]:
        required = ("admin_base_url", "superuser_base_url", "crl_base_url", "aia_base_url")
        if (self.repository.get_setting("ocsp_enabled") or "").strip() == "true":
            required += ("ocsp_url",)
        missing = [key for key in required if not (self.repository.get_setting(key) or "").strip()]
        if missing:
            labels = ", ".join(key.replace("_", " ") for key in missing)
            return _item(
                "service_urls.publication",
                "Service URLs",
                f"Configure: {labels}.",
                status="fail" if any(key in missing for key in ("crl_base_url", "aia_base_url")) else "warn",
                severity="warning",
                owner="administrator",
                action=("Configure service URLs", "#/ca"),
                checked_at=now,
            )
        return _item(
            "service_urls.publication",
            "Service URLs",
            "Portal and certificate publication URLs are configured.",
            status="pass",
            severity="none",
            owner="administrator",
            action=("Review service URLs", "#/ca"),
            checked_at=now,
        )

    def _templates_item(self, now: datetime) -> dict[str, object]:
        count = len(self.repository.list_templates())
        return _item(
            "templates.configured",
            "Certificate templates",
            f"{count} certificate template{'s are' if count != 1 else ' is'} configured."
            if count
            else "No certificate templates are configured.",
            status="pass" if count else "fail",
            severity="none" if count else "warning",
            owner="administrator",
            action=("Manage templates", "#/templates"),
            checked_at=now,
        )

    def _revocation_publication_item(self, now: datetime) -> dict[str, object]:
        issuer = self.issuer_provider()
        if issuer is None:
            return _item(
                "revocation.publication",
                "Revocation publication",
                "CRL and OCSP health cannot be checked until an issuer is configured.",
                status="unknown",
                severity="warning",
                owner="administrator",
                action=("Configure issuer", "#/ca"),
                checked_at=now,
            )

        issuer_subject = issuer.certificate.subject.rfc4514_string()
        crl = self.repository.get_latest_issuer_crl(issuer_subject)
        problems: list[str] = []
        facts: list[str] = []
        if crl is None:
            problems.append("no issuer CRL has been generated")
        else:
            parsed_crl = x509.load_pem_x509_crl(crl.crl_pem.encode())
            next_update = getattr(parsed_crl, "next_update_utc", None)
            if next_update is None:
                next_update = _as_utc(parsed_crl.next_update)
            else:
                next_update = _as_utc(next_update)
            if next_update <= now:
                problems.append(f"the issuer CRL expired on {next_update.date().isoformat()}")
            else:
                facts.append(f"CRL is valid through {next_update.date().isoformat()}")

        ocsp_enabled = (self.repository.get_setting("ocsp_enabled") or "").strip() == "true"
        advisory = False
        if not ocsp_enabled:
            advisory = True
            facts.append("OCSP is disabled")
        else:
            responder = self.repository.get_ocsp_responder(issuer_subject)
            warning = (self.repository.get_setting("ocsp_responder_warning") or "").strip()
            if warning:
                problems.append(warning.rstrip("."))
            elif responder is None:
                problems.append("OCSP is enabled but no responder is available")
            elif _as_utc(responder.not_after) <= now:
                problems.append("the OCSP responder certificate is expired")
            else:
                facts.append(
                    f"OCSP responder is valid through {_as_utc(responder.not_after).date().isoformat()}"
                )

        if problems:
            status, severity = "fail", "warning"
            summary = "; ".join(problems).capitalize() + "."
        elif advisory:
            status, severity = "warn", "info"
            summary = "; ".join(facts) + "."
        else:
            status, severity = "pass", "none"
            summary = "; ".join(facts) + "."
        return _item(
            "revocation.publication",
            "Revocation publication",
            summary,
            status=status,
            severity=severity,
            owner="administrator",
            action=("Review CRL & OCSP", "#/ca"),
            checked_at=now,
        )

    def _notifications_item(self, now: datetime) -> dict[str, object]:
        channels = {
            entry.channel: entry
            for entry in self.comms_repository.list_all()
            if entry.enabled
        }
        rules = [rule for rule in self.notification_repository.list_rules() if rule.enabled]
        usable_rules = [rule for rule in rules if rule.channel.value in channels]
        configured = bool(usable_rules)
        if configured:
            summary = (
                f"{len(usable_rules)} active rule(s) use "
                f"{len({rule.channel.value for rule in usable_rules})} enabled channel(s)."
            )
        else:
            missing = []
            if not channels:
                missing.append("an enabled channel")
            if not rules:
                missing.append("an active notification rule")
            if channels and rules:
                summary = "Active notification rules do not use an enabled channel."
            else:
                summary = "Configure " + " and ".join(missing) + "."
        return _item(
            "notifications.configured",
            "Notifications & integrations",
            summary,
            status="pass" if configured else "warn",
            severity="none" if configured else "warning",
            owner="administrator",
            action=("Configure notifications", "#/channels"),
            checked_at=now,
        )

    def _notification_test_item(self, now: datetime) -> dict[str, object]:
        cutoff = now - timedelta(days=30)
        active_rule_channels = {
            rule.channel.value
            for rule in self.notification_repository.list_rules()
            if rule.enabled
        }
        enabled_channels = {
            entry.channel: _as_utc(entry.updated_at)
            for entry in self.comms_repository.list_all()
            if entry.enabled and entry.channel in active_rule_channels
        }
        events = self.audit_service.list_events(category="comms", limit=100)
        successful = next(
            (
                event
                for event in events
                if event.action == "channel_test"
                and event.outcome.value == "success"
                and event.details.get("success") is True
                and event.object_id in enabled_channels
                and _as_utc(event.occurred_at) >= cutoff
                and _as_utc(event.occurred_at) >= enabled_channels[event.object_id]
            ),
            None,
        )
        return _item(
            "notifications.tested",
            "Notification delivery test",
            (
                "A notification channel test succeeded on "
                f"{_as_utc(successful.occurred_at).date().isoformat()} "
                f"for {successful.object_id}."
                if successful is not None
                else "No enabled channel used by an active rule has a successful test newer "
                "than its current configuration."
            ),
            status="pass" if successful is not None else "warn",
            severity="none" if successful is not None else "warning",
            owner="administrator",
            action=("Test a notification channel", "#/channels"),
            checked_at=now,
        )

    def _audit_integrity_item(self, now: datetime) -> dict[str, object]:
        result = self.audit_service.verify_chain()
        ok = bool(result.get("ok"))
        bad = result.get("first_bad_sequence")
        summary = (
            "The audit hash chain passes verification."
            if ok
            else f"Audit-chain verification failed at sequence {bad}."
        )
        return _item(
            "audit.integrity",
            "Audit integrity",
            summary,
            status="pass" if ok else "fail",
            severity="none" if ok else "critical",
            owner="administrator",
            action=("Inspect audit trail", "#/auditing"),
            checked_at=now,
        )

    def _audit_forwarding_item(self, now: datetime) -> dict[str, object]:
        config = self.audit_service.get_syslog_config()
        enabled = bool(config.get("enabled"))
        return _item(
            "audit.forwarding",
            "Remote audit forwarding",
            "Remote syslog forwarding is configured."
            if enabled
            else "Remote syslog forwarding is disabled; audit records exist only locally.",
            status="pass" if enabled else "warn",
            severity="none" if enabled else "info",
            owner="administrator",
            action=("Configure audit forwarding", "#/auditing"),
            checked_at=now,
        )

    def _application_backup_item(self, now: datetime) -> dict[str, object]:
        latest = self._safe_latest_backup()
        if latest is None:
            return _item(
                "backup.application",
                "Recent application backup",
                "No governed application backup has been delivered to an administrator.",
                status="fail",
                severity="critical",
                owner="administrator",
                action=("Open backups", "#/backups"),
                checked_at=now,
            )
        delivered_at = latest.get("delivered_at")
        if not isinstance(delivered_at, str):
            return _item(
                "backup.application",
                "Recent application backup",
                "Application backup history could not be evaluated.",
                status="unknown",
                severity="warning",
                owner="administrator",
                action=("Open backups", "#/backups"),
                checked_at=now,
            )
        delivered = _as_utc(datetime.fromisoformat(delivered_at))
        age = max(timedelta(0), now - delivered)
        if age <= timedelta(days=RECENT_BACKUP_DAYS):
            status, severity = "pass", "none"
        elif age <= timedelta(days=STALE_BACKUP_DAYS):
            status, severity = "warn", "warning"
        else:
            status, severity = "fail", "critical"
        return _item(
            "backup.application",
            "Recent application backup",
            "A governed encrypted backup was delivered on "
            f"{delivered.date().isoformat()}. Off-host storage and restore success "
            "are not independently verified.",
            status=status,
            severity=severity,
            owner="administrator",
            action=("Open backups", "#/backups"),
            checked_at=now,
        )

    def _expiration_item(self, now: datetime) -> dict[str, object]:
        risk = self._risk_summary(now)
        if risk["expired"]:
            status, severity = "fail", "critical"
            summary = f"{risk['expired']} active certificate(s) are expired."
        elif risk["expiring_7_days"]:
            status, severity = "warn", "warning"
            summary = f"{risk['expiring_7_days']} certificate(s) expire within 7 days."
        elif risk["expiring_30_days"]:
            status, severity = "warn", "info"
            summary = f"{risk['expiring_30_days']} certificate(s) expire within 30 days."
        else:
            status, severity = "pass", "none"
            summary = "No active certificates are expired or due within 30 days."
        return _item(
            "lifecycle.expirations",
            "Certificate expirations",
            summary,
            status=status,
            severity=severity,
            owner="certificate_operator",
            action=None,
            checked_at=now,
        )

    def _issue_revoke_item(self, now: datetime) -> dict[str, object]:
        revoked = {
            revocation.certificate_id: revocation
            for revocation in self.repository.list_revocations()
        }
        exercised = next(
            (
                certificate
                for certificate in self.repository.list_issued_certificates()
                if certificate.status is CertificateStatus.REVOKED
                and certificate.certificate_id in revoked
            ),
            None,
        )
        return _item(
            "lifecycle.issue_revoke_exercised",
            "Issue & revoke exercise",
            (
                "An issued certificate has completed the revoke workflow."
                if exercised is not None
                else "Ask a Certificate Operator to issue and revoke a disposable test certificate."
            ),
            status="pass" if exercised is not None else "warn",
            severity="none" if exercised is not None else "warning",
            owner="certificate_operator",
            action=None,
            checked_at=now,
        )

    def _renewal_failure_item(self, now: datetime) -> dict[str, object]:
        count = self._risk_summary(now)["failed_renewals_30_days"]
        return _item(
            "lifecycle.renewal_failures",
            "Renewal automation",
            f"{count} renewal failure(s) were recorded in the last 30 days."
            if count
            else "No renewal failures were recorded in the last 30 days.",
            status="warn" if count else "pass",
            severity="warning" if count else "none",
            owner="certificate_operator",
            action=None,
            checked_at=now,
        )

    def _license_item(self, now: datetime) -> dict[str, object]:
        summary = self.licensing_service.summary(now)
        active = int(summary.get("active_lineages") or 0)
        reserved = int(summary.get("reserved_lineages") or 0)
        limit = int(summary.get("lineage_limit") or 0)
        invalid = bool(summary.get("verification_error"))
        license_status = str(summary.get("status") or "none")
        days_remaining = summary.get("days_remaining")
        if summary.get("key_configuration_error"):
            status, severity = "fail", "critical"
            message = str(summary["key_configuration_error"])
        elif not summary.get("production_key_configured"):
            status, severity = "fail", "critical"
            message = "No license verification public keys are configured."
        elif summary.get("lineage_state") != "ready":
            status, severity = "fail", "critical"
            message = "Certificate lineage state is unavailable; new issuance is safely blocked."
        elif invalid:
            status, severity = "fail", "warning"
            message = "The stored license could not be verified; the free-tier limit applies."
        elif license_status == "expired":
            status, severity = "warn", "warning"
            message = (
                "The license has expired; new certificate identities use the free-tier "
                "limit while renewals remain available."
            )
        elif license_status == "valid" and isinstance(days_remaining, int) and days_remaining <= 30:
            status, severity = "warn", "warning"
            message = f"The license expires in {days_remaining} day(s)."
        elif limit and active + reserved >= limit:
            status, severity = "fail", "critical"
            message = f"No issuance capacity is currently available ({active}/{limit} active)."
        elif limit and (active + reserved) / limit >= 0.8:
            status, severity = "warn", "warning"
            message = f"Certificate-lineage capacity is {active}/{limit} active."
        else:
            status, severity = "pass", "none"
            message = f"Certificate-lineage capacity is {active}/{limit} active."
        return _item(
            "license.capacity",
            "Certificate capacity",
            message,
            status=status,
            severity=severity,
            owner="administrator",
            action=("Review license", "#/license"),
            checked_at=now,
        )

    def _risk_summary(self, now: datetime) -> dict[str, int]:
        in_7_days = now + timedelta(days=7)
        in_30_days = now + timedelta(days=30)
        in_60_days = now + timedelta(days=60)
        recent_cutoff = now - timedelta(days=30)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        active = [
            cert
            for cert in self.repository.list_issued_certificates()
            if cert.status is CertificateStatus.ACTIVE
        ]
        non_expired = [cert for cert in active if _as_utc(cert.expires_at) > now]
        renewal_errors = 0
        for error in self.service_cert_repository.list_recent_errors():
            if "renew" not in str(error.get("operation", "")).lower():
                continue
            created_at = _as_utc(datetime.fromisoformat(str(error["created_at"])))
            if created_at >= recent_cutoff:
                renewal_errors += 1
        return {
            "expired": sum(1 for cert in active if _as_utc(cert.expires_at) <= now),
            "expiring_7_days": sum(1 for cert in non_expired if _as_utc(cert.expires_at) <= in_7_days),
            "expiring_30_days": sum(1 for cert in non_expired if _as_utc(cert.expires_at) <= in_30_days),
            "expiring_60_days": sum(1 for cert in non_expired if _as_utc(cert.expires_at) <= in_60_days),
            "pending_approval": sum(
                1 for request in self.repository.list_requests() if request.status is RequestStatus.PENDING
            ),
            "revoked_this_month": sum(
                1
                for revocation in self.repository.list_revocations()
                if _as_utc(revocation.revoked_at) >= month_start
            ),
            "failed_notifications_30_days": self.notification_repository.count_failed_since(
                recent_cutoff
            ),
            "failed_renewals_30_days": renewal_errors,
        }

    def _safe_risk_summary(self, now: datetime) -> dict[str, int | None]:
        try:
            return self._risk_summary(now)
        except Exception:  # noqa: BLE001 - preserve the rest of the operations snapshot
            return {
                "expired": None,
                "expiring_7_days": None,
                "expiring_30_days": None,
                "expiring_60_days": None,
                "pending_approval": None,
                "revoked_this_month": None,
                "failed_notifications_30_days": None,
                "failed_renewals_30_days": None,
            }

    def _safe_license_summary(self, now: datetime) -> dict[str, object]:
        try:
            return self.licensing_service.summary(now)
        except Exception:  # noqa: BLE001 - preserve the rest of the operations snapshot
            return {"status": "unknown", "verification_error": "License status unavailable"}

    def _safe_latest_backup(self) -> dict[str, object] | None:
        try:
            return self.backup_repository.latest_delivered()
        except Exception:  # noqa: BLE001 - readiness will surface backup as unavailable
            return None

    def _recent_changes(self) -> list[dict[str, object]]:
        try:
            events = self.audit_service.list_events(limit=8)
        except Exception:  # noqa: BLE001 - optional overview section
            return []
        return [
            {
                "id": event.id,
                "occurred_at": _as_utc(event.occurred_at).isoformat(),
                "category": event.category.value,
                "action": event.action,
                "outcome": event.outcome.value,
                "actor_email": event.actor_email,
                "object_type": event.object_type,
                "object_id": event.object_id,
            }
            for event in events
        ]


def _certificate_expiry(certificate) -> datetime:
    value = getattr(certificate, "not_valid_after_utc", None)
    if value is None:
        value = certificate.not_valid_after
    return _as_utc(value)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _enum_value(value: object) -> str:
    return str(getattr(value, "value", value)).strip().lower()


def _provider_safe_error(job: object) -> str:
    """Format only the queue's pre-sanitized provider error fields."""

    code = _single_line(getattr(job, "last_error_code", None), limit=100)
    message = _single_line(getattr(job, "last_error_message", None), limit=500)
    if code and message:
        return f"{code}: {message}"
    return code or message


def _single_line(value: object, *, limit: int) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())[:limit].rstrip()


def _freshness(now: datetime, refresh_href: str) -> dict[str, object]:
    return {
        "checked_at": now.isoformat(),
        "stale_after_seconds": FRESHNESS_SECONDS,
        "is_stale": False,
        "refresh_href": refresh_href,
    }


def _item(
    item_id: str,
    title: str,
    summary: str,
    *,
    status: str,
    severity: str,
    owner: str,
    action: tuple[str, str] | None,
    checked_at: datetime,
) -> dict[str, object]:
    return {
        "id": item_id,
        "title": title,
        "summary": summary,
        "status": status,
        "severity": severity,
        "owner": owner,
        "action": None if action is None else {"label": action[0], "href": action[1]},
        "checked_at": checked_at.isoformat(),
    }


def _overall_status(items: list[dict[str, object]]) -> str:
    if any(item["severity"] == "critical" and item["status"] != "pass" for item in items):
        return "critical"
    if any(item["status"] != "pass" for item in items):
        return "attention"
    return "healthy"


def _severity_rank(severity: str) -> int:
    return {"none": 0, "info": 1, "warning": 2, "critical": 3}.get(severity, 2)


def _fallback_metadata(builder) -> tuple[str, str, str, str]:
    name = getattr(builder, "__name__", "")
    by_name = {
        "_issuer_item": ("issuer.configured", "Issuing CA", "administrator", "#/ca"),
        "_hsm_item": ("hsm.backend", "CA key protection", "administrator", "#/hsm"),
        "_governance_item": (
            "governance.pending_changes",
            "Privileged change queue",
            "administrator",
            "#/privileged",
        ),
        "_service_urls_item": ("service_urls.publication", "Service URLs", "administrator", "#/ca"),
        "_revocation_publication_item": ("revocation.publication", "Revocation publication", "administrator", "#/ca"),
        "_templates_item": ("templates.configured", "Certificate templates", "administrator", "#/templates"),
        "_notifications_item": ("notifications.configured", "Notifications & integrations", "administrator", "#/channels"),
        "_notification_test_item": ("notifications.tested", "Notification delivery test", "administrator", "#/channels"),
        "_audit_integrity_item": ("audit.integrity", "Audit integrity", "administrator", "#/auditing"),
        "_audit_forwarding_item": ("audit.forwarding", "Remote audit forwarding", "administrator", "#/auditing"),
        "_application_backup_item": ("backup.application", "Recent application backup", "administrator", "#/backups"),
        "_issue_revoke_item": ("lifecycle.issue_revoke_exercised", "Issue & revoke exercise", "certificate_operator", "#/dashboard"),
        "_expiration_item": ("lifecycle.expirations", "Certificate expirations", "certificate_operator", "#/dashboard"),
        "_renewal_failure_item": ("lifecycle.renewal_failures", "Renewal automation", "certificate_operator", "#/dashboard"),
        "_license_item": ("license.capacity", "Certificate capacity", "administrator", "#/license"),
    }
    return by_name.get(
        name,
        ("readiness.unknown", "Readiness check", "administrator", "#/dashboard"),
    )
