from __future__ import annotations

from datetime import datetime, timedelta, timezone
from threading import Lock
from uuid import uuid4

from myownca.comms import CommsError, Message, NotificationChannel
from myownca.domain import CertificateStatus, Role
from myownca.notifications.base import (
    NotificationAudience,
    NotificationEvent,
    NotificationLogEntry,
    NotificationRule,
)
from myownca.notifications.render import (
    context_for_certificate,
    context_for_otp,
    context_for_request,
    render,
)
from myownca.storage.repositories import RepositoryError

# Named per channel so the log says which field is missing, not just "no
# recipient" -- the operator needs to know where to go and fix it.
_UNREACHABLE_REASONS = {
    NotificationChannel.SMS: (
        "Skipped: no phone number on the People record for this rule's audience. "
        "Add one under People to receive SMS."
    ),
    NotificationChannel.SLACK: (
        "Skipped: no Slack handle or email on the People record for this rule's "
        "audience."
    ),
    NotificationChannel.EMAIL: (
        "Skipped: no email address on the People record for this rule's audience."
    ),
}


def _utc_now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    return current if current.tzinfo else current.replace(tzinfo=timezone.utc)


def _certificate_ref(certificate) -> str:
    """Stable notification identity with serial fallback for legacy objects."""
    return getattr(certificate, "certificate_id", None) or certificate.serial_number


class NotificationService:
    """Render templates and dispatch them through the comms module.

    Dispatch is transport-agnostic: it renders once, resolves a list of
    recipients for the rule's audience, sends each via comms, and records one
    ``notification_log`` row per recipient. It never writes the audit chain —
    that stays the web process's responsibility.
    """

    def __init__(
        self,
        repository,
        pki_repository,
        comms,
        *,
        portal_url: str = "",
        secure_links=None,
    ) -> None:
        self.repository = repository
        self.pki_repository = pki_repository
        self.comms = comms
        self.portal_url = portal_url
        # Optional SecureLinkService: lets expiring rules mint renewal links.
        self.secure_links = secure_links
        self._scheduled_lock = Lock()

    def _portal_base(self) -> str:
        stored = (self.pki_repository.get_setting("portal_base_url") or "").strip()
        return (stored or self.portal_url).rstrip("/")

    def _renewal_base(self) -> str:
        stored = (self.pki_repository.get_setting("mtls_base_url") or "").strip()
        return stored.rstrip("/") or self._portal_base()

    # -- recipient resolution -------------------------------------------------

    def _contact(self, person, channel: NotificationChannel) -> str | None:
        if person is None:
            return None
        if channel is NotificationChannel.SMS:
            return person.phone or None
        if channel is NotificationChannel.SLACK:
            return person.slack_handle or person.email
        return person.email

    def _contact_for_email(
        self, email: str, channel: NotificationChannel
    ) -> str | None:
        if channel not in {NotificationChannel.SMS, NotificationChannel.SLACK}:
            return email
        person = self.pki_repository.get_person_by_email(email)
        if channel is NotificationChannel.SMS:
            return person.phone if person and person.phone else None
        return person.slack_handle if person and person.slack_handle else email

    def holder_person(self, certificate):
        """Responsible person for a cert: the holder, or a device's admin."""
        if certificate.holder_person_id:
            return self._person_or_none(certificate.holder_person_id)
        if certificate.holder_device_id:
            try:
                device = self.pki_repository.get_device(certificate.holder_device_id)
            except RepositoryError:
                return None
            return self._person_or_none(device.admin_id)
        return None

    def _person_or_none(self, person_id):
        try:
            return self.pki_repository.get_person(person_id)
        except RepositoryError:
            return None

    def _active_superuser_emails(self) -> list[str]:
        return [
            user.email
            for user in self.pki_repository.list_users()
            if user.role is Role.SUPERUSER and user.is_active and user.email
        ]

    def _active_operator_emails(self) -> list[str]:
        return [
            user.email
            for user in self.pki_repository.list_users()
            if user.role in {Role.ADMIN, Role.SUPERUSER}
            and user.is_active
            and user.email
        ]

    def resolve_recipients(
        self,
        rule: NotificationRule,
        *,
        person=None,
        requester_email: str | None = None,
    ) -> list[str]:
        if rule.audience is NotificationAudience.APPROVERS:
            return [
                contact
                for email in self._active_superuser_emails()
                if (contact := self._contact_for_email(email, rule.channel))
            ]
        if rule.audience is NotificationAudience.OPERATORS:
            return [
                contact
                for email in self._active_operator_emails()
                if (contact := self._contact_for_email(email, rule.channel))
            ]
        if rule.audience is NotificationAudience.REQUESTER:
            if not requester_email:
                return []
            contact = self._contact_for_email(requester_email, rule.channel)
            return [contact] if contact else []
        contact = self._contact(person, rule.channel)
        return [contact] if contact else []

    # -- dispatch -------------------------------------------------------------

    def dispatch(
        self,
        rule: NotificationRule,
        context: dict[str, object],
        recipients: list[str],
        *,
        object_ref: str | None = None,
        now: datetime | None = None,
    ) -> list[NotificationLogEntry]:
        template = self.repository.get_template(rule.template_name)
        full_context = {
            "notification_text": rule.notification_text,
            "portal_url": self._portal_base(),
            **context,
        }
        subject, body = render(template, full_context)
        metadata = {"content_type": template.format.value}
        sent_at = _utc_now(now)
        entries: list[NotificationLogEntry] = []
        for recipient in recipients:
            success = False
            detail = ""
            try:
                result = self.comms.send(
                    rule.channel,
                    recipient,
                    Message(body=body, subject=subject, metadata=metadata),
                )
                success = result.success
                detail = result.detail
            except CommsError as exc:
                detail = str(exc)
            entry = NotificationLogEntry(
                id=str(uuid4()),
                rule_id=rule.id,
                event_type=rule.event_type.value,
                template_name=rule.template_name,
                channel=rule.channel.value,
                recipient=recipient,
                subject=subject,
                object_ref=object_ref,
                success=success,
                detail=detail,
                sent_at=sent_at,
            )
            self.repository.add_log(entry)
            entries.append(entry)
        return entries

    def _log_unreachable(
        self,
        rule: NotificationRule,
        *,
        object_ref: str | None,
        now: datetime,
    ) -> NotificationLogEntry:
        """Record that a rule matched but had nobody to send to.

        Returning silently made an SMS rule indistinguishable from a working
        one: the channel is healthy, the certificate is expiring, and nothing
        arrives because the People row has no phone. The entry is unsuccessful,
        so it never satisfies the dedup check and the next run tries again.
        """
        reason = _UNREACHABLE_REASONS.get(
            rule.channel,
            "No contact address is recorded for this rule's audience.",
        )
        entry = NotificationLogEntry(
            id=str(uuid4()),
            rule_id=rule.id,
            event_type=rule.event_type.value,
            template_name=rule.template_name,
            channel=rule.channel.value,
            recipient="",
            subject="",
            object_ref=object_ref,
            success=False,
            detail=reason,
            sent_at=now,
        )
        self.repository.add_log(entry)
        return entry

    # -- convenience: certificate-bound notification --------------------------

    def notify_certificate(
        self,
        rule: NotificationRule,
        certificate,
        *,
        now: datetime | None = None,
    ) -> list[NotificationLogEntry]:
        moment = _utc_now(now)
        person = self.holder_person(certificate)
        context = context_for_certificate(certificate, person, now=moment)
        recipients = self.resolve_recipients(rule, person=person)
        if not recipients:
            return [
                self._log_unreachable(
                    rule, object_ref=_certificate_ref(certificate), now=moment
                )
            ]
        context.update(self._renewal_link_context(rule, certificate, now=moment))
        return self.dispatch(
            rule, context, recipients, object_ref=_certificate_ref(certificate), now=moment
        )

    def _renewal_link_context(
        self, rule: NotificationRule, certificate, *, now: datetime
    ) -> dict[str, object]:
        """Mint a renewal claim link for the holder ($renewal_url).

        Tokens are hashed at rest, so an outstanding link's URL cannot be
        recovered for reuse — instead older active renewal links for the same
        certificate are revoked (superseded) and a fresh one is minted. The
        per-period notification dedup keeps this to one link per period.
        Cron-safe: writes only secure_links rows, never the audit chain.
        """
        if not rule.include_renewal_link or self.secure_links is None:
            return {}
        if rule.event_type not in (NotificationEvent.EXPIRING, NotificationEvent.EXPIRED):
            return {}
        base = self._renewal_base()
        if not base:
            return {}
        from myownca.holder import LinkPurpose, SecureLinkError  # noqa: PLC0415

        try:
            for stale in self.secure_links.repository.list_links_for_certificate(
                _certificate_ref(certificate),
                serial_number=certificate.serial_number,
                purpose=LinkPurpose.RENEWAL,
            ):
                if self.secure_links.usability(stale, now=now) is None:
                    self.secure_links.revoke(stale.id, now=now)
            link, token = self.secure_links.mint(
                LinkPurpose.RENEWAL,
                created_by="system:notify",
                certificate_id=_certificate_ref(certificate),
                now=now,
            )
        except SecureLinkError:
            return {}
        return {
            "renewal_url": f"{base}/claim/{token}",
            "link_expires": link.expires_at.date().isoformat(),
        }

    # -- event-driven notifications (web process) ------------------------------

    def notify_event(
        self,
        event: NotificationEvent,
        *,
        certificate=None,
        request=None,
        requester_email: str | None = None,
        context_override: dict[str, object] | None = None,
        object_ref: str | None = None,
        now: datetime | None = None,
    ) -> list[NotificationLogEntry]:
        """Dispatch every enabled rule for an in-app event (issued/requested/…).

        ``context_override`` serves events without a certificate or request
        (e.g. access_requested); only audiences resolvable without a person
        (approvers/operators) receive those.

        Best-effort per rule: a broken template or comms failure is recorded (or
        skipped) without raising, so callers can never be broken by notification
        problems.
        """
        moment = _utc_now(now)
        entries: list[NotificationLogEntry] = []
        for rule in self.repository.list_rules(event_type=event):
            if not rule.enabled:
                continue
            try:
                if (
                    event is NotificationEvent.CLOUD_SIGNING_ALERT
                    and object_ref
                    and self.repository.was_attempted_since(
                        rule_id=rule.id,
                        object_ref=object_ref,
                        since=moment - timedelta(days=max(rule.period_days, 1)),
                    )
                ):
                    continue
                if certificate is not None:
                    person = self.holder_person(certificate)
                    context = context_for_certificate(certificate, person, now=moment)
                    ref = _certificate_ref(certificate)
                elif request is not None:
                    person = self.holder_person(request)
                    context = context_for_request(
                        request, requester_email=requester_email, person=person
                    )
                    ref = request.id
                elif context_override is not None:
                    person = None
                    context = dict(context_override)
                    ref = object_ref
                else:
                    continue
                recipients = self.resolve_recipients(
                    rule, person=person, requester_email=requester_email
                )
                if not recipients:
                    # Only report a rule that had someone to reach and could not.
                    # A holder-audience rule on an event with no holder -- an
                    # access request from a stranger, say -- is inapplicable, not
                    # misconfigured, and logging it would bury the real cases.
                    if person is not None or rule.audience is not NotificationAudience.HOLDER:
                        entries.append(
                            self._log_unreachable(rule, object_ref=ref, now=moment)
                        )
                    continue
                entries.extend(
                    self.dispatch(rule, context, recipients, object_ref=ref, now=moment)
                )
            except Exception:  # noqa: BLE001 - notifications are best-effort per rule
                continue
        return entries

    # -- OTP content rendering --------------------------------------------------

    def render_otp(
        self, *, code: str, email: str, expires_minutes: int
    ) -> tuple[str, str] | None:
        """Render the OTP message content, or None when no otp template exists.

        Content only: AuthService chooses one globally enabled delivery channel
        and resolves its account-bound recipient. Only the template/text of an
        OTP rule is honoured here; notification rules never reroute the code.
        """
        template = None
        notification_text = ""
        for rule in self.repository.list_rules(event_type=NotificationEvent.OTP):
            if not rule.enabled:
                continue
            try:
                template = self.repository.get_template(rule.template_name)
                notification_text = rule.notification_text
                break
            except RepositoryError:
                continue
        if template is None:
            candidates = [
                candidate
                for candidate in self.repository.list_templates()
                if candidate.event_type is NotificationEvent.OTP
            ]
            template = candidates[0] if candidates else None
        if template is None:
            return None
        context = {
            "notification_text": notification_text,
            "portal_url": self.portal_url,
            **context_for_otp(otp_code=code, expires_minutes=expires_minutes, email=email),
        }
        return render(template, context)

    # -- scheduled checks (cron / "Run now") -----------------------------------

    _SCHEDULED_EVENTS = (NotificationEvent.EXPIRING, NotificationEvent.EXPIRED)

    def _matches_event(self, certificate, event: NotificationEvent, threshold_days: int, now: datetime) -> bool:
        if certificate.expires_at is None:
            return False
        if event is NotificationEvent.EXPIRING:
            if certificate.status is not CertificateStatus.ACTIVE:
                return False
            days = (certificate.expires_at - now).days
            return 0 <= days <= threshold_days
        if event is NotificationEvent.EXPIRED:
            if certificate.status is CertificateStatus.REVOKED:
                return False
            return certificate.expires_at < now
        return False

    def run_scheduled(
        self,
        now: datetime | None = None,
        *,
        event: NotificationEvent | None = None,
        dry_run: bool = False,
        force: bool = False,
    ) -> dict[str, object]:
        """Run due rules without overlapping another pass on this service instance."""
        if not self._scheduled_lock.acquire(blocking=False):
            return {
                "ran_at": _utc_now(now).isoformat(), "rules": [],
                "skipped_reason": "already_running",
            }
        try:
            return self._run_scheduled(now, event=event, dry_run=dry_run, force=force)
        finally:
            self._scheduled_lock.release()

    def _run_scheduled(
        self, now: datetime | None, *, event: NotificationEvent | None,
        dry_run: bool, force: bool,
    ) -> dict[str, object]:
        """Run all due expiring/expired rules against the issued-cert inventory.

        Safe for the cron runner: writes only ``notification_log`` (via dispatch)
        and rule ``last_run_at`` stamps — never the audit hash chain.
        """
        moment = _utc_now(now)
        certificates = self.pki_repository.list_issued_certificates()
        results: list[dict[str, object]] = []
        for rule in self.repository.list_rules():
            if rule.event_type not in self._SCHEDULED_EVENTS:
                continue
            if event is not None and rule.event_type is not event:
                continue
            if not rule.enabled:
                continue
            due = (
                force
                or rule.last_run_at is None
                or rule.last_run_at + timedelta(days=rule.period_days) <= moment
            )
            entry: dict[str, object] = {
                "rule_id": rule.id,
                "event_type": rule.event_type.value,
                "template_name": rule.template_name,
                "due": due,
                "matched": 0,
                "sent": 0,
                "failed": 0,
                "skipped": 0,
                "dry_run": dry_run,
            }
            if due:
                window_start = moment - timedelta(days=rule.period_days)
                for certificate in certificates:
                    if not self._matches_event(certificate, rule.event_type, rule.threshold_days, moment):
                        continue
                    entry["matched"] += 1
                    certificate_ref = _certificate_ref(certificate)
                    notified = self.repository.was_notified_since(
                        rule_id=rule.id, object_ref=certificate_ref, since=window_start
                    )
                    if certificate_ref != certificate.serial_number:
                        notified = notified or self.repository.was_notified_since(
                            rule_id=rule.id,
                            object_ref=certificate.serial_number,
                            since=window_start,
                        )
                    if notified:
                        entry["skipped"] += 1
                        continue
                    if dry_run:
                        continue
                    sent = self.notify_certificate(rule, certificate, now=moment)
                    if sent:
                        entry["sent"] += sum(item.success for item in sent)
                        entry["failed"] += sum(not item.success for item in sent)
                    else:
                        entry["skipped"] += 1  # no resolvable recipient
                if not dry_run:
                    self.repository.set_rule_last_run(rule.id, moment)
            results.append(entry)
        return {"ran_at": moment.isoformat(), "rules": results}
