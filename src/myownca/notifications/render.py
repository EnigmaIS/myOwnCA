from __future__ import annotations

from datetime import datetime
from string import Template

from myownca.notifications.base import NotificationTemplate

# Variables a template author may reference (documented in the Settings editor).
TEMPLATE_VARIABLES: dict[str, str] = {
    "cert_name": "Certificate common name / subject",
    "cert_subject": "Certificate subject (alias of cert_name)",
    "serial": "Certificate serial number",
    "template_name": "Issuing certificate template id",
    "status": "Certificate status",
    "expiry_date": "Expiry date (YYYY-MM-DD)",
    "days_until_expiry": "Whole days until expiry (negative if expired)",
    "issued_date": "Issue date (YYYY-MM-DD)",
    "person_name": "Responsible person full name",
    "person_email": "Responsible person email",
    "person_phone": "Responsible person phone",
    "person_slack": "Responsible person Slack handle",
    "company": "Responsible person company",
    "request_id": "Certificate request id",
    "request_status": "Certificate request status",
    "requester_email": "Requesting user email",
    "otp_code": "One-time code (OTP templates)",
    "otp_expires_minutes": "Minutes until the OTP expires",
    "notification_text": "Free text configured on the rule",
    "portal_url": "Base URL of the myOwnCA portal",
    "renewal_url": "Secure renewal link (expiring rules with 'include renewal link')",
    "claim_url": "Secure download link (delivery notifications)",
    "link_expires": "Date the secure link expires (YYYY-MM-DD)",
    "access_email": "Requester email (access_requested)",
    "access_name": "Requester name (access_requested)",
    "access_kind": "Requested certificate kind (access_requested)",
    "access_message": "Requester message (access_requested)",
    "cloud_job_id": "Cloud signing job id",
    "cloud_job_status": "Cloud signing job status",
    "cloud_operation": "Cloud signing operation",
    "cloud_resource": "Non-secret resource type/id",
    "cloud_error_code": "Provider-safe cloud error code",
    "cloud_error_message": "Provider-safe cloud error message",
}


# Realistic stand-in values used by the template editor's preview.
SAMPLE_CONTEXT: dict[str, object] = {
    "cert_name": "CN=demo.example.test",
    "cert_subject": "CN=demo.example.test",
    "serial": "0A:1F:3C:2B",
    "template_name": "host",
    "status": "active",
    "expiry_date": "2026-12-31",
    "days_until_expiry": 21,
    "issued_date": "2026-01-01",
    "person_name": "Alice Example",
    "person_email": "alice@example.test",
    "person_phone": "+1 555 0100",
    "person_slack": "@alice",
    "company": "Example Corp",
    "request_id": "req-demo-0001",
    "request_status": "pending",
    "requester_email": "bob@example.test",
    "otp_code": "483921",
    "otp_expires_minutes": 15,
    "notification_text": "(rule notification text)",
    "portal_url": "https://ca.example.test",
    "renewal_url": "https://ca.example.test/claim/SAMPLE-RENEWAL-TOKEN",
    "claim_url": "https://ca.example.test/claim/SAMPLE-DELIVERY-TOKEN",
    "link_expires": "2026-12-15",
    "access_email": "newcomer@example.test",
    "access_name": "New Person",
    "access_kind": "user",
    "access_message": "Please set me up with a user certificate.",
    "cloud_job_id": "job-demo-0001",
    "cloud_job_status": "failed",
    "cloud_operation": "issue_certificate",
    "cloud_resource": "certificate_request:req-demo-0001",
    "cloud_error_code": "provider_unavailable",
    "cloud_error_message": "The cloud signing provider is temporarily unavailable.",
}


def render(template: NotificationTemplate, context: dict[str, object]) -> tuple[str, str]:
    """Render (subject, body), leaving unknown $placeholders intact.

    string.Template (`$var` / `${var}`) is used rather than str.format so HTML and
    JSON bodies — full of literal ``{`` / ``}`` — never collide with the syntax.
    """
    safe = {key: ("" if value is None else str(value)) for key, value in context.items()}
    subject = Template(template.subject).safe_substitute(safe)
    body = Template(template.body).safe_substitute(safe)
    return subject, body


def _date(value: datetime | None) -> str:
    return value.date().isoformat() if value else ""


def context_for_certificate(certificate, person, *, now: datetime) -> dict[str, object]:
    days = (certificate.expires_at - now).days if certificate.expires_at else ""
    return {
        "cert_name": certificate.subject,
        "cert_subject": certificate.subject,
        "serial": certificate.serial_number,
        "template_name": certificate.template_id,
        "status": getattr(certificate.status, "value", certificate.status),
        "expiry_date": _date(certificate.expires_at),
        "days_until_expiry": days,
        "issued_date": _date(certificate.issued_at),
        "person_name": person.full_name if person else "",
        "person_email": person.email if person else "",
        "person_phone": person.phone if person else "",
        "person_slack": person.slack_handle if person else "",
        "company": person.company if person else "",
    }


def context_for_request(request, *, requester_email: str | None = None, person=None) -> dict[str, object]:
    return {
        "request_id": request.id,
        "request_status": getattr(request.status, "value", request.status),
        "template_name": request.template_id,
        "requester_email": requester_email or request.requested_by_user_id or "",
        "person_name": person.full_name if person else "",
        "person_email": person.email if person else "",
        "person_slack": person.slack_handle if person else "",
    }


def context_for_otp(*, otp_code: str, expires_minutes: int, email: str = "") -> dict[str, object]:
    return {
        "otp_code": otp_code,
        "otp_expires_minutes": expires_minutes,
        "person_email": email,
    }
