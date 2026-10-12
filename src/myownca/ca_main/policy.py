from __future__ import annotations

from myownca.domain import ApprovalRecord, CertificateRequest, CertificateTemplate, RequestKind


class ApprovalPolicyError(RuntimeError):
    pass


def required_approvals(request: CertificateRequest, template: CertificateTemplate) -> int:
    if request.kind is RequestKind.FIRST_ISSUANCE:
        return template.first_issuance_approvals
    if request.via_link_auth == "otp":
        # Possession of the old certificate was NOT proven (email code only):
        # a superuser must vouch, even on auto-issue renewal templates.
        return max(template.renewal_approvals, 1)
    return template.renewal_approvals


def assert_request_is_approved(
    request: CertificateRequest,
    template: CertificateTemplate,
    approvals: list[ApprovalRecord],
) -> None:
    distinct_approvers = {approval.superuser_id for approval in approvals}
    needed = required_approvals(request, template)
    if len(distinct_approvers) < needed:
        raise ApprovalPolicyError(
            f"Request requires {needed} distinct Certificate Operator approval(s); "
            f"received {len(distinct_approvers)}"
        )
