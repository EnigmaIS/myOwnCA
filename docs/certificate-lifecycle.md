# Certificate lifecycle operations

This guide describes the normal lifecycle for certificates issued by the online
Issuing Sub CA. It complements the trust-hierarchy ceremony in
[Issuing CA provisioning](issuer-setup.md); it does not provide an Issuing Sub
CA rotation workflow.

## Roles and policy boundary

Administrators manage templates and the policy that controls subject fields,
profiles, key usages, validity, and approval thresholds. Certificate Operators
perform requests, reviews, approvals, issuance, revocation, holder/device work,
and external service-certificate operations. Administrators—not Certificate
Operators—own the templates so an operator cannot unilaterally weaken issuance
policy.

Before enabling a template, document its intended population, profile, subject
and SAN constraints, validity, key-generation/export rules, and approval
threshold. Review it whenever relying-party requirements or public CRL/AIA/OCSP
URLs change.

## Request and approval

1. Create or select the correct person/device holder record and certificate
   template. Submit a CSR or use the approved server-key workflow.
2. Review the request's subject, SANs, profile, holder, and requested key
   material against the template policy before approving it.
3. Obtain the distinct Certificate Operator approvals required by the template.
   A template defaults to two approvals for a first issuance and one for a
   renewal; administrators can set the thresholds per template.
4. When the required approvals are present, issuance creates an active
   certificate. Preserve the request and audit trail as issuance evidence.

Do not use an import or an external service certificate to bypass internal
template policy. Imported material and outbound ACME certificates are distinct
workflows and should be tracked with their own ownership and renewal controls.

## Delivery and renewal

Use the portal's supported export or secure-claim workflow appropriate to the
holder and key backend. A private key held in a non-exportable HSM or cloud
provider cannot be made available in a private-key export. Record who received
private material and protect claim links as credentials.

Renewals stay in the certificate lineage. For an active, non-archived
certificate with the same holder, template, subject, and SANs, use its **Renew**
action rather than creating another first-issuance request. Review the renewed
certificate's subject, validity, chain, and status. Notification rules can
remind holders; enable automatic expiry checks in either privileged portal as
described in [monitoring and
operations](monitoring-and-operations.md).

For outbound ACME certificates, the running service performs automatic renewal
when enabled. `myownca-acme-renew` only reports due certificates and is useful
for alerting.

## Revocation

Revoke an internally issued certificate as soon as its private key, holder
authorization, or certificate purpose is no longer trustworthy. Select the
reason that best describes the event, such as `key_compromise`,
`affiliation_changed`, `superseded`, or `cessation_of_operation`.

After revocation:

1. Confirm the certificate is marked revoked in the portal and audit log.
2. Verify that CRL maintenance generated and published updated material.
3. If OCSP is enabled, verify the responder returns the revoked status.
4. Replace the certificate/key through the appropriate request and approval
   process when the service must continue.
5. Notify affected holders and relying parties when policy requires it.

Revoking a leaf certificate does not remediate a compromised administrator,
Issuer key, Root key, HSM, cloud identity, or state directory. Escalate those
events through [security incident response](security-incident-response.md).

## Periodic review

Review active templates, pending requests, expiring certificates, revoked
certificate publication, holder ownership, external ACME accounts, and key
lifecycle records on an operator-defined cadence. Keep the audit record and the
certificate chain/fingerprint evidence needed by relying parties. The
[monitoring runbook](monitoring-and-operations.md) covers service-level checks.
