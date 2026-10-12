# Security incident response

This runbook is for operators responding to suspected compromise or loss of
control of a production myOwnCA installation. It describes containment and
evidence handling; it does not add an unsupported Root or Issuing Sub CA
rotation workflow.

The completed setup chain contains exactly one active Issuing Sub CA. The
normal portal cannot add, replace, rotate, or retire that issuer. The current
offline CLI can create and sign a Root CRL, but it has no command to add a
Root-level revocation. Treat a Root or Issuing Sub CA compromise as an external
PKI incident requiring an approved replacement trust hierarchy and relying-party
communication plan.

## Immediate actions

1. Open an incident record and assign an incident lead. Preserve timestamps,
   affected certificate/key identifiers, audit records, service and proxy logs,
   and backup identifiers.
2. If signing authority, administrative access, or the state directory may be
   compromised, stop issuance and restrict portal access at the reverse proxy or
   network boundary. Do not destroy the affected state, key, or logs.
3. Keep the offline Root separate from the investigation host. Do not connect
   it to a suspect online system or use it to sign an unreviewed replacement CSR.
4. Determine the scope: leaf private key, user account/session, service/ACME
   credential, Issuing Sub CA key, Root key, HSM, cloud-provider identity, or
   application-state exposure.
5. Inform the PKI owner and relying-party owners according to the organization's
   incident policy. A public CRL/OCSP endpoint must remain reachable only when
   its data can be trusted and kept current.

## Scenario response

### Leaf private key or certificate compromise

Use the Certificate Operator portal to revoke the affected internally issued
certificate with the applicable reason (for example `key_compromise`). Confirm
that CRL maintenance publishes the new CRL and, if enabled, OCSP refreshes the
response. Replace the key/certificate through the normal request and approval
workflow, then preserve the audit evidence and notify relying parties.

Do not use revocation as a substitute for fixing a compromised administrator,
notification channel, or signing backend.

### Administrator account, session, or MFA recovery compromise

Restrict the administrative portal at the proxy, identify affected privileged
actions in the audit log, and invalidate or recover accounts through the
existing governance controls. In Dual control mode, use a distinct active
administrator for governed changes. If the installation no longer has the
required governance coverage, treat that as an incident and follow the
organization's account-recovery authority; do not weaken governance by editing
the database.

Rotate exposed notification, ACME, cloud, or proxy credentials after assessing
their use. `secrets/secrets.env` and database-stored encrypted secrets are part
of the incident scope when the state directory was exposed.

### Software-key or state-directory exposure

Assume that software keys and encrypted secrets may be copied when both the
state directory and the corresponding passphrases/host access were exposed.
Contain the service, preserve a forensic copy under controlled access, and
assess every affected key. Restore from backup only when it predates the
exposure and the recovery environment is trustworthy; restoration alone does
not revoke keys copied by an attacker.

### SmartCard-HSM loss or suspected compromise

Take the token out of service and preserve its inventory, serial, KCV, and audit
records. Never initialize the suspected token during an investigation. For a
hardware loss with intact recovery material, follow [DKEK recovery](hsm-dkek-recovery.md)
on a dedicated replacement token. If the Issuing Sub CA key itself may be
compromised, recovery onto another token does not remove the compromise; plan a
replacement hierarchy outside the application's fixed-issuer boundary.

### AWS KMS, Azure Key Vault, or provider identity compromise

Restrict the provider identity and examine provider audit logs, key policy/RBAC,
and signing history. There is no local signing fallback. Back up the database
and state before changing bindings, then rotate or revoke provider credentials
through the provider and update `secrets/secrets.env` before restarting the
service. Use the provider-specific controls in [cloud signing keys](cloud-key-providers.md).

### Issuing Sub CA or Root compromise

Immediately stop the online service from signing and assemble the PKI incident
team. The current product has no in-place Issuing Sub CA replacement or Root
revocation workflow. Use the organization's external CA incident process to
create, distribute, and communicate a replacement hierarchy; determine how
relying parties will distrust the old hierarchy and replace affected leaf
certificates. Preserve the old application state and Root ceremony records as
evidence. Do not attempt to alter Root/Sub CA records directly in the database.

## Recovery and closure

Before restoring normal traffic, verify the recovered environment with the
[backup and disaster recovery](backup-and-disaster-recovery.md) procedure:
issuer fingerprints, key-backend access, CRL/OCSP publication, account
governance, and proxy boundaries. Document the decision to resume issuance,
the certificates revoked/replaced, customer or relying-party notices, and the
follow-up remediation. Rehearse this runbook after material architecture or
key-backend changes.
