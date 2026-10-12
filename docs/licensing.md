# Production offline licensing

The [EnigmaIS Source-Available Licence 1.0](../LICENSE) from EnigmaIS sp. z o. o.
sets the legal permissions. Source inspection is allowed; modifications and
derivative versions are prohibited. Genuine noncommercial use is free within the
10-active-identity allowance. Every commercial use, including commercial
evaluation and use below that allowance, requires paid terms. Normal configuration,
supported APIs, internal deployment, and backups are permitted; redistribution
requires written permission. Third-party components retain their own licences.

The technical capacity checks described below do not determine legal permission
to use the software. A working installation or an available free capacity slot
does not authorise commercial use.

myOwnCA remains useful without a license and fully functional on air-gapped
networks. The free tier permits 10 active certificate lineages. A vendor-signed,
installation-bound license raises that ceiling.

The certificate-identity count is the only technical capacity restriction. Licensing
never gates renewals, lifecycle monitoring, notifications, renewal links, ACME
automation, revocation, CRL or OCSP generation, certificate export, audit, or
recovery operations.

## Commercial and safety model

- One first issuance creates one certificate lineage and consumes one slot.
- A genuine renewal stays in the lineage, including during key rotation.
- Holder, template, subject, and normalized SANs are immutable within a lineage;
  identity changes are new first issuances.
- A new first-issuance request matching an active, non-archived certificate is
  rejected; use the existing certificate's **Renew** action instead.
- A lineage counts while any certificate in it is active and unexpired. Renewal
  overlap therefore does not double-count.
- External/imported service certificates are not issued by this CA and are not
  counted.
- The implementation deters accidental or casual reuse. A customer controlling
  the source and database can patch enforcement or clone a whole installation;
  contract and audit remain part of the threat model.

## Token schema 2

The token is `<base64url(payload)>.<base64url(rsa-pss-signature)>`. An RSA-4096
PSS/SHA-256 signature covers the exact encoded payload segment. Schema 2 has an exact field set:

```json
{
  "schema": 2,
  "product": "myownca-self-hosted",
  "license_id": "BB-2026-000123",
  "licensed_to": "Acme Corp",
  "installation_id": "11111111-1111-4111-8111-111111111111",
  "issued_at": "2026-07-01T00:00:00+00:00",
  "valid_from": "2026-07-01T00:00:00+00:00",
  "expires_at": "2027-07-01T00:00:00+00:00",
  "max_certificate_lineages": 100,
  "key_id": "release-2026"
}
```

Verification rejects unknown or missing fields, coerced integers/booleans,
non-UTC timestamps, unsupported product/schema values, malformed signatures,
and tokens for another installation. Only schema 2 tokens are accepted.

The installation UUID is created once in `online_settings`. Database backup and
restore preserves it. A fresh database has a new UUID and needs a reissued
license. There is deliberately no UI for changing the UUID.

## Expiry and renewal behavior

- A valid license uses `max(10, max_certificate_lineages)`.
- On expiry, new first issuances immediately use the free-tier ceiling.
- Genuine renewals are always allowed because they stay in an existing lineage
  and create no new capacity.
- Removing, invalidating, or expiring a license blocks only new identities while
  active plus reserved usage is at or above 10.
- Existing certificates, renewals, and automation continue normally even when a
  downgrade leaves usage above the effective ceiling.

## Transactional enforcement

The `CAMainService` used by the online application has a mandatory runtime
licensing policy. Before signing a first issuance, the policy briefly locks the
database quota row, removes expired reservations, counts active lineages plus
live reservations, and reserves a slot for five minutes.

Certificate persistence, request status, lineage assignment, and reservation
consumption commit in one transaction. Failed signing releases the reservation;
crashed reservations expire. This keeps the last slot correct across FastAPI
threads, processes, SQLite, and shared MariaDB deployments.

Legacy certificates are backfilled by following renewal anchors to a
first-issuance root. Historical first-issuance duplicates may retain a shared
lineage only when their holder, template, and normalized identity all match the
stored lineage. An orphan, cycle, or mismatch places licensing in visible safe
mode: new issuance stops, while security operations and diagnostics remain
available.

## API and operations

### Signed company identity in portals

The issuer's required `--licensed-to` argument is the exact company name embedded
in `licensed_to` and covered by the vendor signature. All fully authenticated
account roles see **Licensed to** and this name below the branding logo in their
sidebar or header. Secure-link holders see it after OTP or certificate-possession
verification for delivery, renewal, or enrollment. Login and unverified claim
responses do not expose the recipient.

`GET /internal/license/identity` is available to every fully authenticated account
role and returns only `licensed_to`, `status`, and `verification_warning`. Verified
holder claim-state responses include the same object as `license_identity`.
These responses use the verified token loader, never the separately stored
company-name metadata, and do not calculate capacity. Licence administration
permissions are unchanged.

Expired licences retain the company name with **Licence expired**; future-dated
verified licences show **Licence not yet active**. When the established verified
cache is used after a loading or verification failure, the name remains visible
with **Licence details unavailable**. Without a verified identity, that message
appears alone. No installed licence means no recipient display.

Installation, replacement, removal, and existing licence refreshes update the
current portal. Other open portals update on their next page load. Company-name
changes require a newly signed licence; modifying the token invalidates its
signature. Existing schema 2 licences need no reissue for this display feature.
The API status and warning are computed at runtime and are not new token fields.

### Capacity and administration

`GET /internal/admin/license` returns the canonical fields:

- `usage_unit`, `installation_id`
- `active_lineages`, `reserved_lineages`, `lineage_limit`
- `new_issuance_allowed`, `reason_codes`
- license identity and validity window
- lineage migration/readiness and verification diagnostics

`active_count`, `effective_limit`, the always-true `renewal_allowed`, and the
always-null `renewal_grace_ends_at` are temporary aliases for one compatibility
release. Admins install or remove tokens; Certificate Operators and auditors can
read capacity. Installation mismatch is a stable `409
license_installation_mismatch`; enforcement reports `license_limit_reached`,
`duplicate_certificate_identity`, or `license_state_unavailable`.

The operations dashboard warns at capacity, inside the final 30 license days,
and when lineage/key state is not production-ready. Lifecycle metrics remain
uncluttered and fully visible on the free tier; tier, usage, and the license link
live together in the Capacity panel. License state transitions and blocked
issuance are audit events. Removing an over-free license requires typed
confirmation in the admin UI and never blocks renewal.

## Vendor key operations

Production installations load licensing public keys only from
`myownca_release/license-public-keys.json`, embedded when the application wheel
is sealed and covered by its signed file inventory. Missing, changed, malformed,
or empty key rings block production verification and startup before migrations.
The cached startup ring is used for licence verification; editing configuration
cannot substitute another producer key.

The release operator supplies a public JSON file to the `seal-wheel` command's
required `--license-public-keys FILE` option. Its format is:

```json
{"schema":1,"keys":{"license-2026":"BASE64_RSA4096_DER_SPKI_PUBLIC_KEY"}}
```

Retain existing licence `key_id` values. Validation rejects duplicate/unsafe IDs,
invalid encoding, and keys that are not RSA-4096 with exponent 65537. This ring
contains public keys only. Producer licence-signing private keys remain under
vendor custody and separate from the release-signing key.

`MYOWNCA_LICENSE_PUBLIC_KEYS` is removed everywhere, including development.
Remove it from the process environment, `config.toml`, and `secrets.env` before
starting. Any occurrence causes a startup error, even an empty or identical value;
configuration precedence cannot hide it. No runtime replacement setting exists.

Rotate licensing keys through a new signed release containing the overlapping
old and new keys. Keep old public keys while their licences remain supported.
There is no standalone customer-editable licensing trust update. Source checkouts
without an embedded key ring have no trusted licensing keys and use the existing
free-tier behavior. Tests inject disposable keys directly through test fixtures.

Existing licence token formats, installation binding, capacity rules, and
operational recovery remain unchanged. Signed distributions without this ring
must be rebuilt and resealed before deployment. No database migration is needed.

This closes configuration-level key substitution. A machine owner who replaces
both the release verifier and its trust anchors can still bypass local checks;
protect those components through deployment permissions and host monitoring.

## Obtaining commercial licenses

Commercial licenses are issued outside the customer deployment. Obtain a signed
license from an authorized myOwnCA representative, then install it through
**Admin → License → Upload a license**. The Capacity panel confirms the active
limit and license validity.
