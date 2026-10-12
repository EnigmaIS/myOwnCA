from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

from myownca.domain import Revocation, RevocationReason


class CRLImportError(ValueError):
    """A safe, user-presentable CRL migration validation failure."""


@dataclass(frozen=True, slots=True)
class CRLImportAnalysis:
    crl: x509.CertificateRevocationList | None
    number: int
    revocations: tuple[Revocation, ...]
    this_update: datetime | None
    next_update: datetime | None
    crl_pem: str | None
    sha256: str | None
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "prior_crl_state": "crl" if self.crl is not None else "never_issued_crl",
            "number": self.number if self.crl is not None else None,
            "this_update": self.this_update.isoformat() if self.this_update else None,
            "next_update": self.next_update.isoformat() if self.next_update else None,
            "revocation_count": len(self.revocations),
            "sha256": self.sha256,
            "warnings": list(self.warnings),
        }


_FLAG_TO_REASON = {
    x509.ReasonFlags.unspecified: RevocationReason.UNSPECIFIED,
    x509.ReasonFlags.key_compromise: RevocationReason.KEY_COMPROMISE,
    x509.ReasonFlags.ca_compromise: RevocationReason.CA_COMPROMISE,
    x509.ReasonFlags.affiliation_changed: RevocationReason.AFFILIATION_CHANGED,
    x509.ReasonFlags.superseded: RevocationReason.SUPERSEDED,
    x509.ReasonFlags.cessation_of_operation: RevocationReason.CESSATION_OF_OPERATION,
    x509.ReasonFlags.certificate_hold: RevocationReason.CERTIFICATE_HOLD,
    x509.ReasonFlags.privilege_withdrawn: RevocationReason.PRIVILEGE_WITHDRAWN,
    x509.ReasonFlags.aa_compromise: RevocationReason.AA_COMPROMISE,
}


def analyze_crl_migration(
    issuer_certificate: x509.Certificate,
    *,
    prior_crl_state: str,
    crl_b64: str | None,
    now: datetime | None = None,
    max_bytes: int = 5 * 1024 * 1024,
) -> CRLImportAnalysis:
    state = prior_crl_state.strip().casefold()
    if state not in {"crl", "never_issued_crl"}:
        raise CRLImportError("prior_crl_state must be crl or never_issued_crl")
    if state == "never_issued_crl":
        if crl_b64 and crl_b64.strip():
            raise CRLImportError("Do not upload a CRL when declaring never_issued_crl")
        return CRLImportAnalysis(
            crl=None,
            number=0,
            revocations=(),
            this_update=None,
            next_update=None,
            crl_pem=None,
            sha256=None,
        )
    if not crl_b64 or not crl_b64.strip():
        raise CRLImportError("Upload the latest complete CRL")
    try:
        payload = base64.b64decode(crl_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CRLImportError("CRL upload is not valid base64") from exc
    if not payload:
        raise CRLImportError("CRL upload is empty")
    if len(payload) > max_bytes:
        raise CRLImportError("CRL upload exceeds 5 MiB")
    try:
        crl = (
            x509.load_pem_x509_crl(payload)
            if b"-----BEGIN X509 CRL-----" in payload
            else x509.load_der_x509_crl(payload)
        )
    except ValueError as exc:
        raise CRLImportError("CRL is neither valid PEM nor DER") from exc

    if crl.issuer != issuer_certificate.subject:
        raise CRLImportError("CRL issuer does not match the imported Sub CA")
    try:
        if not crl.is_signature_valid(issuer_certificate.public_key()):
            raise CRLImportError("CRL signature is invalid")
    except (TypeError, UnsupportedAlgorithm, ValueError) as exc:
        raise CRLImportError("CRL signature cannot be verified") from exc

    try:
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound as exc:
        raise CRLImportError("Imported CRL must contain CRLNumber") from exc
    if number < 0 or number >= 2**63 - 1:
        raise CRLImportError("CRLNumber is outside the supported range")
    try:
        crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
    except x509.ExtensionNotFound:
        pass
    else:
        raise CRLImportError("Delta CRLs are not supported")
    try:
        issuing_distribution_point = crl.extensions.get_extension_for_class(
            x509.IssuingDistributionPoint
        ).value
    except x509.ExtensionNotFound:
        pass
    else:
        if (
            issuing_distribution_point.indirect_crl
            or issuing_distribution_point.full_name is not None
            or issuing_distribution_point.relative_name is not None
            or issuing_distribution_point.only_some_reasons is not None
            or issuing_distribution_point.only_contains_user_certs
            or issuing_distribution_point.only_contains_ca_certs
            or issuing_distribution_point.only_contains_attribute_certs
        ):
            raise CRLImportError("Indirect or partitioned CRLs are not supported")

    this_update = _crl_time(crl, "last_update")
    next_update = _crl_time(crl, "next_update")
    if this_update is None:  # pragma: no cover - ASN.1 requires thisUpdate
        raise CRLImportError("CRL does not contain thisUpdate")
    if next_update is not None and next_update <= this_update:
        raise CRLImportError("CRL nextUpdate must be later than thisUpdate")
    _validate_crl_extensions(crl, issuer_certificate)
    revocations = _revocations(crl, this_update)
    current = _utc(now)
    if this_update > current + timedelta(minutes=5):
        raise CRLImportError("CRL thisUpdate is in the future")
    warnings: list[str] = []
    if next_update is None:
        warnings.append("Imported CRL has no nextUpdate; a fresh local CRL will be generated.")
    elif next_update <= current:
        warnings.append("Imported CRL is expired; a fresh local CRL will be generated.")
    der = crl.public_bytes(serialization.Encoding.DER)
    pem = crl.public_bytes(serialization.Encoding.PEM).decode()
    return CRLImportAnalysis(
        crl=crl,
        number=number,
        revocations=tuple(revocations),
        this_update=this_update,
        next_update=next_update,
        crl_pem=pem,
        sha256=hashlib.sha256(der).hexdigest(),
        warnings=tuple(warnings),
    )


def _validate_crl_extensions(
    crl: x509.CertificateRevocationList,
    issuer_certificate: x509.Certificate,
) -> None:
    allowed = {
        ExtensionOID.CRL_NUMBER,
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
        ExtensionOID.ISSUING_DISTRIBUTION_POINT,
    }
    for extension in crl.extensions:
        if extension.critical and extension.oid not in allowed:
            raise CRLImportError(
                f"Unsupported critical CRL extension: {extension.oid.dotted_string}"
            )
    try:
        aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    except x509.ExtensionNotFound:
        return
    expected = x509.SubjectKeyIdentifier.from_public_key(
        issuer_certificate.public_key()
    ).digest
    try:
        expected = issuer_certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.digest
    except x509.ExtensionNotFound:
        pass
    if aki.key_identifier is not None and aki.key_identifier != expected:
        raise CRLImportError("CRL AuthorityKeyIdentifier does not match the Sub CA")
    if (
        aki.authority_cert_serial_number is not None
        and aki.authority_cert_serial_number != issuer_certificate.serial_number
    ):
        raise CRLImportError("CRL AuthorityKeyIdentifier serial does not match the Sub CA")
    if aki.authority_cert_issuer is not None:
        names = [
            name.value
            for name in aki.authority_cert_issuer
            if isinstance(name, x509.DirectoryName)
        ]
        if issuer_certificate.issuer not in names:
            raise CRLImportError(
                "CRL AuthorityKeyIdentifier issuer does not match the Sub CA"
            )


def _revocations(
    crl: x509.CertificateRevocationList,
    this_update: datetime,
) -> list[Revocation]:
    seen: set[int] = set()
    results: list[Revocation] = []
    for entry in crl:
        if entry.serial_number <= 0 or entry.serial_number.bit_length() > 159:
            raise CRLImportError("CRL contains an invalid certificate serial")
        if entry.serial_number in seen:
            raise CRLImportError("CRL contains a duplicate certificate serial")
        seen.add(entry.serial_number)
        for extension in entry.extensions:
            if isinstance(extension.value, x509.CertificateIssuer):
                raise CRLImportError("Indirect CRL entries are not supported")
            if extension.critical and not isinstance(
                extension.value, (x509.CRLReason, x509.InvalidityDate)
            ):
                raise CRLImportError(
                    "CRL contains an unsupported critical revoked-certificate extension"
                )
        reason = RevocationReason.UNSPECIFIED
        try:
            flag = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
        except x509.ExtensionNotFound:
            pass
        else:
            if flag is x509.ReasonFlags.remove_from_crl:
                raise CRLImportError("removeFromCRL is valid only in a delta CRL")
            try:
                reason = _FLAG_TO_REASON[flag]
            except KeyError as exc:
                raise CRLImportError(f"Unsupported CRL reason: {flag.name}") from exc
        revoked_at = _entry_time(entry)
        if revoked_at > this_update:
            raise CRLImportError(
                "CRL contains a revocation date later than thisUpdate"
            )
        invalidity_date = None
        try:
            invalidity_date = entry.extensions.get_extension_for_class(
                x509.InvalidityDate
            ).value.invalidity_date
            invalidity_date = _utc(invalidity_date)
        except x509.ExtensionNotFound:
            pass
        if invalidity_date is not None and invalidity_date > revoked_at:
            raise CRLImportError(
                "CRL invalidityDate must not be later than revocationDate"
            )
        results.append(
            Revocation(
                serial_number=format(entry.serial_number, "x"),
                reason=reason,
                revoked_at=revoked_at,
                invalidity_date=invalidity_date,
            )
        )
    return results


def _crl_time(
    crl: x509.CertificateRevocationList,
    name: str,
) -> datetime | None:
    value = getattr(crl, f"{name}_utc", None)
    if value is None:
        value = getattr(crl, name)
    return _utc(value) if value is not None else None


def _entry_time(entry: x509.RevokedCertificate) -> datetime:
    value = getattr(entry, "revocation_date_utc", None) or entry.revocation_date
    return _utc(value)


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)
