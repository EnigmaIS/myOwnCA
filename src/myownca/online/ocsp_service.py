from __future__ import annotations

import base64
import hashlib
import logging
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from myownca.ca_hsm.pkcs11 import PKCS11Error
from myownca.ca_main.crypto import IssuerMaterial, _reason_flag, _utc_now, certificate_to_pem
from myownca.ca_main.ocsp import (
    build_ocsp_response,
    build_ocsp_response_by_hash,
    build_ocsp_responder_certificate,
    issuer_cert_id_hashes,
    parse_ocsp_request,
    unsuccessful_response,
)
from myownca.domain import CertificateStatus, OcspResponder, OcspStoredResponse
from myownca.service_certs.base import KeyBackend, ServiceCertError
from myownca.service_certs.keystore import ServiceKeyStore
from myownca.storage.repositories import PKIRepository

_RESPONSE_WINDOW = timedelta(days=1)
_CERT_ID_HASHES = (("sha1", hashes.SHA1()), ("sha256", hashes.SHA256()))

logger = logging.getLogger(__name__)


class OcspService:
    def __init__(
        self,
        repository: PKIRepository,
        hsm,
        keystore: ServiceKeyStore,
        issuer_provider,            # () -> IssuerMaterial | None  (the active issuer)
        *,
        validity_days_provider,     # () -> int
        enabled_provider,           # () -> bool
    ) -> None:
        self._repo = repository
        self._hsm = hsm
        self._keystore = keystore
        self._issuer_provider = issuer_provider
        self._validity_days_provider = validity_days_provider
        self._enabled_provider = enabled_provider

    @staticmethod
    def _key_ref(issuer_subject: str) -> str:
        return "ocsp-responder-" + hashlib.sha256(issuer_subject.encode()).hexdigest()[:16]

    def _responder_private_key(self, key_ref: str):
        pem = self._keystore.software_key_pem(key_ref)
        return serialization.load_pem_private_key(pem.encode(), password=None)

    def ensure_responder(self, issuer: IssuerMaterial, now: datetime | None = None) -> OcspResponder | None:
        current = _utc_now(now)
        validity_days = self._validity_days_provider()
        issuer_subject = issuer.certificate.subject.rfc4514_string()
        key_ref = self._key_ref(issuer_subject)
        stored = self._repo.get_ocsp_responder(issuer_subject)
        if stored is not None and stored.key_ref == key_ref:
            remaining = stored.not_after - current
            if remaining > timedelta(days=validity_days) / 3:
                return stored
        # Need a (re)mint. Ensure a software key exists.
        try:
            public_key = self._keystore.public_key(key_ref, KeyBackend.SOFTWARE)
        except ServiceCertError:
            self._keystore.generate(key_ref, KeyBackend.SOFTWARE, "ecdsa-p256")
            public_key = self._keystore.public_key(key_ref, KeyBackend.SOFTWARE)
        try:
            cert = build_ocsp_responder_certificate(
                issuer, public_key, self._hsm, now=current, validity_days=validity_days
            )
        except PKCS11Error:
            self._repo.set_setting(
                "ocsp_responder_warning",
                "OCSP responder certificate needs renewal — unlock the HSM PIN.",
            )
            return None
        responder = OcspResponder(
            issuer_subject=issuer_subject, cert_pem=certificate_to_pem(cert), key_ref=key_ref,
            not_after=cert.not_valid_after_utc, created_at=current,
        )
        self._repo.upsert_ocsp_responder(responder)
        self._repo.set_setting("ocsp_responder_warning", "")
        return responder

    def generate_responses(self, issuer: IssuerMaterial, now: datetime | None = None) -> int:
        if not self._enabled_provider():
            return 0
        current = _utc_now(now)
        responder = self.ensure_responder(issuer, current)
        if responder is None:  # HSM locked, nothing to sign with
            return 0
        responder_cert = x509.load_pem_x509_certificate(responder.cert_pem.encode())
        responder_key = self._responder_private_key(responder.key_ref)
        revoked = {r.certificate_id: r for r in self._repo.list_revocations()}
        issuer_id = issuer.certificate.fingerprint(hashes.SHA256()).hex()
        next_update = current + _RESPONSE_WINDOW
        count = 0
        for issued in self._repo.list_issued_certificates():
            if issued.issuer_id != issuer_id:
                continue
            self._produce_for(
                issued, issuer_cert=issuer.certificate, issuer_subject=responder.issuer_subject,
                responder_cert=responder_cert, responder_key=responder_key,
                revocation=revoked.get(issued.certificate_id),
                current=current,
                next_update=next_update,
            )
            count += len(_CERT_ID_HASHES)
        return count

    def _produce_for(self, issued, *, issuer_cert, issuer_subject, responder_cert, responder_key,
                     revocation, current: datetime, next_update: datetime) -> None:
        subject_cert = x509.load_pem_x509_certificate(issued.certificate_pem.encode())
        if revocation is not None or issued.status is CertificateStatus.REVOKED:
            status = ocsp.OCSPCertStatus.REVOKED
            rtime = revocation.revoked_at if revocation is not None else current
            rreason = _reason_flag(revocation.reason) if revocation is not None else None
        else:
            status, rtime, rreason = ocsp.OCSPCertStatus.GOOD, None, None
        for hash_name, hash_alg in _CERT_ID_HASHES:
            der = build_ocsp_response(
                subject_cert=subject_cert, issuer_cert=issuer_cert,
                responder_cert=responder_cert, responder_key=responder_key,
                cert_status=status, cert_id_hash=hash_alg,
                this_update=current, next_update=next_update,
                revocation_time=rtime, revocation_reason=rreason,
            )
            self._repo.upsert_ocsp_response(OcspStoredResponse(
                issuer_subject=issuer_subject, serial_number=issued.serial_number,
                cert_id_hash=hash_name, response_b64=base64.b64encode(der).decode(),
                this_update=current, next_update=next_update, produced_at=current,
            ))

    def run_scheduled_pass(self, now: datetime | None = None) -> int:
        """The daily tick: regenerate all responses for the active issuer.

        Delegates to generate_responses, which no-ops when OCSP is disabled and
        opportunistically renews the responder cert (HSM-gated) when it's near
        expiry and the token is unlocked. Best-effort.
        """
        issuer = self._issuer_provider()
        if issuer is None:
            return 0
        return self.generate_responses(issuer, now)

    def refresh_response(self, serial_number: str, now: datetime | None = None) -> bool:
        """Re-sign one certificate's OCSP response in place (best-effort).

        Uses the EXISTING responder and the software key — no HSM, so a revocation
        is reflected over OCSP even while the token is locked. Returns False (and
        never raises) when OCSP is off, no responder exists yet, the serial is
        unknown, or anything goes wrong; the next scheduled/manual generate covers it.
        """
        if not self._enabled_provider():
            return False
        try:
            issuer = self._issuer_provider()
            if issuer is None:
                return False
            issuer_subject = issuer.certificate.subject.rfc4514_string()
            responder = self._repo.get_ocsp_responder(issuer_subject)
            if responder is None:
                return False
            issuer_id = issuer.certificate.fingerprint(hashes.SHA256()).hex()
            issued = self._repo.get_certificate_by_issuer_and_serial(
                issuer_id, serial_number
            )
            revocation = next(
                (
                    r
                    for r in self._repo.list_revocations()
                    if r.certificate_id == issued.certificate_id
                ),
                None,
            )
            current = _utc_now(now)
            self._produce_for(
                issued, issuer_cert=issuer.certificate, issuer_subject=issuer_subject,
                responder_cert=x509.load_pem_x509_certificate(responder.cert_pem.encode()),
                responder_key=self._responder_private_key(responder.key_ref),
                revocation=revocation, current=current, next_update=current + _RESPONSE_WINDOW,
            )
            return True
        except Exception:  # noqa: BLE001 - best-effort; OCSP must never break issuance/revocation
            logger.warning("OCSP refresh failed for serial %s", serial_number, exc_info=True)
            return False

    @staticmethod
    def _hash_name(alg) -> str:
        return alg.name  # "sha1" / "sha256" / …

    def respond(self, request_der: bytes, now: datetime | None = None) -> bytes:
        current = _utc_now(now)
        try:
            req = parse_ocsp_request(request_der)
        except Exception:  # noqa: BLE001 - any decode failure is a malformed request
            return unsuccessful_response(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)
        issuer = self._issuer_provider()
        if issuer is None:
            return unsuccessful_response(ocsp.OCSPResponseStatus.UNAUTHORIZED)
        name_hash, key_hash = issuer_cert_id_hashes(issuer.certificate, req.hash_algorithm)
        if (req.issuer_name_hash, req.issuer_key_hash) != (name_hash, key_hash):
            return unsuccessful_response(ocsp.OCSPResponseStatus.UNAUTHORIZED)
        issuer_subject = issuer.certificate.subject.rfc4514_string()
        serial_hex = format(req.serial_number, "x")
        hash_name = self._hash_name(req.hash_algorithm)
        stored = self._repo.get_ocsp_response(issuer_subject, serial_hex, hash_name)
        if stored is not None:
            return base64.b64decode(stored.response_b64)
        # Authoritative but no stored response (serial we never issued, or an
        # unsupported CertID hash): sign an UNKNOWN on the fly with the software key.
        # This public path never mints — it only uses an already-issued responder
        # (minting is HSM-gated and happens on enable/generate), so respond() never
        # touches the HSM and an anonymous request can't drive a signing operation.
        responder = self._repo.get_ocsp_responder(issuer.certificate.subject.rfc4514_string())
        if responder is None:
            return unsuccessful_response(ocsp.OCSPResponseStatus.UNAUTHORIZED)
        responder_cert = x509.load_pem_x509_certificate(responder.cert_pem.encode())
        responder_key = self._responder_private_key(responder.key_ref)
        return build_ocsp_response_by_hash(
            issuer_name_hash=req.issuer_name_hash, issuer_key_hash=req.issuer_key_hash,
            serial_number=req.serial_number, responder_cert=responder_cert,
            responder_key=responder_key, cert_id_hash=req.hash_algorithm,
            this_update=current, next_update=current + _RESPONSE_WINDOW,
        )
