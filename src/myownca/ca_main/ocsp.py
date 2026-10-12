from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from myownca.ca_hsm.base import HSMBackend
from myownca.ca_main.crypto import IssuerMaterial, _utc_now, generate_serial_number


def issuer_cert_id_hashes(
    issuer_cert: x509.Certificate, hash_alg: hashes.HashAlgorithm
) -> tuple[bytes, bytes]:
    """The (issuerNameHash, issuerKeyHash) for a CertID under ``hash_alg``.

    issuerNameHash = hash of the issuer's subject DN (the value a real request
    carries via the leaf's issuer field). issuerKeyHash = hash of the issuer's
    public key, taken from a probe request (key-type-agnostic for RSA/EC).
    """
    name_hash = hashlib.new(hash_alg.name, issuer_cert.subject.public_bytes()).digest()
    probe = ocsp.OCSPRequestBuilder().add_certificate(issuer_cert, issuer_cert, hash_alg).build()
    return name_hash, probe.issuer_key_hash


def _issuer_common_name(issuer_cert: x509.Certificate) -> str:
    attrs = issuer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else "Issuing CA"


def build_ocsp_responder_certificate(
    issuer: IssuerMaterial,
    responder_public_key,
    hsm: HSMBackend,
    now: datetime | None = None,
    validity_days: int = 30,
) -> x509.Certificate:
    """A delegated OCSP-signing certificate, signed by the issuer (HSM-gated)."""
    current = _utc_now(now)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"{_issuer_common_name(issuer.certificate)} OCSP Responder")]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.certificate.subject)
        .public_key(responder_public_key)
        .serial_number(generate_serial_number())
        .not_valid_before(current - timedelta(minutes=5))
        .not_valid_after(current + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)
        .add_extension(x509.OCSPNoCheck(), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(responder_public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.certificate.public_key()),
            critical=False,
        )
    )
    return hsm.sign_certificate(builder, issuer.key_ref)


def build_ocsp_response(
    *,
    subject_cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    responder_cert: x509.Certificate,
    responder_key,
    cert_status: ocsp.OCSPCertStatus,
    cert_id_hash: hashes.HashAlgorithm,
    this_update: datetime,
    next_update: datetime,
    revocation_time: datetime | None = None,
    revocation_reason: x509.ReasonFlags | None = None,
) -> bytes:
    """A signed single-cert OCSP response (DER) for a certificate we hold."""
    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=subject_cert, issuer=issuer_cert, algorithm=cert_id_hash,
            cert_status=cert_status, this_update=this_update, next_update=next_update,
            revocation_time=revocation_time, revocation_reason=revocation_reason,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
        .certificates([responder_cert])
    )
    return builder.sign(responder_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def build_ocsp_response_by_hash(
    *,
    issuer_name_hash: bytes,
    issuer_key_hash: bytes,
    serial_number: int,
    responder_cert: x509.Certificate,
    responder_key,
    cert_id_hash: hashes.HashAlgorithm,
    this_update: datetime,
    next_update: datetime,
    cert_status: ocsp.OCSPCertStatus = ocsp.OCSPCertStatus.UNKNOWN,
) -> bytes:
    """A signed response for a serial we do NOT hold a certificate for (e.g. UNKNOWN)."""
    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response_by_hash(
            issuer_name_hash, issuer_key_hash, serial_number, cert_id_hash,
            cert_status, this_update, next_update, None, None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
        .certificates([responder_cert])
    )
    return builder.sign(responder_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def parse_ocsp_request(der: bytes) -> ocsp.OCSPRequest:
    return ocsp.load_der_ocsp_request(der)


def unsuccessful_response(status: ocsp.OCSPResponseStatus) -> bytes:
    return ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(serialization.Encoding.DER)
