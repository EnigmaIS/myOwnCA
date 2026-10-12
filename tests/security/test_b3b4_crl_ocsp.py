"""B3 (CRL) + B4 (OCSP) revocation-integrity batteries."""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

from myownca.ca_hsm import SoftwareHSM
from myownca.ca_main.crypto import (
    build_crl,
    build_end_entity_certificate,
    create_lab_ca_chain,
    crl_pem_to_der,
    crl_to_pem,
    parse_csr,
)
from myownca.ca_main.ocsp import (
    build_ocsp_responder_certificate,
    build_ocsp_response,
    build_ocsp_response_by_hash,
    issuer_cert_id_hashes,
    parse_ocsp_request,
)
from myownca.domain import Revocation, RevocationReason
from tests.security.conftest import csr_pem, template

UTC = datetime.timezone.utc


def _chain():
    hsm = SoftwareHSM()
    issuer = create_lab_ca_chain(hsm).issuer
    return hsm, issuer


def _leaf(hsm, issuer):
    csr = parse_csr(csr_pem("leaf.test", dns=("leaf.test",)))
    return build_end_entity_certificate(csr, template(), issuer, hsm)


# --- B3: CRL ------------------------------------------------------------------

def test_crl_embeds_number_and_entries_and_verifies():
    hsm, issuer = _chain()
    now = datetime.datetime.now(UTC)
    revs = [Revocation(serial_number=format(i * 0x11111111, "x"),
                       reason=RevocationReason.KEY_COMPROMISE, revoked_at=now) for i in range(1, 11)]
    crl = build_crl(issuer, revs, crl_number=42, hsm=hsm)
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 42
    assert crl.is_signature_valid(issuer.certificate.public_key())
    for rev in revs:
        assert crl.get_revoked_certificate_by_serial_number(int(rev.serial_number, 16)) is not None


def test_crl_der_round_trip():
    hsm, issuer = _chain()
    crl = build_crl(issuer, [], crl_number=1, hsm=hsm)
    der = crl_pem_to_der(crl_to_pem(crl))
    assert x509.load_der_x509_crl(der).extensions.get_extension_for_class(
        x509.CRLNumber).value.crl_number == 1


def test_crl_with_nonhex_serial_fails_cleanly():
    hsm, issuer = _chain()
    bad = [Revocation(serial_number="not-hex-zz", reason=RevocationReason.UNSPECIFIED,
                      revoked_at=datetime.datetime.now(UTC))]
    with pytest.raises(ValueError):
        build_crl(issuer, bad, crl_number=1, hsm=hsm)


def test_large_crl_builds():
    hsm, issuer = _chain()
    now = datetime.datetime.now(UTC)
    revs = [Revocation(serial_number=format(i, "x"), reason=RevocationReason.SUPERSEDED,
                       revoked_at=now) for i in range(1, 5001)]
    crl = build_crl(issuer, revs, crl_number=7, hsm=hsm)
    assert crl.is_signature_valid(issuer.certificate.public_key())


# --- B4: OCSP -----------------------------------------------------------------

def _responder(hsm, issuer):
    rkey = ec.generate_private_key(ec.SECP256R1())
    rcert = build_ocsp_responder_certificate(issuer, rkey.public_key(), hsm)
    return rkey, rcert


def test_responder_cert_shape():
    hsm, issuer = _chain()
    _rkey, rcert = _responder(hsm, issuer)
    eku = rcert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.OCSP_SIGNING in eku
    rcert.extensions.get_extension_for_class(x509.OCSPNoCheck)  # present
    ku = rcert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is False and ku.crl_sign is False


@pytest.mark.parametrize("status", [ocsp.OCSPCertStatus.GOOD, ocsp.OCSPCertStatus.REVOKED])
def test_ocsp_response_status_and_signature(status):
    hsm, issuer = _chain()
    leaf = _leaf(hsm, issuer)
    rkey, rcert = _responder(hsm, issuer)
    now = datetime.datetime.now(UTC)
    rev_time = now if status is ocsp.OCSPCertStatus.REVOKED else None
    rev_reason = x509.ReasonFlags.key_compromise if status is ocsp.OCSPCertStatus.REVOKED else None
    der = build_ocsp_response(
        subject_cert=leaf, issuer_cert=issuer.certificate, responder_cert=rcert, responder_key=rkey,
        cert_status=status, cert_id_hash=hashes.SHA1(), this_update=now,
        next_update=now + datetime.timedelta(days=1), revocation_time=rev_time,
        revocation_reason=rev_reason)
    resp = ocsp.load_der_ocsp_response(der)
    assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
    assert resp.certificate_status == status
    assert resp.serial_number == leaf.serial_number
    # signature verifies under the responder cert's public key
    rcert.public_key().verify(resp.signature, resp.tbs_response_bytes,
                              ec.ECDSA(resp.signature_hash_algorithm))


def test_ocsp_unknown_by_hash():
    hsm, issuer = _chain()
    rkey, rcert = _responder(hsm, issuer)
    nh, kh = issuer_cert_id_hashes(issuer.certificate, hashes.SHA1())
    now = datetime.datetime.now(UTC)
    der = build_ocsp_response_by_hash(
        issuer_name_hash=nh, issuer_key_hash=kh, serial_number=0xDEADBEEF, responder_cert=rcert,
        responder_key=rkey, cert_id_hash=hashes.SHA1(), this_update=now,
        next_update=now + datetime.timedelta(days=1))
    resp = ocsp.load_der_ocsp_response(der)
    assert resp.certificate_status == ocsp.OCSPCertStatus.UNKNOWN
    assert resp.serial_number == 0xDEADBEEF


def test_issuer_name_hash_matches_real_client_request():
    """The gotcha: issuerNameHash must equal a real client's CertID name hash."""
    hsm, issuer = _chain()
    leaf = _leaf(hsm, issuer)
    client_req = ocsp.OCSPRequestBuilder().add_certificate(
        leaf, issuer.certificate, hashes.SHA1()).build()
    nh, kh = issuer_cert_id_hashes(issuer.certificate, hashes.SHA1())
    assert nh == client_req.issuer_name_hash
    assert kh == client_req.issuer_key_hash


@pytest.mark.parametrize("blob", [b"", b"\x00", b"\x30\x80garbage", b"A" * 5000, bytes(range(256))])
def test_parse_ocsp_request_robust(blob):
    with pytest.raises(Exception):
        parse_ocsp_request(blob)
