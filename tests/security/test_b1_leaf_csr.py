"""B1 — leaf / CSR issuance adversarial battery.

Invariants an attacker-controlled CSR must never break:
  * the issued cert is always BasicConstraints(ca=False);
  * the issued KeyUsage never carries key_cert_sign / crl_sign;
  * profile SAN-type policy is enforced;
  * proof-of-possession (CSR self-signature) is required;
  * serials are unpredictable + unique.
Also probes robustness (garbage in -> clean error) and key-strength policy.
"""
from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from myownca.ca_main.crypto import build_end_entity_certificate, parse_csr
from myownca.domain import CertificateProfile
from myownca_core.leaf import CSRValidationError

from tests.security.conftest import (
    WEAK_KEY_NAMES,
    build_weak_key,
    csr_pem,
    tamper_csr_pem,
    template,
)

PROFILES = list(CertificateProfile)


def _issue(issuer, pem, profile=CertificateProfile.HOST_TLS, **kw):
    material, hsm = issuer
    csr = parse_csr(pem)
    return build_end_entity_certificate(csr, template(profile), material, hsm, **kw)


# --- core issuance invariants -------------------------------------------------

@pytest.mark.parametrize("profile", PROFILES)
def test_issued_leaf_is_never_a_ca(issuer, profile):
    san = {"host_tls": dict(dns=("a.test",)), "smime": dict(emails=("a@b.test",)),
           "user_auth": dict(emails=("a@b.test",))}[profile.value]
    cert = _issue(issuer, csr_pem("leaf.test", **san), profile)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False and bc.path_length is None
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is False
    assert ku.crl_sign is False


def test_csr_requesting_ca_true_is_rejected(issuer):
    with pytest.raises(CSRValidationError):
        _issue(issuer, csr_pem("evil.test", dns=("evil.test",), ca=True))


def test_requested_keyusage_is_ignored_not_honored(issuer):
    # CSR explicitly asks for key_cert_sign; the issued cert must not grant it.
    asked = x509.KeyUsage(
        digital_signature=True, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
        encipher_only=False, decipher_only=False)
    cert = _issue(issuer, csr_pem("leaf.test", dns=("leaf.test",), request_key_usage=asked))
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is False and ku.crl_sign is False


# --- SAN policy ---------------------------------------------------------------

def test_host_tls_rejects_exotic_san_types(issuer):
    exotic = [
        x509.UniformResourceIdentifier("https://evil.test"),
        x509.RFC822Name("evil@evil.test"),
    ]
    for name in exotic:
        with pytest.raises(CSRValidationError):
            _issue(issuer, csr_pem("h.test", dns=("h.test",), sans=[name]),
                   CertificateProfile.HOST_TLS)


def test_host_tls_requires_a_dns_san(issuer):
    with pytest.raises(CSRValidationError):
        _issue(issuer, csr_pem("h.test", emails=("only@email.test",)), CertificateProfile.HOST_TLS)


def test_smime_rejects_dns_san(issuer):
    with pytest.raises(CSRValidationError):
        _issue(issuer, csr_pem("u.test", dns=("u.test",), emails=("u@b.test",)),
               CertificateProfile.SMIME)


def test_directory_name_san_is_rejected_everywhere(issuer):
    dn = x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "smuggled")]))
    for profile in PROFILES:
        with pytest.raises(CSRValidationError):
            _issue(issuer, csr_pem("x.test", dns=("x.test",), emails=("x@b.test",), sans=[dn]),
                   profile)


# --- proof of possession ------------------------------------------------------

def test_tampered_csr_signature_is_rejected(issuer):
    with pytest.raises(CSRValidationError):
        _issue(issuer, tamper_csr_pem(csr_pem("leaf.test", dns=("leaf.test",))))


def test_missing_common_name_is_rejected(issuer):
    with pytest.raises(CSRValidationError):
        _issue(issuer, csr_pem(None, dns=("leaf.test",)))


# --- serial randomness --------------------------------------------------------

def test_serials_are_unique_and_unpredictable(issuer):
    serials = set()
    for i in range(300):
        cert = _issue(issuer, csr_pem(f"leaf-{i}.test", dns=(f"leaf-{i}.test",)))
        assert cert.serial_number > 0
        assert cert.serial_number.bit_length() >= 64  # random_serial_number ~ up to 160 bits
        serials.add(cert.serial_number)
    assert len(serials) == 300


# --- robustness: garbage in -> clean error (never a raw crash that 500s) -------

@pytest.mark.parametrize("blob", [
    "", "not a csr", "-----BEGIN CERTIFICATE REQUEST-----\nZm9v\n-----END CERTIFICATE REQUEST-----\n",
    b"\x00\x01\x02\x03", "A" * 100000,
])
def test_garbage_csr_raises_valueerror_not_crash(issuer, blob):
    # CSRValidationError is a ValueError subclass; a caller catching ValueError
    # catches every rejection. The contract: never return, never a non-ValueError.
    with pytest.raises(ValueError):
        parse_csr(blob)


# --- key-strength policy (probe; result recorded by the report) ---------------

# F-2 fix: weak/deprecated subject keys must be REJECTED at issuance.
_WEAK_MUST_REJECT = {"rsa-1024", "ec-secp192r1", "dsa-1024"}
_STRONG_MUST_ISSUE = {"ec-p256"}


@pytest.mark.parametrize("name", WEAK_KEY_NAMES)
def test_key_strength_policy_is_enforced(issuer, name):
    """build_end_entity_certificate must refuse weak RSA/EC + DSA, and accept strong keys."""
    try:
        key = build_weak_key(name)
    except Exception as exc:
        pytest.skip(f"{name}: keygen unsupported: {exc!r}")
    try:
        pem = csr_pem("k.test", key=key, dns=("k.test",))
    except Exception as exc:
        pytest.skip(f"{name}: CSR build unsupported: {exc!r}")
    if name in _WEAK_MUST_REJECT:
        with pytest.raises(CSRValidationError):
            _issue(issuer, pem)
    else:  # strong keys still issue
        cert = _issue(issuer, pem)
        assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False


def test_rsa_2048_still_issues(issuer):
    cert = _issue(issuer, csr_pem("ok.test", dns=("ok.test",)))  # default key = RSA-2048
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
