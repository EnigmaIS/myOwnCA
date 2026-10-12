"""Shared fixtures + adversarial CSR builders for the crypto pentest batteries."""
from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import NameOID

from myownca.ca_hsm import SoftwareHSM
from myownca.ca_main.crypto import IssuerMaterial, create_lab_ca_chain
from myownca.domain import CertificateProfile, CertificateTemplate


@pytest.fixture()
def issuer() -> IssuerMaterial:
    hsm = SoftwareHSM()
    return create_lab_ca_chain(hsm).issuer, hsm


def template(profile: CertificateProfile = CertificateProfile.HOST_TLS) -> CertificateTemplate:
    return CertificateTemplate(id=f"t-{profile.value}", name=profile.value, profile=profile)


# --- adversarial CSR builders -------------------------------------------------

def _sign(builder, key):
    return builder.sign(key, hashes.SHA256())


def csr_pem(
    common_name: str | None,
    *,
    key=None,
    dns: tuple[str, ...] = (),
    emails: tuple[str, ...] = (),
    sans: list[x509.GeneralName] | None = None,
    ca: bool | None = None,
    request_key_usage: x509.KeyUsage | None = None,
) -> str:
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)] if common_name is not None else []
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
    names: list[x509.GeneralName] = [x509.DNSName(n) for n in dns]
    names += [x509.RFC822Name(e) for e in emails]
    if sans:
        names += sans
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if ca is not None:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if request_key_usage is not None:
        builder = builder.add_extension(request_key_usage, critical=True)
    return _sign(builder, key).public_bytes(serialization.Encoding.PEM).decode()


def tamper_csr_pem(pem: str) -> str:
    """A structurally-valid CSR PEM whose self-signature no longer verifies.

    Flips a byte inside the trailing signature value, then re-wraps as PEM so it
    still loads (is_signature_valid -> False) rather than failing to parse.
    """
    import base64
    import textwrap

    csr = x509.load_pem_x509_csr(pem.encode())
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-5] ^= 0xFF
    body = textwrap.fill(base64.b64encode(bytes(der)).decode(), 64)
    return f"-----BEGIN CERTIFICATE REQUEST-----\n{body}\n-----END CERTIFICATE REQUEST-----\n"


WEAK_KEY_NAMES = ["rsa-1024", "ec-secp192r1", "ec-p256", "dsa-1024"]


def build_weak_key(name: str):
    """Build a weak/odd private key by name; raises if cryptography refuses it."""
    if name == "rsa-1024":
        return rsa.generate_private_key(public_exponent=65537, key_size=1024)
    if name == "ec-secp192r1":
        return ec.generate_private_key(ec.SECP192R1())
    if name == "ec-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if name == "dsa-1024":
        return dsa.generate_private_key(key_size=1024)
    raise ValueError(name)
