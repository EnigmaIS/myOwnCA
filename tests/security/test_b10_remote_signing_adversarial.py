"""B10 — hostile provider responses on the cloud-KMS signing path.

A cloud-backed issuer never holds its private key: the CA builds a template with a
throwaway key, asks the provider to sign the TBS bytes, and splices the returned
signature into the DER (`ca_hsm/remote.py:220-262`).

The existing cloud tests cover the cooperative case. These cover a provider that
answers badly -- a misconfigured key alias, a silently rotated key, a truncated or
corrupted response. The CA must fail closed at issuance rather than emit a
certificate that carries a signature which does not verify: nothing downstream
re-checks it, so such a certificate is only discovered when a relying party
rejects it, long after it has been distributed.

The provider is faked with a local software key, which drives the real splice,
the real ECDSA normalisation and the real DER parsers -- no cloud account needed.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from myownca.ca_hsm.remote import (
    CloudKeyValidationError,
    normalize_ecdsa_signature,
    sign_certificate_with_remote_key,
    sign_crl_with_remote_key,
    sign_csr_with_remote_key,
)

NOW = datetime.now(timezone.utc)


def _name(common_name: str = "Cloud Issuer") -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate_builder(public_key) -> x509.CertificateBuilder:
    return (
        x509.CertificateBuilder()
        .subject_name(_name("leaf.test"))
        .issuer_name(_name())
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(minutes=5))
        .not_valid_after(NOW + timedelta(days=365))
    )


def _crl_builder() -> x509.CertificateRevocationListBuilder:
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_name())
        .last_update(NOW)
        .next_update(NOW + timedelta(days=7))
    )


def _csr_builder() -> x509.CertificateSigningRequestBuilder:
    return x509.CertificateSigningRequestBuilder().subject_name(_name("subject.test"))


def _honest_signer(private_key):
    """A provider that signs correctly with the key the CA believes it holds."""

    def sign(payload: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            return private_key.sign(payload, ec.ECDSA(algorithm))
        return private_key.sign(payload, padding.PKCS1v15(), algorithm)

    return sign


def _wrong_key_signer(other_key):
    """Well-formed signature, wrong key: a rotated alias or a misconfigured ARN."""
    return _honest_signer(other_key)


class HonestProviderBaselineTests(unittest.TestCase):
    """The cooperative path must keep working (guards against over-strict fixes)."""

    def test_ec_certificate_crl_and_csr_still_verify(self) -> None:
        key = ec.generate_private_key(ec.SECP384R1())
        public_key = key.public_key()
        signer = _honest_signer(key)

        certificate = sign_certificate_with_remote_key(
            _certificate_builder(public_key), public_key, signer
        )
        crl = sign_crl_with_remote_key(_crl_builder(), public_key, signer)
        csr = sign_csr_with_remote_key(_csr_builder(), public_key, signer)

        public_key.verify(
            certificate.signature, certificate.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA384()),
        )
        self.assertTrue(crl.is_signature_valid(public_key))
        self.assertTrue(csr.is_signature_valid)

    def test_rsa_certificate_still_verifies(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = key.public_key()
        certificate = sign_certificate_with_remote_key(
            _certificate_builder(public_key), public_key, _honest_signer(key)
        )
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )


class WrongKeyResponseTests(unittest.TestCase):
    """A signature from the wrong key must not become an issued certificate."""

    def test_ec_certificate_from_a_different_key_is_refused(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        impostor = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(CloudKeyValidationError):
            sign_certificate_with_remote_key(
                _certificate_builder(key.public_key()),
                key.public_key(),
                _wrong_key_signer(impostor),
            )

    def test_rsa_certificate_from_a_different_key_is_refused(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        impostor = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(CloudKeyValidationError):
            sign_certificate_with_remote_key(
                _certificate_builder(key.public_key()),
                key.public_key(),
                _wrong_key_signer(impostor),
            )

    def test_crl_from_a_different_key_is_refused(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        impostor = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(CloudKeyValidationError):
            sign_crl_with_remote_key(
                _crl_builder(), key.public_key(), _wrong_key_signer(impostor)
            )

    def test_csr_from_a_different_key_is_refused(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        impostor = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(CloudKeyValidationError):
            sign_csr_with_remote_key(
                _csr_builder(), key.public_key(), _wrong_key_signer(impostor)
            )


class CorruptResponseTests(unittest.TestCase):
    """Truncated, empty or garbage responses must fail closed."""

    def _refuses(self, public_key, signer) -> None:
        with self.assertRaises(Exception) as caught:
            sign_certificate_with_remote_key(
                _certificate_builder(public_key), public_key, signer
            )
        self.assertNotIsInstance(caught.exception, AssertionError)

    def test_rsa_truncated_signature_is_refused(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        honest = _honest_signer(key)
        self._refuses(
            key.public_key(),
            lambda payload, algorithm: honest(payload, algorithm)[:-8],
        )

    def test_rsa_empty_signature_is_refused(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._refuses(key.public_key(), lambda payload, algorithm: b"")

    def test_rsa_garbage_signature_is_refused(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._refuses(
            key.public_key(), lambda payload, algorithm: b"\xde\xad\xbe\xef" * 64
        )

    def test_ec_empty_signature_is_refused(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        self._refuses(key.public_key(), lambda payload, algorithm: b"")

    def test_ec_bit_flipped_signature_is_refused(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        honest = _honest_signer(key)

        def corrupt(payload: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
            raw = bytearray(honest(payload, algorithm))
            raw[-1] ^= 0xFF
            return bytes(raw)

        self._refuses(key.public_key(), corrupt)


class EcdsaNormalisationTests(unittest.TestCase):
    """Existing hardening in normalize_ecdsa_signature; pinned so it stays."""

    def test_raw_rs_is_accepted_and_converted(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        width = 32
        raw = (12345).to_bytes(width, "big") + (67890).to_bytes(width, "big")
        self.assertEqual(
            normalize_ecdsa_signature(raw, key.public_key()),
            encode_dss_signature(12345, 67890),
        )

    def test_wrong_width_raw_is_refused(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(CloudKeyValidationError):
            normalize_ecdsa_signature(b"\x01" * 31, key.public_key())

    def test_zero_component_is_refused(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        raw = (0).to_bytes(32, "big") + (1).to_bytes(32, "big")
        with self.assertRaises(CloudKeyValidationError):
            normalize_ecdsa_signature(raw, key.public_key())

    def test_curve_mismatch_width_is_refused(self) -> None:
        """A P-384 provider answer against a P-256 key must not be accepted."""
        key = ec.generate_private_key(ec.SECP256R1())
        raw = (1).to_bytes(48, "big") + (2).to_bytes(48, "big")
        with self.assertRaises(CloudKeyValidationError):
            normalize_ecdsa_signature(raw, key.public_key())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
