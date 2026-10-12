from __future__ import annotations

import datetime
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from myownca.online.portal_tls import (
    PortalTlsError,
    clear,
    materialize,
    portal_paths,
    validate_pair,
)


def _key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _cert_pem(key, common_name: str, *, days_valid: int = 90) -> str:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class PortalTlsTests(unittest.TestCase):
    def test_portal_paths(self) -> None:
        crt, key = portal_paths("/srv/state")
        self.assertEqual(crt, Path("/srv/state/tls/portal.crt"))
        self.assertEqual(key, Path("/srv/state/tls/portal.key"))

    def test_validate_pair_accepts_match(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        validate_pair(_cert_pem(key, "match.example.test"), _key_pem(key))

    def test_validate_pair_rejects_mismatch(self) -> None:
        cert_key = ec.generate_private_key(ec.SECP256R1())
        other_key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(PortalTlsError):
            validate_pair(_cert_pem(cert_key, "x.example.test"), _key_pem(other_key))

    def test_validate_pair_rejects_expired(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(PortalTlsError):
            validate_pair(_cert_pem(key, "old.example.test", days_valid=-1), _key_pem(key))

    def test_validate_pair_rejects_garbage_certificate(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(PortalTlsError):
            validate_pair("not a certificate", _key_pem(key))

    def test_validate_pair_rejects_garbage_key(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(PortalTlsError):
            validate_pair(_cert_pem(key, "x.example.test"), "not a private key")

    def test_materialize_writes_bundle_and_key(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = _cert_pem(key, "leaf.example.test")
        chain = _cert_pem(ec.generate_private_key(ec.SECP256R1()), "Test CA")
        with TemporaryDirectory() as tmp:
            crt_path, key_path = materialize(leaf, chain, _key_pem(key), tmp)
            self.assertTrue(crt_path.exists())
            self.assertTrue(key_path.exists())
            body = crt_path.read_text()
            self.assertEqual(body.count("BEGIN CERTIFICATE"), 2)  # leaf + chain
            self.assertLess(body.index(leaf.strip()), body.index(chain.strip()))  # leaf first
            self.assertIn("BEGIN PRIVATE KEY", key_path.read_text())
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(crt_path.stat().st_mode & 0o777, 0o644)

    def test_materialize_without_chain_writes_leaf_only(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = _cert_pem(key, "leaf.example.test")
        with TemporaryDirectory() as tmp:
            crt_path, _ = materialize(leaf, "", _key_pem(key), tmp)
            self.assertEqual(crt_path.read_text().count("BEGIN CERTIFICATE"), 1)

    def test_clear_removes_files(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        with TemporaryDirectory() as tmp:
            materialize(_cert_pem(key, "c.example.test"), "", _key_pem(key), tmp)
            clear(tmp)
            crt_path, key_path = portal_paths(tmp)
            self.assertFalse(crt_path.exists())
            self.assertFalse(key_path.exists())
            clear(tmp)  # idempotent — no raise when already gone


if __name__ == "__main__":
    unittest.main()
