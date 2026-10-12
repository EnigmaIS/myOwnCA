import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import NameOID

from myownca.ca_main.export import (
    ExportError,
    ExportFormat,
    build_chain_pems,
    export_certificate,
)

_NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
_LATER = _NOW + datetime.timedelta(days=365)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _make_cert(subject_cn: str, *, signer_key, issuer_cn: str, public_key, ca: bool):
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(_name(issuer_cn))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW)
        .not_valid_after(_LATER)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return builder.sign(signer_key, hashes.SHA256())


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


class _ChainFixture(unittest.TestCase):
    """Three-tier PKI (root -> sub -> leaf) built once per class."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.root_key = ec.generate_private_key(ec.SECP256R1())
        cls.sub_key = ec.generate_private_key(ec.SECP256R1())
        cls.leaf_key = ec.generate_private_key(ec.SECP256R1())
        cls.root = _make_cert(
            "Test Root CA",
            signer_key=cls.root_key,
            issuer_cn="Test Root CA",
            public_key=cls.root_key.public_key(),
            ca=True,
        )
        cls.sub = _make_cert(
            "Test Issuing CA",
            signer_key=cls.root_key,
            issuer_cn="Test Root CA",
            public_key=cls.sub_key.public_key(),
            ca=True,
        )
        cls.leaf = _make_cert(
            "leaf.example.test",
            signer_key=cls.sub_key,
            issuer_cn="Test Issuing CA",
            public_key=cls.leaf_key.public_key(),
            ca=False,
        )
        cls.root_pem = _pem(cls.root)
        cls.sub_pem = _pem(cls.sub)
        cls.leaf_pem = _pem(cls.leaf)
        cls.leaf_key_pem = cls.leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()


class ExportFormatsTests(_ChainFixture):
    def test_pem(self) -> None:
        result = export_certificate(self.leaf_pem, "pem", serial_number="0A:1F")
        self.assertEqual(result.filename, "leaf.example.test-0A-1F.crt")
        self.assertEqual(result.media_type, "application/x-pem-file")
        self.assertEqual(
            x509.load_pem_x509_certificate(result.content), self.leaf
        )

    def test_pem_chain(self) -> None:
        result = export_certificate(
            self.leaf_pem, ExportFormat.PEM_CHAIN, chain_pems=[self.sub_pem, self.root_pem]
        )
        self.assertTrue(result.filename.endswith(".pem"))
        certificates = x509.load_pem_x509_certificates(result.content)
        self.assertEqual(certificates, [self.leaf, self.sub, self.root])

    def test_pkcs7(self) -> None:
        result = export_certificate(self.leaf_pem, "pkcs7")
        self.assertTrue(result.filename.endswith(".p7b"))
        self.assertEqual(result.media_type, "application/x-pkcs7-certificates")
        self.assertEqual(pkcs7.load_der_pkcs7_certificates(result.content), [self.leaf])

    def test_der(self) -> None:
        result = export_certificate(self.leaf_pem, "der")
        self.assertTrue(result.filename.endswith(".cer"))
        self.assertEqual(x509.load_der_x509_certificate(result.content), self.leaf)

    def test_pkcs12_round_trip(self) -> None:
        result = export_certificate(
            self.leaf_pem,
            "pkcs12",
            chain_pems=[self.sub_pem, self.root_pem],
            private_key_pem=self.leaf_key_pem,
            password="hunter2-strong",
        )
        self.assertTrue(result.filename.endswith(".pfx"))
        self.assertEqual(result.media_type, "application/x-pkcs12")
        key, certificate, extra = pkcs12.load_key_and_certificates(
            result.content, b"hunter2-strong"
        )
        self.assertEqual(certificate, self.leaf)
        self.assertEqual(extra, [self.sub, self.root])
        self.assertEqual(
            key.private_numbers(), self.leaf_key.private_numbers()
        )

    def test_pem_key_round_trip(self) -> None:
        result = export_certificate(
            self.leaf_pem,
            "pem-key",
            private_key_pem=self.leaf_key_pem,
            password="hunter2-strong",
        )
        text = result.content.decode()
        self.assertIn("BEGIN CERTIFICATE", text)
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", text)
        key = serialization.load_pem_private_key(
            result.content, password=b"hunter2-strong"
        )
        self.assertEqual(key.private_numbers(), self.leaf_key.private_numbers())
        with self.assertRaises(ValueError):
            serialization.load_pem_private_key(result.content, password=b"wrong-password")

    def test_pem_pkcs8_round_trip(self) -> None:
        result = export_certificate(
            self.leaf_pem,
            "pem-pkcs8",
            private_key_pem=self.leaf_key_pem,
            password="hunter2-strong",
        )
        text = result.content.decode()
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", text)
        key = serialization.load_pem_private_key(
            result.content, password=b"hunter2-strong"
        )
        self.assertEqual(key.private_numbers(), self.leaf_key.private_numbers())
        with self.assertRaises(ValueError):
            serialization.load_pem_private_key(result.content, password=b"wrong-password")


class ExportValidationTests(_ChainFixture):
    def test_unknown_format(self) -> None:
        with self.assertRaises(ExportError):
            export_certificate(self.leaf_pem, "tar.gz")

    def test_invalid_certificate(self) -> None:
        with self.assertRaises(ExportError):
            export_certificate("not a pem", "pem")

    def test_key_bearing_formats_require_key(self) -> None:
        for fmt, password in (
            ("pkcs12", "hunter2-strong"),
            ("pem-key", "hunter2-strong"),
            ("pem-pkcs8", "hunter2-strong"),
        ):
            with self.assertRaises(ExportError) as ctx:
                export_certificate(self.leaf_pem, fmt, password=password)
            self.assertIn("private key", str(ctx.exception))

    def test_wrong_key_rejected(self) -> None:
        stranger = ec.generate_private_key(ec.SECP256R1())
        stranger_pem = stranger.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        with self.assertRaises(ExportError) as ctx:
            export_certificate(
                self.leaf_pem,
                "pem-key",
                private_key_pem=stranger_pem,
                password="hunter2-strong",
            )
        self.assertIn("does not match", str(ctx.exception))

    def test_password_required_and_minimum_length(self) -> None:
        for fmt in ("pkcs12", "pem-key", "pem-pkcs8"):
            for password in (None, "", "short"):
                with self.subTest(fmt=fmt, password=password):
                    with self.assertRaises(ExportError):
                        export_certificate(
                            self.leaf_pem,
                            fmt,
                            private_key_pem=self.leaf_key_pem,
                            password=password,
                        )

    def test_password_rejected_for_passwordless_formats(self) -> None:
        with self.assertRaises(ExportError):
            export_certificate(self.leaf_pem, "pem", password="hunter2-strong")

    def test_key_rejected_for_keyless_formats(self) -> None:
        with self.assertRaises(ExportError):
            export_certificate(self.leaf_pem, "der", private_key_pem=self.leaf_key_pem)

    def test_filename_without_serial(self) -> None:
        result = export_certificate(self.leaf_pem, "pem")
        self.assertEqual(result.filename, "leaf.example.test.crt")


class BuildChainTests(_ChainFixture):
    def test_full_chain(self) -> None:
        chain = build_chain_pems(
            self.leaf_pem,
            issuer_candidates=[self.sub_pem],
            root_pem=self.root_pem,
        )
        self.assertEqual(chain, [self.sub_pem, self.root_pem])

    def test_without_root(self) -> None:
        chain = build_chain_pems(self.leaf_pem, issuer_candidates=[self.sub_pem])
        self.assertEqual(chain, [self.sub_pem])

    def test_no_matching_issuer(self) -> None:
        other_key = ec.generate_private_key(ec.SECP256R1())
        other = _make_cert(
            "Unrelated CA",
            signer_key=other_key,
            issuer_cn="Unrelated CA",
            public_key=other_key.public_key(),
            ca=True,
        )
        chain = build_chain_pems(self.leaf_pem, issuer_candidates=[_pem(other)])
        self.assertEqual(chain, [])

    def test_imposter_issuer_with_matching_name_skipped(self) -> None:
        imposter_key = ec.generate_private_key(ec.SECP256R1())
        imposter = _make_cert(
            "Test Issuing CA",  # right DN, wrong key
            signer_key=imposter_key,
            issuer_cn="Test Issuing CA",
            public_key=imposter_key.public_key(),
            ca=True,
        )
        chain = build_chain_pems(
            self.leaf_pem,
            issuer_candidates=[_pem(imposter), self.sub_pem],
            root_pem=self.root_pem,
        )
        self.assertEqual(chain, [self.sub_pem, self.root_pem])

    def test_root_signing_leaf_directly(self) -> None:
        direct_key = ec.generate_private_key(ec.SECP256R1())
        direct = _make_cert(
            "direct.example.test",
            signer_key=self.root_key,
            issuer_cn="Test Root CA",
            public_key=direct_key.public_key(),
            ca=False,
        )
        chain = build_chain_pems(_pem(direct), root_pem=self.root_pem)
        self.assertEqual(chain, [self.root_pem])

    def test_unparseable_candidates_skipped(self) -> None:
        chain = build_chain_pems(
            self.leaf_pem,
            issuer_candidates=["garbage", self.sub_pem],
        )
        self.assertEqual(chain, [self.sub_pem])


if __name__ == "__main__":
    unittest.main()
