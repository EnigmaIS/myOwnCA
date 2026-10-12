from __future__ import annotations

import ipaddress
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from myownca.ca_main.imports import (
    BundleFormat,
    LeafImportError,
    LeafImportErrorCode,
    build_csr_from_certificate,
    create_identity_csr,
    export_leaf_encrypted_pem,
    export_leaf_pkcs12,
    import_leaf_bundle,
    parse_bundle,
    private_key_matches_certificate,
    validate_leaf_bundle,
)


NOW = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)


def _name(common_name: str, *, organization: str = "Test Org") -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _signing_algorithm(private_key):
    return hashes.SHA256()


def _certificate(
    *,
    subject: x509.Name,
    public_key,
    issuer_name: x509.Name,
    issuer_key,
    ca: bool,
    not_before: datetime = NOW - timedelta(days=1),
    not_after: datetime = NOW + timedelta(days=30),
    basic_constraints: bool = True,
    with_leaf_extensions: bool = False,
    ca_key_cert_sign: bool = True,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True
        )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca_key_cert_sign,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    elif with_leaf_extensions:
        builder = (
            builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH,
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                        ObjectIdentifier("1.2.3.4.5.6"),
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("leaf.example.test"),
                        x509.RFC822Name("owner@example.test"),
                        x509.IPAddress(ipaddress.ip_address("192.0.2.10")),
                        x509.UniformResourceIdentifier("spiffe://example.test/leaf"),
                    ]
                ),
                critical=False,
            )
        )
    return builder.sign(issuer_key, _signing_algorithm(issuer_key))


def _pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _key_pem(private_key, password: bytes | None = None) -> bytes:
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password is not None
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )


class LeafImportFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root_key = ec.generate_private_key(ec.SECP384R1())
        cls.root = _certificate(
            subject=_name("Import Root"),
            public_key=cls.root_key.public_key(),
            issuer_name=_name("Import Root"),
            issuer_key=cls.root_key,
            ca=True,
            not_after=NOW + timedelta(days=3650),
        )
        cls.sub_key = ec.generate_private_key(ec.SECP256R1())
        cls.sub = _certificate(
            subject=_name("Active Import Sub-CA"),
            public_key=cls.sub_key.public_key(),
            issuer_name=cls.root.subject,
            issuer_key=cls.root_key,
            ca=True,
            not_after=NOW + timedelta(days=1825),
        )
        cls.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.leaf = _certificate(
            subject=_name("leaf.example.test", organization="Leaf Org"),
            public_key=cls.leaf_key.public_key(),
            issuer_name=cls.sub.subject,
            issuer_key=cls.sub_key,
            ca=False,
            with_leaf_extensions=True,
        )

    def validated_with_key(self):
        parsed = parse_bundle(
            _pem(self.leaf) + _pem(self.sub) + _pem(self.root),
            private_key_data=_key_pem(self.leaf_key),
        )
        return validate_leaf_bundle(parsed, self.sub, now=NOW)


class ParseBundleTests(LeafImportFixture):
    def test_separate_encrypted_pem_key_and_chain(self) -> None:
        parsed = parse_bundle(
            _pem(self.leaf) + _pem(self.sub) + _pem(self.root),
            private_key_data=_key_pem(self.leaf_key, b"import-password"),
            password="import-password",
        )
        self.assertEqual(parsed.source_format, BundleFormat.PEM)
        self.assertEqual(parsed.certificates, (self.leaf, self.sub, self.root))
        self.assertEqual(parsed.preferred_certificate, self.leaf)
        self.assertTrue(private_key_matches_certificate(parsed.private_key, self.leaf))

    def test_combined_pem_accepts_key_before_certificates(self) -> None:
        parsed = parse_bundle(
            _key_pem(self.leaf_key) + _pem(self.leaf) + _pem(self.sub) + _pem(self.root)
        )
        self.assertIsNotNone(parsed.private_key)
        self.assertEqual(parsed.preferred_certificate, self.leaf)

    def test_password_is_tolerated_for_unencrypted_pem_key(self) -> None:
        parsed = parse_bundle(
            _pem(self.leaf),
            private_key_data=_key_pem(self.leaf_key),
            password="unused-password",
        )
        self.assertIsNotNone(parsed.private_key)

    def test_protected_pkcs12(self) -> None:
        payload = pkcs12.serialize_key_and_certificates(
            b"leaf",
            self.leaf_key,
            self.leaf,
            [self.sub, self.root],
            serialization.BestAvailableEncryption(b"p12-password"),
        )
        parsed = parse_bundle(payload, password="p12-password")
        self.assertEqual(parsed.source_format, BundleFormat.PKCS12)
        self.assertEqual(parsed.preferred_certificate, self.leaf)
        validated = validate_leaf_bundle(parsed, _pem(self.sub), now=NOW)
        self.assertEqual(validated.chain, (self.sub, self.root))

    def test_certificate_only_pkcs12(self) -> None:
        payload = pkcs12.serialize_key_and_certificates(
            None,
            None,
            None,
            [self.leaf, self.sub, self.root],
            serialization.NoEncryption(),
        )
        parsed = parse_bundle(payload)
        self.assertIsNone(parsed.private_key)
        validated = validate_leaf_bundle(parsed, self.sub, now=NOW)
        self.assertEqual(validated.certificate, self.leaf)

    def test_parser_is_reusable_for_sub_ca_material(self) -> None:
        payload = pkcs12.serialize_key_and_certificates(
            b"sub-ca",
            self.sub_key,
            self.sub,
            [self.root],
            serialization.BestAvailableEncryption(b"issuer-password"),
        )
        parsed = parse_bundle(payload, password="issuer-password")
        self.assertEqual(parsed.preferred_certificate, self.sub)
        self.assertTrue(private_key_matches_certificate(parsed.private_key, self.sub))

    def test_wrong_pkcs12_password_is_safe_error(self) -> None:
        payload = pkcs12.serialize_key_and_certificates(
            b"leaf",
            self.leaf_key,
            self.leaf,
            None,
            serialization.BestAvailableEncryption(b"right-password"),
        )
        with self.assertRaises(LeafImportError) as caught:
            parse_bundle(payload, password="wrong-password")
        self.assertEqual(caught.exception.code, LeafImportErrorCode.INVALID_CONTAINER)
        self.assertNotIn("right-password", str(caught.exception))

    def test_multiple_private_keys_are_rejected(self) -> None:
        other_key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(LeafImportError) as caught:
            parse_bundle(_pem(self.leaf) + _key_pem(self.leaf_key) + _key_pem(other_key))
        self.assertEqual(caught.exception.code, LeafImportErrorCode.MULTIPLE_PRIVATE_KEYS)

    def test_missing_certificate_is_rejected(self) -> None:
        with self.assertRaises(LeafImportError) as caught:
            parse_bundle(_key_pem(self.leaf_key))
        self.assertEqual(caught.exception.code, LeafImportErrorCode.NO_CERTIFICATE)

    def test_separate_key_is_not_accepted_with_pkcs12(self) -> None:
        payload = pkcs12.serialize_key_and_certificates(
            None, None, None, [self.leaf], serialization.NoEncryption()
        )
        with self.assertRaises(LeafImportError) as caught:
            parse_bundle(payload, private_key_data=_key_pem(self.leaf_key))
        self.assertEqual(caught.exception.code, LeafImportErrorCode.INVALID_INPUT)


class LeafValidationTests(LeafImportFixture):
    def test_valid_leaf_key_chain_and_signals(self) -> None:
        validated = self.validated_with_key()
        self.assertEqual(validated.certificate, self.leaf)
        self.assertEqual(validated.chain, (self.sub, self.root))
        self.assertTrue(validated.has_private_key)
        self.assertEqual(len(validated.fingerprint_sha256), 64)
        self.assertEqual(
            validated.signals.key_usages,
            ("digital_signature", "key_encipherment"),
        )
        self.assertEqual(
            validated.signals.extended_key_usages,
            ("server_auth", "client_auth", "1.2.3.4.5.6"),
        )
        self.assertEqual(validated.signals.dns_names, ("leaf.example.test",))
        self.assertEqual(validated.signals.email_addresses, ("owner@example.test",))
        self.assertEqual(validated.signals.ip_addresses, ("192.0.2.10",))
        self.assertTrue(validated.signals.key_usage_critical)
        self.assertFalse(validated.signals.extended_key_usage_critical)

    def test_certificate_only_pem_is_supported(self) -> None:
        validated = import_leaf_bundle(
            _pem(self.leaf) + _pem(self.sub) + _pem(self.root), self.sub, now=NOW
        )
        self.assertFalse(validated.has_private_key)

    def test_wrong_private_key_is_rejected(self) -> None:
        other_key = ec.generate_private_key(ec.SECP256R1())
        parsed = parse_bundle(_pem(self.leaf), private_key_data=_key_pem(other_key))
        with self.assertRaises(LeafImportError) as caught:
            validate_leaf_bundle(parsed, self.sub, now=NOW)
        self.assertEqual(caught.exception.code, LeafImportErrorCode.KEY_MISMATCH)

    def test_not_yet_valid_and_expired_are_rejected(self) -> None:
        cases = (
            (
                NOW + timedelta(minutes=1),
                NOW + timedelta(days=2),
                LeafImportErrorCode.CERTIFICATE_NOT_YET_VALID,
            ),
            (
                NOW - timedelta(days=2),
                NOW,
                LeafImportErrorCode.CERTIFICATE_EXPIRED,
            ),
        )
        for not_before, not_after, expected_code in cases:
            with self.subTest(expected_code=expected_code):
                certificate = _certificate(
                    subject=_name("time.example.test"),
                    public_key=self.leaf_key.public_key(),
                    issuer_name=self.sub.subject,
                    issuer_key=self.sub_key,
                    ca=False,
                    not_before=not_before,
                    not_after=not_after,
                )
                with self.assertRaises(LeafImportError) as caught:
                    import_leaf_bundle(_pem(certificate), self.sub, now=NOW)
                self.assertEqual(caught.exception.code, expected_code)

    def test_ca_certificate_is_rejected(self) -> None:
        ca_key = ec.generate_private_key(ec.SECP256R1())
        certificate = _certificate(
            subject=_name("Nested CA"),
            public_key=ca_key.public_key(),
            issuer_name=self.sub.subject,
            issuer_key=self.sub_key,
            ca=True,
        )
        with self.assertRaises(LeafImportError) as caught:
            import_leaf_bundle(_pem(certificate), self.sub, now=NOW)
        self.assertEqual(caught.exception.code, LeafImportErrorCode.CERTIFICATE_IS_CA)

    def test_absent_basic_constraints_is_treated_as_non_ca(self) -> None:
        certificate = _certificate(
            subject=_name("legacy-leaf.example.test"),
            public_key=self.leaf_key.public_key(),
            issuer_name=self.sub.subject,
            issuer_key=self.sub_key,
            ca=False,
            basic_constraints=False,
        )
        validated = import_leaf_bundle(_pem(certificate), self.sub, now=NOW)
        self.assertEqual(validated.certificate, certificate)

    def test_wrong_issuer_and_invalid_signature_are_distinct(self) -> None:
        other_key = ec.generate_private_key(ec.SECP256R1())
        other_name = _name("Other Sub-CA")
        wrong_issuer = _certificate(
            subject=_name("wrong-issuer.example.test"),
            public_key=self.leaf_key.public_key(),
            issuer_name=other_name,
            issuer_key=other_key,
            ca=False,
        )
        with self.assertRaises(LeafImportError) as caught:
            import_leaf_bundle(_pem(wrong_issuer), self.sub, now=NOW)
        self.assertEqual(caught.exception.code, LeafImportErrorCode.WRONG_ISSUER)

        imposter = _certificate(
            subject=_name("imposter.example.test"),
            public_key=self.leaf_key.public_key(),
            issuer_name=self.sub.subject,
            issuer_key=other_key,
            ca=False,
        )
        with self.assertRaises(LeafImportError) as caught:
            import_leaf_bundle(_pem(imposter), self.sub, now=NOW)
        self.assertEqual(caught.exception.code, LeafImportErrorCode.INVALID_SIGNATURE)

    def test_multiple_direct_leaves_are_ambiguous(self) -> None:
        second_key = ec.generate_private_key(ec.SECP256R1())
        second = _certificate(
            subject=_name("second.example.test"),
            public_key=second_key.public_key(),
            issuer_name=self.sub.subject,
            issuer_key=self.sub_key,
            ca=False,
        )
        with self.assertRaises(LeafImportError) as caught:
            import_leaf_bundle(_pem(self.leaf) + _pem(second), self.sub, now=NOW)
        self.assertEqual(caught.exception.code, LeafImportErrorCode.AMBIGUOUS_LEAF)

    def test_unrelated_extra_certificate_is_rejected(self) -> None:
        unrelated_key = ec.generate_private_key(ec.SECP256R1())
        unrelated = _certificate(
            subject=_name("Unrelated Root"),
            public_key=unrelated_key.public_key(),
            issuer_name=_name("Unrelated Root"),
            issuer_key=unrelated_key,
            ca=True,
        )
        with self.assertRaises(LeafImportError) as caught:
            import_leaf_bundle(
                _pem(self.leaf) + _pem(self.sub) + _pem(self.root) + _pem(unrelated),
                self.sub,
                now=NOW,
            )
        self.assertEqual(caught.exception.code, LeafImportErrorCode.INVALID_CHAIN)

    def test_chain_parents_must_be_valid_ca_certificates_allowed_to_sign(self) -> None:
        cases = (
            {
                "name": "expired",
                "ca": True,
                "key_cert_sign": True,
                "not_before": NOW - timedelta(days=30),
                "not_after": NOW,
                "message": "not currently valid",
            },
            {
                "name": "not-ca",
                "ca": False,
                "key_cert_sign": True,
                "not_before": NOW - timedelta(days=1),
                "not_after": NOW + timedelta(days=30),
                "message": "CA=true",
            },
            {
                "name": "cannot-sign",
                "ca": True,
                "key_cert_sign": False,
                "not_before": NOW - timedelta(days=1),
                "not_after": NOW + timedelta(days=30),
                "message": "keyCertSign",
            },
        )
        for case in cases:
            with self.subTest(case=case["name"]):
                root_key = ec.generate_private_key(ec.SECP256R1())
                root_name = _name(f"Policy Root {case['name']}")
                root = _certificate(
                    subject=root_name,
                    public_key=root_key.public_key(),
                    issuer_name=root_name,
                    issuer_key=root_key,
                    ca=case["ca"],
                    not_before=case["not_before"],
                    not_after=case["not_after"],
                    ca_key_cert_sign=case["key_cert_sign"],
                )
                sub_key = ec.generate_private_key(ec.SECP256R1())
                sub = _certificate(
                    subject=_name(f"Policy Sub {case['name']}"),
                    public_key=sub_key.public_key(),
                    issuer_name=root.subject,
                    issuer_key=root_key,
                    ca=True,
                )
                leaf = _certificate(
                    subject=_name(f"{case['name']}.example.test"),
                    public_key=self.leaf_key.public_key(),
                    issuer_name=sub.subject,
                    issuer_key=sub_key,
                    ca=False,
                )
                with self.assertRaises(LeafImportError) as caught:
                    import_leaf_bundle(
                        _pem(leaf) + _pem(sub) + _pem(root),
                        sub,
                        now=NOW,
                    )
                self.assertEqual(caught.exception.code, LeafImportErrorCode.INVALID_CHAIN)
                self.assertIn(case["message"], str(caught.exception))

    def test_rsa_sub_ca_signature_is_supported(self) -> None:
        rsa_sub_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_sub = _certificate(
            subject=_name("RSA Sub-CA"),
            public_key=rsa_sub_key.public_key(),
            issuer_name=self.root.subject,
            issuer_key=self.root_key,
            ca=True,
        )
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf = _certificate(
            subject=_name("rsa-issued.example.test"),
            public_key=leaf_key.public_key(),
            issuer_name=rsa_sub.subject,
            issuer_key=rsa_sub_key,
            ca=False,
        )
        validated = import_leaf_bundle(_pem(leaf), rsa_sub, now=NOW)
        self.assertEqual(validated.certificate, leaf)


class LeafExportTests(LeafImportFixture):
    def test_encrypted_pkcs12_round_trip(self) -> None:
        validated = self.validated_with_key()
        output = export_leaf_pkcs12(validated, "export-password", friendly_name="imported-leaf")
        key, certificate, chain = pkcs12.load_key_and_certificates(output, b"export-password")
        self.assertEqual(certificate, self.leaf)
        self.assertEqual(chain, [self.sub, self.root])
        self.assertTrue(private_key_matches_certificate(key, certificate))
        with self.assertRaises(ValueError):
            pkcs12.load_key_and_certificates(output, b"wrong-password")

    def test_encrypted_combined_pem_round_trip(self) -> None:
        validated = self.validated_with_key()
        output = export_leaf_encrypted_pem(validated, "export-password")
        self.assertIn(b"BEGIN ENCRYPTED PRIVATE KEY", output)
        self.assertEqual(output.count(b"BEGIN CERTIFICATE"), 3)
        reparsed = import_leaf_bundle(output, self.sub, password="export-password", now=NOW)
        self.assertEqual(reparsed.certificate, self.leaf)
        self.assertTrue(reparsed.has_private_key)

    def test_key_exports_require_key_and_strong_password(self) -> None:
        certificate_only = import_leaf_bundle(_pem(self.leaf), self.sub, now=NOW)
        with self.assertRaises(LeafImportError) as caught:
            export_leaf_pkcs12(certificate_only, "long-password")
        self.assertEqual(caught.exception.code, LeafImportErrorCode.MISSING_PRIVATE_KEY)

        with self.assertRaises(LeafImportError) as caught:
            export_leaf_encrypted_pem(self.validated_with_key(), "short")
        self.assertEqual(caught.exception.code, LeafImportErrorCode.WEAK_EXPORT_PASSWORD)


class IdentityCSRTests(LeafImportFixture):
    def test_csr_from_certificate_preserves_full_identity_and_key(self) -> None:
        csr_pem = build_csr_from_certificate(self.leaf_key, self.leaf)
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(csr.subject, self.leaf.subject)
        self.assertEqual(
            csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
            self.leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
        )
        self.assertTrue(private_key_matches_certificate(self.leaf_key, self.leaf))
        self.assertEqual(csr.signature_hash_algorithm.name, "sha256")

    def test_mismatched_key_cannot_build_csr(self) -> None:
        with self.assertRaises(LeafImportError) as caught:
            build_csr_from_certificate(ec.generate_private_key(ec.SECP256R1()), self.leaf)
        self.assertEqual(caught.exception.code, LeafImportErrorCode.KEY_MISMATCH)

    def test_identity_csr_uses_disposable_key_but_preserves_identity(self) -> None:
        csr = x509.load_pem_x509_csr(create_identity_csr(self.leaf).encode())
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(csr.subject, self.leaf.subject)
        self.assertNotEqual(
            csr.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            self.leaf.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        self.assertEqual(
            csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
            self.leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
        )


if __name__ == "__main__":
    unittest.main()
