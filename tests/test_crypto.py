from __future__ import annotations

import unittest

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from myownca.ca_main.crypto import (
    CSRValidationError,
    build_end_entity_certificate,
    generate_serial_number,
    parse_csr,
)
from myownca.domain import (
    CertificateProfile,
    CertificateTemplate,
    ExtendedKeyUsageName,
    KeyUsageName,
)
from tests.helpers import TempPKI, make_csr


class CryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()

    def tearDown(self) -> None:
        self.pki.close()

    def test_host_tls_requires_dns_san(self) -> None:
        template = self.pki.add_template("host", CertificateProfile.HOST_TLS)
        csr = parse_csr(make_csr("host.example.test"))

        with self.assertRaises(CSRValidationError):
            build_end_entity_certificate(csr, template, self.pki.lab_chain.issuer, self.pki.hsm)

    def test_subject_requires_common_name(self) -> None:
        template = self.pki.add_template("host", CertificateProfile.HOST_TLS)
        csr = parse_csr(make_csr(None, dns_names=("host.example.test",)))

        with self.assertRaises(CSRValidationError):
            build_end_entity_certificate(csr, template, self.pki.lab_chain.issuer, self.pki.hsm)

    def test_all_v1_profiles_receive_expected_preset_usage_extensions(self) -> None:
        cases = (
            (
                "user",
                CertificateProfile.USER_AUTH,
                make_csr("Alice Example", emails=("alice@example.test",)),
                ExtendedKeyUsageOID.CLIENT_AUTH,
                {"digital_signature": True, "key_encipherment": False},
            ),
            (
                "host",
                CertificateProfile.HOST_TLS,
                make_csr("app.example.test", dns_names=("app.example.test",)),
                ExtendedKeyUsageOID.SERVER_AUTH,
                {"digital_signature": True, "key_encipherment": True},
            ),
            (
                "smime",
                CertificateProfile.SMIME,
                make_csr("Alice Example", emails=("alice@example.test",)),
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
                {
                    "digital_signature": True,
                    "content_commitment": True,
                    "key_encipherment": True,
                },
            ),
        )

        for template_id, profile, csr_pem, expected_eku, expected_key_usages in cases:
            with self.subTest(profile=profile):
                template = self.pki.add_template(template_id, profile)
                certificate = build_end_entity_certificate(
                    parse_csr(csr_pem), template, self.pki.lab_chain.issuer, self.pki.hsm
                )
                eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
                basic_constraints = certificate.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value
                self.assertIn(expected_eku, eku)
                self.assertFalse(basic_constraints.ca)
                for name, expected in expected_key_usages.items():
                    self.assertEqual(getattr(key_usage, name), expected)

    def test_template_usage_policy_can_override_named_key_usages(self) -> None:
        template = CertificateTemplate(
            id="custom-host",
            name="Custom Host",
            profile=CertificateProfile.HOST_TLS,
            key_usages=(KeyUsageName.DIGITAL_SIGNATURE, KeyUsageName.DATA_ENCIPHERMENT),
            extended_key_usages=(ExtendedKeyUsageName.SERVER_AUTH,),
        )
        certificate = build_end_entity_certificate(
            parse_csr(make_csr("app.example.test", dns_names=("app.example.test",))),
            template,
            self.pki.lab_chain.issuer,
            self.pki.hsm,
        )
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(key_usage.digital_signature)
        self.assertTrue(key_usage.data_encipherment)
        self.assertFalse(key_usage.key_encipherment)

    def test_profile_requires_its_core_extended_key_usage(self) -> None:
        with self.assertRaises(ValueError):
            CertificateTemplate(
                id="invalid-host",
                name="Invalid Host",
                profile=CertificateProfile.HOST_TLS,
                extended_key_usages=(ExtendedKeyUsageName.CLIENT_AUTH,),
            )

    def test_smime_requires_email_san(self) -> None:
        template = self.pki.add_template("smime", CertificateProfile.SMIME)
        csr = parse_csr(make_csr("Alice Example", dns_names=("alice.example.test",)))

        with self.assertRaises(CSRValidationError):
            build_end_entity_certificate(csr, template, self.pki.lab_chain.issuer, self.pki.hsm)

    def test_serial_numbers_are_positive_and_non_repeating(self) -> None:
        serials = {generate_serial_number() for _ in range(8)}
        self.assertEqual(len(serials), 8)
        self.assertTrue(all(serial > 0 for serial in serials))
