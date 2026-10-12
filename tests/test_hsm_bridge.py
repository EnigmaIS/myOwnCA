from __future__ import annotations

import datetime
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from myownca.ca_hsm import HSMPinVault, HSMProxy, SoftwareHSM, create_hsm
from myownca.ca_hsm.pkcs11 import (
    PKCS11Error,
    _csr_tbs_with_public_key,
    _dummy_key,
    _InProcessPKCS11HSM,
    _parse_user_pin_tries_left,
    _raw_ecdsa_to_der,
    _read_octet_string,
    _splice_signature,
    _splice_tbs_and_signature,
)
from myownca.ca_main.crypto import build_sub_ca_csr
from myownca.config import Settings


def _cert_builder(public_key) -> x509.CertificateBuilder:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bridge.test")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
    )


class SigningBridgeTests(unittest.TestCase):
    """Validate the dummy-sign + splice technique without a real PKCS#11 token."""

    def _bridge_sign_cert(self, real_key) -> x509.Certificate:
        pub = real_key.public_key()
        dummy = _dummy_key(pub)
        template = _cert_builder(pub).sign(dummy, hashes.SHA256())
        tbs = template.tbs_certificate_bytes
        if isinstance(pub, rsa.RSAPublicKey):
            signature = real_key.sign(tbs, padding.PKCS1v15(), hashes.SHA256())
        else:
            signature = real_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
        spliced = _splice_signature(template.public_bytes(serialization.Encoding.DER), signature)
        return x509.load_der_x509_certificate(spliced)

    def _bridge_sign_csr(self, real_key) -> x509.CertificateSigningRequest:
        pub = real_key.public_key()
        dummy = _dummy_key(pub)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bridge.test")])
        builder = x509.CertificateSigningRequestBuilder().subject_name(name)
        template = builder.sign(dummy, hashes.SHA256())
        tbs = _csr_tbs_with_public_key(
            template.tbs_certrequest_bytes,
            pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        if isinstance(pub, rsa.RSAPublicKey):
            signature = real_key.sign(tbs, padding.PKCS1v15(), hashes.SHA256())
        else:
            signature = real_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
        spliced = _splice_tbs_and_signature(
            template.public_bytes(serialization.Encoding.DER), tbs, signature
        )
        return x509.load_der_x509_csr(spliced)

    def test_ec_certificate_signature_verifies(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = self._bridge_sign_cert(key)
        key.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))

    def test_rsa_certificate_signature_verifies(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = self._bridge_sign_cert(key)
        key.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256()
        )

    def test_ec_csr_signature_verifies(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        csr = self._bridge_sign_csr(key)
        self.assertTrue(csr.is_signature_valid)

    def test_rsa_csr_signature_verifies(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = self._bridge_sign_csr(key)
        self.assertTrue(csr.is_signature_valid)

    def test_raw_ecdsa_to_der_roundtrips(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        der_sig = key.sign(b"hello", ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        size = (key.curve.key_size + 7) // 8
        raw = r.to_bytes(size, "big") + s.to_bytes(size, "big")
        self.assertEqual(decode_dss_signature(_raw_ecdsa_to_der(raw)), (r, s))

    def test_read_octet_string_extracts_payload(self) -> None:
        payload = b"\x04\x41" + b"\xAB" * 65  # EC point as DER OCTET STRING
        self.assertEqual(_read_octet_string(payload), b"\xAB" * 65)


class HSMProxyTests(unittest.TestCase):
    def test_delegates_to_fixed_backend(self) -> None:
        backend = SoftwareHSM()
        backend.generate_key("k1", "ecdsa-p256")
        proxy = HSMProxy(backend, "software")
        self.assertEqual(proxy.active_backend_name(), "software")
        self.assertIsNotNone(proxy.public_key("k1"))
        self.assertFalse(hasattr(proxy, "switch"))
        with self.assertRaises(FrozenInstanceError):
            proxy._name = "pkcs11"

    def test_getattr_delegates_non_protocol_helpers(self) -> None:
        backend = SoftwareHSM()
        backend.generate_key("k", "ecdsa-p256")
        proxy = HSMProxy(backend, "software")
        self.assertIn("BEGIN PUBLIC KEY", proxy.public_key_pem("k"))

    def test_sign_csr_delegates(self) -> None:
        backend = SoftwareHSM()
        backend.generate_key("k", "ecdsa-p256")
        proxy = HSMProxy(backend, "software")
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "proxy.test")])
        csr = proxy.sign_csr(x509.CertificateSigningRequestBuilder().subject_name(name), "k")
        self.assertTrue(csr.is_signature_valid)


class SubCACSRTests(unittest.TestCase):
    class NonExtractableHSM:
        def __init__(self) -> None:
            self.key = ec.generate_private_key(ec.SECP256R1())
            self.private_key_called = False

        def private_key(self, key_ref):
            self.private_key_called = True
            raise AssertionError("private key extraction must not be used")

        def sign_csr(self, builder, key_ref):
            if key_ref != "subca-key":
                raise KeyError(key_ref)
            return builder.sign(self.key, hashes.SHA256())

    def test_build_sub_ca_csr_uses_hsm_signing_api(self) -> None:
        hsm = self.NonExtractableHSM()
        csr = build_sub_ca_csr(hsm, "subca-key", "Hardware Issuing CA")

        self.assertFalse(hsm.private_key_called)
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(
            csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "Hardware Issuing CA",
        )
        basic_constraints = csr.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        self.assertTrue(basic_constraints.ca)
        self.assertEqual(basic_constraints.path_length, 0)


class PinVaultTests(unittest.TestCase):
    def test_unlock_lock_lifecycle(self) -> None:
        vault = HSMPinVault()
        self.assertFalse(vault.is_unlocked("s1"))
        self.assertIsNone(vault.active_pin())
        vault.unlock("s1", "123456")
        self.assertTrue(vault.is_unlocked("s1"))
        self.assertEqual(vault.pin_for("s1"), "123456")
        self.assertEqual(vault.active_pin(), "123456")
        vault.lock("s1")
        self.assertFalse(vault.is_unlocked("s1"))
        self.assertIsNone(vault.pin_for("s1"))

    def test_active_pin_serves_other_sessions(self) -> None:
        vault = HSMPinVault()
        vault.unlock("unlocker", "secret")
        # Approval-triggered issuance runs outside the unlocking session.
        self.assertEqual(vault.active_pin(), "secret")

    def test_unlock_rejects_empty_pin(self) -> None:
        with self.assertRaises(ValueError):
            HSMPinVault().unlock("s1", "")

    def test_expired_session_pin_is_evicted_on_access(self) -> None:
        vault = HSMPinVault()
        vault.unlock(
            "expired",
            "secret",
            expires_at=datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(seconds=1),
        )
        self.assertFalse(vault.is_unlocked("expired"))
        self.assertIsNone(vault.active_pin())


class PKCS11TokenResolutionTests(unittest.TestCase):
    class TokenNotPresent(Exception):
        pass

    class FakeExceptions:
        TokenNotPresent = None

    class FakePkcs11:
        class TokenFlag:
            TOKEN_INITIALIZED = 1
            LOGIN_REQUIRED = 2
            USER_PIN_INITIALIZED = 4

    class FakeToken:
        def __init__(self, label: str) -> None:
            self.label = label
            self.manufacturer_id = "OpenSC"
            self.model = "SmartCard-HSM"
            self.serial = b"SERIAL"
            self.flags = 7

    class FakeSlot:
        def __init__(self, token=None) -> None:
            self.token = token

        def get_token(self):
            if self.token is None:
                raise PKCS11TokenResolutionTests.TokenNotPresent()
            return self.token

    class FakeLib:
        def __init__(self, *tokens) -> None:
            self.tokens = tokens

        def get_slots(self):
            return [PKCS11TokenResolutionTests.FakeSlot(token) for token in self.tokens]

    FakeExceptions.TokenNotPresent = TokenNotPresent
    FakePkcs11.exceptions = FakeExceptions

    def test_single_present_token_is_auto_selected_when_label_differs(self) -> None:
        token = self.FakeToken("SmartCard-HSM (UserPIN)")
        hsm = _InProcessPKCS11HSM("opensc", "myOwnCA", pin_provider=lambda: "123456")
        resolved, auto_selected = hsm._resolve_token(self.FakeLib(token), self.FakePkcs11)
        self.assertIs(resolved, token)
        self.assertTrue(auto_selected)

    def test_padded_matching_label_is_not_considered_auto_selected(self) -> None:
        token = self.FakeToken("  myOwnCA\x00   ")
        hsm = _InProcessPKCS11HSM("opensc", "myOwnCA", pin_provider=lambda: "123456")
        resolved, auto_selected = hsm._resolve_token(self.FakeLib(token), self.FakePkcs11)
        self.assertIs(resolved, token)
        self.assertFalse(auto_selected)

    def test_multiple_non_matching_tokens_report_available_labels(self) -> None:
        hsm = _InProcessPKCS11HSM("opensc", "myOwnCA", pin_provider=lambda: "123456")
        with self.assertRaises(PKCS11Error) as caught:
            hsm._resolve_token(
                self.FakeLib(self.FakeToken("Token A"), self.FakeToken("Token B")),
                self.FakePkcs11,
            )
        self.assertIn("Available token labels: 'Token A', 'Token B'", str(caught.exception))


class PKCS15PinTriesTests(unittest.TestCase):
    def test_parses_user_pin_tries_left(self) -> None:
        output = """
PIN [UserPIN]
        Object Flags   : [0x03], private, modifiable
        Auth ID        : 02
        Tries left     : 3

PIN [SOPIN]
        Auth ID        : 01
        Tries left     : 15
"""
        self.assertEqual(_parse_user_pin_tries_left(output), 3)

    def test_missing_user_pin_tries_left_returns_none(self) -> None:
        output = """
PIN [SOPIN]
        Tries left     : 15
"""
        self.assertIsNone(_parse_user_pin_tries_left(output))


class CreateHsmFactoryTests(unittest.TestCase):
    def _settings(self, **overrides) -> Settings:
        base = dict(
            database_path=Path("./var/x.sqlite3"),
            database_url=None,
            online_key_dir=Path("./var/online-keys"),
            online_key_passphrase=None,
            auth_encryption_secret="secret",
            session_cookie_secure=False,
            lab_mode=True,
            lab_common_name="Lab",
            hsm_backend="software",
            pkcs11_lib_path=None,
            pkcs11_token_label="myOwnCA",
            sc_hsm_tool_path="sc-hsm-tool",
            sc_hsm_reader=None,
            pkcs11_dkek_share_dir=Path("./var/dkek-shares"),
            service_key_dir=Path("./var/service-keys"),
        )
        base.update(overrides)
        return Settings(**base)

    def test_software_backend_default(self) -> None:
        backend, name = create_hsm(self._settings(), pin_vault=HSMPinVault())
        self.assertEqual(name, "software")
        self.assertIsInstance(backend, SoftwareHSM)

    def test_pkcs11_without_lib_raises(self) -> None:
        settings = self._settings(hsm_backend="pkcs11", pkcs11_lib_path=None)
        with mock.patch.object(Settings, "resolve_pkcs11_lib", return_value=None):
            with self.assertRaises(RuntimeError):
                create_hsm(settings, pin_vault=HSMPinVault())

    def test_unknown_backend_raises(self) -> None:
        with self.assertRaises(ValueError):
            create_hsm(self._settings(), pin_vault=HSMPinVault(), backend_name="bogus")


if __name__ == "__main__":
    unittest.main()
