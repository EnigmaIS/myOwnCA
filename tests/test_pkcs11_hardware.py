"""Hardware-gated integration tests for the PKCS#11 backend.

These talk to a real SmartCard-HSM / NitroKey HSM and are skipped unless the
token's User PIN is supplied via the environment:

    MYOWNCA_HSM_TEST_PIN     (required) — User PIN; enables this module
    MYOWNCA_PKCS11_LIB       (optional) — path to opensc-pkcs11.so
    MYOWNCA_PKCS11_TOKEN_LABEL (optional, default "SmartCard-HSM")
    MYOWNCA_HSM_TEST_DKEK_ROUNDTRIP=1 (optional) — explicitly enables the
        destructive round-trip of one test-generated key through wrap/unwrap
    MYOWNCA_HSM_TEST_SC_HSM_TOOL (optional, default "sc-hsm-tool")

The tests generate keys with a unique "bbtest-" label prefix and destroy them
on teardown, so they never touch existing token keys. They never call
``initialize`` (which would wipe the token).
"""

from __future__ import annotations

import os
import unittest
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

_PIN = os.getenv("MYOWNCA_HSM_TEST_PIN")
_TOKEN_LABEL = os.getenv("MYOWNCA_PKCS11_TOKEN_LABEL", "SmartCard-HSM")
_DKEK_ROUNDTRIP = os.getenv("MYOWNCA_HSM_TEST_DKEK_ROUNDTRIP") == "1"
_SC_HSM_TOOL = os.getenv("MYOWNCA_HSM_TEST_SC_HSM_TOOL", "sc-hsm-tool")


def _resolve_lib() -> str | None:
    lib = os.getenv("MYOWNCA_PKCS11_LIB")
    if lib:
        return lib
    for candidate in (
        "/usr/lib/pkcs11/opensc-pkcs11.so",
        "/usr/lib64/pkcs11/opensc-pkcs11.so",
        "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        "/usr/local/lib/opensc-pkcs11.so",
    ):
        if os.path.exists(candidate):
            return candidate
    return None


_LIB = _resolve_lib()


@unittest.skipUnless(_PIN, "set MYOWNCA_HSM_TEST_PIN to run hardware tests")
@unittest.skipUnless(_LIB, "no opensc-pkcs11.so module found")
class PKCS11HardwareTests(unittest.TestCase):
    def setUp(self) -> None:
        from myownca.ca_hsm.pkcs11 import PKCS11HSM

        self.hsm = PKCS11HSM(_LIB, _TOKEN_LABEL, pin_provider=lambda: _PIN)
        self._labels: list[str] = []

    def tearDown(self) -> None:
        for label in self._labels:
            try:
                self.hsm.delete_key(label)
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass

    def _label(self) -> str:
        label = f"bbtest-{uuid.uuid4().hex[:12]}"
        self._labels.append(label)
        return label

    def _builder(self, public_key) -> x509.CertificateBuilder:
        import datetime

        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hw.test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        )

    def test_status_reports_initialized_token(self) -> None:
        status = self.hsm.status()
        self.assertTrue(status["token_present"], status)
        self.assertTrue(status["token"]["initialized"])

    def test_self_test_passes(self) -> None:
        result = self.hsm.self_test()
        self.assertTrue(result["passed"])
        self.assertEqual(result["algorithm"], "ecdsa-p256")

    def test_ec_keygen_sign_certificate_and_verify(self) -> None:
        label = self._label()
        self.hsm.generate_key(label, "ecdsa-p256")
        pub = self.hsm.public_key(label)
        self.assertIsInstance(pub, ec.EllipticCurvePublicKey)

        cert = self.hsm.sign_certificate(self._builder(pub), label)
        # The token's public key must verify the spliced signature.
        pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        self.assertEqual(
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "hw.test"
        )

    def test_ec_keygen_sign_csr_and_verify(self) -> None:
        label = self._label()
        self.hsm.generate_key(label, "ecdsa-p256")
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hw.test")])
        csr = self.hsm.sign_csr(
            x509.CertificateSigningRequestBuilder().subject_name(name),
            label,
        )

        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(
            csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "hw.test"
        )

    def test_ec_sign_crl_and_verify(self) -> None:
        import datetime

        label = self._label()
        self.hsm.generate_key(label, "ecdsa-p256")
        pub = self.hsm.public_key(label)
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hw.test")]))
            .last_update(now - datetime.timedelta(minutes=1))
            .next_update(now + datetime.timedelta(days=1))
        )
        crl = self.hsm.sign_crl(builder, label)
        self.assertTrue(
            crl.is_signature_valid(pub),
            "CRL signature failed to verify against token public key",
        )

    def test_rsa_keygen_sign_data_pss_and_verify(self) -> None:
        label = self._label()
        self.hsm.generate_key(label, "rsa-2048")
        pub = self.hsm.public_key(label)
        self.assertIsInstance(pub, rsa.RSAPublicKey)

        payload = b"myownca recovery metadata payload"
        signature = self.hsm.sign_data(payload, label)
        # Matches the recovery metadata verifier: PSS(SHA256, MAX_LENGTH).
        pub.verify(
            signature,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    def test_list_and_delete_key_roundtrip(self) -> None:
        label = self._label()
        self.hsm.generate_key(label, "ecdsa-p256")
        matches = [key for key in self.hsm.list_keys() if key["label"] == label]
        self.assertEqual(len(matches), 1)
        self.assertIsInstance(matches[0]["key_reference"], int)
        self.assertGreaterEqual(matches[0]["key_reference"], 1)
        self.assertLessEqual(matches[0]["key_reference"], 255)
        destroyed = self.hsm.delete_key(label)
        self.assertGreaterEqual(destroyed, 1)
        self._labels.remove(label)  # already cleaned up
        self.assertNotIn(label, [key["label"] for key in self.hsm.list_keys()])

    def test_duplicate_label_rejected(self) -> None:
        label = self._label()
        self.hsm.generate_key(label, "ecdsa-p256")
        with self.assertRaises(ValueError):
            self.hsm.generate_key(label, "ecdsa-p256")

    @unittest.skipUnless(
        _DKEK_ROUNDTRIP,
        "set MYOWNCA_HSM_TEST_DKEK_ROUNDTRIP=1 on a dedicated DKEK-enabled token",
    )
    def test_dkek_wrap_delete_unwrap_roundtrip(self) -> None:
        """Recover only a key created by this test; never overwrite a token slot."""

        from myownca.ca_hsm.scctl import ScHsmCtl

        scctl = ScHsmCtl(_SC_HSM_TOOL)
        status = scctl.dkek_status()
        if not status.complete:
            self.skipTest("the selected SmartCard-HSM has no complete DKEK configuration")

        label = self._label()
        self.hsm.generate_key(label, "ecdsa-p256")
        public_der = self.hsm.public_key(label).public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        matches = [item for item in self.hsm.list_keys() if item["label"] == label]
        self.assertEqual(len(matches), 1)
        reference = matches[0]["key_reference"]
        if reference is None:
            self.skipTest("the token did not expose a one-byte SmartCard-HSM key reference")

        wrapped = scctl.wrap_key(reference, user_pin=_PIN)
        self.assertTrue(wrapped)
        self.hsm.delete_key(label)
        scctl.unwrap_key(
            wrapped,
            user_pin=_PIN,
            key_reference=reference,
            force=False,
        )

        restored_der = self.hsm.public_key(label).public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.assertEqual(restored_der, public_der)


if __name__ == "__main__":
    unittest.main()
