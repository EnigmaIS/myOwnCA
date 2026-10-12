import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from myownca import keygen
from myownca.ca_hsm.software import SoftwareHSM
from myownca.service_certs.base import KeyBackend, ServiceCertError
from myownca.service_certs.keystore import ServiceKeyStore


class GeneratePrivateKeyTests(unittest.TestCase):
    def test_rsa_2048(self) -> None:
        key = keygen.generate_private_key("rsa-2048")
        self.assertIsInstance(key, rsa.RSAPrivateKey)
        self.assertEqual(key.key_size, 2048)

    def test_ecdsa_curves(self) -> None:
        for algorithm, curve in (
            ("ecdsa-p256", "secp256r1"),
            ("ecdsa-p384", "secp384r1"),
            ("ecdsa-p521", "secp521r1"),
        ):
            key = keygen.generate_private_key(algorithm)
            self.assertIsInstance(key, ec.EllipticCurvePrivateKey)
            self.assertEqual(key.curve.name, curve)

    def test_catalogue_lists_all_requested_sizes(self) -> None:
        # Large RSA sizes are catalogued but not generated here (too slow for CI).
        for algorithm in (
            "rsa-2048",
            "rsa-3072",
            "rsa-4096",
            "ecdsa-p256",
            "ecdsa-p384",
            "ecdsa-p521",
        ):
            self.assertIn(algorithm, keygen.SUPPORTED_ALGORITHMS)

    def test_certificate_catalogue_excludes_non_issuable_algorithms(self) -> None:
        self.assertEqual(
            keygen.CERTIFICATE_ALGORITHMS,
            ("rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"),
        )

    def test_unsupported_algorithm(self) -> None:
        with self.assertRaises(keygen.KeygenError) as ctx:
            keygen.generate_private_key("rsa-512")
        self.assertIsInstance(ctx.exception, ValueError)

    def test_callable_entropy_source_is_resolved(self) -> None:
        calls: list[str | None] = []

        def source() -> str | None:
            calls.append("called")
            return None

        keygen.generate_private_key("ecdsa-p256", entropy_source=source)
        self.assertEqual(calls, ["called"])


class EntropySourceTests(unittest.TestCase):
    def _file_with(self, payload: bytes) -> str:
        handle = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(os.unlink, handle.name)
        handle.write(payload)
        handle.close()
        return handle.name

    def test_validate_accepts_random_file(self) -> None:
        keygen.validate_entropy_source(self._file_with(os.urandom(256)))

    def test_validate_accepts_dev_urandom(self) -> None:
        keygen.validate_entropy_source("/dev/urandom")

    def test_validate_rejects_missing_path(self) -> None:
        with self.assertRaises(keygen.EntropyError):
            keygen.validate_entropy_source("/nonexistent/trng")

    def test_validate_rejects_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(keygen.EntropyError):
                keygen.validate_entropy_source(tmp)

    def test_validate_rejects_short_source(self) -> None:
        with self.assertRaises(keygen.EntropyError) as ctx:
            keygen.validate_entropy_source(self._file_with(os.urandom(10)))
        self.assertIn("10/64", str(ctx.exception))

    def test_validate_rejects_constant_output(self) -> None:
        with self.assertRaises(keygen.EntropyError) as ctx:
            keygen.validate_entropy_source(self._file_with(b"\x00" * 64))
        self.assertIn("constant", str(ctx.exception))

    def test_feed_without_source_is_noop(self) -> None:
        keygen.feed_entropy(None)
        keygen.feed_entropy("")

    def test_feed_mixes_valid_source(self) -> None:
        keygen.feed_entropy(self._file_with(os.urandom(64)))

    def test_generate_fails_closed_on_broken_source(self) -> None:
        with self.assertRaises(keygen.EntropyError):
            keygen.generate_private_key("ecdsa-p256", entropy_source="/nonexistent/trng")

    def test_generate_succeeds_with_valid_source(self) -> None:
        key = keygen.generate_private_key(
            "ecdsa-p256", entropy_source=self._file_with(os.urandom(64))
        )
        self.assertIsInstance(key, ec.EllipticCurvePrivateKey)


class WiringTests(unittest.TestCase):
    def test_software_hsm_supports_new_algorithms(self) -> None:
        hsm = SoftwareHSM()
        hsm.generate_key("k1", "ecdsa-p521")
        self.assertEqual(hsm.private_key("k1").curve.name, "secp521r1")

    def test_software_hsm_fails_closed_on_broken_entropy_source(self) -> None:
        hsm = SoftwareHSM(entropy_source="/nonexistent/trng")
        with self.assertRaises(keygen.EntropyError):
            hsm.generate_key("k1", "ecdsa-p256")

    def test_software_hsm_resolves_callable_source_per_generation(self) -> None:
        sources: list[str | None] = [None]
        hsm = SoftwareHSM(entropy_source=lambda: sources[-1])
        hsm.generate_key("k1", "ecdsa-p256")
        sources.append("/nonexistent/trng")
        with self.assertRaises(keygen.EntropyError):
            hsm.generate_key("k2", "ecdsa-p256")

    def test_keystore_wraps_keygen_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ServiceKeyStore(Path(tmp))
            with self.assertRaises(ServiceCertError):
                store.generate("svc", KeyBackend.SOFTWARE, "rsa-512")

    def test_keystore_fails_closed_on_broken_entropy_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ServiceKeyStore(Path(tmp), entropy_source="/nonexistent/trng")
            with self.assertRaises(ServiceCertError):
                store.generate("svc", KeyBackend.SOFTWARE, "ecdsa-p256")

    def test_keystore_generates_new_algorithms(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ServiceKeyStore(Path(tmp))
            store.generate("svc", KeyBackend.SOFTWARE, "ecdsa-p521")
            public = store.public_key("svc", KeyBackend.SOFTWARE)
            self.assertEqual(public.curve.name, "secp521r1")


if __name__ == "__main__":
    unittest.main()
