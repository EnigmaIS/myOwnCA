from __future__ import annotations

import datetime
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from myownca.ca_hsm.aws_kms import AWSKMSHSM, AWSKMSError, AWSKMSUnavailable
from myownca.ca_hsm.azure_key_vault import (
    AzureKeyVaultError,
    AzureKeyVaultHSM,
    AzureKeyVaultUnavailable,
)
from myownca.ca_hsm.remote import (
    CloudKeyValidationError,
    NonExportablePrivateKeyError,
    normalize_ecdsa_signature,
    signature_hash_for,
)


def _name() -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cloud-kms.test")])


def _certificate_builder(subject_public_key) -> x509.CertificateBuilder:
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_name())
        .issuer_name(_name())
        .public_key(subject_public_key)
        .serial_number(1234)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    )


def _crl_builder() -> x509.CertificateRevocationListBuilder:
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_name())
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
    )


def _hash_from_suffix(value: str) -> hashes.HashAlgorithm:
    if value.endswith("256"):
        return hashes.SHA256()
    if value.endswith("384"):
        return hashes.SHA384()
    if value.endswith("512"):
        return hashes.SHA512()
    raise AssertionError(value)


def _aws_key_spec(private_key) -> str:
    if isinstance(private_key, rsa.RSAPrivateKey):
        return f"RSA_{private_key.key_size}"
    return f"ECC_NIST_P{private_key.curve.key_size}"


def _aws_algorithms(private_key) -> list[str]:
    if isinstance(private_key, rsa.RSAPrivateKey):
        return ["RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PSS_SHA_256"]
    return [f"ECDSA_SHA_{signature_hash_for(private_key.public_key()).digest_size * 8}"]


class FakeAWSClient:
    def __init__(self, private_key) -> None:
        self.private_key = private_key
        self.arn = "arn:aws:kms:eu-central-1:123456789012:key/key-id"
        self.key_state = "Enabled"
        self.key_usage = "SIGN_VERIFY"
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.sign_error: Exception | None = None

    def create_key(self, **kwargs):
        self.calls.append(("create_key", kwargs))
        return {"KeyMetadata": {"Arn": self.arn}}

    def describe_key(self, **kwargs):
        self.calls.append(("describe_key", kwargs))
        return {
            "KeyMetadata": {
                "Arn": self.arn,
                "Enabled": self.key_state == "Enabled",
                "KeyState": self.key_state,
                "KeyUsage": self.key_usage,
                "KeySpec": _aws_key_spec(self.private_key),
            }
        }

    def get_public_key(self, **kwargs):
        self.calls.append(("get_public_key", kwargs))
        return {
            "KeyId": self.arn,
            "PublicKey": self.private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            "KeyUsage": self.key_usage,
            "KeySpec": _aws_key_spec(self.private_key),
            "SigningAlgorithms": _aws_algorithms(self.private_key),
        }

    def sign(self, **kwargs):
        self.calls.append(("sign", kwargs))
        if self.sign_error is not None:
            raise self.sign_error
        self.assert_digest_request(kwargs)
        algorithm = str(kwargs["SigningAlgorithm"])
        digest_algorithm = _hash_from_suffix(algorithm)
        digest = kwargs["Message"]
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            rsa_padding = (
                padding.PSS(
                    mgf=padding.MGF1(digest_algorithm),
                    salt_length=digest_algorithm.digest_size,
                )
                if "PSS" in algorithm
                else padding.PKCS1v15()
            )
            signature = self.private_key.sign(
                digest,
                rsa_padding,
                utils.Prehashed(digest_algorithm),
            )
        else:
            signature = self.private_key.sign(
                digest,
                ec.ECDSA(utils.Prehashed(digest_algorithm)),
            )
        return {"Signature": signature, "SigningAlgorithm": algorithm}

    def schedule_key_deletion(self, **kwargs):
        self.calls.append(("schedule_key_deletion", kwargs))
        return {"DeletionDate": datetime.datetime(2026, 2, 1, tzinfo=datetime.timezone.utc)}

    def cancel_key_deletion(self, **kwargs):
        self.calls.append(("cancel_key_deletion", kwargs))
        return {"KeyId": self.arn}

    def enable_key(self, **kwargs):
        self.calls.append(("enable_key", kwargs))
        return {}

    def list_keys(self, **kwargs):
        self.calls.append(("list_keys", kwargs))
        return {"Keys": []}

    @staticmethod
    def assert_digest_request(kwargs) -> None:
        if kwargs["MessageType"] != "DIGEST":
            raise AssertionError("AWS payload was not pre-hashed")
        expected_size = _hash_from_suffix(str(kwargs["SigningAlgorithm"])).digest_size
        if len(kwargs["Message"]) != expected_size:
            raise AssertionError("AWS digest has the wrong length")


class FakeAWSError(Exception):
    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.response = {
            "Error": {"Code": code, "Message": "redacted by adapter"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


class AWSKMSBackendTests(unittest.TestCase):
    def _backend(self, private_key) -> tuple[AWSKMSHSM, FakeAWSClient]:
        client = FakeAWSClient(private_key)
        return AWSKMSHSM(region_name="eu-central-1", client=client), client

    def test_attach_resolves_alias_and_validates_key(self) -> None:
        backend, _ = self._backend(ec.generate_private_key(ec.SECP384R1()))

        key_ref = backend.attach_key("alias/myownca", expected_algorithm="ecdsa-p384")
        metadata = backend.validate_key(key_ref)

        self.assertEqual(key_ref, "arn:aws:kms:eu-central-1:123456789012:key/key-id")
        self.assertEqual(metadata["algorithm"], "ecdsa-p384")
        self.assertEqual(metadata["protection"], "kms")

    def test_generate_key_uses_asymmetric_signing_spec_and_returns_arn(self) -> None:
        backend, client = self._backend(ec.generate_private_key(ec.SECP521R1()))

        key_ref = backend.generate_key("issuing-ca", "ecdsa-p521")

        self.assertEqual(key_ref, client.arn)
        request = next(value for name, value in client.calls if name == "create_key")
        self.assertEqual(request["KeySpec"], "ECC_NIST_P521")
        self.assertEqual(request["KeyUsage"], "SIGN_VERIFY")

    def test_generate_key_maps_every_supported_aws_key_spec(self) -> None:
        backend, client = self._backend(ec.generate_private_key(ec.SECP256R1()))
        cases = {
            "rsa-2048": "RSA_2048",
            "rsa-3072": "RSA_3072",
            "rsa-4096": "RSA_4096",
            "ecdsa-p256": "ECC_NIST_P256",
            "ecdsa-p384": "ECC_NIST_P384",
            "ecdsa-p521": "ECC_NIST_P521",
        }

        for index, (algorithm, expected_spec) in enumerate(cases.items()):
            with self.subTest(algorithm=algorithm):
                backend.generate_key(f"key-{index}", algorithm)
                request = [value for name, value in client.calls if name == "create_key"][-1]
                self.assertEqual(request["KeySpec"], expected_spec)

    def test_ec_certificate_crl_and_csr_signatures_verify(self) -> None:
        private_key = ec.generate_private_key(ec.SECP384R1())
        backend, client = self._backend(private_key)
        public_key = private_key.public_key()

        certificate = backend.sign_certificate(_certificate_builder(public_key), "alias/ca")
        crl = backend.sign_crl(_crl_builder(), client.arn)
        csr = backend.sign_csr(
            x509.CertificateSigningRequestBuilder().subject_name(_name()), client.arn
        )

        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA384()),
        )
        self.assertTrue(crl.is_signature_valid(public_key))
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(
            csr.public_key().public_numbers(),
            public_key.public_numbers(),
        )
        signing_algorithms = [
            value["SigningAlgorithm"] for name, value in client.calls if name == "sign"
        ]
        self.assertEqual(
            signing_algorithms,
            ["ECDSA_SHA_384", "ECDSA_SHA_384", "ECDSA_SHA_384"],
        )
        self.assertTrue(
            all(call[1]["KeyId"] == client.arn for call in client.calls if call[0] == "sign")
        )

    def test_rsa_x509_uses_pkcs1_and_data_uses_pss(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        backend, client = self._backend(private_key)

        certificate = backend.sign_certificate(
            _certificate_builder(private_key.public_key()), client.arn
        )
        data_signature = backend.sign_data(b"payload", client.arn)

        private_key.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        private_key.public_key().verify(
            data_signature,
            b"payload",
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO),
            hashes.SHA256(),
        )
        algorithms = [
            value["SigningAlgorithm"] for name, value in client.calls if name == "sign"
        ]
        self.assertEqual(
            algorithms,
            ["RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PSS_SHA_256"],
        )

    def test_key_validation_rejects_non_signing_key(self) -> None:
        backend, client = self._backend(ec.generate_private_key(ec.SECP256R1()))
        client.key_usage = "ENCRYPT_DECRYPT"

        with self.assertRaises(CloudKeyValidationError) as caught:
            backend.attach_key(client.arn)

        self.assertEqual(caught.exception.code, "INVALID_KEY_USAGE")
        self.assertFalse(caught.exception.retryable)

    def test_provider_errors_are_classified_without_leaking_message(self) -> None:
        backend, client = self._backend(ec.generate_private_key(ec.SECP256R1()))
        client.sign_error = FakeAWSError("ThrottlingException", 400)

        with self.assertRaises(AWSKMSError) as caught:
            backend.sign_data(b"payload", client.arn)

        self.assertTrue(caught.exception.retryable)
        self.assertEqual(caught.exception.code, "ThrottlingException")
        self.assertNotIn("redacted by adapter", str(caught.exception))

    def test_transport_errors_are_retryable(self) -> None:
        backend, client = self._backend(ec.generate_private_key(ec.SECP256R1()))
        endpoint_error = type("EndpointConnectionError", (Exception,), {})
        client.sign_error = endpoint_error("network path unavailable")

        with self.assertRaises(AWSKMSError) as caught:
            backend.sign_data(b"payload", client.arn)

        self.assertTrue(caught.exception.retryable)
        self.assertEqual(caught.exception.code, "EndpointConnectionError")

    def test_larger_ec_key_rejects_incompatible_generic_data_contract(self) -> None:
        backend, client = self._backend(ec.generate_private_key(ec.SECP384R1()))

        with self.assertRaises(CloudKeyValidationError) as caught:
            backend.sign_data(b"recovery metadata", client.arn)

        self.assertEqual(caught.exception.code, "UNSUPPORTED_DATA_SIGNATURE")

    def test_delete_recover_and_connection_test(self) -> None:
        backend, client = self._backend(ec.generate_private_key(ec.SECP256R1()))

        deleted = backend.delete_key(client.arn)
        recovered = backend.recover_key(client.arn)
        status = backend.test_connection()

        self.assertEqual(deleted["state"], "pending_deletion")
        self.assertEqual(recovered, client.arn)
        self.assertTrue(status["reachable"])
        self.assertIn("cancel_key_deletion", [name for name, _ in client.calls])
        self.assertIn("enable_key", [name for name, _ in client.calls])

    def test_private_key_is_never_exported(self) -> None:
        backend, client = self._backend(ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaises(NonExportablePrivateKeyError):
            backend.private_key(client.arn)

    def test_sdk_import_is_lazy_when_client_is_injected(self) -> None:
        client = FakeAWSClient(ec.generate_private_key(ec.SECP256R1()))
        with mock.patch.dict(sys.modules, {"boto3": None}):
            backend = AWSKMSHSM(region_name="eu-central-1", client=client)
            self.assertTrue(backend.test_connection()["reachable"])

    def test_missing_sdk_has_actionable_error(self) -> None:
        with mock.patch.dict(sys.modules, {"boto3": None}):
            with self.assertRaises(AWSKMSUnavailable) as caught:
                AWSKMSHSM(region_name="eu-central-1")
        self.assertEqual(caught.exception.code, "SDK_NOT_INSTALLED")


def _azure_jwk(private_key):
    public_numbers = private_key.public_key().public_numbers()
    if isinstance(public_numbers, rsa.RSAPublicNumbers):
        return SimpleNamespace(
            kty="RSA-HSM",
            n=public_numbers.n.to_bytes(private_key.key_size // 8, "big"),
            e=public_numbers.e.to_bytes(3, "big"),
            key_ops=["sign", "verify"],
        )
    width = (private_key.curve.key_size + 7) // 8
    return SimpleNamespace(
        kty="EC-HSM",
        crv=f"P-{private_key.curve.key_size}",
        x=public_numbers.x.to_bytes(width, "big"),
        y=public_numbers.y.to_bytes(width, "big"),
        key_ops=["sign", "verify"],
    )


class FakePoller:
    def __init__(self, result) -> None:
        self._result = result

    def result(self):
        return self._result


class FakeAzureCryptoClient:
    def __init__(self, private_key) -> None:
        self.private_key = private_key
        self.calls: list[tuple[str, bytes]] = []
        self.sign_error: Exception | None = None

    def sign(self, algorithm, digest):
        algorithm = str(getattr(algorithm, "value", algorithm))
        self.calls.append((algorithm, digest))
        if self.sign_error is not None:
            raise self.sign_error
        digest_algorithm = _hash_from_suffix(algorithm)
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            rsa_padding = (
                padding.PSS(
                    mgf=padding.MGF1(digest_algorithm),
                    salt_length=digest_algorithm.digest_size,
                )
                if algorithm.startswith("PS")
                else padding.PKCS1v15()
            )
            signature = self.private_key.sign(
                digest,
                rsa_padding,
                utils.Prehashed(digest_algorithm),
            )
        else:
            der = self.private_key.sign(
                digest,
                ec.ECDSA(utils.Prehashed(digest_algorithm)),
            )
            r, s = decode_dss_signature(der)
            width = (self.private_key.curve.key_size + 7) // 8
            signature = r.to_bytes(width, "big") + s.to_bytes(width, "big")
        return SimpleNamespace(signature=signature)


class FakeAzureKeyClient:
    def __init__(self, private_key) -> None:
        self.private_key = private_key
        self.name = "issuing-ca"
        self.version = "abcdef0123456789"
        self.vault_url = "https://unit-test.vault.azure.net"
        self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []
        self.enabled = True
        self.key_ops = ["sign", "verify"]
        self.tags = {"myownca-managed": "true"}

    def _key(self):
        jwk = _azure_jwk(self.private_key)
        jwk.key_ops = self.key_ops
        return SimpleNamespace(
            id=f"{self.vault_url}/keys/{self.name}/{self.version}",
            name=self.name,
            key_type=jwk.kty,
            key=jwk,
            properties=SimpleNamespace(enabled=self.enabled, tags=self.tags),
        )

    def get_key(self, name, version=None):
        self.calls.append(("get_key", (name, version), {}))
        return self._key()

    def create_rsa_key(self, name, **kwargs):
        self.calls.append(("create_rsa_key", (name,), kwargs))
        return self._key()

    def create_ec_key(self, name, **kwargs):
        self.calls.append(("create_ec_key", (name,), kwargs))
        return self._key()

    def begin_delete_key(self, name):
        self.calls.append(("begin_delete_key", (name,), {}))
        return FakePoller(SimpleNamespace(recovery_id="recovery-id", deleted_on=None))

    def begin_recover_deleted_key(self, name):
        self.calls.append(("begin_recover_deleted_key", (name,), {}))
        return FakePoller(self._key())

    def list_properties_of_keys(self):
        self.calls.append(("list_properties_of_keys", (), {}))
        return iter(())


class FakeAzureError(Exception):
    def __init__(self, code: str, status: int) -> None:
        super().__init__("provider detail must not leak")
        self.error = SimpleNamespace(code=code)
        self.status_code = status


class AzureKeyVaultBackendTests(unittest.TestCase):
    def _backend(self, private_key):
        key_client = FakeAzureKeyClient(private_key)
        crypto = FakeAzureCryptoClient(private_key)
        refs: list[str] = []

        def factory(key_ref: str):
            refs.append(key_ref)
            return crypto

        backend = AzureKeyVaultHSM(
            vault_url=key_client.vault_url,
            key_client=key_client,
            cryptography_client_factory=factory,
        )
        return backend, key_client, crypto, refs

    def test_attach_pins_latest_key_version_and_validates_metadata(self) -> None:
        backend, key_client, _, _ = self._backend(ec.generate_private_key(ec.SECP384R1()))

        key_ref = backend.attach_key(
            f"{key_client.vault_url}/keys/{key_client.name}",
            expected_algorithm="ecdsa-p384",
        )
        metadata = backend.validate_key(key_ref)

        self.assertEqual(
            key_ref,
            f"{key_client.vault_url}/keys/{key_client.name}/{key_client.version}",
        )
        self.assertEqual(metadata["algorithm"], "ecdsa-p384")
        self.assertEqual(metadata["protection"], "hsm")

    def test_generate_standard_ec_key_returns_versioned_reference(self) -> None:
        private_key = ec.generate_private_key(ec.SECP521R1())
        key_client = FakeAzureKeyClient(private_key)
        backend = AzureKeyVaultHSM(
            vault_url=key_client.vault_url,
            key_protection="standard",
            key_client=key_client,
        )

        key_ref = backend.generate_key("issuing-ca", "ecdsa-p521")

        self.assertTrue(key_ref.endswith(f"/{key_client.version}"))
        call = next(value for value in key_client.calls if value[0] == "create_ec_key")
        self.assertEqual(call[2]["curve"], "P-521")
        self.assertFalse(call[2]["hardware_protected"])
        self.assertEqual(call[2]["key_operations"], ["sign", "verify"])

    def test_managed_delete_guard_requires_version_and_ownership_tag(self) -> None:
        backend, key_client, _, _ = self._backend(
            ec.generate_private_key(ec.SECP256R1())
        )
        key_ref = f"{key_client.vault_url}/keys/{key_client.name}/{key_client.version}"

        self.assertEqual(backend.validate_managed_key_for_deletion(key_ref), key_ref)
        with self.assertRaises(CloudKeyValidationError) as unversioned:
            backend.validate_managed_key_for_deletion(key_client.name)
        self.assertEqual(unversioned.exception.code, "UNVERSIONED_KEY_REFERENCE")

        key_client.tags = {"myownca-managed": "false"}
        with self.assertRaises(CloudKeyValidationError) as unmanaged:
            backend.validate_managed_key_for_deletion(key_ref)
        self.assertEqual(unmanaged.exception.code, "KEY_NOT_MANAGED_BY_MYOWNCA")

    def test_generate_key_maps_every_supported_azure_algorithm(self) -> None:
        backend, key_client, _, _ = self._backend(ec.generate_private_key(ec.SECP256R1()))
        cases = {
            "rsa-2048": ("create_rsa_key", "size", 2048),
            "rsa-3072": ("create_rsa_key", "size", 3072),
            "rsa-4096": ("create_rsa_key", "size", 4096),
            "ecdsa-p256": ("create_ec_key", "curve", "P-256"),
            "ecdsa-p384": ("create_ec_key", "curve", "P-384"),
            "ecdsa-p521": ("create_ec_key", "curve", "P-521"),
        }

        for index, (algorithm, expected) in enumerate(cases.items()):
            with self.subTest(algorithm=algorithm):
                backend.generate_key(f"key-{index}", algorithm)
                call = key_client.calls[-1]
                self.assertEqual(call[0], expected[0])
                self.assertEqual(call[2][expected[1]], expected[2])

    def test_raw_ec_signatures_are_normalized_for_p521_x509(self) -> None:
        private_key = ec.generate_private_key(ec.SECP521R1())
        backend, key_client, crypto, refs = self._backend(private_key)
        key_ref = f"{key_client.vault_url}/keys/{key_client.name}"

        certificate = backend.sign_certificate(
            _certificate_builder(private_key.public_key()), key_ref
        )
        crl = backend.sign_crl(_crl_builder(), key_ref)
        csr = backend.sign_csr(x509.CertificateSigningRequestBuilder().subject_name(_name()), key_ref)

        private_key.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA512()),
        )
        self.assertTrue(crl.is_signature_valid(private_key.public_key()))
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(
            [algorithm for algorithm, _ in crypto.calls],
            ["ES512", "ES512", "ES512"],
        )
        canonical = f"{key_client.vault_url}/keys/{key_client.name}/{key_client.version}"
        self.assertEqual(refs, [canonical] * 3)

    def test_larger_ec_key_rejects_incompatible_generic_data_contract(self) -> None:
        backend, key_client, _, _ = self._backend(
            ec.generate_private_key(ec.SECP384R1())
        )

        with self.assertRaises(CloudKeyValidationError) as caught:
            backend.sign_data(b"recovery metadata", key_client.name)

        self.assertEqual(caught.exception.code, "UNSUPPORTED_DATA_SIGNATURE")

    def test_rsa_x509_uses_rs256_and_data_uses_ps256(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        backend, key_client, crypto, _ = self._backend(private_key)
        key_ref = f"{key_client.vault_url}/keys/{key_client.name}/{key_client.version}"

        certificate = backend.sign_certificate(
            _certificate_builder(private_key.public_key()), key_ref
        )
        data_signature = backend.sign_data(b"payload", key_ref)

        private_key.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        private_key.public_key().verify(
            data_signature,
            b"payload",
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO),
            hashes.SHA256(),
        )
        self.assertEqual([algorithm for algorithm, _ in crypto.calls], ["RS256", "PS256"])

    def test_validation_rejects_key_without_sign_operation(self) -> None:
        backend, key_client, _, _ = self._backend(ec.generate_private_key(ec.SECP256R1()))
        key_client.key_ops = ["verify"]

        with self.assertRaises(CloudKeyValidationError) as caught:
            backend.attach_key(key_client.name)

        self.assertEqual(caught.exception.code, "INVALID_KEY_USAGE")

    def test_cross_vault_reference_is_rejected(self) -> None:
        backend, _, _, _ = self._backend(ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaises(CloudKeyValidationError):
            backend.attach_key("https://other.vault.azure.net/keys/issuing-ca/version")

    def test_provider_errors_are_classified(self) -> None:
        backend, key_client, crypto, _ = self._backend(ec.generate_private_key(ec.SECP256R1()))
        crypto.sign_error = FakeAzureError("TooManyRequests", 429)

        with self.assertRaises(AzureKeyVaultError) as caught:
            backend.sign_data(b"payload", key_client.name)

        self.assertTrue(caught.exception.retryable)
        self.assertEqual(caught.exception.code, "TooManyRequests")
        self.assertNotIn("provider detail", str(caught.exception))

    def test_soft_delete_recovery_and_connection_test(self) -> None:
        backend, key_client, _, _ = self._backend(ec.generate_private_key(ec.SECP256R1()))

        deleted = backend.delete_key(key_client.name)
        recovered = backend.recover_key(key_client.name)
        status = backend.test_connection()

        self.assertEqual(deleted["state"], "deleted")
        self.assertTrue(recovered.endswith(f"/{key_client.version}"))
        self.assertTrue(status["reachable"])

    def test_private_key_is_never_exported(self) -> None:
        backend, key_client, _, _ = self._backend(ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaises(NonExportablePrivateKeyError):
            backend.private_key(key_client.name)

    def test_sdk_imports_are_lazy_with_injected_clients(self) -> None:
        key_client = FakeAzureKeyClient(ec.generate_private_key(ec.SECP256R1()))
        with mock.patch.dict(
            sys.modules,
            {
                "azure": None,
                "azure.identity": None,
                "azure.keyvault": None,
                "azure.keyvault.keys": None,
            },
        ):
            backend = AzureKeyVaultHSM(
                vault_url=key_client.vault_url,
                key_client=key_client,
            )
            self.assertTrue(backend.test_connection()["reachable"])

    def test_missing_sdk_has_actionable_error(self) -> None:
        with mock.patch.dict(sys.modules, {"azure": None, "azure.identity": None}):
            with self.assertRaises(AzureKeyVaultUnavailable) as caught:
                AzureKeyVaultHSM(
                    vault_url="https://unit-test.vault.azure.net",
                    tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )
        self.assertEqual(caught.exception.code, "SDK_NOT_INSTALLED")


class RemoteSigningHelpersTests(unittest.TestCase):
    def test_curve_specific_hash_selection(self) -> None:
        cases = (
            (ec.SECP256R1(), hashes.SHA256),
            (ec.SECP384R1(), hashes.SHA384),
            (ec.SECP521R1(), hashes.SHA512),
        )
        for curve, expected in cases:
            with self.subTest(curve=curve.name):
                public_key = ec.generate_private_key(curve).public_key()
                self.assertIsInstance(signature_hash_for(public_key), expected)

    def test_ecdsa_normalizer_accepts_der_and_fixed_width_signatures(self) -> None:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        der = private_key.sign(b"payload", ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        width = (public_key.curve.key_size + 7) // 8
        raw = r.to_bytes(width, "big") + s.to_bytes(width, "big")

        self.assertEqual(decode_dss_signature(normalize_ecdsa_signature(der, public_key)), (r, s))
        self.assertEqual(decode_dss_signature(normalize_ecdsa_signature(raw, public_key)), (r, s))

    def test_malformed_raw_ecdsa_signature_is_rejected(self) -> None:
        public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
        with self.assertRaises(CloudKeyValidationError):
            normalize_ecdsa_signature(b"not-a-signature", public_key)


if __name__ == "__main__":
    unittest.main()
