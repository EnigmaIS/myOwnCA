from __future__ import annotations

import datetime
import stat
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from myownca.ca_hsm.base import KeyImportError, KeyMismatchError
from myownca.ca_hsm.software import SoftwareHSM


def _certificate(private_key, common_name: str = "Imported Sub CA") -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )


@pytest.mark.parametrize(
    "private_key, expected_algorithm",
    [
        (rsa.generate_private_key(public_exponent=65537, key_size=2048), "rsa-2048"),
        (ec.generate_private_key(ec.SECP256R1()), "ecdsa-p256"),
        (ec.generate_private_key(ec.SECP384R1()), "ecdsa-p384"),
    ],
)
def test_software_hsm_import_and_live_verification(private_key, expected_algorithm) -> None:
    certificate = _certificate(private_key)
    hsm = SoftwareHSM()

    assert hsm.import_key("imported-ca", private_key, certificate) == "imported-ca"
    verification = hsm.verify_key("imported-ca", certificate)

    assert verification.algorithm == expected_algorithm
    assert verification.signing_verified
    assert len(verification.public_key_sha256) == 64
    assert hsm.certificate("imported-ca") == certificate


def test_software_hsm_rejects_mismatched_certificate_without_storing_key() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    hsm = SoftwareHSM()

    with pytest.raises(KeyMismatchError, match="does not match"):
        hsm.import_key("mismatch", private_key, _certificate(other_key))

    with pytest.raises(KeyError):
        hsm.private_key("mismatch")


def test_software_hsm_rejects_weak_rsa_import() -> None:
    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(KeyImportError, match="Unsupported certificate key"):
        SoftwareHSM().import_key("weak", weak_key, _certificate(weak_key))


def test_persistent_import_requires_passphrase() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    with TemporaryDirectory() as temp_dir:
        with pytest.raises(KeyImportError, match="requires an encryption passphrase"):
            SoftwareHSM(temp_dir).import_key("unencrypted", key, _certificate(key))
        assert list(Path(temp_dir).iterdir()) == []


def test_persistent_import_is_encrypted_mode_0600_and_reloadable() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = _certificate(key)
    with TemporaryDirectory() as temp_dir:
        hsm = SoftwareHSM(temp_dir, passphrase="correct horse battery staple")
        hsm.import_key("persistent", key, certificate)

        key_path = Path(temp_dir) / "persistent.pem"
        certificate_path = Path(temp_dir) / "persistent.crt"
        payload = key_path.read_bytes()
        assert b"BEGIN ENCRYPTED PRIVATE KEY" in payload
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
        assert b"BEGIN CERTIFICATE" in certificate_path.read_bytes()

        reloaded = SoftwareHSM(temp_dir, passphrase="correct horse battery staple")
        assert reloaded.verify_key("persistent", certificate).algorithm == "ecdsa-p256"
        assert reloaded.certificate("persistent") == certificate


def test_existing_generated_key_can_be_verified_without_import() -> None:
    hsm = SoftwareHSM()
    hsm.generate_key("existing", "ecdsa-p256")
    certificate = _certificate(hsm.private_key("existing"))

    result = hsm.verify_key("existing", certificate)

    assert result.key_ref == "existing"
    assert result.algorithm == "ecdsa-p256"


def test_private_key_file_is_valid_pkcs8_after_atomic_write() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with TemporaryDirectory() as temp_dir:
        SoftwareHSM(temp_dir, passphrase="secret").import_key(
            "pkcs8", key, _certificate(key)
        )
        loaded = serialization.load_pem_private_key(
            (Path(temp_dir) / "pkcs8.pem").read_bytes(), password=b"secret"
        )
        assert loaded.public_key().public_numbers() == key.public_key().public_numbers()


def test_software_hsm_delete_removes_key_and_certificate_sidecar() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    with TemporaryDirectory() as temp_dir:
        hsm = SoftwareHSM(temp_dir, passphrase="secret")
        hsm.import_key("retired", key, _certificate(key))

        assert hsm.delete_key("retired") == 1
        assert not (Path(temp_dir) / "retired.pem").exists()
        assert not (Path(temp_dir) / "retired.crt").exists()
        with pytest.raises(KeyError):
            hsm.private_key("retired")
