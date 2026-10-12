from __future__ import annotations

import os
import re
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from myownca_core.private_files import mkdir_private

from myownca import keygen
from myownca.ca_hsm.base import (
    KeyImportError,
    KeyVerification,
    validate_imported_key,
    verify_backend_key,
)


class SoftwareHSM:
    """Development backend matching the future HSM boundary.

    When ``key_dir`` is provided, keys are persisted as PEM files so local offline
    ceremony commands can survive separate invocations. This is a lab/development
    aid, not the intended production key-storage posture.
    """

    def __init__(
        self,
        key_dir: str | Path | None = None,
        passphrase: str | bytes | None = None,
        entropy_source: keygen.EntropySource = None,
    ) -> None:
        self._keys: dict[str, CertificateIssuerPrivateKeyTypes] = {}
        self._certificates: dict[str, x509.Certificate] = {}
        self._key_dir = Path(key_dir) if key_dir is not None else None
        self._passphrase = passphrase.encode() if isinstance(passphrase, str) else passphrase
        self._entropy_source = entropy_source
        self._lock = threading.RLock()
        if self._key_dir is not None:
            mkdir_private(self._key_dir)

    def generate_key(self, label: str, algorithm: str = "rsa-2048") -> str:
        self._validate_label(label)
        with self._lock:
            persisted_key_exists = self._key_dir is not None and self._key_path(label).exists()
            if label in self._keys or persisted_key_exists:
                raise ValueError(f"Key label already exists: {label}")
            private_key = keygen.generate_private_key(
                algorithm, entropy_source=self._entropy_source
            )
            self._persist_key(label, private_key)
            self._keys[label] = private_key
        return label

    def import_key(
        self,
        label: str,
        private_key: CertificateIssuerPrivateKeyTypes,
        certificate: x509.Certificate | None = None,
    ) -> str:
        """Import a strong RSA/EC key, optionally with its matching certificate.

        Persistent imports are refused unless an encryption passphrase is
        configured. This is intentionally stricter than the legacy development
        key generator, which can still create unencrypted lab keys.
        """

        self._validate_label(label)
        validate_imported_key(private_key, certificate)
        if self._key_dir is not None and not self._passphrase:
            raise KeyImportError(
                "Persistent SoftwareHSM key import requires an encryption passphrase"
            )
        with self._lock:
            key_exists = label in self._keys or (
                self._key_dir is not None and self._key_path(label).exists()
            )
            cert_exists = label in self._certificates or (
                self._key_dir is not None and self._certificate_path(label).exists()
            )
            if key_exists or cert_exists:
                raise ValueError(f"Key label already exists: {label}")
            self._persist_import(label, private_key, certificate)
            self._keys[label] = private_key
            if certificate is not None:
                self._certificates[label] = certificate
        return label

    def verify_key(self, key_ref: str, certificate: x509.Certificate) -> KeyVerification:
        return verify_backend_key(self, key_ref, certificate)

    def public_key(self, key_ref: str) -> CertificatePublicKeyTypes:
        return self.private_key(key_ref).public_key()

    def public_key_pem(self, key_ref: str) -> str:
        return (
            self.public_key(key_ref)
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

    def private_key(self, key_ref: str) -> CertificateIssuerPrivateKeyTypes:
        self._validate_label(key_ref)
        with self._lock:
            if key_ref in self._keys:
                return self._keys[key_ref]
            if self._key_dir is not None:
                key_path = self._key_path(key_ref)
                if key_path.exists():
                    private_key = serialization.load_pem_private_key(
                        key_path.read_bytes(),
                        password=self._passphrase,
                    )
                    self._keys[key_ref] = private_key
                    return private_key
        raise KeyError(f"Unknown key reference: {key_ref}")

    def certificate(self, key_ref: str) -> x509.Certificate | None:
        """Return an imported certificate sidecar, if one was supplied."""

        self._validate_label(key_ref)
        with self._lock:
            if key_ref in self._certificates:
                return self._certificates[key_ref]
            if self._key_dir is not None:
                certificate_path = self._certificate_path(key_ref)
                if certificate_path.exists():
                    certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
                    self._certificates[key_ref] = certificate
                    return certificate
        return None

    def sign_certificate(
        self, builder: x509.CertificateBuilder, key_ref: str
    ) -> x509.Certificate:
        private_key = self.private_key(key_ref)
        return builder.sign(private_key=private_key, algorithm=_signature_algorithm(private_key))

    def sign_crl(
        self, builder: x509.CertificateRevocationListBuilder, key_ref: str
    ) -> x509.CertificateRevocationList:
        private_key = self.private_key(key_ref)
        return builder.sign(private_key=private_key, algorithm=_signature_algorithm(private_key))

    def sign_csr(
        self, builder: x509.CertificateSigningRequestBuilder, key_ref: str
    ) -> x509.CertificateSigningRequest:
        private_key = self.private_key(key_ref)
        return builder.sign(private_key, _signature_algorithm(private_key))

    def sign_data(self, payload: bytes, key_ref: str) -> bytes:
        private_key = self.private_key(key_ref)
        if isinstance(private_key, rsa.RSAPrivateKey):
            return private_key.sign(
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        raise ValueError("Unsupported key type for generic signing")

    def list_keys(self) -> list[dict[str, object]]:
        labels = set(self._keys)
        if self._key_dir is not None:
            labels.update(path.stem for path in self._key_dir.glob("*.pem") if not path.name.endswith(".crt.pem"))
        return [
            {
                "label": label,
                "key_type": type(self.public_key(label)).__name__,
                "key_size": getattr(self.public_key(label), "key_size", None),
                "id": label,
                "key_reference": None,
            }
            for label in sorted(labels)
        ]

    def delete_key(self, label: str) -> int:
        """Destroy one app-managed software key and its certificate sidecar."""
        self._validate_label(label)
        with self._lock:
            existed = label in self._keys
            self._keys.pop(label, None)
            self._certificates.pop(label, None)
            if self._key_dir is not None:
                key_path = self._key_path(label)
                cert_path = self._certificate_path(label)
                existed = existed or key_path.exists() or cert_path.exists()
                key_path.unlink(missing_ok=True)
                cert_path.unlink(missing_ok=True)
        if not existed:
            raise ValueError(f"Unknown key reference: {label}")
        return 1

    def _persist_key(self, label: str, private_key: CertificateIssuerPrivateKeyTypes) -> None:
        if self._key_dir is None:
            return
        encryption = (
            serialization.BestAvailableEncryption(self._passphrase)
            if self._passphrase
            else serialization.NoEncryption()
        )
        self._atomic_write(
            self._key_path(label),
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                encryption,
            ),
            mode=0o600,
        )

    def _persist_import(
        self,
        label: str,
        private_key: CertificateIssuerPrivateKeyTypes,
        certificate: x509.Certificate | None,
    ) -> None:
        if self._key_dir is None:
            return
        key_path = self._key_path(label)
        certificate_path = self._certificate_path(label)
        try:
            self._persist_key(label, private_key)
            if certificate is not None:
                self._atomic_write(
                    certificate_path,
                    certificate.public_bytes(serialization.Encoding.PEM),
                    mode=0o644,
                )
        except Exception:
            # The label was confirmed unused while holding ``_lock``. Removing
            # these paths therefore rolls back only this attempted import.
            key_path.unlink(missing_ok=True)
            certificate_path.unlink(missing_ok=True)
            raise

    def _key_path(self, label: str) -> Path:
        if self._key_dir is None:
            return Path(f"{label}.pem")
        return self._key_dir / f"{label}.pem"

    def _certificate_path(self, label: str) -> Path:
        if self._key_dir is None:
            return Path(f"{label}.crt")
        return self._key_dir / f"{label}.crt"

    def _atomic_write(self, path: Path, payload: bytes, *, mode: int) -> None:
        if self._key_dir is None:  # pragma: no cover - callers already guard this
            return
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            dir=self._key_dir,
        )
        temporary_path = Path(temporary_name)
        try:
            os.chmod(temporary_path, mode)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary_path.unlink(missing_ok=True)

    @staticmethod
    def _validate_label(label: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", label):
            raise ValueError(f"Unsafe key label: {label}")


def _signature_algorithm(private_key: CertificateIssuerPrivateKeyTypes):
    return hashes.SHA256()
