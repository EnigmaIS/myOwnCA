from __future__ import annotations

import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
)
from cryptography.x509.oid import NameOID
from myownca_core.private_files import atomic_write, mkdir_private

from myownca import keygen
from myownca.service_certs.base import KeyBackend, ServiceCertError

_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")


class ServiceKeyStore:
    """Private-key storage for service certificates.

    Software keys are PEM files (optionally passphrase-encrypted) under
    ``key_dir``; PKCS#11 and cloud keys are generated remotely and never leave
    their provider. CSRs are signed with the matching key (directly for
    software, via the active HSM/KMS signing bridge otherwise).
    """

    def __init__(
        self,
        key_dir: str | Path,
        *,
        passphrase: str | bytes | None = None,
        hsm=None,
        entropy_source: keygen.EntropySource = None,
    ) -> None:
        self._key_dir = Path(key_dir)
        mkdir_private(self._key_dir)
        self._passphrase = passphrase.encode() if isinstance(passphrase, str) else passphrase
        self._hsm = hsm
        self._entropy_source = entropy_source

    # -- key lifecycle --------------------------------------------------------

    def generate(
        self, key_ref: str, backend: KeyBackend, algorithm: str = "ecdsa-p256"
    ) -> str:
        self._validate_label(key_ref)
        if backend is not KeyBackend.SOFTWARE:
            return self._require_hsm(backend).generate_key(key_ref, algorithm)
        if self._software_path(key_ref).exists():
            raise ServiceCertError(f"Key already exists: {key_ref}")
        self._write_software_key(key_ref, self._generate_software_key(algorithm))
        return key_ref

    def store_software_key(self, key_ref: str, private_key: CertificateIssuerPrivateKeyTypes) -> None:
        self._validate_label(key_ref)
        if self._software_path(key_ref).exists():
            raise ServiceCertError(f"Key already exists: {key_ref}")
        self._write_software_key(key_ref, private_key)

    def delete(self, key_ref: str, backend: KeyBackend) -> None:
        if backend in {KeyBackend.AWS_KMS, KeyBackend.AZURE_KEY_VAULT}:
            # Removing a certificate only releases its reference. Cloud key
            # deletion is an explicit, audited operation which first checks
            # ownership, remaining consumers, and queued signing jobs.
            return
        if backend is KeyBackend.PKCS11:
            try:
                self._require_hsm(backend).delete_key(key_ref)
            except Exception:  # noqa: BLE001 - best-effort; provider may be offline
                pass
            return
        self._software_path(key_ref).unlink(missing_ok=True)

    def public_key(self, key_ref: str, backend: KeyBackend) -> CertificatePublicKeyTypes:
        if backend is not KeyBackend.SOFTWARE:
            return self._require_hsm(backend).public_key(key_ref)
        return self._load_software_key(key_ref).public_key()

    # -- CSR + verification ---------------------------------------------------

    def build_csr(
        self,
        key_ref: str,
        backend: KeyBackend,
        *,
        common_name: str,
        dns_names: tuple[str, ...] = (),
    ) -> str:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        if dns_names:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
                critical=False,
            )
        if backend is not KeyBackend.SOFTWARE:
            csr = self._require_hsm(backend).sign_csr(builder, key_ref)
        else:
            private_key = self._load_software_key(key_ref)
            csr = builder.sign(private_key, _csr_hash(private_key))
        return csr.public_bytes(serialization.Encoding.PEM).decode()

    def certificate_matches_key(
        self, certificate: x509.Certificate, key_ref: str, backend: KeyBackend
    ) -> bool:
        cert_pub = certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_pub = self.public_key(key_ref, backend).public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return cert_pub == key_pub

    # -- internals ------------------------------------------------------------

    def _generate_software_key(self, algorithm: str) -> CertificateIssuerPrivateKeyTypes:
        try:
            return keygen.generate_private_key(algorithm, entropy_source=self._entropy_source)
        except keygen.KeygenError as exc:
            raise ServiceCertError(str(exc)) from exc

    def _require_hsm(self, backend: KeyBackend):
        if self._hsm is None:
            raise ServiceCertError(f"{backend.value} key backend is not available")
        active_name = getattr(self._hsm, "active_backend_name", None)
        if callable(active_name) and active_name() != backend.value:
            raise ServiceCertError(
                f"Certificate key uses {backend.value}, but the active key backend is "
                f"{active_name()}"
            )
        return self._hsm

    def _software_path(self, key_ref: str) -> Path:
        self._validate_label(key_ref)
        return self._key_dir / f"{key_ref}.pem"

    def _write_software_key(self, key_ref: str, private_key: CertificateIssuerPrivateKeyTypes) -> None:
        encryption = (
            serialization.BestAvailableEncryption(self._passphrase)
            if self._passphrase
            else serialization.NoEncryption()
        )
        atomic_write(
            self._software_path(key_ref),
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                encryption,
            ),
            exclusive=True,
        )

    def _load_software_key(self, key_ref: str) -> CertificateIssuerPrivateKeyTypes:
        path = self._software_path(key_ref)
        if not path.exists():
            raise ServiceCertError(f"Unknown key reference: {key_ref}")
        return serialization.load_pem_private_key(path.read_bytes(), password=self._passphrase)

    def software_key_pem(self, key_ref: str) -> str:
        """Return a software private key as unencrypted PKCS#8 PEM.

        Only valid for software-backed keys (HSM/KMS keys never leave their provider).
        """
        key = self._load_software_key(key_ref)
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    @staticmethod
    def _validate_label(label: str) -> None:
        if not _LABEL_RE.fullmatch(label):
            raise ServiceCertError(f"Unsafe key label: {label}")


def _csr_hash(private_key: CertificateIssuerPrivateKeyTypes):
    return hashes.SHA256()
