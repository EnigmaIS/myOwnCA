from __future__ import annotations

from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from myownca.ca_hsm.base import HSMBackend


@dataclass(frozen=True, slots=True)
class HSMProxy:
    """Immutable named facade for the backend selected during setup/startup."""

    _backend: HSMBackend
    _name: str

    @property
    def backend(self) -> HSMBackend:
        return self._backend

    def active_backend_name(self) -> str:
        return self._name

    def generate_key(self, label: str, algorithm: str = "rsa-2048") -> str:
        return self.backend.generate_key(label, algorithm)

    def public_key(self, key_ref: str) -> CertificatePublicKeyTypes:
        return self.backend.public_key(key_ref)

    def private_key(self, key_ref: str) -> CertificateIssuerPrivateKeyTypes:
        return self.backend.private_key(key_ref)

    def sign_certificate(self, builder: x509.CertificateBuilder, key_ref: str) -> x509.Certificate:
        return self.backend.sign_certificate(builder, key_ref)

    def sign_crl(
        self, builder: x509.CertificateRevocationListBuilder, key_ref: str
    ) -> x509.CertificateRevocationList:
        return self.backend.sign_crl(builder, key_ref)

    def sign_csr(
        self, builder: x509.CertificateSigningRequestBuilder, key_ref: str
    ) -> x509.CertificateSigningRequest:
        return self.backend.sign_csr(builder, key_ref)

    def sign_data(self, payload: bytes, key_ref: str) -> bytes:
        return self.backend.sign_data(payload, key_ref)

    def __getattr__(self, name: str):
        # Delegate non-Protocol helpers (e.g. SoftwareHSM.public_key_pem) to the
        # active backend. __getattr__ only fires for attributes not defined above.
        return getattr(self.backend, name)
