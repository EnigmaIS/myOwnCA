"""Encrypted at-rest vault for server-generated end-entity private keys.

These are the only subject private keys the CA ever holds, and only because
the user opted into "generate a key for me" instead of submitting a CSR. Keys
are Fernet-encrypted with a context-separated derivation of the auth
encryption secret, surface solely through key-bearing exports, and are purged
on request rejection or by an explicit (audited) action.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.x509.oid import NameOID


class ServerKeyError(ValueError):
    """A vaulted key is missing or cannot be decrypted."""


class RequestKeyVault:
    def __init__(self, repository, encryption_secret: str) -> None:
        self.repository = repository
        digest = hashlib.sha256(f"server-keys:{encryption_secret}".encode()).digest()
        self.cipher = Fernet(base64.urlsafe_b64encode(digest))

    def store(
        self,
        request_id: str,
        private_key: CertificateIssuerPrivateKeyTypes,
        algorithm: str,
        now: datetime | None = None,
    ) -> None:
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        self.repository.add_request_private_key(
            request_id,
            key_pem_encrypted=self.cipher.encrypt(pem.encode()).decode(),
            algorithm=algorithm,
            created_at=now or datetime.now(timezone.utc),
        )

    def load_pem(self, request_id: str) -> str | None:
        row = self.repository.get_request_private_key(request_id)
        if row is None:
            return None
        try:
            return self.cipher.decrypt(row["key_pem_encrypted"].encode()).decode()
        except InvalidToken as exc:
            raise ServerKeyError(
                "Vaulted key cannot be decrypted (was the encryption secret changed?)"
            ) from exc

    def held(self, request_id: str) -> bool:
        return self.repository.has_request_private_key(request_id)

    def purge(self, request_id: str) -> bool:
        return self.repository.delete_request_private_key(request_id)

    def copy(self, source_request_id: str, target_request_id: str) -> bool:
        """Re-reference a key under a renewal request (same ciphertext)."""
        row = self.repository.get_request_private_key(source_request_id)
        if row is None:
            return False
        self.repository.add_request_private_key(
            target_request_id,
            key_pem_encrypted=row["key_pem_encrypted"],
            algorithm=row["algorithm"],
            created_at=datetime.now(timezone.utc),
        )
        return True


def build_csr_for_key(
    private_key: CertificateIssuerPrivateKeyTypes,
    *,
    common_name: str,
    dns_names: tuple[str, ...] = (),
    email_addresses: tuple[str, ...] = (),
) -> str:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    general_names: list[x509.GeneralName] = [x509.DNSName(name) for name in dns_names]
    general_names.extend(x509.RFC822Name(address) for address in email_addresses)
    if general_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(general_names),
            critical=False,
        )
    return builder.sign(private_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
