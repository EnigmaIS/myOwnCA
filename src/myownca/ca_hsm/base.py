from __future__ import annotations

import datetime
import hashlib
import hmac
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from myownca_core.keygen import KeygenError, certificate_algorithm_for_public_key


class KeyImportError(RuntimeError):
    """A key cannot be imported or proven to match its certificate."""


class KeyMismatchError(KeyImportError):
    """The supplied key and certificate contain different public keys."""


@dataclass(frozen=True, slots=True)
class KeyVerification:
    """Result of a public-key comparison followed by a live signing proof."""

    key_ref: str
    algorithm: str
    public_key_sha256: str
    certificate_sha256: str
    signing_verified: bool = True


class SigningKeyBackend(Protocol):
    """Common signing boundary for local and non-exportable remote keys."""

    def generate_key(self, label: str, algorithm: str = "rsa-2048") -> str: ...

    def public_key(self, key_ref: str) -> CertificatePublicKeyTypes: ...

    def sign_certificate(
        self, builder: x509.CertificateBuilder, key_ref: str
    ) -> x509.Certificate: ...

    def sign_crl(
        self, builder: x509.CertificateRevocationListBuilder, key_ref: str
    ) -> x509.CertificateRevocationList: ...

    def sign_csr(
        self, builder: x509.CertificateSigningRequestBuilder, key_ref: str
    ) -> x509.CertificateSigningRequest: ...

    def sign_data(self, payload: bytes, key_ref: str) -> bytes: ...


class HSMBackend(SigningKeyBackend, Protocol):
    """Legacy backend contract for callers which can request a private key.

    New code should prefer :class:`SigningKeyBackend`. Remote KMS backends never
    return private key material, while the existing software backend still can.
    """

    def private_key(self, key_ref: str) -> CertificateIssuerPrivateKeyTypes: ...


@runtime_checkable
class ImportableKeyBackend(SigningKeyBackend, Protocol):
    """Optional capability implemented only by backends accepting raw keys.

    Cloud KMS implementations intentionally do not implement this protocol;
    callers must attach their already-imported provider key instead.
    """

    def import_key(
        self,
        label: str,
        private_key: CertificateIssuerPrivateKeyTypes,
        certificate: x509.Certificate | None = None,
    ) -> str: ...

    def verify_key(self, key_ref: str, certificate: x509.Certificate) -> KeyVerification: ...


def imported_key_algorithm(
    key: CertificateIssuerPrivateKeyTypes | CertificatePublicKeyTypes,
) -> str:
    """Return the supported myOwnCA algorithm name or reject weak/unknown keys."""

    public_key = key.public_key() if hasattr(key, "public_key") else key
    try:
        algorithm = certificate_algorithm_for_public_key(public_key)
    except KeygenError as exc:
        raise KeyImportError(str(exc)) from exc
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.public_numbers().e != 65537:
            raise KeyImportError("Imported RSA keys must use public exponent 65537")
    return algorithm


def public_key_fingerprint(public_key: CertificatePublicKeyTypes) -> str:
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def public_keys_match(
    first: CertificatePublicKeyTypes,
    second: CertificatePublicKeyTypes,
) -> bool:
    """Compare canonical SubjectPublicKeyInfo encodings in constant time."""

    first_der = first.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    second_der = second.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hmac.compare_digest(first_der, second_der)


def validate_imported_key(
    private_key: CertificateIssuerPrivateKeyTypes,
    certificate: x509.Certificate | None = None,
) -> str:
    """Validate import policy, certificate matching, and local key ownership."""

    algorithm = imported_key_algorithm(private_key)
    public_key = private_key.public_key()
    if certificate is not None and not public_keys_match(public_key, certificate.public_key()):
        raise KeyMismatchError("Private key does not match the supplied certificate")

    challenge = b"myOwnCA imported-key proof v1\x00" + hashlib.sha256(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).digest()
    try:
        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(challenge, padding.PKCS1v15(), hashes.SHA256())
            public_key.verify(signature, challenge, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))
            public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
        else:  # pragma: no cover - imported_key_algorithm rejects this first
            raise KeyImportError("Only RSA and EC private keys can be imported")
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise KeyImportError("Imported private key failed its signing proof") from exc
    return algorithm


def verify_backend_key(
    backend: SigningKeyBackend,
    key_ref: str,
    certificate: x509.Certificate,
) -> KeyVerification:
    """Prove an existing backend key matches ``certificate`` and can sign.

    A short-lived in-memory certificate is signed instead of using ``sign_data``
    so the check works for every supported local and cloud signing backend,
    including P-384/P-521 cloud keys whose legacy generic-data contract is
    deliberately unavailable.
    """

    public_key = backend.public_key(key_ref)
    algorithm = imported_key_algorithm(public_key)
    if not public_keys_match(public_key, certificate.public_key()):
        raise KeyMismatchError("HSM key does not match the supplied certificate")

    now = datetime.datetime.now(datetime.timezone.utc)
    proof_name = x509.Name(
        [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "myOwnCA key verification")]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(proof_name)
        .issuer_name(proof_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(minutes=5))
    )
    try:
        proof = backend.sign_certificate(builder, key_ref)
        hash_algorithm = proof.signature_hash_algorithm
        if hash_algorithm is None:
            raise KeyImportError("Backend produced a signature without a supported hash")
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                proof.signature,
                proof.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                proof.signature,
                proof.tbs_certificate_bytes,
                ec.ECDSA(hash_algorithm),
            )
        else:  # pragma: no cover - imported_key_algorithm rejects this first
            raise KeyImportError("Backend returned an unsupported public key")
    except KeyImportError:
        raise
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise KeyImportError("HSM key failed its signing proof") from exc

    return KeyVerification(
        key_ref=key_ref,
        algorithm=algorithm,
        public_key_sha256=public_key_fingerprint(public_key),
        certificate_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
    )
