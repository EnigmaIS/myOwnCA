from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from enum import StrEnum

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

_DER = serialization.Encoding.DER


class SigningPurpose(StrEnum):
    X509 = "x509"
    DATA = "data"


class CloudBackendError(RuntimeError):
    """Base error carrying the retry decision needed by the signing queue."""

    def __init__(
        self,
        provider: str,
        operation: str,
        *,
        code: str | None = None,
        retryable: bool = False,
        detail: str | None = None,
    ) -> None:
        self.provider = provider
        self.operation = operation
        self.code = code
        self.retryable = retryable
        self.detail = detail
        suffix = f" ({code})" if code else ""
        if detail:
            suffix = f"{suffix}: {detail}"
        super().__init__(f"{provider} {operation} failed{suffix}")


class CloudBackendUnavailable(CloudBackendError):
    """Raised when an optional provider SDK or its required configuration is absent."""


class CloudKeyValidationError(CloudBackendError):
    """Raised when a remote key cannot safely be used for signing."""


class NonExportablePrivateKeyError(CloudBackendError):
    """Raised when code attempts to export private material from a remote KMS."""


class RemoteSigningBackend(ABC):
    """HSM-compatible implementation for providers exposing a remote sign API."""

    provider_name: str

    def private_key(self, key_ref: str) -> CertificateIssuerPrivateKeyTypes:
        raise NonExportablePrivateKeyError(
            self.provider_name,
            "private_key",
            code="NON_EXPORTABLE",
            detail="private keys never leave the cloud key service",
        )

    def public_key_pem(self, key_ref: str) -> str:
        return (
            self.public_key(key_ref)
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

    def canonicalize_key_ref(self, key_ref: str) -> str:
        """Pin aliases/latest-version references before fetching and signing."""

        return key_ref

    @abstractmethod
    def public_key(self, key_ref: str) -> CertificatePublicKeyTypes:
        raise NotImplementedError

    @abstractmethod
    def _sign_remote(
        self,
        payload: bytes,
        key_ref: str,
        public_key: CertificatePublicKeyTypes,
        hash_algorithm: hashes.HashAlgorithm,
        purpose: SigningPurpose,
    ) -> bytes:
        raise NotImplementedError

    def sign_certificate(
        self, builder: x509.CertificateBuilder, key_ref: str
    ) -> x509.Certificate:
        key_ref = self.canonicalize_key_ref(key_ref)
        public_key = self.public_key(key_ref)
        return sign_certificate_with_remote_key(
            builder,
            public_key,
            lambda payload, algorithm: self._normalized_signature(
                payload, key_ref, public_key, algorithm, SigningPurpose.X509
            ),
        )

    def sign_crl(
        self, builder: x509.CertificateRevocationListBuilder, key_ref: str
    ) -> x509.CertificateRevocationList:
        key_ref = self.canonicalize_key_ref(key_ref)
        public_key = self.public_key(key_ref)
        return sign_crl_with_remote_key(
            builder,
            public_key,
            lambda payload, algorithm: self._normalized_signature(
                payload, key_ref, public_key, algorithm, SigningPurpose.X509
            ),
        )

    def sign_csr(
        self, builder: x509.CertificateSigningRequestBuilder, key_ref: str
    ) -> x509.CertificateSigningRequest:
        key_ref = self.canonicalize_key_ref(key_ref)
        public_key = self.public_key(key_ref)
        return sign_csr_with_remote_key(
            builder,
            public_key,
            lambda payload, algorithm: self._normalized_signature(
                payload, key_ref, public_key, algorithm, SigningPurpose.X509
            ),
        )

    def sign_data(self, payload: bytes, key_ref: str) -> bytes:
        key_ref = self.canonicalize_key_ref(key_ref)
        public_key = self.public_key(key_ref)
        if isinstance(public_key, ec.EllipticCurvePublicKey) and public_key.key_size > 256:
            raise CloudKeyValidationError(
                self.provider_name,
                "sign generic data",
                code="UNSUPPORTED_DATA_SIGNATURE",
                detail=(
                    "cloud P-384/P-521 keys cannot satisfy the "
                    "ECDSA/SHA-256 generic data-signing contract"
                ),
            )
        # Recovery metadata uses one stable cross-backend SHA-256 contract.
        algorithm = hashes.SHA256()
        return self._normalized_signature(
            payload, key_ref, public_key, algorithm, SigningPurpose.DATA
        )

    def _normalized_signature(
        self,
        payload: bytes,
        key_ref: str,
        public_key: CertificatePublicKeyTypes,
        hash_algorithm: hashes.HashAlgorithm,
        purpose: SigningPurpose,
    ) -> bytes:
        signature = self._sign_remote(
            payload,
            key_ref,
            public_key,
            hash_algorithm,
            purpose,
        )
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return normalize_ecdsa_signature(signature, public_key)
        return signature


RemoteSigner = Callable[[bytes, hashes.HashAlgorithm], bytes]


def signature_hash_for(public_key: CertificatePublicKeyTypes) -> hashes.HashAlgorithm:
    """Select the X.509/JWA hash associated with a supported signing key."""

    if isinstance(public_key, rsa.RSAPublicKey):
        return hashes.SHA256()
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.key_size <= 256:
            return hashes.SHA256()
        if public_key.key_size <= 384:
            return hashes.SHA384()
        if public_key.key_size <= 521:
            return hashes.SHA512()
    raise CloudKeyValidationError(
        "cloud KMS",
        "select signing algorithm",
        code="UNSUPPORTED_KEY_TYPE",
    )


def algorithm_name_for(public_key: CertificatePublicKeyTypes) -> str:
    if isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size in {2048, 3072, 4096}:
        return f"rsa-{public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        names = {256: "ecdsa-p256", 384: "ecdsa-p384", 521: "ecdsa-p521"}
        if public_key.key_size in names:
            return names[public_key.key_size]
    raise CloudKeyValidationError(
        "cloud KMS",
        "validate key",
        code="UNSUPPORTED_KEY_TYPE",
    )


def hash_payload(payload: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
    digest = hashes.Hash(algorithm)
    digest.update(payload)
    return digest.finalize()


def _assert_signature_verifies(
    public_key: CertificatePublicKeyTypes,
    payload: bytes,
    signature: bytes,
    algorithm: hashes.HashAlgorithm,
) -> None:
    """Refuse to hand back anything the signing key did not actually sign.

    The provider's answer is spliced into the DER verbatim, and nothing
    downstream re-checks it, so an unverified splice would let a misconfigured
    alias, a silently rotated key or a truncated response yield a CA-issued
    certificate that no relying party can validate — discovered only once it has
    been distributed. Verifying here turns that into a failed issuance.
    """
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, payload, ec.ECDSA(algorithm))
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, payload, padding.PKCS1v15(), algorithm)
        else:
            raise CloudKeyValidationError(
                "cloud KMS", "verify signature", code="UNSUPPORTED_KEY_TYPE"
            )
    except CloudKeyValidationError:
        raise
    except Exception as exc:
        raise CloudKeyValidationError(
            "cloud KMS", "verify signature", code="SIGNATURE_VERIFICATION_FAILED"
        ) from exc


def sign_certificate_with_remote_key(
    builder: x509.CertificateBuilder,
    public_key: CertificatePublicKeyTypes,
    signer: RemoteSigner,
) -> x509.Certificate:
    algorithm = signature_hash_for(public_key)
    template = builder.sign(_dummy_key(public_key), algorithm)
    tbs = template.tbs_certificate_bytes
    signature = signer(tbs, algorithm)
    _assert_signature_verifies(public_key, tbs, signature, algorithm)
    return x509.load_der_x509_certificate(
        _splice_signature(template.public_bytes(_DER), signature)
    )


def sign_crl_with_remote_key(
    builder: x509.CertificateRevocationListBuilder,
    public_key: CertificatePublicKeyTypes,
    signer: RemoteSigner,
) -> x509.CertificateRevocationList:
    algorithm = signature_hash_for(public_key)
    template = builder.sign(_dummy_key(public_key), algorithm)
    tbs = template.tbs_certlist_bytes
    signature = signer(tbs, algorithm)
    _assert_signature_verifies(public_key, tbs, signature, algorithm)
    return x509.load_der_x509_crl(_splice_signature(template.public_bytes(_DER), signature))


def sign_csr_with_remote_key(
    builder: x509.CertificateSigningRequestBuilder,
    public_key: CertificatePublicKeyTypes,
    signer: RemoteSigner,
) -> x509.CertificateSigningRequest:
    algorithm = signature_hash_for(public_key)
    template = builder.sign(_dummy_key(public_key), algorithm)
    tbs = _csr_tbs_with_public_key(
        template.tbs_certrequest_bytes,
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    signature = signer(tbs, algorithm)
    _assert_signature_verifies(public_key, tbs, signature, algorithm)
    return x509.load_der_x509_csr(
        _splice_tbs_and_signature(template.public_bytes(_DER), tbs, signature)
    )


def normalize_ecdsa_signature(
    signature: bytes, public_key: ec.EllipticCurvePublicKey
) -> bytes:
    """Accept either ASN.1 DER or fixed-width ``r || s`` and always return DER."""

    try:
        r, s = decode_dss_signature(signature)
    except ValueError:
        width = (public_key.curve.key_size + 7) // 8
        if len(signature) != width * 2:
            raise CloudKeyValidationError(
                "cloud KMS",
                "normalize ECDSA signature",
                code="MALFORMED_SIGNATURE",
            ) from None
        r = int.from_bytes(signature[:width], "big")
        s = int.from_bytes(signature[width:], "big")
    if r <= 0 or s <= 0:
        raise CloudKeyValidationError(
            "cloud KMS",
            "normalize ECDSA signature",
            code="MALFORMED_SIGNATURE",
        )
    return encode_dss_signature(r, s)


def _dummy_key(public_key: CertificatePublicKeyTypes) -> CertificateIssuerPrivateKeyTypes:
    if isinstance(public_key, rsa.RSAPublicKey):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return ec.generate_private_key(public_key.curve)
    raise CloudKeyValidationError(
        "cloud KMS",
        "create X.509 signing template",
        code="UNSUPPORTED_KEY_TYPE",
    )


def _splice_signature(der: bytes, signature: bytes) -> bytes:
    tag, content, end = _read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise _malformed_der("expected one outer SEQUENCE")
    info, offset = _read_element(content, 0)
    signature_algorithm, offset = _read_element(content, offset)
    _, final_offset = _read_element(content, offset)
    if final_offset != len(content):
        raise _malformed_der("unexpected data after signature")
    signature_bit_string = _encode_tlv(0x03, b"\x00" + signature)
    return _encode_tlv(0x30, info + signature_algorithm + signature_bit_string)


def _splice_tbs_and_signature(der: bytes, tbs: bytes, signature: bytes) -> bytes:
    tag, content, end = _read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise _malformed_der("expected one outer SEQUENCE")
    _, offset = _read_element(content, 0)
    signature_algorithm, offset = _read_element(content, offset)
    _, final_offset = _read_element(content, offset)
    if final_offset != len(content):
        raise _malformed_der("unexpected data after signature")
    signature_bit_string = _encode_tlv(0x03, b"\x00" + signature)
    return _encode_tlv(0x30, tbs + signature_algorithm + signature_bit_string)


def _csr_tbs_with_public_key(tbs: bytes, public_key_der: bytes) -> bytes:
    tag, content, end = _read_tlv(tbs, 0)
    if tag != 0x30 or end != len(tbs):
        raise _malformed_der("expected CSR info SEQUENCE")
    version, offset = _read_element(content, 0)
    subject, offset = _read_element(content, offset)
    _, offset = _read_element(content, offset)
    return _encode_tlv(0x30, version + subject + public_key_der + content[offset:])


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise _malformed_der("missing length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(data):
        raise _malformed_der("invalid length")
    if data[offset] == 0:
        raise _malformed_der("non-minimal length")
    length = int.from_bytes(data[offset : offset + count], "big")
    if length < 0x80:
        raise _malformed_der("non-minimal length")
    return length, offset + count


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise _malformed_der("missing tag")
    tag = data[offset]
    length, body_offset = _read_length(data, offset + 1)
    end = body_offset + length
    if end > len(data):
        raise _malformed_der("truncated element")
    return tag, data[body_offset:end], end


def _read_element(data: bytes, offset: int) -> tuple[bytes, int]:
    _, _, end = _read_tlv(data, offset)
    return data[offset:end], end


def _encode_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("DER length cannot be negative")
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _encode_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(content)) + content


def _malformed_der(detail: str) -> CloudKeyValidationError:
    return CloudKeyValidationError(
        "cloud KMS",
        "assemble signed object",
        code="MALFORMED_DER",
        detail=detail,
    )
