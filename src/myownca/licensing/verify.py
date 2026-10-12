"""Strict RSA-4096 PSS/SHA-256 verification for offline licenses."""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timezone
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from myownca.licensing.base import (
    LICENSE_PRODUCT,
    LICENSE_SCHEMA,
    License,
    LicenseError,
)

_MAX_TOKEN_BYTES = 8 * 1024
_MAX_LINEAGES = 10_000_000
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SCHEMA_2_FIELDS = {
    "schema",
    "product",
    "license_id",
    "licensed_to",
    "installation_id",
    "issued_at",
    "valid_from",
    "expires_at",
    "max_certificate_lineages",
    "key_id",
}


def _b64url_decode(segment: str, *, field: str) -> bytes:
    if not segment or not segment.isascii():
        raise LicenseError(f"License {field} is empty or non-ASCII")
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.b64decode(segment + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise LicenseError(f"Malformed base64 in license {field}") from exc


_RSA_LICENSE_KEY_BITS = 4096
_RSA_LICENSE_SIGNATURE_BYTES = _RSA_LICENSE_KEY_BITS // 8


def _public_key(key_id: str, public_keys: dict[str, str]) -> rsa.RSAPublicKey:
    encoded = public_keys.get(key_id)
    if encoded is None:
        raise LicenseError(f"License signed by an unknown key: {key_id!r}")
    try:
        raw = base64.b64decode(encoded, validate=True)
        public_key = serialization.load_der_public_key(raw)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("license public key must be RSA")
        if public_key.key_size != _RSA_LICENSE_KEY_BITS:
            raise ValueError(f"license RSA public key must be {_RSA_LICENSE_KEY_BITS} bits")
        if public_key.public_numbers().e != 65537:
            raise ValueError("license RSA public key must use exponent 65537")
        return public_key
    except (binascii.Error, ValueError) as exc:
        raise LicenseError(f"Configured public key {key_id!r} is unusable") from exc


def _parse_dt(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise LicenseError(f"License field {field!r} must be an ISO-8601 UTC string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LicenseError(f"License field {field!r} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LicenseError(f"License field {field!r} must include a UTC offset")
    if parsed.utcoffset().total_seconds() != 0:
        raise LicenseError(f"License field {field!r} must be expressed in UTC")
    return parsed.astimezone(timezone.utc)


def _non_empty_string(payload: dict[str, object], field: str, *, maximum: int) -> str:
    value = payload[field]
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise LicenseError(f"License field {field!r} must be a non-empty trimmed string")
    return value


def _identifier(payload: dict[str, object], field: str) -> str:
    value = _non_empty_string(payload, field, maximum=128)
    if not _ID_RE.fullmatch(value):
        raise LicenseError(f"License field {field!r} contains unsupported characters")
    return value


def _strict_json_object(raw: bytes) -> dict[str, object]:
    def object_pairs(pairs):
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise LicenseError(f"Duplicate license field: {key!r}")
            result[key] = value
        return result

    try:
        payload = json.loads(raw, object_pairs_hook=object_pairs)
    except LicenseError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise LicenseError("License payload is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise LicenseError("License payload must be a JSON object")
    return payload


def verify_token(
    token: str,
    *,
    public_keys: dict[str, str] | None = None,
) -> License:
    """Verify a token and return its typed payload.

    Validity and installation matching are policy decisions made by
    :class:`LicenseService`; this function verifies signature and exact schema.
    """

    if not isinstance(token, str) or not token or len(token.encode("utf-8")) > _MAX_TOKEN_BYTES:
        raise LicenseError("Empty or oversized license token")
    stripped = token.strip()
    parts = stripped.split(".")
    if len(parts) != 2:
        raise LicenseError("License token must have exactly two segments")
    payload_segment, signature_segment = parts
    payload = _strict_json_object(_b64url_decode(payload_segment, field="payload"))

    schema = payload.get("schema")
    if type(schema) is not int:  # bool is deliberately rejected
        raise LicenseError("License field 'schema' must be an integer")
    if schema != LICENSE_SCHEMA:
        raise LicenseError(f"Unsupported license schema: {schema!r}")
    expected_fields = _SCHEMA_2_FIELDS
    missing = expected_fields - payload.keys()
    unknown = payload.keys() - expected_fields
    if missing:
        raise LicenseError(f"License payload is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise LicenseError(f"License payload has unknown fields: {', '.join(sorted(unknown))}")

    key_id = _identifier(payload, "key_id")
    signature = _b64url_decode(signature_segment, field="signature")
    if len(signature) != _RSA_LICENSE_SIGNATURE_BYTES:
        raise LicenseError(
            f"License signature must contain {_RSA_LICENSE_SIGNATURE_BYTES} bytes"
        )
    # The application supplies the producer key ring from the signed release.
    # Explicit key injection remains available to standalone callers and tests.
    keys = {} if public_keys is None else public_keys
    public_key = _public_key(key_id, keys)
    try:
        public_key.verify(
            signature,
            payload_segment.encode("ascii"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise LicenseError("License signature does not verify") from exc
    except (UnicodeEncodeError, ValueError) as exc:
        raise LicenseError("License signature is malformed") from exc

    license_id = _identifier(payload, "license_id")
    licensed_to = _non_empty_string(payload, "licensed_to", maximum=256)
    issued_at = _parse_dt(payload["issued_at"], "issued_at")
    valid_from = _parse_dt(payload["valid_from"], "valid_from")
    expires_at = _parse_dt(payload["expires_at"], "expires_at")
    if issued_at > valid_from:
        raise LicenseError("License issued_at must not be after valid_from")
    if expires_at <= valid_from:
        raise LicenseError("License expires_at must be after valid_from")

    limit_field = "max_certificate_lineages"
    maximum = payload[limit_field]
    if type(maximum) is not int or not 1 <= maximum <= _MAX_LINEAGES:
        raise LicenseError(
            f"License field {limit_field!r} must be an integer between 1 and {_MAX_LINEAGES}"
        )

    product = _non_empty_string(payload, "product", maximum=64)
    if product != LICENSE_PRODUCT:
        raise LicenseError(f"License is for a different product: {product!r}")
    installation_id = _non_empty_string(payload, "installation_id", maximum=36)
    try:
        if str(UUID(installation_id)) != installation_id:
            raise ValueError("installation id is not canonical")
    except ValueError as exc:
        raise LicenseError("License installation_id must be a canonical UUID") from exc

    return License(
        license_id=license_id,
        licensed_to=licensed_to,
        installation_id=installation_id,
        issued_at=issued_at,
        valid_from=valid_from,
        expires_at=expires_at,
        max_certificate_lineages=maximum,
        key_id=key_id,
        product=product,
        schema=schema,
    )
