"""Producer licensing trust packaged inside the signed application inventory."""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from myownca_release.verify import VerificationError, parse_json, read_metadata

LICENSE_KEYS = "myownca_release/license-public-keys.json"
LEGACY_SETTING = "MYOWNCA_LICENSE_PUBLIC_KEYS"
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def reject_license_override(mapping: Mapping) -> None:
    if LEGACY_SETTING in mapping:
        raise VerificationError(
            "MYOWNCA_LICENSE_PUBLIC_KEYS is no longer supported. Remove it from the "
            "process environment, config.toml, and secrets.env; licensing keys belong "
            "to the signed release."
        )


def validate_license_keys(value: dict) -> dict[str, str]:
    if (set(value) != {"schema", "keys"} or type(value["schema"]) is not int
            or value["schema"] != 1 or not isinstance(value["keys"], dict)
            or not 1 <= len(value["keys"]) <= 32):
        raise VerificationError("Invalid or empty embedded licensing key ring")
    result = {}
    for key_id, encoded in value["keys"].items():
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise VerificationError("Invalid licensing key identifier")
        try:
            if not isinstance(encoded, str):
                raise ValueError("Expected a string")
            raw = base64.b64decode(encoded, validate=True)
            key = serialization.load_der_public_key(raw)
            if (not isinstance(key, rsa.RSAPublicKey) or key.key_size != 4096
                    or key.public_numbers().e != 65537):
                raise ValueError("Expected RSA-4096")
            if key.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo) != raw:
                raise ValueError("Expected canonical DER/SPKI")
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise VerificationError("Licensing keys must be RSA-4096 Base64 DER/SPKI") from exc
        result[key_id] = encoded
    return result


def read_license_keys(path: Path) -> dict[str, str]:
    return validate_license_keys(parse_json(read_metadata(path)))
