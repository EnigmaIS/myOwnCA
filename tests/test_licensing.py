import base64
import json
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from myownca.licensing import LicenseError, LicenseStatus, verify_token

NOW = datetime(2026, 6, 13, 12, 0, tzinfo=timezone.utc)
INSTALLATION_ID = "11111111-1111-4111-8111-111111111111"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign(private_key: rsa.RSAPrivateKey, payload: dict) -> str:
    segment = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signature = private_key.sign(
        segment.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )
    return f"{segment}.{_b64url(signature)}"


def _payload(**overrides) -> dict:
    base = {
        "schema": 2,
        "product": "myownca-self-hosted",
        "license_id": "BB-2026-000123",
        "licensed_to": "Acme Corp",
        "installation_id": INSTALLATION_ID,
        "issued_at": NOW.isoformat(),
        "valid_from": NOW.isoformat(),
        "expires_at": (NOW + timedelta(days=365)).isoformat(),
        "max_certificate_lineages": 100,
        "key_id": "test",
    }
    base.update(overrides)
    return base


class LicenseVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        public_b64 = base64.b64encode(
            cls.key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()
        cls.public_keys = {"test": public_b64}

    def test_round_trip(self) -> None:
        license = verify_token(_sign(self.key, _payload()), public_keys=self.public_keys)
        self.assertEqual(license.licensed_to, "Acme Corp")
        self.assertEqual(license.max_certificate_lineages, 100)
        self.assertEqual(license.key_id, "test")
        self.assertIs(license.status(NOW), LicenseStatus.VALID)
        self.assertTrue(license.is_active(NOW))
        self.assertEqual(license.days_remaining(NOW), 365)

    def test_window_edges(self) -> None:
        license = verify_token(_sign(self.key, _payload()), public_keys=self.public_keys)
        self.assertIs(license.status(NOW - timedelta(days=1)), LicenseStatus.NOT_YET_VALID)
        self.assertIs(license.status(NOW + timedelta(days=365)), LicenseStatus.EXPIRED)
        self.assertIs(license.status(NOW + timedelta(days=395)), LicenseStatus.EXPIRED)
        self.assertFalse(license.is_active(NOW + timedelta(days=400)))
        self.assertEqual(license.days_remaining(NOW + timedelta(days=400)), 0)

    def test_tampered_payload_rejected(self) -> None:
        token = _sign(self.key, _payload(max_certificate_lineages=100))
        segment, signature = token.split(".")
        forged_payload = json.loads(base64.urlsafe_b64decode(segment + "=="))
        forged_payload["max_certificate_lineages"] = 100000
        forged_segment = _b64url(json.dumps(forged_payload, separators=(",", ":")).encode())
        with self.assertRaises(LicenseError):
            verify_token(f"{forged_segment}.{signature}", public_keys=self.public_keys)

    def test_tampered_signature_rejected(self) -> None:
        token = _sign(self.key, _payload())
        segment, signature = token.split(".")
        altered = bytearray(base64.urlsafe_b64decode(signature + "=="))
        altered[-1] ^= 1
        with self.assertRaises(LicenseError) as ctx:
            verify_token(f"{segment}.{_b64url(bytes(altered))}", public_keys=self.public_keys)
        self.assertIn("signature", str(ctx.exception))

    def test_unknown_key_id_rejected(self) -> None:
        with self.assertRaises(LicenseError) as ctx:
            verify_token(
                _sign(self.key, _payload(key_id="nope")),
                public_keys=self.public_keys,
            )
        self.assertIn("unknown key", str(ctx.exception).lower())

    def test_malformed_tokens(self) -> None:
        for bad in ("", "onlyonesegment", "a.b.c", "!!!.@@@", "."):
            with self.assertRaises(LicenseError):
                verify_token(bad)

    def test_non_object_payload_rejected(self) -> None:
        segment = _b64url(json.dumps([1, 2, 3]).encode())
        token = _sign(self.key, json.loads(base64.urlsafe_b64decode(segment + "==")))
        with self.assertRaises(LicenseError):
            verify_token(token)

    def test_bad_fields_rejected(self) -> None:
        for override in (
            {"max_certificate_lineages": "lots"},
            {"max_certificate_lineages": -1},
            {"licensed_to": ""},
            {"license_id": 123},
            {"expires_at": "not-a-date"},
            {"valid_from": (NOW + timedelta(days=400)).isoformat()},  # after expiry
        ):
            with self.assertRaises(LicenseError):
                verify_token(
                    _sign(self.key, _payload(**override)),
                    public_keys=self.public_keys,
                )

    def test_key_ring_accepts_an_additional_key_id(self) -> None:
        # Key-ring parsing and key-id routing are independent from key-rotation
        # ceremony; reuse the test key to keep tests bounded.
        public_keys = {**self.public_keys, "v2": self.public_keys["test"]}
        license = verify_token(
            _sign(self.key, _payload(key_id="v2")), public_keys=public_keys
        )
        self.assertEqual(license.key_id, "v2")

if __name__ == "__main__":
    unittest.main()
