from __future__ import annotations

import base64
import hashlib
import unittest

from cryptography.fernet import Fernet, InvalidToken

from myownca.secret_keys import (
    CA_AUTH_DOMAIN,
    COMMS_DOMAIN,
    SERVICE_CERTS_DOMAIN,
    derive_fernet_key,
    domain_cipher,
    legacy_fernet_key,
)

SECRET = "an-operator-encryption-secret"
DOMAINS = (CA_AUTH_DOMAIN, COMMS_DOMAIN, SERVICE_CERTS_DOMAIN)


class DomainKeyTests(unittest.TestCase):
    def test_domains_are_pairwise_distinct(self) -> None:
        keys = [derive_fernet_key(SECRET, d) for d in DOMAINS]
        self.assertEqual(len(set(keys)), len(keys))

    def test_domain_key_differs_from_legacy(self) -> None:
        legacy = legacy_fernet_key(SECRET)
        for domain in DOMAINS:
            self.assertNotEqual(derive_fernet_key(SECRET, domain), legacy)

    def test_derivation_matches_the_documented_formula(self) -> None:
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(f"{COMMS_DOMAIN}:{SECRET}".encode()).digest()
        )
        self.assertEqual(derive_fernet_key(SECRET, COMMS_DOMAIN), expected)

    def test_legacy_matches_the_pre_f1_formula(self) -> None:
        expected = base64.urlsafe_b64encode(hashlib.sha256(SECRET.encode()).digest())
        self.assertEqual(legacy_fernet_key(SECRET), expected)

    def test_keys_are_valid_fernet_shape(self) -> None:
        for key in [legacy_fernet_key(SECRET)] + [
            derive_fernet_key(SECRET, d) for d in DOMAINS
        ]:
            self.assertEqual(len(base64.urlsafe_b64decode(key)), 32)

    def test_reserved_domains_are_not_reused(self) -> None:
        """server-keys / audit / recovery are live elsewhere; never collide."""
        for taken in ("server-keys", "audit", "recovery"):
            self.assertNotIn(taken, DOMAINS)


class DomainCipherFallbackTests(unittest.TestCase):
    def test_reads_legacy_ciphertext(self) -> None:
        legacy = Fernet(legacy_fernet_key(SECRET))
        token = legacy.encrypt(b"pre-existing secret")
        cipher = domain_cipher(SECRET, COMMS_DOMAIN)
        self.assertEqual(cipher.decrypt(token), b"pre-existing secret")

    def test_writes_with_the_domain_key(self) -> None:
        cipher = domain_cipher(SECRET, COMMS_DOMAIN)
        token = cipher.encrypt(b"new secret")
        # The domain key alone can read it...
        self.assertEqual(Fernet(derive_fernet_key(SECRET, COMMS_DOMAIN)).decrypt(token), b"new secret")
        # ...and the legacy key alone cannot.
        with self.assertRaises(InvalidToken):
            Fernet(legacy_fernet_key(SECRET)).decrypt(token)

    def test_new_ciphertext_is_not_cross_domain_readable(self) -> None:
        """The point of F-1: a comms token must not open under service-certs."""
        comms_token = domain_cipher(SECRET, COMMS_DOMAIN).encrypt(b"smtp-password")
        other = Fernet(derive_fernet_key(SECRET, SERVICE_CERTS_DOMAIN))
        with self.assertRaises(InvalidToken):
            other.decrypt(comms_token)

    def test_wrong_secret_still_fails_closed(self) -> None:
        token = domain_cipher(SECRET, COMMS_DOMAIN).encrypt(b"x")
        with self.assertRaises(InvalidToken):
            domain_cipher("a-different-secret", COMMS_DOMAIN).decrypt(token)

    def test_rotate_converts_legacy_to_domain(self) -> None:
        legacy = Fernet(legacy_fernet_key(SECRET))
        token = legacy.encrypt(b"convert me")
        cipher = domain_cipher(SECRET, CA_AUTH_DOMAIN)
        rotated = cipher.rotate(token)
        self.assertEqual(
            Fernet(derive_fernet_key(SECRET, CA_AUTH_DOMAIN)).decrypt(rotated), b"convert me"
        )
        with self.assertRaises(InvalidToken):
            legacy.decrypt(rotated)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
