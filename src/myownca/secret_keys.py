"""Domain-separated Fernet keys for secrets held at rest.

Every subsystem that stores ciphertext derives its key from the single operator
secret (``MYOWNCA_AUTH_ENCRYPTION_SECRET``). Before finding F-1, three of them
derived the *same* key — ``sha256(secret)`` with no context — so a read primitive
against one subsystem's ciphertext also opened the other two. Each subsystem now
mixes a domain label into the derivation, matching the pattern
``ca_main/server_keys.py`` already used.

Reading stays backwards compatible: a service cipher is a ``MultiFernet`` whose
primary key is the domain key and whose fallback is the pre-F-1 key, so

  * everything written from now on is domain-separated, and
  * every row written before the upgrade still decrypts — including a database
    restored from a backup taken at any point either side of the migration.

The fallback is deliberately temporary. While it exists the *write* domains are
separated but a cross-domain *read* still succeeds, so F-1 is only partially
closed; ``docs/security/2026-08-04-f1-fernet-domain-separation-design.md`` records
the criteria for removing it.

The operator secret itself is never changed by any of this. It also derives the
audit-chain and recovery-code HMAC peppers, which are one-way and cannot be
re-encrypted — see ``tests/security/test_b7_pepper_vectors.py``.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken, MultiFernet


class SecretDecryptionError(ValueError):
    """A stored secret could not be decrypted with the configured operator secret.

    Deliberately a ``ValueError``: ``InvalidToken`` is not, so an unhandled one is
    classed as an upstream failure by the ACME route (HTTP 502, which sends the
    operator chasing Let's Encrypt) and as a bare 500 on the login path. This
    surfaces the real cause — nearly always a changed or mismatched
    ``MYOWNCA_AUTH_ENCRYPTION_SECRET``.
    """


def decrypt_secret(cipher: MultiFernet, ciphertext: str, *, what: str) -> str:
    """Decrypt with a clear error instead of a bare ``InvalidToken``."""
    try:
        return cipher.decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise SecretDecryptionError(
            f"{what} could not be decrypted. This usually means "
            "MYOWNCA_AUTH_ENCRYPTION_SECRET differs from the value used when it "
            "was stored."
        ) from exc

#: Domain labels. Permanent: changing one strands every row it wrote.
#: ``server-keys``, ``audit`` and ``recovery`` are already in use elsewhere and
#: must never be reused here.
CA_AUTH_DOMAIN = "ca-auth"
COMMS_DOMAIN = "comms"
SERVICE_CERTS_DOMAIN = "service-certs"


def derive_fernet_key(secret: str, domain: str) -> bytes:
    """The Fernet key for one subsystem."""
    return base64.urlsafe_b64encode(hashlib.sha256(f"{domain}:{secret}".encode()).digest())


def legacy_fernet_key(secret: str) -> bytes:
    """The pre-F-1 undifferentiated key. Read-only fallback; never encrypt with it."""
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())


def domain_cipher(secret: str, domain: str) -> MultiFernet:
    """A cipher that writes domain-separated and still reads pre-F-1 ciphertext.

    ``MultiFernet`` encrypts with the first key and decrypts by trying each in
    turn, so ordering is load-bearing: the domain key must come first.
    """
    return MultiFernet(
        [Fernet(derive_fernet_key(secret, domain)), Fernet(legacy_fernet_key(secret))]
    )
