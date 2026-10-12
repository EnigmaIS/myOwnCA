"""B5 — secret-at-rest (Fernet) battery.

Confirms: tamper is always detected; wrong key fails closed; round-trips hold;
and each subsystem derives its own key (finding F-1, fixed 2026-08-04).

The two domain-separation tests below previously asserted the DEFECT — that the
three subsystems shared one key and their ciphertexts were interchangeable. They
are inverted, not deleted, so they now guard the fix.

They deliberately exercise the per-domain keys rather than the live service
ciphers: those are MultiFernet([domain, legacy]) during the migration window, so
asserting cross-domain isolation against them would pass vacuously.
"""
from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.fernet import Fernet, InvalidToken

from myownca.ca_auth.service import _derive_fernet_key as auth_kdf
from myownca.comms.service import _derive_fernet_key as comms_kdf
from myownca.service_certs.service import _derive_fernet_key as svc_kdf

SECRET = "an-operator-encryption-secret-value"


def _server_keys_kdf(secret: str) -> bytes:
    # The context-separated derivation used by ca_main/server_keys.py.
    return base64.urlsafe_b64encode(hashlib.sha256(f"server-keys:{secret}".encode()).digest())


# --- domain separation --------------------------------------------------------

def test_subsystem_kdfs_are_pairwise_distinct():
    """F-1 fixed: every subsystem derives its own domain-separated key."""
    keys = {
        "ca_auth": auth_kdf(SECRET),
        "comms": comms_kdf(SECRET),
        "service_certs": svc_kdf(SECRET),
        "server_keys": _server_keys_kdf(SECRET),
    }
    assert len(set(keys.values())) == len(keys), f"key collision among {list(keys)}"


def test_ciphertext_is_not_cross_decryptable_between_subsystems():
    """F-1 fixed: one subsystem's ciphertext must not open under another's key.

    Uses the raw per-domain keys on purpose — the live service ciphers still carry
    the legacy read fallback, which would make this pass without proving anything.
    """
    keys = {
        "ca_auth": auth_kdf(SECRET),
        "comms": comms_kdf(SECRET),
        "service_certs": svc_kdf(SECRET),
        "server_keys": _server_keys_kdf(SECRET),
    }
    for writer, write_key in keys.items():
        token = Fernet(write_key).encrypt(b"smtp-password-or-dns-cred")
        for reader, read_key in keys.items():
            if reader == writer:
                continue
            with pytest.raises(InvalidToken):
                Fernet(read_key).decrypt(token)


def test_server_keys_vault_stays_isolated():
    """The server-keys vault was already separated; it must remain so."""
    assert _server_keys_kdf(SECRET) != auth_kdf(SECRET)
    other = Fernet(auth_kdf(SECRET))
    vault = Fernet(_server_keys_kdf(SECRET))
    token = other.encrypt(b"x")
    with pytest.raises(InvalidToken):
        vault.decrypt(token)  # the vault cannot read another domain's ciphertext


# --- AEAD properties ----------------------------------------------------------

def test_tamper_never_yields_a_different_plaintext():
    """The AEAD invariant: mutating any byte either fails closed OR (for a
    redundant base64-padding bit) returns the *exact* original plaintext —
    never a different plaintext. We mutate the raw token bytes through every
    bit so the HMAC must reject any change to the actual ciphertext/IV/tag.
    """
    cipher = Fernet(auth_kdf(SECRET))
    pt = b"sensitive-private-key-pem"
    token = bytearray(cipher.encrypt(pt))
    for i in range(len(token)):
        for bit in range(8):
            mutated = bytearray(token)
            mutated[i] ^= 1 << bit
            try:
                out = cipher.decrypt(bytes(mutated))
            except (InvalidToken, ValueError):
                continue  # fail-closed -> good
            assert out == pt, "tamper yielded a DIFFERENT plaintext"


def test_wrong_secret_fails_closed():
    good = Fernet(auth_kdf(SECRET))
    bad = Fernet(auth_kdf("a-different-secret"))
    token = good.encrypt(b"x")
    with pytest.raises(InvalidToken):
        bad.decrypt(token)


@pytest.mark.parametrize("payload", [b"", b"\x00" * 1, b"\xff" * 4096, b"binary\x00\x01\x02", b"x" * 100000])
def test_round_trip_arbitrary_payloads(payload):
    cipher = Fernet(svc_kdf(SECRET))
    assert cipher.decrypt(cipher.encrypt(payload)) == payload


def test_kdf_output_is_valid_fernet_key_shape():
    for kdf in (auth_kdf, comms_kdf, svc_kdf):
        key = kdf(SECRET)
        assert len(base64.urlsafe_b64decode(key)) == 32  # 256-bit Fernet key
