"""B6 — auth crypto primitives: TOTP (RFC 6238 vectors), Argon2, constant-time gate."""
from __future__ import annotations

import base64
import pathlib

import pytest
from argon2 import PasswordHasher, Type

from myownca.ca_auth import totp

# RFC 6238 Appendix B reference vectors (SHA1, secret = ASCII "12345678901234567890").
RFC_SECRET_B32 = base64.b32encode(b"12345678901234567890").decode()
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("unix_time,expected", RFC_VECTORS)
def test_totp_matches_rfc6238_vectors(unix_time, expected):
    step = unix_time // 30
    assert totp.code_for_step(RFC_SECRET_B32, step, digits=8) == expected


def _pad(s: str) -> str:
    return (s + "=" * ((8 - len(s) % 8) % 8)).upper()


def test_totp_secret_is_160_bit():
    # generate_secret uses token_bytes(20) -> 160 bits of entropy
    assert len(base64.b32decode(_pad(totp.generate_secret()))) == 20


def test_totp_codes_differ_across_adjacent_steps():
    s = totp.generate_secret()
    codes = {totp.code_for_step(s, st) for st in range(100, 110)}
    assert len(codes) >= 8  # essentially all distinct


# --- Argon2 (the password hasher used by AuthService) -------------------------

def test_argon2id_params_and_verify():
    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32,
                        salt_len=16, type=Type.ID)
    h1 = ph.hash("correct horse battery staple")
    h2 = ph.hash("correct horse battery staple")
    assert h1 != h2  # random salt -> distinct hashes
    assert h1.startswith("$argon2id$")
    assert ph.verify(h1, "correct horse battery staple") is True
    from argon2.exceptions import VerifyMismatchError
    with pytest.raises(VerifyMismatchError):
        ph.verify(h1, "wrong password")


# --- constant-time comparison gate (static) -----------------------------------

def test_secret_comparisons_are_constant_time():
    """Sensitive comparisons (CSRF, TOTP, challenge) must use compare_digest."""
    src = pathlib.Path(__file__).resolve().parents[2] / "src/myownca/ca_auth/service.py"
    text = src.read_text()
    assert text.count("secrets.compare_digest") >= 3
    # no obvious plaintext-equality on a password/token/code variable
    for bad in ("password == ", "csrf_token == ", "code == challenge", "token == session"):
        assert bad not in text, f"non-constant-time comparison found: {bad!r}"
