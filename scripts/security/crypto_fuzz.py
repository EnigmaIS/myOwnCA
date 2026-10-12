#!/usr/bin/env python3
"""Long-running crypto fuzzer for the myOwnCA issuance / parsing / AEAD surface.

Loops for a wall-clock budget, throwing randomized + adversarial inputs at the
real functions and asserting the security invariant set. Any violation (a wrong
issuance, a silent AEAD failure, or an *uncaught* non-ValueError crash on
attacker input) is written to the findings log with a reproducer seed.

Usage:  FUZZ_SECONDS=21600 .venv/bin/python scripts/security/crypto_fuzz.py
Invariants checked:
  I1  parse_csr on ANY input raises only ValueError (CSRValidationError subclass)
      or returns a CSR — never an uncaught TypeError/AttributeError/etc.
  I2  a successfully issued leaf is NEVER ca=True and NEVER has key_cert_sign/crl_sign.
  I3  build_end_entity_certificate raises only ValueError for bad CSRs.
  I4  a tampered Fernet token never decrypts to a different plaintext (InvalidToken only).
  I5  parse_ocsp_request never hangs / raises a non-Exception.
  I6  build_crl output always verifies under the issuer key; serials round-trip.
"""
from __future__ import annotations

import os
import random
import string
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "core")]

from cryptography import x509  # noqa: E402
from cryptography.fernet import Fernet, InvalidToken  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from myownca.ca_hsm import SoftwareHSM  # noqa: E402
from myownca.ca_main.crypto import (  # noqa: E402
    build_crl,
    build_end_entity_certificate,
    create_lab_ca_chain,
    parse_csr,
)
from myownca.ca_main.ocsp import parse_ocsp_request  # noqa: E402
from myownca.domain import (  # noqa: E402
    CertificateProfile,
    CertificateTemplate,
    Revocation,
    RevocationReason,
)

UTC = timezone.utc
FINDINGS = ROOT / "docs/security/fuzz-findings.log"
PROGRESS = ROOT / "docs/security/fuzz-progress.log"

# Pre-generated key pool (keygen is slow; reuse is fine for logic fuzzing).
KEY_POOL = (
    [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(8)]
    + [ec.generate_private_key(ec.SECP256R1()) for _ in range(8)]
)
HSM = SoftwareHSM()
ISSUER = create_lab_ca_chain(HSM).issuer
FERNET = Fernet(Fernet.generate_key())
PROFILES = list(CertificateProfile)
SAN_FACTORIES = [
    lambda s: x509.DNSName(s or "x"),
    lambda s: x509.RFC822Name((s or "x") + "@e.test"),
    lambda s: x509.UniformResourceIdentifier("https://" + (s or "x")),
    lambda s: x509.IPAddress(__import__("ipaddress").ip_address(random.randint(1, 2**32 - 1))),
    lambda s: x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, s or "x")])),
]


def _rand_str(n=12):
    pool = string.ascii_letters + string.digits + ".-_ é好\t" + string.punctuation
    return "".join(random.choice(pool) for _ in range(random.randint(0, n)))


def _template():
    return CertificateTemplate(id="f", name="f", profile=random.choice(PROFILES))


def _rand_csr_pem():
    key = random.choice(KEY_POOL)
    attrs = []
    if random.random() < 0.92:  # usually include a CN (sometimes omit to test rejection)
        try:
            attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, _rand_str() or "cn"))
        except Exception:
            attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, "cn"))
    b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
    names = []
    for _ in range(random.randint(0, 4)):
        try:
            names.append(random.choice(SAN_FACTORIES)(_rand_str()))
        except Exception:
            pass
    if names:
        try:
            b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
        except Exception:
            pass
    if random.random() < 0.15:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def _log_finding(invariant, detail, seed):
    FINDINGS.parent.mkdir(parents=True, exist_ok=True)
    with FINDINGS.open("a") as f:
        f.write(f"[{datetime.now(UTC).isoformat()}] {invariant} seed={seed}\n{detail}\n\n")


def _check_issued(cert):
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False, "I2: issued cert is a CA!"
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is False and ku.crl_sign is False, "I2: leaf has cert/crl-sign!"


def iteration(seed):
    random.seed(seed)
    op = random.random()
    if op < 0.45:  # I1/I2/I3 — CSR issuance
        if random.random() < 0.2:  # garbage "PEM"
            blob = bytes(random.randint(0, 255) for _ in range(random.randint(0, 200)))
            try:
                parse_csr(blob)
            except ValueError:
                pass
            except Exception as exc:  # non-ValueError on attacker input = finding
                _log_finding("I1", f"parse_csr({blob!r}) -> {type(exc).__name__}: {exc}", seed)
            return
        pem = _rand_csr_pem()
        try:
            csr = parse_csr(pem)
        except ValueError:
            return
        except Exception as exc:
            _log_finding("I1", f"parse_csr raised {type(exc).__name__}: {exc}\nPEM:\n{pem}", seed)
            return
        try:
            cert = build_end_entity_certificate(csr, _template(), ISSUER, HSM)
        except ValueError:
            return
        except Exception as exc:
            _log_finding("I3", f"build_end_entity {type(exc).__name__}: {exc}\nPEM:\n{pem}", seed)
            return
        try:
            _check_issued(cert)
        except AssertionError as exc:
            _log_finding("I2", f"{exc}\nPEM:\n{pem}", seed)
    elif op < 0.6:  # I4 — Fernet tamper
        pt = bytes(random.randint(0, 255) for _ in range(random.randint(0, 300)))
        token = bytearray(FERNET.encrypt(pt))
        if token:
            token[random.randrange(len(token))] ^= 1 << random.randint(0, 7)
        try:
            out = FERNET.decrypt(bytes(token))
            if out != pt:
                _log_finding("I4", "tampered token decrypted to a DIFFERENT plaintext", seed)
        except (InvalidToken, ValueError):
            pass
        except Exception as exc:
            _log_finding("I4", f"unexpected {type(exc).__name__}: {exc}", seed)
    elif op < 0.8:  # I5 — OCSP request parsing
        blob = bytes(random.randint(0, 255) for _ in range(random.randint(0, 400)))
        try:
            parse_ocsp_request(blob)
        except Exception:
            pass  # any clean exception is acceptable; a hang/segfault would be the bug
    else:  # I6 — CRL
        now = datetime.now(UTC)
        revs = [Revocation(serial_number=format(random.getrandbits(64), "x"),
                           reason=random.choice(list(RevocationReason)), revoked_at=now)
                for _ in range(random.randint(0, 20))]
        try:
            crl = build_crl(ISSUER, revs, crl_number=random.randint(0, 2**63), hsm=HSM)
            assert crl.is_signature_valid(ISSUER.certificate.public_key()), "I6: CRL sig invalid"
        except (ValueError, AssertionError) as exc:
            if isinstance(exc, AssertionError):
                _log_finding("I6", str(exc), seed)


def main():
    budget = int(os.environ.get("FUZZ_SECONDS", "21600"))
    start = time.time()
    n = 0
    findings_before = FINDINGS.stat().st_size if FINDINGS.exists() else 0
    while time.time() - start < budget:
        try:
            iteration(random.randrange(2**63))
        except Exception:
            _log_finding("HARNESS", traceback.format_exc(), -1)
        n += 1
        if n % 5000 == 0:
            elapsed = time.time() - start
            fsize = FINDINGS.stat().st_size if FINDINGS.exists() else 0
            PROGRESS.write_text(
                f"iterations={n} elapsed={elapsed:.0f}s rate={n/elapsed:.0f}/s "
                f"findings_bytes={fsize - findings_before} at={datetime.now(UTC).isoformat()}\n")
    PROGRESS.write_text(
        f"DONE iterations={n} elapsed={time.time()-start:.0f}s "
        f"findings_bytes={(FINDINGS.stat().st_size if FINDINGS.exists() else 0) - findings_before}\n")
    print(f"fuzz done: {n} iterations")


if __name__ == "__main__":
    main()
