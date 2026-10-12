#!/usr/bin/env python3
"""Live end-to-end check of the cloud-KMS signing path against a REAL provider.

The B10 battery (``tests/security/test_b10_remote_signing_adversarial.py``) fakes
the provider with a local software key. That proves the splice, the ECDSA
normalisation and the F-3 verification gate are correct, but it cannot prove that
a real AWS KMS / Azure Key Vault key round-trips: the signature encoding, the
digest-vs-message contract, the algorithm identifiers and the key-version pinning
are all provider behaviour. This script closes that gap.

Run it yourself — it needs your own credentials, which should never be pasted into
a chat transcript or committed. It reads them from the environment only (never
argv, so they stay out of shell history and ``ps``), never prints them, and never
prints key material. Output is one PASS/FAIL line per check plus a verdict.

It is read-only with respect to your CA: it signs three throwaway objects with an
existing key and verifies them locally. It creates nothing, stores nothing and
deletes nothing. It does consume a handful of KMS sign operations (billable, a
fraction of a cent).

AWS KMS
-------
    export MYOWNCA_LIVE_PROVIDER=aws
    export MYOWNCA_LIVE_AWS_REGION=eu-central-1
    export MYOWNCA_LIVE_KEY_REF='arn:aws:kms:eu-central-1:123456789012:key/…'
    # credentials: omit to use the ambient chain (instance role, SSO, ~/.aws), or
    export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… [AWS_SESSION_TOKEN=…]
    .venv/bin/python scripts/security/cloud_signing_live_check.py

The key needs ``kms:DescribeKey``, ``kms:GetPublicKey`` and ``kms:Sign``, with a
key usage of SIGN_VERIFY and an RSA_2048+ or ECC_NIST_P256/384/521 spec.

Azure Key Vault / Managed HSM
-----------------------------
    export MYOWNCA_LIVE_PROVIDER=azure
    export MYOWNCA_LIVE_AZURE_VAULT_URL=https://my-vault.vault.azure.net
    export MYOWNCA_LIVE_KEY_REF=my-issuing-key          # name, or a full key URL
    export MYOWNCA_LIVE_AZURE_TENANT_ID=… MYOWNCA_LIVE_AZURE_CLIENT_ID=… \
           MYOWNCA_LIVE_AZURE_CLIENT_SECRET=…
    .venv/bin/python scripts/security/cloud_signing_live_check.py

The service principal needs the Key Vault Crypto User role (get + sign).

Exit status: 0 = every check passed, 1 = a check failed, 2 = misconfigured.
"""
from __future__ import annotations

import os
import sys
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from myownca.ca_hsm.remote import (  # noqa: E402
    CloudKeyValidationError,
    algorithm_name_for,
    signature_hash_for,
)

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_MISCONFIGURED = 2


def _env(name: str, *, required: bool = True) -> str:
    value = os.environ.get(name, "").strip()
    if required and not value:
        raise SystemExit(f"[CONFIG] {name} is not set — see the docstring at the top of this file.")
    return value


def _build_backend() -> tuple[object, str]:
    """Construct the configured backend. Credentials come from the environment."""

    provider = _env("MYOWNCA_LIVE_PROVIDER").lower()
    key_ref = _env("MYOWNCA_LIVE_KEY_REF")

    if provider == "aws":
        from myownca.ca_hsm.aws_kms import AWSKMSHSM

        access_key = os.environ.get("AWS_ACCESS_KEY_ID") or None
        secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY") or None
        return (
            AWSKMSHSM(
                region_name=_env("MYOWNCA_LIVE_AWS_REGION"),
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=os.environ.get("AWS_SESSION_TOKEN") or None,
            ),
            key_ref,
        )

    if provider == "azure":
        from myownca.ca_hsm.azure_key_vault import AzureKeyVaultHSM

        return (
            AzureKeyVaultHSM(
                vault_url=_env("MYOWNCA_LIVE_AZURE_VAULT_URL"),
                tenant_id=_env("MYOWNCA_LIVE_AZURE_TENANT_ID"),
                client_id=_env("MYOWNCA_LIVE_AZURE_CLIENT_ID"),
                client_secret=_env("MYOWNCA_LIVE_AZURE_CLIENT_SECRET"),
            ),
            key_ref,
        )

    raise SystemExit(f"[CONFIG] MYOWNCA_LIVE_PROVIDER must be 'aws' or 'azure', got {provider!r}.")


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _verify(public_key, payload: bytes, signature: bytes, algorithm) -> None:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, payload, ec.ECDSA(algorithm))
    elif isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, payload, padding.PKCS1v15(), algorithm)
    else:
        raise AssertionError("unsupported key type")


class Checks:
    def __init__(self) -> None:
        self.failures = 0

    def run(self, label: str, function) -> object:
        """Report one check. Only a *string* result is echoed, never key material."""

        try:
            result = function()
        except Exception as exc:  # noqa: BLE001 - this is the reporting boundary
            self.failures += 1
            print(f"FAIL  {label}\n        {type(exc).__name__}: {exc}")
            if os.environ.get("MYOWNCA_LIVE_TRACEBACK"):
                traceback.print_exc()
            return None
        detail = f" — {result}" if isinstance(result, str) and result else ""
        print(f"PASS  {label}{detail}")
        return result


def main() -> int:
    backend, key_ref = _build_backend()
    checks = Checks()
    now = datetime.now(timezone.utc)

    print(f"Provider: {backend.provider_name}")
    print("Signing three throwaway objects with the configured key; nothing is stored.\n")

    configured_ref = key_ref
    resolved: list[str] = []

    def canonicalize() -> str:
        """Say whether resolution actually happened — an already-concrete ref
        round-trips unchanged, which proves nothing about alias/version lookup."""

        canonical = str(backend.canonicalize_key_ref(configured_ref))
        resolved.append(canonical)
        if canonical == configured_ref:
            return f"already concrete, unchanged: {canonical}"
        return f"RESOLVED {configured_ref} -> {canonical}"

    if checks.run("key reference pins to a concrete key/version", canonicalize) is None:
        return EXIT_FAILED
    key_ref = resolved[0]

    public_key = checks.run("public key fetched", lambda: backend.public_key(key_ref))
    if public_key is None:
        return EXIT_FAILED
    checks.run("key type/size is a supported issuing profile", lambda: algorithm_name_for(public_key))
    algorithm = signature_hash_for(public_key)

    def certificate() -> str:
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name("myOwnCA live signing check"))
            .issuer_name(_name("myOwnCA live signing check"))
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(minutes=5))
        )
        signed = backend.sign_certificate(builder, key_ref)
        _verify(public_key, signed.tbs_certificate_bytes, signed.signature, algorithm)
        return f"{len(signed.signature)}-byte signature verifies"

    def crl() -> str:
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(_name("myOwnCA live signing check"))
            .last_update(now)
            .next_update(now + timedelta(minutes=5))
        )
        signed = backend.sign_crl(builder, key_ref)
        if not signed.is_signature_valid(public_key):
            raise AssertionError("CRL signature does not verify under the issuer key")
        return "CRL signature verifies"

    def csr() -> str:
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            _name("myOwnCA live signing check")
        )
        signed = backend.sign_csr(builder, key_ref)
        if not signed.is_signature_valid:
            raise AssertionError("CSR self-signature does not verify")
        if signed.public_key().public_numbers() != public_key.public_numbers():
            raise AssertionError("CSR carries a public key other than the KMS key")
        return "CSR self-signature verifies and carries the KMS public key"

    def rejects_non_exportable() -> str:
        try:
            backend.private_key(key_ref)
        except Exception as exc:  # noqa: BLE001 - any refusal is the correct outcome
            return f"private-key export refused ({type(exc).__name__})"
        raise AssertionError("backend returned private key material — it must never be exportable")

    def gate_is_active() -> str:
        """F-3 regression: a wrong-key response must fail issuance, not produce a cert."""

        from myownca.ca_hsm.remote import sign_certificate_with_remote_key

        impostor = (
            ec.generate_private_key(public_key.curve)
            if isinstance(public_key, ec.EllipticCurvePublicKey)
            else rsa.generate_private_key(public_exponent=65537, key_size=public_key.key_size)
        )

        def hostile(payload: bytes, hash_algorithm) -> bytes:
            if isinstance(impostor, ec.EllipticCurvePrivateKey):
                return impostor.sign(payload, ec.ECDSA(hash_algorithm))
            return impostor.sign(payload, padding.PKCS1v15(), hash_algorithm)

        builder = (
            x509.CertificateBuilder()
            .subject_name(_name("myOwnCA live signing check"))
            .issuer_name(_name("myOwnCA live signing check"))
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(minutes=5))
        )
        try:
            sign_certificate_with_remote_key(builder, public_key, hostile)
        except CloudKeyValidationError:
            return "a wrong-key provider response is refused (F-3 gate active)"
        raise AssertionError("wrong-key response produced a certificate — the F-3 gate is missing")

    checks.run("certificate signed by the live key verifies", certificate)
    checks.run("CRL signed by the live key verifies", crl)
    checks.run("CSR signed by the live key verifies", csr)
    checks.run("private key is non-exportable", rejects_non_exportable)
    checks.run("hostile-response gate rejects a wrong-key signature", gate_is_active)

    print()
    if checks.failures:
        print(f"VERDICT: FAILED — {checks.failures} check(s) failed.")
        print("Re-run with MYOWNCA_LIVE_TRACEBACK=1 for full tracebacks.")
        return EXIT_FAILED
    print("VERDICT: PASSED — the live cloud signing path produces verifiable objects.")
    return EXIT_OK


if __name__ == "__main__":
    try:
        status = main()
    except SystemExit as misconfigured:  # _env()/_build_backend() raise with a message
        print(misconfigured.code)
        status = EXIT_MISCONFIGURED
    raise SystemExit(status)
