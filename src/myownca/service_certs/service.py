from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from myownca.secret_keys import (
    SERVICE_CERTS_DOMAIN,
    decrypt_secret,
    derive_fernet_key,
    domain_cipher,
)
from myownca.service_certs.acme_client import AcmeClient
from myownca.service_certs.base import (
    AcmeAccount,
    AcmeAccountInUseError,
    AcmeCertConfig,
    AcmeChallenge,
    AcmeOrderCheckpoint,
    AcmeOrderIndeterminate,
    ChallengeType,
    KeyBackend,
    ServiceCertError,
    ServiceCertificate,
    ServiceCertSource,
    ServiceCertStatus,
)
from myownca.service_certs.dns_provider import (
    DnsProvider,
    provider_from_account,
    resolve_cname,
    wait_for_txt,
)
from myownca.service_certs.keystore import ServiceKeyStore
from myownca.service_certs.repository import ServiceCertRepository


def eligible_for_portal_tls(cert: ServiceCertificate) -> bool:
    """Only software-keyed certs can be materialized as portal TLS."""
    return cert.key_backend == KeyBackend.SOFTWARE


class ServiceCertService:
    def __init__(
        self,
        repository: ServiceCertRepository,
        keystore: ServiceKeyStore,
        encryption_secret: str,
        *,
        acme_client: AcmeClient | None = None,
    ) -> None:
        self.repository = repository
        self.keystore = keystore
        self.cipher = domain_cipher(encryption_secret, SERVICE_CERTS_DOMAIN)
        self.acme = acme_client or AcmeClient()
        self._http01_tokens: dict[str, str] = {}
        self._lock = threading.RLock()

    # -- reads ----------------------------------------------------------------

    def list_certs(self) -> list[ServiceCertificate]:
        return self.repository.list_all()

    def get_cert(self, cert_id: str) -> ServiceCertificate:
        return self.repository.get(cert_id)

    def portal_tls_material(self, cert_id: str) -> tuple[str, str, str]:
        """Return ``(certificate_pem, chain_pem, key_pem)`` for use as the portal TLS cert.

        Raises ``ServiceCertError`` for HSM-keyed certs (non-extractable) or a cert
        that has no issued certificate yet (e.g. a pending CSR).
        """
        cert = self.get_cert(cert_id)
        if not eligible_for_portal_tls(cert):
            raise ServiceCertError(
                "Only software-keyed certificates can be used as portal TLS "
                "(PKCS#11/HSM keys are non-extractable)"
            )
        if not cert.certificate_pem:
            raise ServiceCertError("This certificate has no issued certificate yet")
        key_pem = self.keystore.software_key_pem(cert.key_ref)
        return cert.certificate_pem, cert.chain_pem or "", key_pem

    def get_active_by_name(self, name: str) -> ServiceCertificate | None:
        cert = self.repository.get_by_name(name)
        if cert is None or cert.status is not ServiceCertStatus.ACTIVE:
            return None
        return cert

    # -- capability 1: CSR for an external CA ---------------------------------

    def generate_csr(
        self,
        name: str,
        *,
        common_name: str,
        dns_names: tuple[str, ...] = (),
        key_backend: KeyBackend = KeyBackend.SOFTWARE,
        algorithm: str = "ecdsa-p256",
    ) -> tuple[ServiceCertificate, str]:
        cert = self.prepare_csr(
            name,
            key_backend=key_backend,
            algorithm=algorithm,
        )
        # Keep the pending row and key if CSR construction fails.  The online
        # composition root registers the key before completion and applies the
        # mandatory grace period; this service layer must never destroy key
        # material as an error-side effect.
        return self.complete_csr(
            cert.id,
            common_name=common_name,
            dns_names=dns_names,
        )

    def prepare_csr(
        self,
        name: str,
        *,
        key_backend: KeyBackend = KeyBackend.SOFTWARE,
        algorithm: str = "ecdsa-p256",
        prepared_key_ref: str | None = None,
        certificate_id: str | None = None,
    ) -> ServiceCertificate:
        self._assert_unique_name(name)
        if prepared_key_ref is not None:
            if key_backend is KeyBackend.SOFTWARE:
                raise ServiceCertError(
                    "A prepared provider key cannot be used with the software backend"
                )
            # This is an internal saga hand-off. Resolve the public key so a
            # malformed/stale reference fails before any certificate row is stored.
            self.keystore.public_key(prepared_key_ref, key_backend)
            key_ref = prepared_key_ref
        else:
            key_ref = self.keystore.generate(_new_key_ref(), key_backend, algorithm)
        now = datetime.now(timezone.utc)
        cert = ServiceCertificate(
            id=certificate_id or str(uuid4()),
            name=name,
            source=ServiceCertSource.CSR_EXTERNAL,
            status=ServiceCertStatus.PENDING,
            key_backend=key_backend,
            key_ref=key_ref,
            created_at=now,
            updated_at=now,
            csr_pem=None,
        )
        self.repository.add(cert)
        return cert

    def complete_csr(
        self,
        cert_id: str,
        *,
        common_name: str,
        dns_names: tuple[str, ...] = (),
    ) -> tuple[ServiceCertificate, str]:
        cert = self.repository.get(cert_id)
        if cert.csr_pem:
            return cert, cert.csr_pem
        csr_pem = self.keystore.build_csr(
            cert.key_ref,
            cert.key_backend,
            common_name=common_name,
            dns_names=dns_names,
        )
        updated = replace(
            cert,
            csr_pem=csr_pem,
            updated_at=datetime.now(timezone.utc),
        )
        self.repository.update(updated)
        return updated, csr_pem

    def import_signed_certificate(
        self, cert_id: str, certificate_pem: str, chain_pem: str | None = None
    ) -> ServiceCertificate:
        cert = self.repository.get(cert_id)
        leaf = _parse_certificate(certificate_pem)
        if not self.keystore.certificate_matches_key(leaf, cert.key_ref, cert.key_backend):
            raise ServiceCertError("Certificate public key does not match the stored private key")
        updated = _with_leaf(cert, leaf, certificate_pem, chain_pem)
        self.repository.update(updated)
        return updated

    # -- capability 2: import existing cert + key -----------------------------

    def import_pem(
        self,
        name: str,
        *,
        certificate_pem: str,
        private_key_pem: str,
        chain_pem: str | None = None,
        key_passphrase: str | None = None,
    ) -> ServiceCertificate:
        self._assert_unique_name(name)
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=key_passphrase.encode() if key_passphrase else None,
        )
        leaf = _parse_certificate(certificate_pem)
        return self._store_imported(name, private_key, leaf, certificate_pem, chain_pem)

    def import_p12(self, name: str, p12_bytes: bytes, password: str | None) -> ServiceCertificate:
        self._assert_unique_name(name)
        pw = password.encode() if password else None
        private_key, leaf, additional = pkcs12.load_key_and_certificates(p12_bytes, pw)
        if private_key is None or leaf is None:
            raise ServiceCertError("PKCS#12 file must contain both a certificate and a private key")
        certificate_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
        chain_pem = (
            "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in additional)
            if additional
            else None
        )
        return self._store_imported(name, private_key, leaf, certificate_pem, chain_pem)

    def _store_imported(self, name, private_key, leaf, certificate_pem, chain_pem) -> ServiceCertificate:
        cert_pub = leaf.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_pub = private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if cert_pub != key_pub:
            raise ServiceCertError("Certificate public key does not match the provided private key")
        key_ref = _new_key_ref()
        self.keystore.store_software_key(key_ref, private_key)
        now = datetime.now(timezone.utc)
        cert = ServiceCertificate(
            id=str(uuid4()),
            name=name,
            source=ServiceCertSource.IMPORTED,
            status=ServiceCertStatus.ACTIVE,
            key_backend=KeyBackend.SOFTWARE,
            key_ref=key_ref,
            created_at=now,
            updated_at=now,
            certificate_pem=certificate_pem,
            chain_pem=chain_pem,
            subject=leaf.subject.rfc4514_string(),
            not_before=leaf.not_valid_before_utc,
            not_after=leaf.not_valid_after_utc,
        )
        self.repository.add(cert)
        return cert

    def delete(self, cert_id: str) -> None:
        """Archive a service certificate without deleting its private key.

        Provider cleanup belongs to the durable key-lifecycle worker.  Keeping
        this compatibility method non-destructive prevents direct callers from
        bypassing the fixed retirement grace period.
        """

        cert = self.repository.get(cert_id)
        self.repository.update(
            replace(
                cert,
                status=ServiceCertStatus.SUPERSEDED,
                updated_at=datetime.now(timezone.utc),
            )
        )

    # -- capability 3: ACME ---------------------------------------------------

    def create_account(self, directory_url: str, contact: str = "") -> AcmeAccount:
        account_key_pem = self.acme.generate_account_key_pem()
        account_url = self.acme.register_account(directory_url, account_key_pem, contact)
        account = AcmeAccount(
            id=str(uuid4()),
            directory_url=directory_url,
            account_url=account_url,
            account_key_ciphertext=self.cipher.encrypt(account_key_pem.encode()).decode(),
            contact=contact,
            created_at=datetime.now(timezone.utc),
        )
        self.repository.add_account(account)
        return account

    def set_account_dns_provider(self, account_id: str, provider: str, credentials: dict) -> None:
        self.repository.get_account(account_id)  # 404s on unknown id
        ciphertext = self.cipher.encrypt(json.dumps(credentials).encode()).decode()
        self.repository.set_account_dns_provider(account_id, provider, ciphertext)

    def _dns_provider(self, account) -> DnsProvider | None:
        return provider_from_account(
            account,
            lambda ct: decrypt_secret(self.cipher, ct, what="Stored DNS-provider credentials"),
        )

    def _run_dns01_automated(self, account, csr_pem: str) -> str:
        _order_url, order_json, challenges = self.acme.begin_dns01(
            account.directory_url, self._account_key(account), account.account_url, csr_pem
        )
        return self._complete_dns01_order(account, order_json, challenges)

    def _complete_dns01_order(
        self,
        account: AcmeAccount,
        order_json: str,
        challenges: list[AcmeChallenge],
    ) -> str:
        provider = self._dns_provider(account)
        if provider is None:
            raise ServiceCertError("DNS-01 requires a DNS provider on the ACME account")
        published: list[tuple[str, str]] = []
        try:
            for c in challenges:
                # Follow a `_acme-challenge` CNAME delegation, if any, so the TXT is
                # written in (and validated from) the zone the CNAME points at — the
                # common pattern when the apex is hosted away from the automatable zone.
                name = resolve_cname(self.acme.dns_record_name(c.domain))
                provider.publish_txt(name, c.dns_txt_value)
                published.append((name, c.dns_txt_value))
            for name, value in published:
                if not wait_for_txt(name, value):
                    raise ServiceCertError(
                        f"DNS-01 propagation timed out for {name}; the TXT record is not yet "
                        "visible on the authoritative nameservers"
                    )
            return self.acme.complete_dns01(
                account.directory_url, self._account_key(account), account.account_url, order_json
            )
        finally:
            for name, value in published:
                try:
                    provider.remove_txt(name, value)
                except Exception:  # noqa: BLE001 - cleanup is best-effort
                    pass

    def list_accounts(self) -> list[AcmeAccount]:
        return self.repository.list_accounts()

    def account_dependents(self, account_id: str) -> list[ServiceCertificate]:
        return self.repository.list_account_dependents(account_id)

    def delete_account(self, account_id: str, *, force: bool = False) -> None:
        self.repository.get_account(account_id)  # raises on unknown id
        dependents = self.repository.list_account_dependents(account_id)
        if dependents and not force:
            raise AcmeAccountInUseError(dependents)
        self.repository.delete_account(account_id)

    def request_certificate(
        self,
        name: str,
        *,
        account_id: str,
        domains: tuple[str, ...],
        challenge_type: ChallengeType,
        key_backend: KeyBackend = KeyBackend.SOFTWARE,
        algorithm: str = "ecdsa-p256",
        renew_before_days: int = 30,
    ) -> dict[str, object]:
        cert = self.prepare_acme_certificate(
            name,
            account_id=account_id,
            domains=domains,
            challenge_type=challenge_type,
            key_backend=key_backend,
            algorithm=algorithm,
            renew_before_days=renew_before_days,
        )
        return self.complete_acme_certificate(cert.id)

    def prepare_acme_certificate(
        self,
        name: str,
        *,
        account_id: str,
        domains: tuple[str, ...],
        challenge_type: ChallengeType,
        key_backend: KeyBackend = KeyBackend.SOFTWARE,
        algorithm: str = "ecdsa-p256",
        renew_before_days: int = 30,
        prepared_key_ref: str | None = None,
        certificate_id: str | None = None,
    ) -> ServiceCertificate:
        if not domains:
            raise ServiceCertError("At least one domain is required")
        self._assert_unique_name(name)
        self.repository.get_account(account_id)
        if prepared_key_ref is not None:
            if key_backend is KeyBackend.SOFTWARE:
                raise ServiceCertError(
                    "A prepared provider key cannot be used with the software backend"
                )
            self.keystore.public_key(prepared_key_ref, key_backend)
            key_ref = prepared_key_ref
        else:
            key_ref = self.keystore.generate(_new_key_ref(), key_backend, algorithm)
        now = datetime.now(timezone.utc)
        cert = ServiceCertificate(
            id=certificate_id or str(uuid4()),
            name=name,
            source=ServiceCertSource.ACME,
            status=ServiceCertStatus.PENDING,
            key_backend=key_backend,
            key_ref=key_ref,
            created_at=now,
            updated_at=now,
            csr_pem=None,
        )
        self.repository.add(cert)
        self.repository.set_cert_config(
            AcmeCertConfig(
                service_certificate_id=cert.id,
                account_id=account_id,
                domains=domains,
                challenge_type=challenge_type,
                renew_before_days=renew_before_days,
            )
        )
        return cert

    def complete_acme_certificate(
        self, cert_id: str, *, idempotency_key: str | None = None
    ) -> dict[str, object]:
        cert = self.repository.get(cert_id)
        if cert.status is ServiceCertStatus.ACTIVE:
            return {"status": "issued", "certificate_id": cert.id}
        config = self.repository.get_cert_config(cert.id)
        if config is None:
            raise ServiceCertError("ACME certificate configuration is missing")
        account = self.repository.get_account(config.account_id)
        checkpoint = (
            self.repository.get_acme_order_checkpoint(idempotency_key)
            if idempotency_key is not None
            else None
        )
        if checkpoint is not None:
            self._validate_checkpoint(checkpoint, cert, "issue")
            csr_pem = checkpoint.csr_pem
        elif cert.csr_pem:
            csr_pem = cert.csr_pem
        else:
            csr_pem = self.keystore.build_csr(
                cert.key_ref,
                cert.key_backend,
                common_name=config.domains[0],
                dns_names=config.domains,
            )
            cert = replace(
                cert,
                csr_pem=csr_pem,
                updated_at=datetime.now(timezone.utc),
            )
            self.repository.update(cert)

        if idempotency_key is not None:
            checkpoint = checkpoint or self._create_acme_checkpoint(
                idempotency_key,
                cert,
                purpose="issue",
                csr_pem=csr_pem,
            )
            issued = self._complete_checkpointed_acme_order(
                cert, config, account, checkpoint
            )
            return {"status": "issued", "certificate_id": issued.id}

        if config.challenge_type is ChallengeType.HTTP_01:
            fullchain = self.acme.order_http01(
                account.directory_url,
                self._account_key(account),
                account.account_url,
                csr_pem,
                self._publish_http01,
                self._cleanup_http01,
            )
            issued = self._install_fullchain(cert, fullchain)
            return {"status": "issued", "certificate_id": issued.id}

        fullchain = self._run_dns01_automated(account, csr_pem)
        issued = self._install_fullchain(cert, fullchain)
        return {"status": "issued", "certificate_id": issued.id}

    def renew(
        self, cert_id: str, *, idempotency_key: str | None = None
    ) -> dict[str, object]:
        cert = self.repository.get(cert_id)
        config = self.repository.get_cert_config(cert_id)
        if cert.source is not ServiceCertSource.ACME or config is None:
            raise ServiceCertError("Only ACME-managed certificates can be renewed automatically")
        account = self.repository.get_account(config.account_id)
        checkpoint = (
            self.repository.get_acme_order_checkpoint(idempotency_key)
            if idempotency_key is not None
            else None
        )
        if checkpoint is not None:
            self._validate_checkpoint(checkpoint, cert, "renew")
            csr_pem = checkpoint.csr_pem
        else:
            csr_pem = self.keystore.build_csr(
                cert.key_ref,
                cert.key_backend,
                common_name=config.domains[0],
                dns_names=config.domains,
            )
        if idempotency_key is not None:
            checkpoint = checkpoint or self._create_acme_checkpoint(
                idempotency_key,
                cert,
                purpose="renew",
                csr_pem=csr_pem,
            )
            self._complete_checkpointed_acme_order(cert, config, account, checkpoint)
            return {"status": "renewed", "certificate_id": cert.id}

        if config.challenge_type is ChallengeType.HTTP_01:
            fullchain = self.acme.order_http01(
                account.directory_url,
                self._account_key(account),
                account.account_url,
                csr_pem,
                self._publish_http01,
                self._cleanup_http01,
            )
            self._install_fullchain(cert, fullchain)
            return {"status": "renewed", "certificate_id": cert.id}
        fullchain = self._run_dns01_automated(account, csr_pem)
        self._install_fullchain(cert, fullchain)
        return {"status": "renewed", "certificate_id": cert.id}

    def due_for_renewal(self, now: datetime | None = None) -> list[ServiceCertificate]:
        current = now or datetime.now(timezone.utc)
        due: list[ServiceCertificate] = []
        for cert in self.repository.list_all():
            if cert.source is not ServiceCertSource.ACME or cert.not_after is None:
                continue
            config = self.repository.get_cert_config(cert.id)
            window = timedelta(days=config.renew_before_days if config else 30)
            if cert.not_after - window <= current:
                due.append(cert)
        return due

    # -- HTTP-01 challenge serving (used by the public .well-known route) ------

    def http01_keyauth(self, token: str) -> str | None:
        with self._lock:
            return self._http01_tokens.get(token)

    def _publish_http01(self, token: str, key_authorization: str) -> None:
        with self._lock:
            self._http01_tokens[token] = key_authorization

    def _cleanup_http01(self, token: str) -> None:
        with self._lock:
            self._http01_tokens.pop(token, None)

    # -- internals ------------------------------------------------------------

    def _account_key(self, account: AcmeAccount) -> str:
        return decrypt_secret(
            self.cipher, account.account_key_ciphertext, what="The stored ACME account key"
        )

    def _create_acme_checkpoint(
        self,
        idempotency_key: str,
        cert: ServiceCertificate,
        *,
        purpose: str,
        csr_pem: str,
    ) -> AcmeOrderCheckpoint:
        return self.repository.get_or_create_acme_order_checkpoint(
            idempotency_key=idempotency_key,
            service_certificate_id=cert.id,
            purpose=purpose,
            csr_pem=csr_pem,
            csr_sha256=_sha256_text(csr_pem),
            prior_certificate_sha256=_certificate_sha256(cert.certificate_pem),
        )

    @staticmethod
    def _validate_checkpoint(
        checkpoint: AcmeOrderCheckpoint,
        cert: ServiceCertificate,
        purpose: str,
    ) -> None:
        if (
            checkpoint.service_certificate_id != cert.id
            or checkpoint.purpose != purpose
            or checkpoint.csr_sha256 != _sha256_text(checkpoint.csr_pem)
        ):
            raise ServiceCertError(
                "ACME idempotency key is bound to another or invalid operation"
            )

    def _complete_checkpointed_acme_order(
        self,
        cert: ServiceCertificate,
        config: AcmeCertConfig,
        account: AcmeAccount,
        checkpoint: AcmeOrderCheckpoint,
    ) -> ServiceCertificate:
        """Resume one ACME order and checkpoint its result before local install."""
        current = self.repository.get(cert.id)
        current_fingerprint = _certificate_sha256(current.certificate_pem)

        # A renewal may have committed just before a worker lost its lease.  A
        # changed leaf relative to the pre-order fingerprint proves that this
        # operation (or a newer one) already installed a result; do not create
        # another order or roll a newer certificate back.
        if (
            checkpoint.purpose == "renew"
            and checkpoint.fullchain_pem is None
            and current_fingerprint is not None
            and current_fingerprint != checkpoint.prior_certificate_sha256
        ):
            return current

        if checkpoint.fullchain_pem is None and checkpoint.order_json is None:
            if (
                config.challenge_type is ChallengeType.DNS_01
                and self._dns_provider(account) is None
            ):
                raise ServiceCertError(
                    "DNS-01 requires a DNS provider on the ACME account"
                )
            if not self.repository.claim_acme_order_creation(
                checkpoint.idempotency_key
            ):
                raise AcmeOrderIndeterminate(
                    "ACME order creation has an indeterminate outcome; "
                    "operator reconciliation is required before starting another order"
                )
            if config.challenge_type is ChallengeType.HTTP_01:
                order_url, order_json = self.acme.begin_http01(
                    account.directory_url,
                    self._account_key(account),
                    account.account_url,
                    checkpoint.csr_pem,
                )
                challenges: list[AcmeChallenge] = []
            else:
                order_url, order_json, challenges = self.acme.begin_dns01(
                    account.directory_url,
                    self._account_key(account),
                    account.account_url,
                    checkpoint.csr_pem,
                )
            checkpoint = self.repository.save_acme_order(
                checkpoint.idempotency_key,
                order_url=order_url,
                order_json=order_json,
                challenges_json=_dump_acme_challenges(challenges),
            )

        if checkpoint.fullchain_pem is None:
            if checkpoint.order_json is None:  # pragma: no cover - storage invariant
                raise ServiceCertError("ACME order checkpoint is incomplete")
            if config.challenge_type is ChallengeType.HTTP_01:
                fullchain = self.acme.complete_http01(
                    account.directory_url,
                    self._account_key(account),
                    account.account_url,
                    checkpoint.order_json,
                    self._publish_http01,
                    self._cleanup_http01,
                )
            else:
                fullchain = self._complete_dns01_order(
                    account,
                    checkpoint.order_json,
                    _load_acme_challenges(checkpoint.challenges_json),
                )
            checkpoint = self.repository.save_acme_fullchain(
                checkpoint.idempotency_key, fullchain
            )

        if checkpoint.fullchain_pem is None:  # pragma: no cover - storage invariant
            raise ServiceCertError("ACME result checkpoint is incomplete")
        result_fingerprint = _fullchain_leaf_sha256(checkpoint.fullchain_pem)
        current = self.repository.get(cert.id)
        current_fingerprint = _certificate_sha256(current.certificate_pem)
        if current_fingerprint == result_fingerprint:
            return current
        if (
            checkpoint.purpose == "renew"
            and current_fingerprint is not None
            and current_fingerprint != checkpoint.prior_certificate_sha256
        ):
            # A later renewal won the race.  Never replace it with this older result.
            return current
        return self._install_fullchain(current, checkpoint.fullchain_pem)

    def _install_fullchain(self, cert: ServiceCertificate, fullchain_pem: str) -> ServiceCertificate:
        leaf_pem, chain_pem = _split_fullchain(fullchain_pem)
        leaf = _parse_certificate(leaf_pem)
        if not self.keystore.certificate_matches_key(
            leaf, cert.key_ref, cert.key_backend
        ):
            raise ServiceCertError(
                "ACME certificate public key does not match the stored private key"
            )
        updated = _with_leaf(cert, leaf, leaf_pem, chain_pem)
        self.repository.update(updated)
        return updated

    def _assert_unique_name(self, name: str) -> None:
        if not name or not name.strip():
            raise ServiceCertError("A service certificate name is required")
        if self.repository.get_by_name(name) is not None:
            raise ServiceCertError(f"A service certificate named '{name}' already exists")


def _with_leaf(cert, leaf, certificate_pem, chain_pem) -> ServiceCertificate:
    return ServiceCertificate(
        id=cert.id,
        name=cert.name,
        source=cert.source,
        status=ServiceCertStatus.ACTIVE,
        key_backend=cert.key_backend,
        key_ref=cert.key_ref,
        created_at=cert.created_at,
        updated_at=datetime.now(timezone.utc),
        csr_pem=cert.csr_pem,
        certificate_pem=certificate_pem,
        chain_pem=chain_pem,
        subject=leaf.subject.rfc4514_string(),
        not_before=leaf.not_valid_before_utc,
        not_after=leaf.not_valid_after_utc,
    )


def _parse_certificate(certificate_pem: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(certificate_pem.encode())
    except ValueError as exc:
        raise ServiceCertError(f"Invalid certificate PEM: {exc}") from exc


def _split_fullchain(fullchain_pem: str) -> tuple[str, str | None]:
    marker = "-----END CERTIFICATE-----"
    blocks = [b + marker for b in fullchain_pem.split(marker) if b.strip()]
    if not blocks:
        raise ServiceCertError("ACME returned an empty certificate chain")
    leaf = blocks[0].lstrip("\n")
    chain = "".join(b.lstrip("\n") for b in blocks[1:]) if len(blocks) > 1 else None
    return leaf, chain


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _certificate_sha256(certificate_pem: str | None) -> str | None:
    if certificate_pem is None:
        return None
    return _parse_certificate(certificate_pem).fingerprint(hashes.SHA256()).hex()


def _fullchain_leaf_sha256(fullchain_pem: str) -> str:
    leaf_pem, _ = _split_fullchain(fullchain_pem)
    fingerprint = _certificate_sha256(leaf_pem)
    if fingerprint is None:  # pragma: no cover - leaf PEM is non-null by construction
        raise ServiceCertError("ACME returned an empty certificate chain")
    return fingerprint


def _dump_acme_challenges(challenges: list[AcmeChallenge]) -> str:
    return json.dumps(
        [
            {
                "domain": challenge.domain,
                "challenge_type": challenge.challenge_type.value,
                "token": challenge.token,
                "key_authorization": challenge.key_authorization,
                "dns_txt_value": challenge.dns_txt_value,
            }
            for challenge in challenges
        ],
        separators=(",", ":"),
        sort_keys=True,
    )


def _load_acme_challenges(payload: str) -> list[AcmeChallenge]:
    try:
        rows = json.loads(payload)
        if not isinstance(rows, list):
            raise TypeError("challenge payload must be a list")
        return [
            AcmeChallenge(
                domain=str(row["domain"]),
                challenge_type=ChallengeType(str(row["challenge_type"])),
                token=str(row["token"]),
                key_authorization=str(row["key_authorization"]),
                dns_txt_value=(
                    None
                    if row.get("dns_txt_value") is None
                    else str(row["dns_txt_value"])
                ),
            )
            for row in rows
            if isinstance(row, dict)
        ]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ServiceCertError("Stored ACME challenge checkpoint is invalid") from exc


def _new_key_ref() -> str:
    return f"svc-{uuid4().hex}"


def _derive_fernet_key(secret: str) -> bytes:
    """This subsystem's domain-separated Fernet key (see myownca.secret_keys)."""
    return derive_fernet_key(secret, SERVICE_CERTS_DOMAIN)
