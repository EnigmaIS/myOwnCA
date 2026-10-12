from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class ServiceCertSource(StrEnum):
    CSR_EXTERNAL = "csr_external"
    IMPORTED = "imported"
    ACME = "acme"


class ServiceCertStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    SUPERSEDED = "superseded"


class KeyBackend(StrEnum):
    SOFTWARE = "software"
    PKCS11 = "pkcs11"
    AWS_KMS = "aws_kms"
    AZURE_KEY_VAULT = "azure_key_vault"


class ChallengeType(StrEnum):
    HTTP_01 = "http-01"
    DNS_01 = "dns-01"


class ServiceCertError(RuntimeError):
    """Raised for service-certificate management failures."""


class ServiceCertUnavailable(ServiceCertError):
    """Raised when a bundled service-certificate integration cannot be imported."""


class AcmeOrderIndeterminate(ServiceCertError):
    """The provider may have created an order whose URL was not received."""


class AcmeAccountInUseError(ServiceCertError):
    """Deleting an ACME account that still backs issued certificates, without ``force``."""

    def __init__(self, dependents) -> None:
        self.dependents = tuple(dependents)
        names = ", ".join(c.name for c in self.dependents)
        super().__init__(
            f"Account still backs {len(self.dependents)} certificate(s) ({names}); "
            "pass force=true to delete the account and drop their auto-renewal."
        )


@dataclass(frozen=True, slots=True)
class ServiceCertificate:
    id: str
    name: str
    source: ServiceCertSource
    status: ServiceCertStatus
    key_backend: KeyBackend
    key_ref: str
    created_at: datetime
    updated_at: datetime
    csr_pem: str | None = None
    certificate_pem: str | None = None
    chain_pem: str | None = None
    subject: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None


@dataclass(frozen=True, slots=True)
class AcmeAccount:
    id: str
    directory_url: str
    account_key_ciphertext: str
    created_at: datetime
    account_url: str | None = None
    contact: str = ""
    dns_provider: str | None = None
    dns_credentials_ciphertext: str | None = None


@dataclass(frozen=True, slots=True)
class AcmeCertConfig:
    service_certificate_id: str
    account_id: str
    domains: tuple[str, ...]
    challenge_type: ChallengeType
    renew_before_days: int = 30


@dataclass(frozen=True, slots=True)
class AcmeChallenge:
    domain: str
    challenge_type: ChallengeType
    token: str
    key_authorization: str
    # For dns-01: the value to publish at _acme-challenge.<domain> TXT.
    dns_txt_value: str | None = None


@dataclass(frozen=True, slots=True)
class AcmeOrderCheckpoint:
    """Durable state for one idempotent ACME issue or renewal operation."""

    idempotency_key: str
    service_certificate_id: str
    purpose: str
    state: str
    csr_pem: str
    csr_sha256: str
    prior_certificate_sha256: str | None
    order_url: str | None
    order_json: str | None
    challenges_json: str
    fullchain_pem: str | None
    created_at: datetime
    updated_at: datetime
