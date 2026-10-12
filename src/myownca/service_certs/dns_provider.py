"""DNS-01 challenge automation through a DNS-provider API.

A thin ``DnsProvider`` seam (publish/remove a TXT record) with a ``dns-lexicon``
implementation, plus a bounded poll of the record's authoritative nameservers so we
only finalize once the TXT is visible. ``dns-lexicon`` and ``dnspython`` are bundled
and lazy-imported; an import failure surfaces a clear ``ServiceCertUnavailable``.
"""

from __future__ import annotations

import json
import time
from typing import Callable, Protocol

from myownca.service_certs.base import ServiceCertError, ServiceCertUnavailable

Decrypt = Callable[[str], str]


class DnsProvider(Protocol):
    def publish_txt(self, record_name: str, value: str) -> None: ...
    def remove_txt(self, record_name: str, value: str) -> None: ...


def _lexicon_config_dict(provider_name: str, credentials: dict, domain: str) -> dict:
    """The lexicon config mapping for a provider/zone (split out so it is testable).

    ``resolve_zone_name`` is the load-bearing option: it makes lexicon resolve the real
    hosted zone with a live DNS (SOA) walk instead of guessing it with tldextract.
    Without it, lexicon reduces a delegated sub-zone like ``trinity.athae.net`` to the
    registrable domain ``athae.net``; the provider then can't find that zone in the
    account and raises "No domain found". Pairs with the ``_acme-challenge`` CNAME
    following in ``resolve_cname()`` so apex-elsewhere setups validate via the sub-zone.
    """
    return {
        "provider_name": provider_name,
        "domain": domain,
        "resolve_zone_name": True,
        provider_name: dict(credentials),
    }


def _lexicon_client(provider_name: str, credentials: dict, domain: str):
    """Build a configured lexicon Client context manager for ``domain`` (lazy import)."""
    try:
        from lexicon.client import Client  # noqa: PLC0415
        from lexicon.config import ConfigResolver  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - exercised only without the dep
        raise ServiceCertUnavailable(
            "DNS-01 automation is bundled with myownca; reinstall the complete distribution"
        ) from exc
    config = ConfigResolver().with_dict(_lexicon_config_dict(provider_name, credentials, domain))
    return Client(config)


def _cname_target(name: str) -> str | None:
    """One-step CNAME target for ``name`` via dnspython, or None if it isn't a CNAME.

    CNAME following is an optional enhancement: when dnspython is unavailable we just
    return None (no following). DNS-01 still raises a clear bundled-integration error at
    the publish/poll step, so the missing dependency is never silently swallowed.
    """
    try:
        import dns.resolver  # noqa: PLC0415
    except ImportError:
        return None
    try:
        answer = dns.resolver.resolve(name, "CNAME")
    except Exception:  # noqa: BLE001 - NoAnswer / NXDOMAIN / etc. -> not a CNAME
        return None
    target = str(answer[0].target).rstrip(".")
    return target or None


def resolve_cname(record_name: str, *, _lookup: Callable[[str], "str | None"] = _cname_target) -> str:
    """Follow the CNAME chain for a challenge name, returning the final target.

    Supports DNS-01 *CNAME delegation*: ``_acme-challenge.<domain>`` is CNAMEd into a
    zone you can automate (often a different provider/account). The TXT must be written
    at — and validated from — that target. Returns ``record_name`` unchanged when there
    is no CNAME. The chain is bounded and loop-safe.
    """
    current = record_name.rstrip(".")
    seen = {current}
    for _ in range(10):
        target = _lookup(current)
        if not target or target == current or target in seen:
            break
        seen.add(target)
        current = target
    return current


def _zone_of(record_name: str) -> str:
    """Best-effort zone for a record: drop the leftmost label (the `_acme-challenge`).

    This handles the common cases (`_acme-challenge.example.test` -> `example.test`,
    and a wildcard's `_acme-challenge.example.test`). For a sub-delegated record like
    `_acme-challenge.sub.example.test` this returns `sub.example.test`; most lexicon
    providers (incl. LuaDNS) then resolve the real managed zone themselves by
    longest-suffix match, so the extra label is harmless.
    """
    labels = record_name.rstrip(".").split(".")
    return ".".join(labels[1:]) if len(labels) > 2 else record_name.rstrip(".")


class LexiconDnsProvider:
    """Publish/remove a TXT record via dns-lexicon (LuaDNS and ~90 other providers)."""

    def __init__(self, provider_name: str, credentials: dict) -> None:
        self._provider = provider_name
        self._credentials = credentials

    def publish_txt(self, record_name: str, value: str) -> None:
        try:
            with _lexicon_client(self._provider, self._credentials, _zone_of(record_name)) as ops:
                ops.create_record(rtype="TXT", name=record_name, content=value)
        except ServiceCertUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - surface provider errors as a clean ServiceCertError
            raise ServiceCertError(
                f"DNS provider '{self._provider}' could not publish the TXT record for "
                f"{record_name} (zone {_zone_of(record_name)}): {exc}"
            ) from exc

    def remove_txt(self, record_name: str, value: str) -> None:
        try:
            with _lexicon_client(self._provider, self._credentials, _zone_of(record_name)) as ops:
                ops.delete_record(rtype="TXT", name=record_name, content=value)
        except ServiceCertUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - surface provider errors as a clean ServiceCertError
            raise ServiceCertError(
                f"DNS provider '{self._provider}' could not remove the TXT record for "
                f"{record_name} (zone {_zone_of(record_name)}): {exc}"
            ) from exc


def _authoritative_txt_values(record_name: str) -> set[str]:
    """TXT values for ``record_name`` as served by its authoritative nameservers (lazy dnspython)."""
    try:
        import dns.resolver  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - exercised only without the dep
        raise ServiceCertUnavailable(
            "DNS-01 automation is bundled with myownca; reinstall the complete distribution"
        ) from exc
    labels = record_name.rstrip(".").split(".")
    nameservers: list[str] = []
    for i in range(len(labels) - 1):  # walk up to the delegated zone
        try:
            answer = dns.resolver.resolve(".".join(labels[i:]), "NS")
            nameservers = [str(r.target) for r in answer]
            break
        except Exception:  # noqa: BLE001 - try the parent zone
            continue
    ips: list[str] = []
    for ns in nameservers:
        try:
            ips.append(str(dns.resolver.resolve(ns, "A")[0]))
        except Exception:  # noqa: BLE001
            continue
    values: set[str] = set()
    resolver = dns.resolver.Resolver(configure=False)
    for ip in ips:
        resolver.nameservers = [ip]
        try:
            for rdata in resolver.resolve(record_name, "TXT"):
                values.add(b"".join(rdata.strings).decode())
        except Exception:  # noqa: BLE001 - this NS may not have it yet
            continue
    return values


def wait_for_txt(
    record_name: str,
    expected_value: str,
    *,
    timeout_seconds: int = 120,
    interval_seconds: int = 5,
    _resolve: Callable[[str], set[str]] = _authoritative_txt_values,
    _sleep: Callable[[float], None] = time.sleep,
    _clock: Callable[[], float] = time.monotonic,
) -> bool:
    """Poll the authoritative nameservers until ``expected_value`` is visible, or timeout."""
    deadline = _clock() + timeout_seconds
    while True:
        if expected_value in _resolve(record_name):
            return True
        if _clock() >= deadline:
            return False
        _sleep(interval_seconds)


def provider_from_account(account, decrypt: Decrypt) -> DnsProvider | None:
    """A ``LexiconDnsProvider`` for the account's configured provider, or None."""
    if not getattr(account, "dns_provider", None) or not account.dns_credentials_ciphertext:
        return None
    credentials = json.loads(decrypt(account.dns_credentials_ciphertext))
    return LexiconDnsProvider(account.dns_provider, credentials)
