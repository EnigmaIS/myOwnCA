"""Automatic renewal of ACME service certificates.

A small background scheduler renews certificates inside their renewal window
without human intervention. In phase 1 only HTTP-01 certificates are
"automatable" (the app serves the challenge itself); a DNS-01 certificate with no
DNS provider configured is reported as needing manual action and left untouched.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Callable

from myownca.service_certs.base import ChallengeType, ServiceCertificate, ServiceCertSource
from myownca.service_certs.service import ServiceCertService

logger = logging.getLogger(__name__)

# Audit actions the caller may record per cert (passed to ``on_event``).
RENEWED = "acme_auto_renewed"
FAILED = "acme_auto_renew_failed"
MANUAL = "acme_manual_renewal_due"

OnEvent = Callable[[str, ServiceCertificate], None]
RenewCallback = Callable[[ServiceCertificate], object]


def is_renewal_automatable(service: ServiceCertService, cert: ServiceCertificate) -> bool:
    """HTTP-01 always; DNS-01 only when the cert's ACME account has a DNS provider."""
    if cert.source is not ServiceCertSource.ACME:
        return False
    config = service.repository.get_cert_config(cert.id)
    if config is None:
        return False
    if config.challenge_type is ChallengeType.HTTP_01:
        return True
    if config.challenge_type is ChallengeType.DNS_01:
        # Match provider_from_account's guard: both the provider and its (encrypted)
        # credentials must be present for the renewal to actually be automatable.
        account = service.repository.get_account(config.account_id)
        return bool(account.dns_provider) and account.dns_credentials_ciphertext is not None
    return False


def renew_due(
    service: ServiceCertService,
    *,
    now: datetime | None = None,
    on_event: OnEvent | None = None,
    renew_callback: RenewCallback | None = None,
) -> list[dict]:
    """Renew every automatable cert that is due. Best-effort; never raises.

    Returns one row per due cert: ``{"id", "name", "status"}`` with status
    ``"renewed"``, ``"failed"``, or ``"manual_required"``. ``on_event(action, cert)``
    is invoked per row so the caller can audit.
    """
    current = now or datetime.now(timezone.utc)
    results: list[dict] = []
    for cert in service.due_for_renewal(current):
        if not is_renewal_automatable(service, cert):
            results.append({"id": cert.id, "name": cert.name, "status": "manual_required"})
            if on_event:
                on_event(MANUAL, cert)
            continue
        try:
            if renew_callback is None:
                service.renew(cert.id)
            else:
                renew_callback(cert)
        except Exception as exc:  # noqa: BLE001 - one bad cert must not stop the rest
            logger.warning("auto-renew failed for service cert %s", cert.id, exc_info=True)
            try:
                service.repository.record_error("auto_renew", cert.name, str(exc))
            except Exception:  # noqa: BLE001 - recording must not break the sweep
                logger.warning("failed to record auto-renew error for %s", cert.id, exc_info=True)
            results.append({"id": cert.id, "name": cert.name, "status": "failed"})
            if on_event:
                on_event(FAILED, cert)
            continue
        results.append({"id": cert.id, "name": cert.name, "status": "renewed"})
        if on_event:
            on_event(RENEWED, cert)
    return results


class RenewalScheduler:
    """Daemon thread that runs ``renew_due`` every ``interval_seconds``."""

    def __init__(
        self,
        service: ServiceCertService,
        *,
        interval_seconds: int,
        on_event: OnEvent | None = None,
        renew_callback: RenewCallback | None = None,
    ) -> None:
        self._service = service
        self._interval = max(int(interval_seconds), 1)
        self._on_event = on_event
        self._renew_callback = renew_callback
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self) -> list[dict]:
        return renew_due(
            self._service,
            on_event=self._on_event,
            renew_callback=self._renew_callback,
        )

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_running():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="acme-renewal", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self) -> None:
        # Wait first, then renew, so process startup isn't blocked by a renewal pass.
        # ``Event.wait`` returns True the instant stop() is called, so shutdown is prompt.
        while not self._stop.wait(self._interval):
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 - keep the thread alive across any error
                logger.warning("renewal scheduler pass failed", exc_info=True)
