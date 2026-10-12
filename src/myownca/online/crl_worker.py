from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography.hazmat.primitives import hashes

from myownca.ca_main.crypto import IssuerMaterial
from myownca.ca_main.service import CAMainService
from myownca.domain import IssuerCRL
from myownca.storage.repositories import PKIRepository

logger = logging.getLogger(__name__)


class CRLMaintenanceWorker:
    """Event-driven CRL generation backed by the durable database queue."""

    def __init__(
        self,
        repository: PKIRepository,
        service: CAMainService,
        issuer_provider: Callable[[], IssuerMaterial | None],
        *,
        renewal_margin: timedelta = timedelta(hours=24),
        safety_reconciliation_seconds: int = 300,
        on_generated: Callable[[IssuerCRL], None] | None = None,
    ) -> None:
        self.repository = repository
        self.service = service
        self.issuer_provider = issuer_provider
        self.renewal_margin = renewal_margin
        self.safety_reconciliation_seconds = max(
            int(safety_reconciliation_seconds), 1
        )
        self.on_generated = on_generated
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lease_owner = f"crl-worker:{uuid4()}"

    def start(self) -> None:
        if self.is_running():
            return
        self._stop.clear()
        self.repository.recover_expired_crl_jobs()
        self._thread = threading.Thread(
            target=self._loop,
            name="crl-maintenance",
            daemon=True,
        )
        self._thread.start()
        self.kick()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def kick(self, _issuer_id: str | None = None) -> None:
        self._wake.set()

    def enqueue(
        self,
        issuer: IssuerMaterial,
        *,
        now: datetime | None = None,
    ):
        issuer_id = issuer.certificate.fingerprint(hashes.SHA256()).hex()
        job = self.repository.enqueue_crl_refresh(
            issuer_id,
            issuer.certificate.subject.rfc4514_string(),
            now=now,
        )
        self.kick(issuer_id)
        return job

    def run_once(self, now: datetime | None = None) -> IssuerCRL | None:
        current = _utc(now)
        self.repository.recover_expired_crl_jobs(current)
        issuer = self.issuer_provider()
        if issuer is None:
            return None
        issuer_id = issuer.certificate.fingerprint(hashes.SHA256()).hex()
        issuer_subject = issuer.certificate.subject.rfc4514_string()
        latest = self.repository.get_latest_issuer_crl(issuer_subject, issuer_id)
        job = self.repository.get_crl_job(issuer_id)
        renewal_due = (
            latest is None
            or latest.next_update is None
            or latest.next_update <= current + self.renewal_margin
        )
        if renewal_due and (job is None or job.status == "complete"):
            job = self.repository.enqueue_crl_refresh(
                issuer_id, issuer_subject, now=current
            )
        claimed = self.repository.claim_crl_job(
            issuer_id,
            lease_owner=self._lease_owner,
            now=current,
            lease_seconds=300,
        )
        if claimed is None:
            return None
        try:
            generated_now = False
            crl = (
                self.repository.get_issuer_crl_by_number(
                    issuer_subject,
                    issuer_id,
                    claimed.reserved_number,
                )
                if claimed.reserved_number is not None
                else None
            )
            if crl is None:
                crl = self.service.generate_crl(
                    issuer,
                    now=current,
                    crl_number=claimed.reserved_number,
                )
                generated_now = True
            completed = self.repository.complete_crl_job(
                issuer_id,
                lease_owner=self._lease_owner,
                completed_generation=claimed.requested_generation,
                now=current,
            )
            if generated_now and self.on_generated is not None:
                self.on_generated(crl)
            if completed.status == "pending":
                self.kick(issuer_id)
            return crl
        except Exception as exc:  # noqa: BLE001 - durable retry is the contract
            logger.warning("CRL generation failed for issuer %s", issuer_id, exc_info=True)
            self.repository.fail_crl_job(
                issuer_id,
                lease_owner=self._lease_owner,
                error=f"CRL generation failed ({type(exc).__name__})",
                now=current,
            )
            return None

    def status(self) -> dict[str, object]:
        issuer = self.issuer_provider()
        if issuer is None:
            return {
                "issuer_id": None,
                "job": None,
                "latest": None,
                "worker_running": self.is_running(),
            }
        issuer_id = issuer.certificate.fingerprint(hashes.SHA256()).hex()
        subject = issuer.certificate.subject.rfc4514_string()
        job = self.repository.get_crl_job(issuer_id)
        latest = self.repository.get_latest_issuer_crl(subject, issuer_id)
        return {
            "issuer_id": issuer_id,
            "worker_running": self.is_running(),
            "job": (
                {
                    "id": job.job_id,
                    "status": job.status,
                    "requested_generation": job.requested_generation,
                    "completed_generation": job.completed_generation,
                    "next_attempt_at": job.next_attempt_at.isoformat(),
                    "attempt_count": job.attempt_count,
                    "reserved_number": job.reserved_number,
                    "last_error": job.last_error,
                }
                if job is not None
                else None
            ),
            "latest": (
                {
                    "number": latest.number,
                    "this_update": (
                        latest.this_update.isoformat()
                        if latest.this_update is not None
                        else None
                    ),
                    "next_update": (
                        latest.next_update.isoformat()
                        if latest.next_update is not None
                        else None
                    ),
                    "generated_at": latest.generated_at.isoformat(),
                }
                if latest is not None
                else None
            ),
        }

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._wake.clear()
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 - keep the recovery worker alive
                logger.warning("CRL maintenance pass failed", exc_info=True)
            if self._stop.is_set():
                return
            self._wake.wait(self._wait_timeout())

    def _wait_timeout(self) -> float:
        timeout = float(self.safety_reconciliation_seconds)
        issuer = self.issuer_provider()
        if issuer is None:
            return timeout
        issuer_id = issuer.certificate.fingerprint(hashes.SHA256()).hex()
        subject = issuer.certificate.subject.rfc4514_string()
        current = datetime.now(timezone.utc)
        job = self.repository.get_crl_job(issuer_id)
        if job is not None and job.status == "pending":
            timeout = min(timeout, max((job.next_attempt_at - current).total_seconds(), 0.0))
        latest = self.repository.get_latest_issuer_crl(subject, issuer_id)
        if latest is not None and latest.next_update is not None:
            renew_at = latest.next_update - self.renewal_margin
            timeout = min(timeout, max((renew_at - current).total_seconds(), 0.0))
        return max(timeout, 0.05)


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)
