from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from myownca.online.operations import OperationsService


NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)


class _JobRepository:
    def __init__(self, jobs: list[object] | None = None, *, failure: Exception | None = None):
        self.jobs = jobs or []
        self.failure = failure

    def list_all(self, *, limit: int = 100) -> list[object]:
        if self.failure is not None:
            raise self.failure
        return self.jobs[:limit]


def _service(job_repository: _JobRepository | None = None) -> OperationsService:
    unused = object()
    return OperationsService(
        repository=unused,
        notification_repository=unused,
        service_cert_repository=unused,
        comms_repository=unused,
        licensing_service=unused,
        audit_service=unused,
        proposal_repository=unused,
        backup_repository=unused,
        issuer_provider=lambda: None,
        hsm_backend_provider=lambda: "software",
        lab_mode=False,
        signing_job_repository=job_repository,
    )


def _job(
    job_id: str,
    status: str,
    created_at: datetime,
    *,
    error_code: str | None = None,
    error_message: str | None = None,
) -> object:
    return SimpleNamespace(
        id=job_id,
        status=status,
        created_at=created_at,
        last_error_code=error_code,
        last_error_message=error_message,
        # Operational alerts must never inspect or serialize either field.
        cloud_key_id="secret-vault-key-reference",
        payload={"certificate": "secret-payload-material"},
    )


class CloudSigningOperationsAlertTests(unittest.TestCase):
    def test_absent_empty_or_unavailable_queue_does_not_change_local_dashboard(self) -> None:
        self.assertEqual(_service()._cloud_signing_alert_items(NOW), [])
        self.assertEqual(
            _service(_JobRepository())._cloud_signing_alert_items(NOW), []
        )
        self.assertEqual(
            _service(
                _JobRepository(failure=RuntimeError("queue unavailable"))
            )._cloud_signing_alert_items(NOW),
            [],
        )

    def test_stale_active_and_failed_jobs_have_stable_non_secret_alerts(self) -> None:
        jobs = [
            _job(
                "queued-1",
                "queued",
                NOW - timedelta(minutes=16),
                error_code="provider_throttled",
                error_message="Provider is temporarily unavailable",
            ),
            _job("running-1", "running", NOW - timedelta(minutes=15)),
            _job(
                "failed-1",
                "failed",
                NOW - timedelta(minutes=1),
                error_code="invalid_key_state",
                error_message="Remote signing key is not enabled",
            ),
            _job("fresh-queued", "queued", NOW - timedelta(minutes=14)),
            _job("succeeded-1", "succeeded", NOW - timedelta(days=1)),
            _job("canceled-1", "canceled", NOW - timedelta(days=1)),
        ]

        alerts = _service(_JobRepository(jobs))._cloud_signing_alert_items(NOW)

        self.assertEqual(
            [alert["id"] for alert in alerts],
            [
                "cloud_signing.job.queued-1",
                "cloud_signing.job.running-1",
                "cloud_signing.job.failed-1",
            ],
        )
        self.assertEqual(alerts[0]["status"], "warn")
        self.assertEqual(alerts[0]["severity"], "warning")
        self.assertIn("queued-1", alerts[0]["summary"])
        self.assertIn("provider_throttled", alerts[0]["summary"])
        self.assertEqual(alerts[1]["action"]["href"], "#/hsm")
        self.assertEqual(alerts[2]["status"], "fail")
        self.assertEqual(alerts[2]["severity"], "critical")
        self.assertIn("invalid_key_state", alerts[2]["summary"])

        rendered = repr(alerts)
        self.assertNotIn("secret-vault-key-reference", rendered)
        self.assertNotIn("secret-payload-material", rendered)
        for alert in alerts:
            self.assertEqual(
                set(alert),
                {
                    "id",
                    "title",
                    "summary",
                    "status",
                    "severity",
                    "owner",
                    "action",
                    "checked_at",
                },
            )

    def test_provider_safe_error_is_single_line_and_bounded(self) -> None:
        job = _job(
            "failed-2",
            "failed",
            NOW,
            error_code="provider_error\ncode",
            error_message="detail\n" + ("x" * 1_000),
        )

        alert = _service(_JobRepository([job]))._cloud_signing_alert_items(NOW)[0]

        self.assertNotIn("\n", alert["summary"])
        self.assertLess(len(alert["summary"]), 700)


if __name__ == "__main__":
    unittest.main()
