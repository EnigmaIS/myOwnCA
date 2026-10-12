from __future__ import annotations

import datetime
import unittest
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.asymmetric import ec

from myownca.service_certs import ChallengeType
from myownca.service_certs.renewal import (
    RenewalScheduler,
    is_renewal_automatable,
    renew_due,
)
from tests.test_service_certs import _FakeAcme, _cert_for_public_key, _pem, _self_signed, _service


def _fullchain() -> str:
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _cert_for_public_key(leaf_key.public_key(), ca_key, "example.test")
    return _pem(leaf) + _pem(_self_signed(ca_key, "Test CA"))


def _due(cert) -> datetime.datetime:
    return cert.not_after - datetime.timedelta(days=10)


def _http01_cert(svc, name="web"):
    account = svc.create_account("https://acme.test/dir", "ops@example.test")
    result = svc.request_certificate(
        name, account_id=account.id, domains=("example.test",),
        challenge_type=ChallengeType.HTTP_01,
    )
    return svc.get_cert(result["certificate_id"])


def _run_lifespan(app) -> list[str]:
    """Drive the ASGI lifespan protocol (startup then shutdown) without an HTTP client."""
    import asyncio

    async def _cycle() -> list[str]:
        incoming = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
        sent: list[str] = []

        async def receive():
            return next(incoming)

        async def send(message) -> None:
            sent.append(message["type"])

        await app({"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send)
        return sent

    return asyncio.run(_cycle())


class RenewDueTests(unittest.TestCase):
    def test_renews_due_http01_cert(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            cert = _http01_cert(svc)
            events: list[tuple[str, str]] = []
            rows = renew_due(svc, now=_due(cert), on_event=lambda a, c: events.append((a, c.id)))
            self.assertEqual([r["status"] for r in rows], ["renewed"])
            self.assertEqual(events, [("acme_auto_renewed", cert.id)])

    def test_skips_not_due_cert(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            _http01_cert(svc)
            rows = renew_due(svc, now=datetime.datetime.now(datetime.timezone.utc))
            self.assertEqual(rows, [])

    def test_dns01_with_provider_auto_renews(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            account = svc.create_account("https://acme.test/dir")
            svc.set_account_dns_provider(account.id, "fake", {"auth_username": "u", "auth_token": "t"})
            import myownca.service_certs.service as svc_mod
            svc_mod.wait_for_txt = lambda *a, **k: True  # type: ignore[attr-defined]

            class _FakeProvider:
                def publish_txt(self, name, value): pass
                def remove_txt(self, name, value): pass

            svc._dns_provider = lambda acct: _FakeProvider()  # type: ignore[method-assign]
            result = svc.request_certificate(
                "web", account_id=account.id, domains=("example.test",),
                challenge_type=ChallengeType.DNS_01,
            )
            cert = svc.get_cert(result["certificate_id"])
            events: list[str] = []
            rows = renew_due(svc, now=_due(cert), on_event=lambda a, c: events.append(a))
            self.assertEqual([r["status"] for r in rows], ["renewed"])
            self.assertEqual(events, ["acme_auto_renewed"])

    def test_manual_required_when_dns01_provider_removed(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            account = svc.create_account("https://acme.test/dir")
            svc.set_account_dns_provider(account.id, "fake", {"auth_username": "u", "auth_token": "t"})
            import myownca.service_certs.service as svc_mod
            svc_mod.wait_for_txt = lambda *a, **k: True  # type: ignore[attr-defined]

            class _P:
                def publish_txt(self, n, v): pass
                def remove_txt(self, n, v): pass

            svc._dns_provider = lambda acct: _P()  # type: ignore[method-assign]
            cert = svc.get_cert(svc.request_certificate(
                "web", account_id=account.id, domains=("example.test",),
                challenge_type=ChallengeType.DNS_01)["certificate_id"])
            # Provider unset after issuance -> the scheduler can't auto-renew it.
            svc.repository.set_account_dns_provider(account.id, None, None)
            events: list[str] = []
            rows = renew_due(svc, now=_due(cert), on_event=lambda a, c: events.append(a))
            self.assertEqual([r["status"] for r in rows], ["manual_required"])
            self.assertEqual(events, ["acme_manual_renewal_due"])

    def test_failed_renew_is_recorded_and_does_not_raise(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            cert = _http01_cert(svc)

            def boom(_cert_id):
                raise RuntimeError("acme down")

            svc.renew = boom  # type: ignore[method-assign]
            events: list[str] = []
            rows = renew_due(svc, now=_due(cert), on_event=lambda a, c: events.append(a))
            self.assertEqual([r["status"] for r in rows], ["failed"])
            self.assertEqual(events, ["acme_auto_renew_failed"])

    def test_failed_renew_records_error_row(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            cert = _http01_cert(svc)

            def boom(_cert_id):
                raise RuntimeError("renew-boom")

            svc.renew = boom  # type: ignore[method-assign]
            renew_due(svc, now=_due(cert))
            errors = svc.repository.list_recent_errors()
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0]["operation"], "auto_renew")
            self.assertEqual(errors[0]["target"], cert.name)
            self.assertIn("renew-boom", errors[0]["message"])

    def test_is_renewal_automatable(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            # HTTP-01 is always automatable.
            http_cert = _http01_cert(svc, "h")
            self.assertTrue(is_renewal_automatable(svc, http_cert))
            # Non-ACME cert is never automatable.
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            key = _ec.generate_private_key(_ec.SECP256R1())
            from tests.test_service_certs import _key_pem, _self_signed, _pem
            leaf = _self_signed(key, "imported.example.test")
            imported = svc.import_pem("imported", certificate_pem=_pem(leaf), private_key_pem=_key_pem(key))
            self.assertFalse(is_renewal_automatable(svc, imported))
            # DNS-01 with a provider: automatable.
            account = svc.create_account("https://acme.test/dir2")
            svc.set_account_dns_provider(account.id, "fake", {"auth_username": "u", "auth_token": "t"})
            import myownca.service_certs.service as svc_mod
            svc_mod.wait_for_txt = lambda *a, **k: True  # type: ignore[attr-defined]

            class _P:
                def publish_txt(self, n, v): pass
                def remove_txt(self, n, v): pass

            svc._dns_provider = lambda acct: _P()  # type: ignore[method-assign]
            dresult = svc.request_certificate(
                "d", account_id=account.id, domains=("example.test",),
                challenge_type=ChallengeType.DNS_01,
            )
            dcert = svc.get_cert(dresult["certificate_id"])
            self.assertTrue(is_renewal_automatable(svc, dcert))


class Dns01AutomatableTests(unittest.TestCase):
    def test_dns01_with_provider_is_automatable(self) -> None:
        from tempfile import TemporaryDirectory

        from myownca.service_certs import ChallengeType
        from myownca.service_certs.renewal import is_renewal_automatable

        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            account = svc.create_account("https://acme.test/dir")
            svc.set_account_dns_provider(account.id, "fake", {"auth_username": "u", "auth_token": "t"})

            class _FakeProvider:
                def publish_txt(self, name, value): pass
                def remove_txt(self, name, value): pass

            svc._dns_provider = lambda acct: _FakeProvider()  # type: ignore[method-assign]
            import myownca.service_certs.service as svc_mod
            svc_mod.wait_for_txt = lambda *a, **k: True  # type: ignore[attr-defined]
            result = svc.request_certificate(
                "web", account_id=account.id, domains=("example.test",),
                challenge_type=ChallengeType.DNS_01,
            )
            cert = svc.get_cert(result["certificate_id"])
            self.assertTrue(is_renewal_automatable(svc, cert))


class SchedulerTests(unittest.TestCase):
    def test_start_then_stop_is_clean(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            scheduler = RenewalScheduler(svc, interval_seconds=3600)
            self.assertFalse(scheduler.is_running())
            scheduler.start()
            self.assertTrue(scheduler.is_running())
            scheduler.stop()  # stop interrupts the interval wait immediately
            self.assertFalse(scheduler.is_running())

    def test_run_once_returns_empty_when_nothing_due(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            _http01_cert(svc)  # 90-day cert, not due at real now
            self.assertEqual(RenewalScheduler(svc, interval_seconds=3600).run_once(), [])


class SettingsAcmeTests(unittest.TestCase):
    def test_defaults_on_daily(self) -> None:
        from myownca.config import Settings

        settings = Settings.from_mapping({})
        self.assertTrue(settings.acme_auto_renew)
        self.assertEqual(settings.acme_renew_interval_seconds, 86400)

    def test_env_overrides(self) -> None:
        from myownca.config import Settings

        settings = Settings.from_mapping(
            {"MYOWNCA_ACME_AUTORENEW": "false", "MYOWNCA_ACME_RENEW_INTERVAL_SECONDS": "3600"}
        )
        self.assertFalse(settings.acme_auto_renew)
        self.assertEqual(settings.acme_renew_interval_seconds, 3600)

    def test_bad_interval_falls_back_to_default(self) -> None:
        from myownca.config import Settings

        for bad in ("1day", "-5", "0", "abc"):
            settings = Settings.from_mapping({"MYOWNCA_ACME_RENEW_INTERVAL_SECONDS": bad})
            self.assertEqual(settings.acme_renew_interval_seconds, 86400, bad)


class SchedulerWiringTests(unittest.TestCase):
    def test_create_app_attaches_a_stopped_scheduler(self) -> None:
        from pathlib import Path

        from myownca.online.app import create_app
        from myownca.service_certs.renewal import RenewalScheduler

        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "api.sqlite3", online_key_dir=Path(tempdir) / "keys")
            scheduler = app.state.renewal_scheduler
            self.assertIsInstance(scheduler, RenewalScheduler)
            # create_app must NOT start the thread (the lifespan does, only when serving).
            self.assertFalse(scheduler.is_running())

    def _app_with_autorenew(self, value: str, tempdir: str):
        import os
        from pathlib import Path
        from unittest import mock

        from myownca.online.app import create_app

        with mock.patch.dict(os.environ, {"MYOWNCA_ACME_AUTORENEW": value}):
            return create_app(Path(tempdir) / "api.sqlite3", online_key_dir=Path(tempdir) / "keys")

    def test_lifespan_starts_then_stops_scheduler_when_enabled(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = self._app_with_autorenew("true", tempdir)
            calls = {"start": 0, "stop": 0}
            sched = app.state.renewal_scheduler
            sched.start = lambda: calls.__setitem__("start", calls["start"] + 1)
            sched.stop = lambda: calls.__setitem__("stop", calls["stop"] + 1)
            sent = _run_lifespan(app)
            self.assertEqual(sent, ["lifespan.startup.complete", "lifespan.shutdown.complete"])
            self.assertEqual((calls["start"], calls["stop"]), (1, 1))

    def test_lifespan_does_not_start_when_disabled(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = self._app_with_autorenew("false", tempdir)
            calls = {"start": 0, "stop": 0}
            sched = app.state.renewal_scheduler
            sched.start = lambda: calls.__setitem__("start", calls["start"] + 1)
            sched.stop = lambda: calls.__setitem__("stop", calls["stop"] + 1)
            sent = _run_lifespan(app)
            self.assertEqual(sent, ["lifespan.startup.complete", "lifespan.shutdown.complete"])
            self.assertEqual(calls["start"], 0)  # disabled → never started
            self.assertEqual(calls["stop"], 1)  # stop() always runs on shutdown


if __name__ == "__main__":
    unittest.main()
