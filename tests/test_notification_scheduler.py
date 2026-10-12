from __future__ import annotations

import asyncio
import os
from datetime import timedelta
from queue import Queue
from threading import Event, Thread
from unittest import mock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

from myownca.comms import CommsError, DeliveryResult
from myownca.domain import Role
from myownca.notifications import NotificationEvent, NotificationRepository, NotificationService
from myownca.notifications.cli import main as notify_main
from myownca.notifications.schedule import NotificationSchedule, NotificationScheduleSettings
from myownca.online.app import create_app
from myownca.online.scheduler import IntervalScheduler
from myownca.storage.database import Database
from myownca.storage.repositories import PKIRepository
from tests.helpers import add_login_ready_user, create_active_session, request_with_session, route_endpoint
from tests import test_notifications_schedule as inventory_tests

NOW = inventory_tests.NOW


@pytest.fixture
def inventory():
    case = inventory_tests.RunScheduledTests()
    case.setUp()
    case._add_cert("SOON", expires=NOW + timedelta(days=10))
    case._rule("r-exp", NotificationEvent.EXPIRING, template="notify-expiring")
    yield case
    case.tearDown()


def settings(enabled=True, interval=86400):
    return NotificationScheduleSettings(enabled=enabled, interval_seconds=interval)


def watch_wait(scheduler):
    """Observe worker wait boundaries without sleeps or production-sized delays."""
    waits = Queue()
    original = scheduler._condition.wait

    def wait(timeout=None):
        waits.put(timeout)
        return original(timeout)

    scheduler._condition.wait = wait
    return waits


def test_live_cadence_recalculates_from_completion(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("myownca.online.scheduler.monotonic", lambda: clock[0])
    calls = Queue()
    scheduler = IntervalScheduler(lambda: calls.put(clock[0]), interval_seconds=100, name="test")
    waits = watch_wait(scheduler)
    scheduler.start()
    try:
        assert waits.get(timeout=2) == 100  # existing callers still wait first
        clock[0] = 20
        scheduler.configure(interval_seconds=200, enabled=True)
        assert waits.get(timeout=2) == 180
        scheduler.configure(interval_seconds=10, enabled=True)
        assert calls.get(timeout=2) == 20  # shortened deadline already passed
        assert waits.get(timeout=2) == 10
        scheduler.configure(interval_seconds=10, enabled=True)
        assert waits.get(timeout=2) == 10
        assert calls.empty()
        scheduler.configure(interval_seconds=1, enabled=False)
        assert waits.get(timeout=2) is None
        clock[0] = 1000
        scheduler.configure(interval_seconds=100, enabled=True)
        assert calls.get(timeout=2) == 1000
        assert waits.get(timeout=2) == 100
    finally:
        scheduler.stop()
    assert not scheduler.is_running()


def test_active_pass_updates_coalesce_and_stop_retains_worker(monkeypatch):
    entered, release = Event(), Event()
    calls = []
    clock = [0.0]
    monkeypatch.setattr("myownca.online.scheduler.monotonic", lambda: clock[0])

    def tick():
        calls.append(1)
        entered.set()
        assert release.wait(2)

    scheduler = IntervalScheduler(tick, interval_seconds=100, name="test", run_immediately=True)
    waits = watch_wait(scheduler)
    scheduler.start()
    assert entered.wait(2)
    try:
        scheduler.configure(interval_seconds=200, enabled=False)
        scheduler.configure(interval_seconds=300, enabled=True)
        clock[0] = 500
        release.set()
        assert waits.get(timeout=2) == 300
        assert len(calls) == 2  # one coalesced enable request, no concurrent execution
    finally:
        release.set()
        scheduler.stop()

    entered.clear()
    release.clear()
    scheduler.start()
    assert entered.wait(2)
    thread = scheduler._thread
    try:
        # Simulate expiry of the bounded join while the delivery is still blocked.
        with mock.patch.object(thread, "join"):
            scheduler.stop()
        scheduler.start()
        assert scheduler._thread is thread
        assert scheduler.is_running()
    finally:
        release.set()
        scheduler.stop()
    assert not scheduler.is_running()


def test_failure_does_not_kill_worker(monkeypatch, caplog):
    clock = [0.0]
    monkeypatch.setattr("myownca.online.scheduler.monotonic", lambda: clock[0])
    tick = mock.Mock(side_effect=[RuntimeError("delivery broke"), None])
    scheduler = IntervalScheduler(tick, interval_seconds=10, name="test", run_immediately=True)
    waits = watch_wait(scheduler)
    scheduler.start()
    try:
        assert waits.get(timeout=2) == 10
        assert "scheduler pass failed" in caplog.text
        clock[0] = 10
        scheduler.configure(interval_seconds=10, enabled=True)
        assert waits.get(timeout=2) == 10
        assert tick.call_count == 2
        assert scheduler.is_running()
    finally:
        scheduler.stop()


def test_schedule_persistence_atomic_failure_and_unchanged_update(inventory):
    schedule = NotificationSchedule(inventory.pki.repository, inventory.service)
    assert schedule.settings() == settings(False)
    with mock.patch.object(schedule.scheduler, "configure") as configure:
        schedule.update(settings(True, 3600))
        schedule.update(settings(True, 3600))
        configure.assert_called_once_with(interval_seconds=3600, enabled=True)
        with mock.patch.object(schedule.repository, "set_setting", side_effect=RuntimeError):
            with pytest.raises(RuntimeError):
                schedule.update(settings(False, 60))
        assert schedule.settings() == settings(True, 3600)
    restarted = NotificationSchedule(inventory.pki.repository, inventory.service)
    assert restarted.settings() == settings(True, 3600)
    assert not restarted.scheduler.is_running()


@pytest.mark.parametrize("interval", [0, -1, 1.5, "60", True, 2147483648])
def test_invalid_cadence(interval):
    with pytest.raises(ValidationError):
        settings(interval=interval)


@pytest.mark.parametrize("failure", ["result", "exception", "unreachable"])
def test_failed_deliveries_are_visible_and_keep_rule_cadence(inventory, failure, caplog):
    if failure == "unreachable":
        inventory.service.resolve_recipients = mock.Mock(return_value=[])
    elif failure == "exception":
        inventory.comms.send = mock.Mock(side_effect=CommsError("offline"))
    else:
        inventory.comms.send = mock.Mock(side_effect=lambda channel, recipient, message:
            DeliveryResult(channel=channel, recipient=recipient, success=False, detail="offline"))
    schedule = NotificationSchedule(inventory.pki.repository, inventory.service)
    schedule.update(settings())
    with mock.patch("myownca.notifications.service._utc_now", return_value=NOW):
        schedule.scheduler.run_once()
    assert "sent=0 failed=1" in caplog.text
    assert inventory.repo.get_rule("r-exp").last_run_at == NOW
    assert not inventory.repo.list_log()[0].success
    assert not inventory.service.run_scheduled(NOW + timedelta(days=1))["rules"][0]["due"]


def test_service_overlap_and_exception_release(inventory):
    entered, release = Event(), Event()
    send = inventory.comms.send

    def blocked_send(*args):
        entered.set()
        assert release.wait(2)
        return send(*args)

    inventory.comms.send = blocked_send
    thread = Thread(target=lambda: inventory.service.run_scheduled(NOW))
    thread.start()
    try:
        assert entered.wait(2)
        overlap = inventory.service.run_scheduled(NOW, force=True)
        assert overlap["skipped_reason"] == "already_running"
        assert overlap["rules"] == []
    finally:
        release.set()
        thread.join(2)
    assert len(inventory.comms.sent) == 1
    with mock.patch.object(inventory.service.pki_repository, "list_issued_certificates",
                           side_effect=RuntimeError("database failed")):
        with pytest.raises(RuntimeError):
            inventory.service.run_scheduled(NOW)
    assert "skipped_reason" not in inventory.service.run_scheduled(NOW)


def test_restart_catchup_and_exact_period_boundary(inventory):
    assert inventory.service.run_scheduled(NOW)["rules"][0]["sent"] == 1
    restarted = NotificationService(inventory.repo, inventory.pki.repository, inventory.comms)
    before = restarted.run_scheduled(NOW + timedelta(days=7, microseconds=-1))
    assert not before["rules"][0]["due"]
    # Preserve the existing inclusive successful-delivery dedup boundary.
    exact = restarted.run_scheduled(NOW + timedelta(days=7))
    assert exact["rules"][0]["due"]
    assert exact["rules"][0]["skipped"] == 1
    inventory._rule("r-dead", NotificationEvent.EXPIRED, template="notify-expired")
    later = restarted.run_scheduled(NOW + timedelta(days=100))
    assert next(row for row in later["rules"] if row["rule_id"] == "r-dead")["sent"] == 1
    assert len(inventory.comms.sent) == 2  # no replay of missed periods
    assert all(not row["due"] for row in restarted.run_scheduled(
        NOW + timedelta(days=100))["rules"])


def test_partial_pass_failure_retries_without_resending_success(inventory):
    inventory._add_cert("SECOND", expires=NOW + timedelta(days=10))
    send = inventory.comms.send
    attempts = []

    def fail_second(*args):
        attempts.append(1)
        if len(attempts) == 2:
            raise RuntimeError("unexpected transport error")
        return send(*args)

    inventory.comms.send = fail_second
    with pytest.raises(RuntimeError):
        inventory.service.run_scheduled(NOW)
    assert inventory.repo.get_rule("r-exp").last_run_at is None
    assert len(inventory.comms.sent) == 1
    inventory.comms.send = send
    restarted = NotificationService(inventory.repo, inventory.pki.repository, inventory.comms)
    summary = restarted.run_scheduled(NOW + timedelta(hours=1))
    assert summary["rules"][0]["sent"] == 1
    assert summary["rules"][0]["skipped"] == 1
    assert len(inventory.comms.sent) == 2


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("MYOWNCA_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("MYOWNCA_SERVICE_KEY_DIR", str(tmp_path / "service-keys"))
    return create_app(tmp_path / "app.sqlite3", online_key_dir=tmp_path / "keys", lab_mode=True)


def authenticated(app, role):
    email = f"{role.value}@test.example"
    secret = add_login_ready_user(app, user_id=role.value, email=email, role=role)
    return create_active_session(app, email=email, totp_secret=secret)


def test_api_shared_settings_authorization_csrf_and_audit(app):
    get = route_endpoint(app, "/internal/notifications/schedule", "GET")
    put = route_endpoint(app, "/internal/notifications/schedule", "PUT")
    tokens = {role: authenticated(app, role) for role in (
        Role.ADMIN, Role.SUPERUSER, Role.USER, Role.AUDITOR,
    )}
    with pytest.raises(HTTPException) as error:
        get(request_with_session())
    assert error.value.status_code == 401
    for role in (Role.ADMIN, Role.SUPERUSER):
        token, csrf = tokens[role]
        interval = 3600 if role == Role.ADMIN else 7200
        assert put(settings(True, interval), request_with_session(token, csrf, method="PUT")) == {
            "enabled": True, "interval_seconds": interval,
        }
        for reader in (Role.ADMIN, Role.SUPERUSER):
            assert get(request_with_session(*tokens[reader]))["interval_seconds"] == interval
        with pytest.raises(HTTPException) as error:
            put(settings(False), request_with_session(token, "wrong", method="PUT"))
        assert error.value.status_code == 403
    for role in (Role.USER, Role.AUDITOR):
        for operation in (
            lambda: get(request_with_session(*tokens[role])),
            lambda: put(settings(), request_with_session(*tokens[role], method="PUT")),
        ):
            with pytest.raises(HTTPException) as error:
                operation()
            assert error.value.status_code == 403
    events = [e for e in app.state.audit.repository.list_events(limit=20)
              if e.action == "notification_schedule_updated"]
    assert len(events) == 2
    assert events[0].details["previous"]["interval_seconds"] == 3600
    assert events[0].details["current"]["interval_seconds"] == 7200
    assert not app.state.notification_scheduler.is_running()


def test_portal_reports_overlap_with_background_pass(app):
    token, csrf = authenticated(app, Role.SUPERUSER)
    entered, release = Event(), Event()

    def blocked_pass(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        return {"rules": []}

    app.state.notification_schedule.update(settings())
    with mock.patch.object(app.state.notifications, "_run_scheduled", side_effect=blocked_pass):
        thread = Thread(target=app.state.notification_scheduler.run_once)
        thread.start()
        try:
            assert entered.wait(2)
            summary = route_endpoint(app, "/internal/notifications/run", "POST")(
                request_with_session(token, csrf, method="POST")
            )
            assert summary["skipped_reason"] == "already_running"
            event = next(e for e in app.state.audit.repository.list_events(limit=10)
                         if e.action == "notifications_run")
            assert event.details["skipped_reason"] == "already_running"
        finally:
            release.set()
            thread.join(2)


@pytest.mark.parametrize("enabled", [False, True])
def test_lifespan_and_live_settings_do_not_block_startup(app, enabled):
    schedule = app.state.notification_schedule
    schedule.update(settings(enabled))
    entered, release = Event(), Event()
    calls = []

    def run():
        calls.append(1)
        entered.set()
        assert release.wait(2)
        return {"rules": []}

    app.state.notifications.run_scheduled = run
    assert not schedule.scheduler.is_running()
    assert schedule.notifications.repository.database is app.state.repository.database

    async def cycle():
        async with app.router.lifespan_context(app):
            assert schedule.scheduler.is_running()
            if not enabled:
                assert not entered.is_set()
                schedule.update(settings(True, 60))
            assert await asyncio.to_thread(entered.wait, 2)
            schedule.update(settings(False, 120))
            release.set()

    try:
        asyncio.run(cycle())
    finally:
        release.set()
        schedule.scheduler.stop()
    assert calls == [1]
    assert not schedule.scheduler.is_running()


@pytest.mark.parametrize("use_url", [False, True])
def test_cli_selects_effective_database(tmp_path, monkeypatch, use_url, capsys):
    path = tmp_path / "fallback.sqlite3"
    url = f"sqlite:///{tmp_path / 'url.sqlite3'}" if use_url else ""
    monkeypatch.setenv("MYOWNCA_DATABASE_PATH", str(path))
    monkeypatch.setenv("MYOWNCA_DATABASE_URL", url)
    with mock.patch("myownca.notifications.cli.Database", wraps=Database) as database:
        assert notify_main(["--dry-run", "--force", "--event", "expired"]) == 0
    database.assert_called_once_with(url or path)
    assert "No enabled" in capsys.readouterr().out
    assert path.exists() is (not use_url)


def test_application_explicit_database_override_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("MYOWNCA_DATABASE_URL", "mysql+pymysql://unused:unused@invalid/unused")
    monkeypatch.setenv("MYOWNCA_STATE_DIR", str(tmp_path / "state"))
    app = create_app(tmp_path / "explicit.sqlite3", online_key_dir=tmp_path / "keys")
    assert app.state.notification_schedule.notifications.repository.database.dialect == "sqlite"


@pytest.mark.skipif(not os.environ.get("MYOWNCA_TEST_MARIADB_ADMIN_URL"),
                    reason="set MYOWNCA_TEST_MARIADB_ADMIN_URL for real MariaDB coverage")
def test_real_mariadb_notification_schedule(tmp_path, monkeypatch, inventory):
    admin_url = make_url(os.environ["MYOWNCA_TEST_MARIADB_ADMIN_URL"])
    name = f"myownca_notify_test_{uuid4().hex}"
    engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as connection:
        connection.exec_driver_sql(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4")
    target = admin_url.set(database=name).render_as_string(hide_password=False)
    try:
        monkeypatch.setenv("MYOWNCA_STATE_DIR", str(tmp_path / "state"))
        monkeypatch.setenv("MYOWNCA_DATABASE_URL", target)
        monkeypatch.setenv("MYOWNCA_DATABASE_PATH", str(tmp_path / "unused.sqlite3"))
        monkeypatch.setenv("MYOWNCA_SERVICE_KEY_DIR", str(tmp_path / "service-keys"))
        app = create_app(online_key_dir=tmp_path / "keys", lab_mode=True)
        schedule = app.state.notification_schedule
        database = schedule.notifications.repository.database
        assert database.dialect in {"mysql", "mariadb"}
        # All repositories use MariaDB; only outbound delivery is replaced.
        repository = NotificationRepository(database)
        repository.add_template(inventory.repo.get_template("notify-expiring"))
        repository.add_rule(inventory.repo.get_rule("r-exp"))
        pki = app.state.repository
        source = inventory.pki.repository
        pki.add_person(source.get_person("p1"))
        pki.add_template(source.get_template("host"))
        pki.add_request(source.get_request("req-SOON"))
        pki.add_issued_certificate(source.list_issued_certificates()[0])
        schedule.notifications.comms = inventory.comms
        schedule.update(settings(True, 3600))
        with mock.patch("myownca.notifications.service._utc_now", return_value=NOW):
            schedule.scheduler.run_once()
        assert repository.get_rule("r-exp").last_run_at == NOW
        assert repository.list_log()[0].success
        restarted = NotificationSchedule(PKIRepository(Database(target)), schedule.notifications)
        assert restarted.settings() == settings(True, 3600)
        with mock.patch("myownca.notifications.service._utc_now", return_value=NOW):
            restarted.scheduler.run_once()
        assert len(inventory.comms.sent) == 1
        assert notify_main(["--dry-run"]) == 0
        assert not (tmp_path / "unused.sqlite3").exists()
        database._engine.dispose()
    finally:
        with engine.connect() as connection:
            connection.exec_driver_sql(f"DROP DATABASE `{name}`")
        engine.dispose()
