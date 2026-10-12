from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest

from myownca.audit import AuditActor, AuditCategory, AuditOutcome, AuditRepository, AuditService
from myownca.audit.syslog import SyslogForwarder, forwarder_from_config
from myownca.storage.database import Database


def _service(tempdir: str) -> AuditService:
    db = Database(Path(tempdir) / "audit.sqlite3")
    db.migrate()
    return AuditService(AuditRepository(db), "unit-secret")


class HashChainTests(unittest.TestCase):
    def test_records_chain_and_verify(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            first = svc.record(AuditCategory.USER, "create", object_id="u1")
            second = svc.record(AuditCategory.CERTIFICATE, "issue", object_id="ser1")
            self.assertEqual(first.sequence, 1)
            self.assertEqual(second.sequence, 2)
            self.assertEqual(second.prev_hash, first.record_hash)
            self.assertEqual(svc.verify_chain(), {"ok": True, "first_bad_sequence": None})

    def test_tamper_is_detected(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            svc.record(AuditCategory.USER, "create", object_id="u1")
            svc.record(AuditCategory.USER, "delete", object_id="u1")
            with svc.repository.database.connect() as connection:
                connection.execute("UPDATE audit_events SET action = 'tampered' WHERE sequence = 1")
            result = svc.verify_chain()
            self.assertFalse(result["ok"])
            self.assertEqual(result["first_bad_sequence"], 1)

    def test_detail_secrets_are_caller_controlled(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            event = svc.record(
                AuditCategory.HSM,
                "backend_switch",
                actor=AuditActor(id="a1", email="a@x", role="admin", source_ip="10.0.0.1"),
                details={"backend": "pkcs11"},
            )
            self.assertEqual(event.actor_email, "a@x")
            self.assertEqual(event.source_ip, "10.0.0.1")
            self.assertEqual(event.details, {"backend": "pkcs11"})


class SyslogForwarderTests(unittest.TestCase):
    def test_format_pri_and_header(self) -> None:
        fwd = SyslogForwarder("logs.example.test", 514, "udp", 13)
        frame = fwd._format(5, "user.create", '{"a":1}', None)
        # PRI = facility*8 + severity = 13*8 + 5 = 109
        self.assertTrue(frame.startswith(b"<109>1 "), frame[:20])
        self.assertIn(b"myownca", frame)
        self.assertTrue(frame.endswith(b'{"a":1}'))

    def test_udp_emit_sends(self) -> None:
        fwd = SyslogForwarder("logs.example.test", 514, "udp", 13)
        with mock.patch("myownca.audit.syslog.socket.socket") as sock_cls:
            sock = sock_cls.return_value.__enter__.return_value
            self.assertTrue(fwd.emit(5, "x", "hello"))
            sock.sendto.assert_called_once()

    def test_emit_is_best_effort_on_error(self) -> None:
        fwd = SyslogForwarder("logs.example.test", 514, "udp", 13)
        with mock.patch("myownca.audit.syslog.socket.socket", side_effect=OSError("down")):
            self.assertFalse(fwd.emit(5, "x", "hello"))

    def test_disabled_or_invalid_config_yields_no_forwarder(self) -> None:
        self.assertIsNone(forwarder_from_config({"enabled": False, "host": "h"}))
        self.assertIsNone(forwarder_from_config({"enabled": True, "host": ""}))
        self.assertIsNotNone(
            forwarder_from_config({"enabled": True, "host": "h", "port": 514, "protocol": "udp", "facility": 13})
        )

    def test_service_forwards_when_enabled(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            svc.set_syslog_config(enabled=True, host="logs.example.test", port=514, protocol="udp", facility=13)
            with mock.patch("myownca.audit.syslog.socket.socket") as sock_cls:
                sock = sock_cls.return_value.__enter__.return_value
                svc.record(AuditCategory.SYSTEM, "test")
                sock.sendto.assert_called_once()
                self.assertIn(b'"hash_version": 2', sock.sendto.call_args.args[0])

    def test_set_syslog_config_validates(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir)
            with self.assertRaises(ValueError):
                svc.set_syslog_config(enabled=True, host="", port=514, protocol="udp", facility=13)
            with self.assertRaises(ValueError):
                svc.set_syslog_config(enabled=False, host="h", port=514, protocol="carrier-pigeon", facility=13)


class AuditAPITests(unittest.TestCase):
    def _app(self, tempdir: str):
        from myownca.domain import Role
        from myownca.online.app import create_app
        from tests.helpers import add_login_ready_user, create_active_session

        app = create_app(Path(tempdir) / "api.sqlite3", online_key_dir=Path(tempdir) / "keys")
        admin_secret = add_login_ready_user(
            app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
        )
        add_login_ready_user(app, user_id="aud-1", email="aud@example.test", role=Role.AUDITOR)
        add_login_ready_user(app, user_id="user-1", email="user@example.test", role=Role.USER)
        admin = create_active_session(app, email="admin1@example.test", totp_secret=admin_secret)
        auditor = create_active_session(app, email="aud@example.test")
        user = create_active_session(app, email="user@example.test")
        return app, admin, auditor, user

    def test_list_gating_and_verify(self) -> None:
        from fastapi import HTTPException
        from tests.helpers import request_with_session, route_endpoint

        with TemporaryDirectory() as tempdir:
            app, admin, auditor, user = self._app(tempdir)
            app.state.audit.record(AuditCategory.SYSTEM, "seed")

            events = route_endpoint(app, "/internal/audit/events", "GET")(
                request_with_session(auditor[0])
            )
            self.assertTrue(any(e["action"] == "seed" for e in events))
            self.assertTrue(all(e["hash_version"] == 2 for e in events))

            with self.assertRaises(HTTPException) as forbidden:
                route_endpoint(app, "/internal/audit/events", "GET")(request_with_session(user[0]))
            self.assertEqual(forbidden.exception.status_code, 403)

            verify = route_endpoint(app, "/internal/audit/verify", "GET")(
                request_with_session(admin[0])
            )
            self.assertTrue(verify["ok"])

    def test_syslog_config_roundtrip_is_audited(self) -> None:
        from tests.helpers import request_with_session, route_endpoint
        from myownca.online.app import SyslogConfigUpdate

        with TemporaryDirectory() as tempdir:
            app, admin, _, _ = self._app(tempdir)
            updated = route_endpoint(app, "/internal/audit/syslog", "PUT")(
                SyslogConfigUpdate(enabled=True, host="logs.example.test", port=514, protocol="udp", facility=13),
                request_with_session(admin[0], admin[1], method="PUT"),
            )
            self.assertTrue(updated["enabled"])
            self.assertEqual(updated["host"], "logs.example.test")
            events = app.state.audit.list_events(category="audit")
            self.assertTrue(any(e.action == "syslog_config_update" for e in events))


async def _asgi_request(app, method: str, path: str, body: bytes = b"") -> int:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "scheme": "http",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 5555),
        "server": ("testserver", 80),
    }
    messages: list[dict] = []
    request_sent = False

    async def receive():
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    await app(scope, receive, send)
    start = next(m for m in messages if m["type"] == "http.response.start")
    return start["status"]


class AuditMiddlewareTests(unittest.TestCase):
    def test_mutating_request_is_audited(self) -> None:
        import asyncio

        from myownca.online.app import create_app

        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "mw.sqlite3", online_key_dir=Path(tempdir) / "keys")
            # Unauthenticated mutating request: still audited at the API layer.
            status = asyncio.run(
                _asgi_request(
                    app,
                    "POST",
                    "/internal/auth/login",
                    b'{"email": "x@example.test", "password": "nope"}',
                )
            )
            self.assertEqual(status, 401)
            api_events = app.state.audit.list_events(category="api")
            self.assertTrue(
                any(e.action == "POST /internal/auth/login" for e in api_events), api_events
            )
            self.assertTrue(all(e.outcome == AuditOutcome.DENIED for e in api_events))

    def test_get_requests_not_audited(self) -> None:
        import asyncio

        from myownca.online.app import create_app

        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "mw2.sqlite3", online_key_dir=Path(tempdir) / "keys")
            asyncio.run(_asgi_request(app, "GET", "/health"))
            self.assertEqual(app.state.audit.list_events(category="api"), [])


@pytest.fixture
def audit_service(tmp_path):
    return _service(str(tmp_path))


def test_v2_canonical_payload_and_hmac_vector(audit_service):
    event_id = "00000000-0000-0000-0000-000000000001"
    expected = (
        '{"action":"create","actor_email":"a@example.test","actor_id":"a1",'
        '"actor_role":"admin","category":"user","details_json":"{}","hash_version":2,'
        '"id":"00000000-0000-0000-0000-000000000001","object_id":"u1",'
        '"object_type":"user","occurred_at":"2026-09-16T12:00:00+00:00",'
        '"outcome":"success","prev_hash":"' + "0" * 64
        + '","sequence":1,"source_ip":"127.0.0.1"}'
    )
    with (
        mock.patch("myownca.audit.repository.uuid4", return_value=event_id),
        mock.patch.object(audit_service, "_hash", wraps=audit_service._hash) as hasher,
    ):
        event = audit_service.record(
            AuditCategory.USER, "create",
            actor=AuditActor("a1", "a@example.test", "admin", "127.0.0.1"),
            object_type="user", object_id="u1",
            now=datetime(2026, 9, 16, 12, tzinfo=timezone.utc),
        )
    hasher.assert_called_once_with(expected)
    assert event.record_hash == "54ae25de3f26f4c982b4316db1b6506598bd0e4fdbabc38d5be3ecb26387c809"
    assert event.hash_version == 2
    assert audit_service.list_events()[0] == event
    assert audit_service.verify_chain() == {"ok": True, "first_bad_sequence": None}


@pytest.mark.parametrize(("column", "replacement"), [
    ("id", "changed-id"), ("hash_version", 1), ("sequence", 20),
    ("occurred_at", "2026-01-01T00:00:00+00:00"), ("category", "system"),
    ("action", "changed"), ("outcome", "failure"), ("actor_id", "changed-actor"),
    ("actor_email", "attacker@example.test"), ("actor_role", "auditor"),
    ("source_ip", "192.0.2.2"), ("object_type", "certificate"), ("object_id", "changed"),
    ("details_json", '{"changed":true}'), ("prev_hash", "f" * 64),
    ("record_hash", "f" * 64),
])
def test_every_stored_field_is_integrity_protected(audit_service, column, replacement):
    audit_service.record(AuditCategory.SYSTEM, "first")
    event = audit_service.record(
        AuditCategory.USER, "create", actor=AuditActor("a1", "a@x", "admin", "192.0.2.1"),
        object_type="user", object_id="u1", details={"a": 1},
    )
    with audit_service.repository.database.connect() as connection:
        columns = connection.execute("SELECT * FROM audit_events LIMIT 1").fetchone()
        assert column in columns
        connection.execute(
            f"UPDATE audit_events SET {column} = ? WHERE id = ?", (replacement, event.id)
        )
    bad_sequence = replacement if column == "sequence" else 2
    assert audit_service.verify_chain() == {"ok": False, "first_bad_sequence": bad_sequence}


@pytest.mark.parametrize("version", [0, 1, 3, -1, "invalid", 2.5])
def test_unsupported_stored_versions_fail_closed(audit_service, version):
    audit_service.record(AuditCategory.SYSTEM, "first")
    with audit_service.repository.database.connect() as connection:
        connection.execute("UPDATE audit_events SET hash_version = ?", (version,))
    assert audit_service.verify_chain() == {"ok": False, "first_bad_sequence": 1}


@pytest.mark.parametrize("version", [None, True, "2", 2.0])
def test_malformed_version_is_rejected_without_hashing(audit_service, version):
    # Exercise values that a conforming INTEGER NOT NULL schema cannot return.
    with mock.patch.object(audit_service.repository.database, "connect") as connect:
        connect.return_value.__enter__.return_value.execute.return_value.fetchall.return_value = [
            {"sequence": 7, "hash_version": version}
        ]
        hasher = mock.Mock()
        assert audit_service.repository.verify_chain(hasher) == (False, 7)
        hasher.assert_not_called()


@pytest.mark.parametrize("field", [
    "actor_id", "actor_email", "actor_role", "source_ip", "object_type", "object_id",
])
@pytest.mark.parametrize(("original", "replacement"), [(None, ""), ("", None)])
def test_null_and_empty_strings_are_distinct(audit_service, field, original, replacement):
    audit_service.record(
        AuditCategory.USER, "create", actor=AuditActor(original, original, original, original),
        object_type=original, object_id=original,
    )
    with audit_service.repository.database.connect() as connection:
        connection.execute(f"UPDATE audit_events SET {field} = ?", (replacement,))
    assert audit_service.verify_chain() == {"ok": False, "first_bad_sequence": 1}


def test_delimiters_unicode_and_exact_stored_strings(audit_service):
    event = audit_service.record(
        AuditCategory.USER, "create|雪", actor=AuditActor("a|b", "c", "管理员", "::1"),
        object_type="c", details={"unicode": "雪", "nested": {"x": "a|b"}},
    )
    assert audit_service.list_events()[0].to_dict() == event.to_dict()
    assert audit_service.verify_chain()["ok"]
    with audit_service.repository.database.connect() as connection:
        connection.execute("UPDATE audit_events SET actor_id = 'a', object_type = 'b|c'")
    assert not audit_service.verify_chain()["ok"]


@pytest.mark.parametrize(("column", "value"), [
    ("details_json", '{"a":1}'),
    ("occurred_at", "2026-09-16T12:00:00Z"),
])
def test_semantically_equivalent_stored_text_tampering_fails(audit_service, column, value):
    audit_service.record(
        AuditCategory.SYSTEM, "first", details={"a": 1},
        now=datetime(2026, 9, 16, 12, tzinfo=timezone.utc),
    )
    with audit_service.repository.database.connect() as connection:
        connection.execute(f"UPDATE audit_events SET {column} = ?", (value,))
    assert not audit_service.verify_chain()["ok"]


def test_migration_restart_and_wrong_secret(tmp_path):
    service = _service(str(tmp_path))
    assert service.verify_chain() == {"ok": True, "first_bad_sequence": None}
    event = service.record(AuditCategory.SYSTEM, "first")
    with service.repository.database.connect() as connection:
        before = connection.execute("SELECT * FROM audit_events").fetchall()
        version_column = next(
            row for row in connection.execute("PRAGMA table_info(audit_events)").fetchall()
            if row["name"] == "hash_version"
        )
    assert version_column["notnull"] == 1
    assert version_column["dflt_value"] is None
    reopened = _service(str(tmp_path))  # New engine, migration rerun, new service.
    with reopened.repository.database.connect() as connection:
        assert connection.execute("SELECT * FROM audit_events").fetchall() == before
    assert reopened.verify_chain()["ok"]
    second = reopened.record(AuditCategory.SYSTEM, "second")
    assert second.hash_version == 2
    assert second.prev_hash == event.record_hash
    assert reopened.verify_chain()["ok"]
    wrong = AuditService(reopened.repository, "wrong-secret")
    assert wrong.verify_chain() == {"ok": False, "first_bad_sequence": 1}


def test_interior_deletion_breaks_chain_but_suffix_deletion_needs_checkpoint(audit_service):
    audit_service.record(AuditCategory.SYSTEM, "first")
    middle = audit_service.record(AuditCategory.SYSTEM, "middle")
    audit_service.record(AuditCategory.SYSTEM, "last")
    with audit_service.repository.database.connect() as connection:
        connection.execute("DELETE FROM audit_events WHERE id = ?", (middle.id,))
    assert audit_service.verify_chain() == {"ok": False, "first_bad_sequence": 3}
    with audit_service.repository.database.connect() as connection:
        connection.execute("DELETE FROM audit_events WHERE sequence = 3")
    assert audit_service.verify_chain() == {"ok": True, "first_bad_sequence": None}


if __name__ == "__main__":
    unittest.main()
