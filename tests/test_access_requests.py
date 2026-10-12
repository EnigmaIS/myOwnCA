import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException, Request

from myownca.comms import CommsService, DeliveryResult, NotificationChannel
from myownca.domain import Role
from myownca.holder import AccessRequestService, AccessRequestRepository
from myownca.notifications import (
    NotificationAudience,
    NotificationEvent,
    NotificationRepository,
    NotificationRule,
    NotificationTemplate,
)
from myownca.online.app import AccessRequestConfigUpdate, AccessRequestCreate, AccessRequestVerify, create_app
from tests.helpers import (
    TempPKI,
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)

NOW = datetime(2026, 6, 12, 9, 0, tzinfo=timezone.utc)


def _ok_send(channel, recipient, message):  # noqa: ARG001 - mock signature
    return DeliveryResult(
        channel=NotificationChannel.EMAIL, recipient=recipient, success=True, detail="ok"
    )


def _public_request(ip: str = "203.0.113.9") -> Request:
    return Request(
        {"type": "http", "method": "POST", "path": "/", "headers": [], "client": (ip, 1234)}
    )


class AccessRequestServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.service = AccessRequestService(AccessRequestRepository(self.pki.database))

    def tearDown(self) -> None:
        self.pki.close()

    def test_submit_and_verify_happy_path(self) -> None:
        request, code = self.service.submit(
            email="New@Example.Test ", name="New Person", kind="user",
            message="onboard me", now=NOW,
        )
        self.assertEqual(request.email, "new@example.test")  # normalised
        self.assertEqual(request.status.value, "unverified")
        self.assertNotEqual(request.verify_code_hash, code)
        verified = self.service.verify(request.id, code, now=NOW)
        self.assertEqual(verified.status.value, "pending")
        self.assertIsNone(verified.verify_code_hash)  # consumed

    def test_invalid_email_or_kind_rejected(self) -> None:
        from myownca.holder import AccessRequestError

        with self.assertRaises(AccessRequestError):
            self.service.submit(email="not-an-email", now=NOW)
        with self.assertRaises(AccessRequestError):
            self.service.submit(email="a@example.test", kind="root-ca", now=NOW)

    def test_per_email_budget(self) -> None:
        for _ in range(3):
            self.assertIsNotNone(self.service.submit(email="a@example.test", now=NOW))
        self.assertIsNone(self.service.submit(email="a@example.test", now=NOW))
        # the next day the budget resets
        self.assertIsNotNone(
            self.service.submit(email="a@example.test", now=NOW + timedelta(days=1, hours=1))
        )

    def test_wrong_code_locks_after_five(self) -> None:
        request, code = self.service.submit(email="a@example.test", now=NOW)
        for _ in range(5):
            self.assertIsNone(self.service.verify(request.id, "000000", now=NOW))
        # correct code no longer works (code cleared at lockout)
        self.assertIsNone(self.service.verify(request.id, code, now=NOW))

    def test_expired_code_rejected(self) -> None:
        request, code = self.service.submit(email="a@example.test", now=NOW)
        self.assertIsNone(self.service.verify(request.id, code, now=NOW + timedelta(minutes=16)))

    def test_decide_requires_pending(self) -> None:
        from myownca.holder import AccessRequestError

        request, code = self.service.submit(email="a@example.test", now=NOW)
        with self.assertRaises(AccessRequestError):
            self.service.decide(request.id, approve=True, decided_by="su-1", now=NOW)
        self.service.verify(request.id, code, now=NOW)
        decided = self.service.decide(request.id, approve=True, decided_by="su-1", now=NOW)
        self.assertEqual(decided.status.value, "approved")
        self.assertEqual(decided.decided_by, "su-1")
        with self.assertRaises(AccessRequestError):
            self.service.decide(request.id, approve=False, decided_by="su-1", now=NOW)


def _app(tempdir: str):
    app = create_app(Path(tempdir) / "a.sqlite3", lab_mode=True)
    su = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
    su_session = create_active_session(app, email="su1@example.test", totp_secret=su)
    # Enable self-service with a wildcard covering all .test domains used in this suite.
    repo = app.state.repository
    repo.set_setting("access_request_enabled", "true")
    repo.set_setting("access_request_allowed_domains", json.dumps(["*.test"]))
    return app, su_session


class AccessRequestApiTests(unittest.TestCase):
    def _submit(self, app, **overrides):
        payload = AccessRequestCreate(
            **{"email": "new@example.test", "name": "New Person", "kind": "user",
               "message": "please onboard me", **overrides}
        )
        return route_endpoint(app, "/internal/access-requests", "POST")(
            payload, _public_request(overrides.pop("ip", "203.0.113.9"))
        )

    def test_submit_sends_code_and_verify_notifies_approvers(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, (token, csrf) = _app(tempdir)
            notif_repo = NotificationRepository(app.state.repository.database)
            notif_repo.add_template(
                NotificationTemplate(
                    name="notify-access",
                    event_type=NotificationEvent.ACCESS_REQUESTED,
                    subject="Access request from $access_email",
                    body="$access_name ($access_kind): $access_message",
                )
            )
            notif_repo.add_rule(
                NotificationRule(
                    id="r-access",
                    event_type=NotificationEvent.ACCESS_REQUESTED,
                    template_name="notify-access",
                    channel=NotificationChannel.EMAIL,
                    audience=NotificationAudience.APPROVERS,
                )
            )
            with mock.patch.object(CommsService, "send", side_effect=_ok_send) as sent:
                submitted = self._submit(app)
            self.assertTrue(submitted["submitted"])
            code_mail = sent.call_args_list[0]
            self.assertEqual(code_mail.args[1], "new@example.test")
            import re

            code = re.search(r"\b(\d{6})\b", code_mail.args[2].body).group(1)

            with mock.patch.object(CommsService, "send", side_effect=_ok_send) as sent:
                verified = route_endpoint(
                    app, "/internal/access-requests/{request_id}/verify", "POST"
                )(submitted["request_id"], AccessRequestVerify(code=code), _public_request())
            self.assertEqual(verified["status"], "pending")
            approver_mail = sent.call_args_list[0]
            self.assertEqual(approver_mail.args[1], "su1@example.test")
            self.assertIn("Access request from new@example.test", approver_mail.args[2].subject)

            listing = route_endpoint(app, "/internal/access-requests", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual(len(listing), 1)
            self.assertEqual(listing[0]["status"], "pending")

    def test_honeypot_drops_silently(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su = _app(tempdir)
            with mock.patch.object(CommsService, "send", side_effect=_ok_send) as sent:
                response = self._submit(app, website="https://spam.example")
            self.assertTrue(response["submitted"])  # uniform response
            self.assertEqual(sent.call_count, 0)
            self.assertEqual(app.state.access_requests.list_requests(), [])

    def test_per_ip_rate_limit(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su = _app(tempdir)
            with mock.patch.object(CommsService, "send", side_effect=_ok_send):
                for index in range(5):
                    self._submit(app, email=f"u{index}@example.test")
                throttled = self._submit(app, email="u6@example.test")
            self.assertTrue(throttled["submitted"])  # still generic
            self.assertEqual(len(app.state.access_requests.list_requests()), 5)

    def test_unverified_requests_hidden_from_queue(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, (token, csrf) = _app(tempdir)
            with mock.patch.object(CommsService, "send", side_effect=_ok_send):
                self._submit(app)
            listing = route_endpoint(app, "/internal/access-requests", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual(listing, [])

    def test_approve_and_deny_routes(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, (token, csrf) = _app(tempdir)
            with mock.patch.object(CommsService, "send", side_effect=_ok_send):
                first = self._submit(app)
                second = self._submit(app, email="other@example.test")
            for submitted in (first, second):
                request_row = app.state.access_requests.repository.get(submitted["request_id"])
                app.state.access_requests.repository.mark_verified(request_row.id, NOW)
            approved = route_endpoint(
                app, "/internal/access-requests/{request_id}/approve", "POST"
            )(first["request_id"], request_with_session(token, csrf, method="POST"))
            self.assertEqual(approved["status"], "approved")
            self.assertEqual(approved["decided_by"], "su-1")
            denied = route_endpoint(
                app, "/internal/access-requests/{request_id}/deny", "POST"
            )(second["request_id"], request_with_session(token, csrf, method="POST"))
            self.assertEqual(denied["status"], "denied")
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/access-requests/{request_id}/approve", "POST")(
                    second["request_id"], request_with_session(token, csrf, method="POST")
                )
            self.assertEqual(ctx.exception.status_code, 409)

    def test_queue_requires_privileged_role(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su = _app(tempdir)
            user_secret = add_login_ready_user(
                app, user_id="user-1", email="user@example.test", role=Role.USER
            )
            user_token, user_csrf = create_active_session(
                app, email="user@example.test", totp_secret=user_secret
            )
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/access-requests", "GET")(
                    request_with_session(user_token, user_csrf)
                )
            self.assertEqual(ctx.exception.status_code, 403)

    def test_verify_unknown_id_uniform_400(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _su = _app(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/access-requests/{request_id}/verify", "POST")(
                    "ghost", AccessRequestVerify(code="123456"), _public_request()
                )
            self.assertEqual(ctx.exception.status_code, 400)


class AccessRequestConfigTests(unittest.TestCase):
    def _admin_app(self, tempdir: str):
        app = create_app(Path(tempdir) / "c.sqlite3", lab_mode=True)
        secret = add_login_ready_user(app, user_id="admin-1", email="admin@example.test", role=Role.ADMIN)
        token, csrf = create_active_session(app, email="admin@example.test", totp_secret=secret)
        return app, token, csrf

    def test_default_disabled_public_config(self) -> None:
        with TemporaryDirectory() as d:
            app, _t, _c = self._admin_app(d)
            self.assertEqual(route_endpoint(app, "/access-request/config", "GET")(), {"enabled": False})

    def test_put_then_public_and_admin_get(self) -> None:
        with TemporaryDirectory() as d:
            app, token, csrf = self._admin_app(d)
            saved = route_endpoint(app, "/internal/access-request/config", "PUT")(
                AccessRequestConfigUpdate(enabled=True, allowed_domains="Example.com, *.example.com"),
                request_with_session(token, csrf, method="PUT"),
            )
            self.assertEqual(saved, {"enabled": True, "allowed_domains": ["example.com", "*.example.com"]})
            self.assertEqual(route_endpoint(app, "/access-request/config", "GET")(), {"enabled": True})
            got = route_endpoint(app, "/internal/access-request/config", "GET")(request_with_session(token))
            self.assertEqual(got, {"enabled": True, "allowed_domains": ["example.com", "*.example.com"]})

    def test_enabled_but_no_domains_reads_as_off_publicly(self) -> None:
        with TemporaryDirectory() as d:
            app, token, csrf = self._admin_app(d)
            route_endpoint(app, "/internal/access-request/config", "PUT")(
                AccessRequestConfigUpdate(enabled=True, allowed_domains=""),
                request_with_session(token, csrf, method="PUT"),
            )
            # Public surface treats "enabled but no domains" as off.
            self.assertEqual(route_endpoint(app, "/access-request/config", "GET")(), {"enabled": False})
            with self.assertRaises(HTTPException) as page_ctx:
                route_endpoint(app, "/request-access", "GET")()
            self.assertEqual(page_ctx.exception.status_code, 404)
            with self.assertRaises(HTTPException) as submit_ctx:
                route_endpoint(app, "/internal/access-requests", "POST")(
                    AccessRequestCreate(email="u@example.com"), _public_request()
                )
            self.assertEqual(submit_ctx.exception.status_code, 404)
            # The admin still sees the real config: on, but with no domains.
            got = route_endpoint(app, "/internal/access-request/config", "GET")(request_with_session(token))
            self.assertEqual(got, {"enabled": True, "allowed_domains": []})

    def test_put_bad_domain_400(self) -> None:
        with TemporaryDirectory() as d:
            app, token, csrf = self._admin_app(d)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/access-request/config", "PUT")(
                    AccessRequestConfigUpdate(enabled=True, allowed_domains="nodot"),
                    request_with_session(token, csrf, method="PUT"),
                )
            self.assertEqual(ctx.exception.status_code, 400)

    def test_put_requires_admin(self) -> None:
        with TemporaryDirectory() as d:
            app = create_app(Path(d) / "c.sqlite3", lab_mode=True)
            secret = add_login_ready_user(app, user_id="su-1", email="su@example.test", role=Role.SUPERUSER)
            token, csrf = create_active_session(app, email="su@example.test", totp_secret=secret)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/access-request/config", "PUT")(
                    AccessRequestConfigUpdate(enabled=True, allowed_domains="example.com"),
                    request_with_session(token, csrf, method="PUT"),
                )
            self.assertEqual(ctx.exception.status_code, 403)

    def test_request_access_page_404_when_disabled(self) -> None:
        with TemporaryDirectory() as d:
            app, _t, _c = self._admin_app(d)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/request-access", "GET")()
            self.assertEqual(ctx.exception.status_code, 404)

    def test_submit_404_when_disabled(self) -> None:
        with TemporaryDirectory() as d:
            app, _t, _c = self._admin_app(d)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/access-requests", "POST")(
                    AccessRequestCreate(email="u@example.com"), _public_request()
                )
            self.assertEqual(ctx.exception.status_code, 404)

    def test_submit_400_disallowed_domain(self) -> None:
        with TemporaryDirectory() as d:
            app, token, csrf = self._admin_app(d)
            route_endpoint(app, "/internal/access-request/config", "PUT")(
                AccessRequestConfigUpdate(enabled=True, allowed_domains="example.com"),
                request_with_session(token, csrf, method="PUT"),
            )
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/access-requests", "POST")(
                    AccessRequestCreate(email="u@other.com"), _public_request()
                )
            self.assertEqual(ctx.exception.status_code, 400)

    def test_submit_succeeds_for_allowed_domain(self) -> None:
        with TemporaryDirectory() as d:
            app, token, csrf = self._admin_app(d)
            route_endpoint(app, "/internal/access-request/config", "PUT")(
                AccessRequestConfigUpdate(enabled=True, allowed_domains="example.com"),
                request_with_session(token, csrf, method="PUT"),
            )
            with mock.patch.object(CommsService, "send", side_effect=_ok_send) as sent:
                res = route_endpoint(app, "/internal/access-requests", "POST")(
                    AccessRequestCreate(email="u@example.com"), _public_request()
                )
            self.assertTrue(res["submitted"])
            self.assertEqual(sent.call_count, 1)


if __name__ == "__main__":
    unittest.main()
