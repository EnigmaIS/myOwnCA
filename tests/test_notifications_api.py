from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException

from myownca.comms import NotificationChannel
from myownca.domain import Role
from myownca.notifications import NotificationAudience, NotificationEvent, NotificationFormat
from myownca.online.app import (
    NotificationRuleCreate,
    NotificationRuleUpdate,
    NotificationTemplateCreate,
    NotificationTemplatePreview,
    NotificationTemplateUpdate,
    create_app,
)
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)


def _app(tempdir: str):
    app = create_app(Path(tempdir) / "napi.sqlite3", lab_mode=True)
    su = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="user-1", email="user@example.test", role=Role.USER)
    tokens = {
        "su": create_active_session(app, email="su1@example.test", totp_secret=su),
        "user": create_active_session(app, email="user@example.test"),
    }
    return app, tokens


def _template_payload(name="notify-expiring") -> NotificationTemplateCreate:
    return NotificationTemplateCreate(
        name=name,
        event_type=NotificationEvent.EXPIRING,
        format=NotificationFormat.TEXT,
        subject="$cert_name expires $expiry_date",
        body="Hi $person_name — $notification_text",
    )


class NotificationTemplateAPITests(unittest.TestCase):
    def test_template_crud_roundtrip(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _app(tempdir)
            token, csrf = tokens["su"]
            created = route_endpoint(app, "/internal/notifications/templates", "POST")(
                _template_payload(), request_with_session(token, csrf, method="POST")
            )
            self.assertEqual(created["name"], "notify-expiring")

            listed = route_endpoint(app, "/internal/notifications/templates", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual([row["name"] for row in listed], ["notify-expiring"])

            updated = route_endpoint(app, "/internal/notifications/templates/{name}", "PUT")(
                "notify-expiring",
                NotificationTemplateUpdate(
                    event_type=NotificationEvent.EXPIRING,
                    format=NotificationFormat.HTML,
                    subject="s2",
                    body="<b>$person_name</b>",
                ),
                request_with_session(token, csrf, method="PUT"),
            )
            self.assertEqual(updated["format"], "html")

            deleted = route_endpoint(app, "/internal/notifications/templates/{name}", "DELETE")(
                "notify-expiring", request_with_session(token, csrf, method="DELETE")
            )
            self.assertEqual(deleted["name"], "notify-expiring")

    def test_duplicate_template_name_conflicts(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _app(tempdir)
            token, csrf = tokens["su"]
            create = route_endpoint(app, "/internal/notifications/templates", "POST")
            create(_template_payload(), request_with_session(token, csrf, method="POST"))
            with self.assertRaises(HTTPException) as ctx:
                create(_template_payload(), request_with_session(token, csrf, method="POST"))
            self.assertEqual(ctx.exception.status_code, 409)

    def test_template_delete_in_use_409_and_unknown_404(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _app(tempdir)
            token, csrf = tokens["su"]
            route_endpoint(app, "/internal/notifications/templates", "POST")(
                _template_payload(), request_with_session(token, csrf, method="POST")
            )
            route_endpoint(app, "/internal/notifications/rules", "POST")(
                NotificationRuleCreate(
                    event_type=NotificationEvent.EXPIRING,
                    template_name="notify-expiring",
                    channel=NotificationChannel.EMAIL,
                ),
                request_with_session(token, csrf, method="POST"),
            )
            delete = route_endpoint(app, "/internal/notifications/templates/{name}", "DELETE")
            with self.assertRaises(HTTPException) as ctx:
                delete("notify-expiring", request_with_session(token, csrf, method="DELETE"))
            self.assertEqual(ctx.exception.status_code, 409)
            with self.assertRaises(HTTPException) as ctx:
                delete("ghost", request_with_session(token, csrf, method="DELETE"))
            self.assertEqual(ctx.exception.status_code, 404)

    def test_preview_renders_draft_and_stored(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _app(tempdir)
            token, csrf = tokens["su"]
            preview = route_endpoint(app, "/internal/notifications/templates/{name}/preview", "POST")
            draft = preview(
                "unsaved",
                NotificationTemplatePreview(subject="$serial!", body="To $person_email: $notification_text"),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertEqual(draft["subject"], "0A:1F:3C:2B!")
            self.assertIn("alice@example.test", draft["body"])

            route_endpoint(app, "/internal/notifications/templates", "POST")(
                _template_payload(), request_with_session(token, csrf, method="POST")
            )
            stored = preview(
                "notify-expiring",
                NotificationTemplatePreview(),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertIn("expires 2026-12-31", stored["subject"])

            with self.assertRaises(HTTPException) as ctx:
                preview("ghost", NotificationTemplatePreview(), request_with_session(token, csrf, method="POST"))
            self.assertEqual(ctx.exception.status_code, 404)

    def test_ordinary_user_is_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _app(tempdir)
            token, csrf = tokens["user"]
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/notifications/templates", "GET")(
                    request_with_session(token, csrf)
                )
            self.assertEqual(ctx.exception.status_code, 403)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/notifications/templates", "POST")(
                    _template_payload(), request_with_session(token, csrf, method="POST")
                )
            self.assertEqual(ctx.exception.status_code, 403)


class NotificationRuleAPITests(unittest.TestCase):
    def test_rule_crud_roundtrip(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _app(tempdir)
            token, csrf = tokens["su"]
            route_endpoint(app, "/internal/notifications/templates", "POST")(
                _template_payload(), request_with_session(token, csrf, method="POST")
            )
            created = route_endpoint(app, "/internal/notifications/rules", "POST")(
                NotificationRuleCreate(
                    event_type=NotificationEvent.EXPIRING,
                    template_name="notify-expiring",
                    channel=NotificationChannel.EMAIL,
                    audience=NotificationAudience.HOLDER,
                    period_days=7,
                    threshold_days=14,
                    notification_text="renew please",
                ),
                request_with_session(token, csrf, method="POST"),
            )
            rule_id = created["id"]
            self.assertEqual(created["threshold_days"], 14)

            updated = route_endpoint(app, "/internal/notifications/rules/{rule_id}", "PUT")(
                rule_id,
                NotificationRuleUpdate(
                    event_type=NotificationEvent.EXPIRING,
                    template_name="notify-expiring",
                    channel=NotificationChannel.SLACK,
                    audience=NotificationAudience.HOLDER,
                    enabled=False,
                    period_days=3,
                    threshold_days=7,
                ),
                request_with_session(token, csrf, method="PUT"),
            )
            self.assertEqual(updated["channel"], "slack")
            self.assertFalse(updated["enabled"])

            listed = route_endpoint(app, "/internal/notifications/rules", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual([row["id"] for row in listed], [rule_id])

            deleted = route_endpoint(app, "/internal/notifications/rules/{rule_id}", "DELETE")(
                rule_id, request_with_session(token, csrf, method="DELETE")
            )
            self.assertEqual(deleted["id"], rule_id)

    def test_rule_with_unknown_template_conflicts(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _app(tempdir)
            token, csrf = tokens["su"]
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/notifications/rules", "POST")(
                    NotificationRuleCreate(
                        event_type=NotificationEvent.EXPIRING,
                        template_name="ghost",
                        channel=NotificationChannel.EMAIL,
                    ),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(ctx.exception.status_code, 409)

    def test_log_endpoint_lists_deliveries(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _app(tempdir)
            token, csrf = tokens["su"]
            log = route_endpoint(app, "/internal/notifications/log", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual(log, [])


if __name__ == "__main__":
    unittest.main()
