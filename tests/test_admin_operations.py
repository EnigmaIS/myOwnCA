from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException

from myownca.comms import DeliveryResult, NotificationChannel
from myownca.domain import Role
from myownca.notifications import (
    NotificationEvent,
    NotificationRule,
    NotificationTemplate,
)
from myownca.online.app import CommsSendRequest, create_app
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)


class AdminOperationsApiTests(unittest.TestCase):
    def _app(self, tempdir: str, *, lab_mode: bool = False):
        database_path = Path(tempdir) / "operations.sqlite3"
        app = create_app(
            database_path,
            lab_mode=lab_mode,
            online_key_dir=Path(tempdir) / "keys",
        )
        secret = add_login_ready_user(
            app,
            user_id="admin-1",
            email="admin1@example.test",
            role=Role.ADMIN,
        )
        token, csrf = create_active_session(
            app,
            email="admin1@example.test",
            totp_secret=secret,
        )
        return app, database_path, token, csrf

    def test_operations_has_stable_actionable_shape_and_deterministic_order(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, token, _ = self._app(tempdir)
            result = route_endpoint(app, "/internal/admin/operations", "GET")(
                request_with_session(token)
            )

            expected_ids = [
                "issuer.configured",
                "governance.pending_changes",
                "service_urls.publication",
                "revocation.publication",
                "templates.configured",
                "notifications.configured",
                "notifications.tested",
                "audit.integrity",
                "audit.forwarding",
                "backup.application",
                "lifecycle.issue_revoke_exercised",
                "lifecycle.expirations",
                "lifecycle.renewal_failures",
                "license.capacity",
            ]
            items = result["readiness"]["items"]
            self.assertEqual([item["id"] for item in items], expected_ids)
            self.assertEqual(result["summary"]["readiness_total"], len(expected_ids))
            security_ids = [item["id"] for item in result["security_posture"]]
            self.assertEqual(len(security_ids), len(set(security_ids)))
            self.assertNotIn("hsm.backend", [item["id"] for item in items])
            self.assertNotIn("hsm.backend", security_ids)
            self.assertIn("governance.pending_changes", security_ids)
            self.assertEqual(result["freshness"]["refresh_href"], "/internal/admin/operations")
            self.assertFalse(result["freshness"]["is_stale"])
            for item in items:
                self.assertIn(item["status"], {"pass", "warn", "fail", "unknown"})
                self.assertIn(item["severity"], {"none", "info", "warning", "critical"})
                self.assertIn(item["owner"], {"administrator", "certificate_operator"})
                self.assertIn("checked_at", item)
                if item["action"] is not None:
                    self.assertIsInstance(item["action"], dict)
                    self.assertTrue(item["action"]["href"])
            self.assertFalse(result["backup"]["off_host_storage_verified"])
            self.assertFalse(result["backup"]["restore_verified"])
            self.assertEqual(result["backup"]["href"], "#/backups")

    def test_lab_issuer_is_not_reported_as_production_ready(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, token, _ = self._app(tempdir, lab_mode=True)
            result = route_endpoint(app, "/internal/admin/readiness", "GET")(
                request_with_session(token)
            )
            issuer = next(item for item in result["items"] if item["id"] == "issuer.configured")
            self.assertEqual(issuer["status"], "warn")
            self.assertIn("lab issuer", issuer["summary"].lower())
            self.assertIn("before production", issuer["summary"].lower())

    def test_attestation_routes_are_removed_and_backup_status_is_observable(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, token, _ = self._app(tempdir)
            self.assertFalse(
                any(route.path == "/internal/admin/recovery-attestations" for route in app.routes)
            )
            status = route_endpoint(app, "/internal/admin/backups", "GET")(
                request_with_session(token)
            )
            self.assertIsNone(status["latest_delivered"])
            self.assertEqual(status["fresh_days"], 7)
            self.assertEqual(status["stale_days"], 30)

    def test_operations_routes_reject_non_admin(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(
                Path(tempdir) / "operations.sqlite3",
                lab_mode=False,
                online_key_dir=Path(tempdir) / "keys",
            )
            add_login_ready_user(
                app,
                user_id="user-1",
                email="user1@example.test",
                role=Role.USER,
            )
            token, csrf = create_active_session(app, email="user1@example.test")
            for path in (
                "/internal/admin/operations",
                "/internal/admin/readiness",
                "/internal/admin/backups",
            ):
                with self.assertRaises(HTTPException) as denied:
                    route_endpoint(app, path, "GET")(request_with_session(token))
                self.assertEqual(denied.exception.status_code, 403)

    def test_failed_subsystem_becomes_unknown_without_blank_overview(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, token, _ = self._app(tempdir)
            with mock.patch.object(
                app.state.operations.comms_repository,
                "list_all",
                side_effect=RuntimeError("channel store unavailable"),
            ):
                result = route_endpoint(app, "/internal/admin/operations", "GET")(
                    request_with_session(token)
                )
            notifications = next(
                item
                for item in result["readiness"]["items"]
                if item["id"] == "notifications.configured"
            )
            self.assertEqual(notifications["status"], "unknown")
            self.assertEqual(notifications["severity"], "warning")
            self.assertEqual(len(result["readiness"]["items"]), 14)

    def test_pending_privileged_change_is_visible_as_governance_work(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, token, _ = self._app(tempdir)
            with mock.patch.object(
                app.state.operations.proposal_repository,
                "list_pending_proposals",
                return_value=[object()],
            ):
                result = route_endpoint(app, "/internal/admin/operations", "GET")(
                    request_with_session(token)
                )
            governance = next(
                item
                for item in result["readiness"]["items"]
                if item["id"] == "governance.pending_changes"
            )
            self.assertEqual(governance["status"], "warn")
            self.assertEqual(governance["owner"], "administrator")
            self.assertEqual(governance["action"]["href"], "#/privileged")

    def test_unavailable_backup_store_does_not_blank_overview(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, token, _ = self._app(tempdir)
            with mock.patch.object(
                app.state.operations.backup_repository,
                "latest_delivered",
                side_effect=RuntimeError("backup store unavailable"),
            ):
                result = route_endpoint(app, "/internal/admin/operations", "GET")(
                    request_with_session(token)
                )
            backup = next(
                item for item in result["readiness"]["items"] if item["id"] == "backup.application"
            )
            self.assertEqual(backup["status"], "fail")

    def test_notification_readiness_credits_only_current_successful_dedicated_test(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, token, csrf = self._app(tempdir)
            app.state.notifications.repository.add_template(
                NotificationTemplate(
                    name="expiry-alert",
                    event_type=NotificationEvent.EXPIRING,
                )
            )
            app.state.notifications.repository.add_rule(
                NotificationRule(
                    id="expiry-webhook",
                    event_type=NotificationEvent.EXPIRING,
                    template_name="expiry-alert",
                    channel=NotificationChannel.WEBHOOK,
                )
            )
            configured_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            app.state.comms.repository.upsert(
                channel="webhook",
                enabled=True,
                config_json="{}",
                secret_ciphertext="",
                updated_at=configured_at,
            )
            payload = CommsSendRequest(
                channel="webhook",
                recipient="ops@example.test",
                body="test",
            )

            # A successful ordinary send is not evidence of an explicit channel test.
            success = DeliveryResult(
                channel=NotificationChannel.WEBHOOK,
                recipient="ops@example.test",
                success=True,
            )
            with mock.patch.object(app.state.comms, "send", return_value=success):
                route_endpoint(app, "/internal/comms/send", "POST")(
                    payload,
                    request_with_session(token, csrf, method="POST"),
                )
            readiness = route_endpoint(app, "/internal/admin/readiness", "GET")(
                request_with_session(token)
            )
            test_item = next(
                item for item in readiness["items"] if item["id"] == "notifications.tested"
            )
            self.assertEqual(test_item["status"], "warn")

            # A dedicated test that returns a failed result is audited as failure and not credited.
            failed = DeliveryResult(
                channel=NotificationChannel.WEBHOOK,
                recipient="ops@example.test",
                success=False,
                detail="remote rejected test",
            )
            with mock.patch.object(app.state.comms, "send", return_value=failed):
                route_endpoint(app, "/internal/comms/test", "POST")(
                    payload,
                    request_with_session(token, csrf, method="POST"),
                )
            readiness = route_endpoint(app, "/internal/admin/readiness", "GET")(
                request_with_session(token)
            )
            test_item = next(
                item for item in readiness["items"] if item["id"] == "notifications.tested"
            )
            self.assertEqual(test_item["status"], "warn")

            with mock.patch.object(app.state.comms, "send", return_value=success):
                route_endpoint(app, "/internal/comms/test", "POST")(
                    payload,
                    request_with_session(token, csrf, method="POST"),
                )
            readiness = route_endpoint(app, "/internal/admin/readiness", "GET")(
                request_with_session(token)
            )
            test_item = next(
                item for item in readiness["items"] if item["id"] == "notifications.tested"
            )
            self.assertEqual(test_item["status"], "pass")

            # Editing the channel invalidates the old test until the current config is tested.
            app.state.comms.repository.upsert(
                channel="webhook",
                enabled=True,
                config_json='{"url":"https://new.example.test"}',
                secret_ciphertext="",
                updated_at=datetime.now(timezone.utc) + timedelta(seconds=1),
            )
            readiness = route_endpoint(app, "/internal/admin/readiness", "GET")(
                request_with_session(token)
            )
            test_item = next(
                item for item in readiness["items"] if item["id"] == "notifications.tested"
            )
            self.assertEqual(test_item["status"], "warn")

    def test_notification_readiness_requires_rule_channel_to_be_enabled_and_tested(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, token, _ = self._app(tempdir)
            app.state.notifications.repository.add_template(
                NotificationTemplate(
                    name="expiry-alert",
                    event_type=NotificationEvent.EXPIRING,
                )
            )
            app.state.notifications.repository.add_rule(
                NotificationRule(
                    id="expiry-email",
                    event_type=NotificationEvent.EXPIRING,
                    template_name="expiry-alert",
                    channel=NotificationChannel.EMAIL,
                )
            )
            app.state.comms.repository.upsert(
                channel="webhook",
                enabled=True,
                config_json="{}",
                secret_ciphertext="",
                updated_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            )

            readiness = route_endpoint(app, "/internal/admin/readiness", "GET")(
                request_with_session(token)
            )
            configured = next(
                item for item in readiness["items"] if item["id"] == "notifications.configured"
            )
            tested = next(
                item for item in readiness["items"] if item["id"] == "notifications.tested"
            )
            self.assertEqual(configured["status"], "warn")
            self.assertIn("do not use an enabled channel", configured["summary"])
            self.assertEqual(tested["status"], "warn")


if __name__ == "__main__":
    unittest.main()
