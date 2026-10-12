from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException
from fastapi import Response
from cryptography.hazmat.primitives.asymmetric import ec

from myownca.ca_hsm import SoftwareHSM
from myownca.ca_hsm.recovery import HSMKeyRecoveryService
from myownca.ca_main.crypto import certificate_to_pem, create_lab_ca_chain
from myownca.domain import Role, SubCA
from myownca.online.app import (
    HSMPinUnlock,
    HSMRawBackupExport,
    create_app,
)
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    create_app_with_hsm,
    request_with_session,
    route_endpoint,
)


class HSMApiTests(unittest.TestCase):
    def _admin_app(self, tempdir: str, *, backend=None, backend_name: str = "software"):
        database_path = Path(tempdir) / "hsm.sqlite3"
        app = (
            create_app(database_path)
            if backend is None
            else create_app_with_hsm(backend, backend_name, database_path)
        )
        secret = add_login_ready_user(
            app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN
        )
        token, csrf = create_active_session(
            app, email="admin1@example.test", totp_secret=secret
        )
        return app, token, csrf

    def test_status_reports_software_backend_and_locked_pin(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, _ = self._admin_app(tempdir)
            body = route_endpoint(app, "/internal/hsm/status", "GET")(
                request_with_session(token)
            )
            self.assertEqual(body["backend"], "software")
            self.assertFalse(body["pin_unlocked"])
            self.assertNotIn("token", body)

    def test_status_reports_fixed_cloud_backend(self) -> None:
        class CloudBackend:
            def status(self) -> dict[str, bool]:
                return {"ready": True}

        for backend_name in ("aws_kms", "azure_key_vault"):
            with self.subTest(backend=backend_name), TemporaryDirectory() as tempdir:
                app, token, _ = self._admin_app(
                    tempdir,
                    backend=CloudBackend(),
                    backend_name=backend_name,
                )
                body = route_endpoint(app, "/internal/hsm/status", "GET")(
                    request_with_session(token)
                )
                self.assertEqual(body["backend"], backend_name)
                self.assertEqual(body["provider"], {"ready": True})

    def test_pin_unlock_then_lock_lifecycle(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = self._admin_app(tempdir)
            unlock = route_endpoint(app, "/internal/hsm/pin/unlock", "POST")
            status = route_endpoint(app, "/internal/hsm/status", "GET")
            lock = route_endpoint(app, "/internal/hsm/pin/lock", "POST")

            unlock(HSMPinUnlock(pin="123456"), request_with_session(token, csrf, method="POST"))
            self.assertTrue(status(request_with_session(token))["pin_unlocked"])
            self.assertEqual(app.state.pin_vault.active_pin(), "123456")

            lock(request_with_session(token, csrf, method="POST"))
            self.assertFalse(status(request_with_session(token))["pin_unlocked"])

    def test_logout_evicts_unlocked_pin(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = self._admin_app(tempdir)
            route_endpoint(app, "/internal/hsm/pin/unlock", "POST")(
                HSMPinUnlock(pin="123456"),
                request_with_session(token, csrf, method="POST"),
            )
            route_endpoint(app, "/internal/auth/logout", "POST")(
                request_with_session(token, csrf, method="POST"),
                Response(),
            )
            self.assertIsNone(app.state.pin_vault.active_pin())

    def test_pkcs11_pin_unlock_verifies_pin_before_storing(self) -> None:
        class VerifyingBackend:
            seen_pin = ""

            def verify_pin(self, pin: str) -> None:
                self.seen_pin = pin

            def status(self) -> dict[str, bool]:
                return {"token_present": True}

        with TemporaryDirectory() as tempdir:
            backend = VerifyingBackend()
            app, token, csrf = self._admin_app(
                tempdir,
                backend=backend,
                backend_name="pkcs11",
            )

            route_endpoint(app, "/internal/hsm/pin/unlock", "POST")(
                HSMPinUnlock(pin="123456"), request_with_session(token, csrf, method="POST")
            )

            self.assertEqual(backend.seen_pin, "123456")
            self.assertEqual(app.state.pin_vault.active_pin(), "123456")
            status = route_endpoint(app, "/internal/hsm/status", "GET")(
                request_with_session(token)
            )
            self.assertEqual(status["backend"], "pkcs11")
            self.assertTrue(status["pin_required"])

    def test_pkcs11_pin_unlock_rejects_bad_pin_and_stays_locked(self) -> None:
        class RejectingBackend:
            def verify_pin(self, pin: str) -> None:
                raise RuntimeError("bad PIN")

        with TemporaryDirectory() as tempdir:
            app, token, csrf = self._admin_app(
                tempdir,
                backend=RejectingBackend(),
                backend_name="pkcs11",
            )

            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/hsm/pin/unlock", "POST")(
                    HSMPinUnlock(pin="000000"), request_with_session(token, csrf, method="POST")
                )

            self.assertEqual(ctx.exception.status_code, 400)
            self.assertEqual(ctx.exception.detail, "HSM PIN unlock failed: bad PIN")
            self.assertIsNone(app.state.pin_vault.active_pin())

    def test_runtime_backend_switch_route_is_removed(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, _ = self._admin_app(tempdir)
            routes = {
                (method, route.path)
                for route in app.routes
                for method in getattr(route, "methods", set())
            }
            self.assertNotIn(("POST", "/internal/hsm/backend/switch"), routes)

    def test_pin_unlock_rejects_token_key_mismatching_active_subca(self) -> None:
        class WrongTokenBackend:
            def verify_pin(self, _pin: str) -> None:
                return None

            def public_key(self, _key_ref: str):
                return ec.generate_private_key(ec.SECP256R1()).public_key()

        with TemporaryDirectory() as tempdir:
            chain = create_lab_ca_chain(SoftwareHSM())
            app, token, csrf = self._admin_app(
                tempdir,
                backend=WrongTokenBackend(),
                backend_name="pkcs11",
            )
            sub_ca = SubCA(
                id="active-pkcs11-subca",
                certificate_pem=certificate_to_pem(chain.issuer.certificate),
                key_ref="issuer-on-token",
                subject=chain.issuer.certificate.subject.rfc4514_string(),
                created_at=datetime.now(timezone.utc),
                key_backend="pkcs11",
                token_label="production-token",
            )
            app.state.repository.add_sub_ca(sub_ca, activate=True)

            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/internal/hsm/pin/unlock", "POST")(
                    HSMPinUnlock(pin="123456"),
                    request_with_session(token, csrf, method="POST"),
                )

            self.assertEqual(caught.exception.status_code, 409)
            self.assertIsNone(app.state.pin_vault.active_pin())

    def test_key_listing_unsupported_on_software_backend(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, _ = self._admin_app(tempdir)
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/hsm/keys", "GET")(request_with_session(token))
            self.assertEqual(ctx.exception.status_code, 400)

    def test_key_listing_empty_backend_error_names_exception(self) -> None:
        class EmptyErrorBackend:
            def list_keys(self) -> list[dict[str, object]]:
                raise RuntimeError()

        with TemporaryDirectory() as tempdir:
            app, token, _ = self._admin_app(
                tempdir,
                backend=EmptyErrorBackend(),
                backend_name="pkcs11",
            )

            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/hsm/keys", "GET")(request_with_session(token))

            self.assertEqual(ctx.exception.status_code, 400)
            self.assertEqual(ctx.exception.detail, "HSM key listing failed: RuntimeError")

    def test_recovery_routes_are_removed_and_native_export_exists(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, _ = self._admin_app(tempdir)
            routes = {
                (method, route.path)
                for route in app.routes
                for method in getattr(route, "methods", set())
            }
            self.assertIn(("POST", "/internal/hsm/keys/wrapped-backup"), routes)
            self.assertIn(("POST", "/internal/hsm/token-backup/export-proposals"), routes)
            self.assertIn(("POST", "/internal/admin/hsm/token-backup/proposals/{proposal_id}/approve"), routes)
            self.assertIn(("POST", "/internal/hsm/token-backup/export"), routes)
            self.assertNotIn(("POST", "/internal/hsm/keys/recovery-backup"), routes)
            self.assertNotIn(("POST", "/internal/hsm/keys/recovery-restore"), routes)

    def test_native_export_requires_exact_confirmation_and_pkcs11(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf = self._admin_app(tempdir)
            export = route_endpoint(app, "/internal/hsm/token-backup/export", "POST")
            with self.assertRaises(HTTPException) as wrong:
                export(
                    HSMRawBackupExport(
                        reason="Export native HSM backups",
                        confirmation="EXPORT HSM",
                    ),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(wrong.exception.status_code, 403)
            with self.assertRaises(HTTPException) as software:
                export(
                    HSMRawBackupExport(
                        reason="Export native HSM backups",
                        confirmation="EXPORT ENTIRE HSM",
                    ),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(software.exception.status_code, 409)

    def test_native_export_returns_plain_transport_zip_without_persisting(self) -> None:
        class TokenBackend:
            def verify_pin(self, pin: str) -> None:
                if pin != "123456":
                    raise RuntimeError("bad PIN")

        with TemporaryDirectory() as tempdir:
            app, token, csrf = self._admin_app(
                tempdir,
                backend=TokenBackend(),
                backend_name="pkcs11",
            )
            add_login_ready_user(
                app,
                user_id="admin-2",
                email="admin2@example.test",
                role=Role.ADMIN,
            )
            approver_token, approver_csrf = create_active_session(
                app,
                email="admin2@example.test",
                totp_secret="JBSWY3DPEHPK3PXP",
            )
            propose = route_endpoint(
                app,
                "/internal/hsm/token-backup/export-proposals",
                "POST",
            )
            proposal = propose(
                HSMRawBackupExport(
                    reason="Export native HSM backups for the recovery ceremony",
                    confirmation="REQUEST EXPORT ENTIRE HSM",
                ),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertEqual(proposal["change_type"], "hsm_raw_backup_export")
            self.assertEqual(proposal["status"], "pending")
            self.assertEqual(proposal["required_approvals"], 1)
            route_endpoint(app, "/internal/hsm/pin/unlock", "POST")(
                HSMPinUnlock(pin="123456"),
                request_with_session(token, csrf, method="POST"),
            )
            with self.assertRaises(HTTPException) as self_approval:
                route_endpoint(
                    app,
                    "/internal/admin/hsm/token-backup/proposals/{proposal_id}/approve",
                    "POST",
                )(
                    proposal["id"],
                    HSMRawBackupExport(
                        reason="Try to approve the export myself",
                        confirmation="APPROVE EXPORT ENTIRE HSM",
                    ),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(self_approval.exception.status_code, 400)
            route_endpoint(app, "/internal/hsm/pin/unlock", "POST")(
                HSMPinUnlock(pin="123456"),
                request_with_session(approver_token, approver_csrf, method="POST"),
            )
            with mock.patch.object(
                HSMKeyRecoveryService,
                "create_raw_backup_archive",
                return_value=b"native-transport-zip",
            ) as create:
                response = route_endpoint(
                    app,
                    "/internal/admin/hsm/token-backup/proposals/{proposal_id}/approve",
                    "POST",
                )(
                    proposal["id"],
                    HSMRawBackupExport(
                        reason="Approve export for the recovery ceremony",
                        confirmation="APPROVE EXPORT ENTIRE HSM",
                    ),
                    request_with_session(approver_token, approver_csrf, method="POST"),
                )

            self.assertEqual(response.body, b"native-transport-zip")
            self.assertEqual(response.headers["content-type"], "application/zip")
            self.assertEqual(
                response.headers["content-disposition"],
                'attachment; filename="hsm-raw-key-backups.zip"',
            )
            self.assertEqual(response.headers["cache-control"], "no-store")
            create.assert_called_once_with(user_pin="123456")

    def test_routes_reject_non_admin(self) -> None:
        with TemporaryDirectory() as tempdir:
            app = create_app(Path(tempdir) / "hsm.sqlite3")
            add_login_ready_user(
                app, user_id="user-1", email="user1@example.test", role=Role.USER
            )
            token, _ = create_active_session(app, email="user1@example.test")
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/hsm/status", "GET")(request_with_session(token))
            self.assertEqual(ctx.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
