from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException

from myownca.ca_auth.service import AuthenticationError
from myownca.ca_auth.totp import code_for_step, current_step
from myownca.ca_hsm.scctl import DKEKStatus, ScHsmCtl
from myownca.domain import Role, TOTPFactor
from myownca.key_lifecycle import KeyOwnership
from myownca.online.app import (
    DKEKShareImport,
    DestructiveActionConfirmation,
    TOTPCodeCreate,
    create_app,
)
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    create_app_with_hsm,
    request_with_session,
    route_endpoint,
)

_SECRET = "JBSWY3DPEHPK3PXP"
_PASSWORD = "very-long-test-password"
_REASON = "Approved maintenance change for the CA trust service"


class _DeletableBackend:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    def delete_key(self, label: str) -> int:
        self.deleted.append(label)
        return 1

    def verify_pin(self, _pin: str) -> None:
        return None

    def status(self) -> dict[str, object]:
        return {
            "token_present": True,
            "token": {"initialized": False},
        }


class DestructiveSafeguardTests(unittest.TestCase):
    def _admin_app(self, tempdir: str, *, backend=None, backend_name: str = "software"):
        dkek_dir = Path(tempdir) / "dkek"
        with mock.patch.dict(
            "os.environ",
            {
                "MYOWNCA_STATE_DIR": tempdir,
                "MYOWNCA_PKCS11_DKEK_SHARE_DIR": str(dkek_dir),
            },
        ):
            database_path = Path(tempdir) / "safeguards.sqlite3"
            app = (
                create_app(
                    database_path,
                    online_key_dir=Path(tempdir) / "keys",
                )
                if backend is None
                else create_app_with_hsm(
                    backend,
                    backend_name,
                    database_path,
                    online_key_dir=Path(tempdir) / "keys",
                )
            )
        secret = add_login_ready_user(
            app,
            user_id="admin-1",
            email="admin1@example.test",
            role=Role.ADMIN,
            totp_secret=_SECRET,
        )
        token, csrf = create_active_session(
            app,
            email="admin1@example.test",
            totp_secret=secret,
        )
        return app, token, csrf, dkek_dir

    @staticmethod
    def _event(app, action: str):
        return next(
            event for event in app.state.audit.list_events(limit=100) if event.action == action
        )

    def test_recent_mfa_status_reauthentication_and_replay_are_server_enforced(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf, dkek_dir = self._admin_app(tempdir)
            me = route_endpoint(app, "/internal/auth/me", "GET")(request_with_session(token))
            self.assertTrue(me["mfa_recent"])
            self.assertIsNotNone(me["mfa_verified_at"])
            self.assertEqual(me["mfa_window_seconds"], 600)
            self.assertGreater(me["mfa_valid_for_seconds"], 0)

            session, _ = app.state.auth_service.require_session(token)
            app.state.auth_repository.update_session(
                session.id,
                mfa_verified_at=datetime.now(timezone.utc) - timedelta(minutes=11),
            )
            dkek_dir.mkdir(parents=True)
            share = dkek_dir / "reauth-share.pbe"
            share.write_bytes(b"encrypted-share")
            payload = DestructiveActionConfirmation(
                reason=_REASON,
                confirmation=f"DELETE DKEK {share.name}",
            )
            endpoint = route_endpoint(
                app,
                "/internal/hsm/dkek/shares/{filename}",
                "DELETE",
            )
            with self.assertRaises(HTTPException) as stale:
                endpoint(
                    share.name,
                    payload,
                    request_with_session(token, csrf, method="DELETE"),
                )
            self.assertEqual(stale.exception.status_code, 403)
            self.assertIn("Recent MFA", stale.exception.detail)
            denied = self._event(app, "dkek_share_delete_denied")
            self.assertEqual(denied.details["guard"], "recent_mfa")
            self.assertEqual(denied.details["reason"], _REASON)

            factor = app.state.auth_repository.get_totp_factor("admin-1")
            assert factor is not None
            app.state.auth_repository.add_or_update_totp_factor(
                TOTPFactor(
                    user_id=factor.user_id,
                    secret_ciphertext=factor.secret_ciphertext,
                    confirmed_at=factor.confirmed_at,
                    last_verified_step=None,
                )
            )
            code = code_for_step(_SECRET, current_step())
            refreshed = route_endpoint(app, "/internal/auth/totp/reauthenticate", "POST")(
                TOTPCodeCreate(code=code),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertTrue(refreshed["mfa_recent"])
            self.assertIsNotNone(refreshed["mfa_verified_at"])

            with self.assertRaises(HTTPException) as replay:
                route_endpoint(app, "/internal/auth/totp/reauthenticate", "POST")(
                    TOTPCodeCreate(code=code),
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(replay.exception.status_code, 400)

            result = endpoint(
                share.name,
                payload,
                request_with_session(token, csrf, method="DELETE"),
            )
            self.assertEqual(result, {"filename": share.name})
            self.assertFalse(share.exists())
            event = self._event(app, "dkek_share_delete")
            self.assertEqual(event.details["reason"], _REASON)

    def test_recovery_code_session_is_active_but_not_recent_mfa(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, active_token, _, _ = self._admin_app(tempdir)
            codes = app.state.auth_service.regenerate_recovery_codes(active_token)
            login = app.state.auth_service.login(
                "admin1@example.test",
                _PASSWORD,
            )
            recovered = app.state.auth_service.verify_recovery_code(login.token, codes[0])
            self.assertEqual(recovered.session.stage.value, "active")
            self.assertIsNone(recovered.session.mfa_verified_at)
            with self.assertRaises(AuthenticationError):
                app.state.auth_service.require_recent_mfa(recovered.session)

    def test_reason_and_exact_confirmation_fail_closed_and_are_audited(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, token, csrf, dkek_dir = self._admin_app(tempdir)
            dkek_dir.mkdir(parents=True)
            share = dkek_dir / "guard-share.pbe"
            share.write_bytes(b"encrypted-share")
            endpoint = route_endpoint(
                app,
                "/internal/hsm/dkek/shares/{filename}",
                "DELETE",
            )
            wrong = DestructiveActionConfirmation(
                reason=_REASON,
                confirmation="delete dkek guard-share.pbe",
            )
            with self.assertRaises(HTTPException) as mismatch:
                endpoint(
                    share.name,
                    wrong,
                    request_with_session(token, csrf, method="DELETE"),
                )
            self.assertEqual(mismatch.exception.status_code, 403)
            self.assertIn("exactly match", mismatch.exception.detail)

            blank_reason = DestructiveActionConfirmation(
                reason="          ",
                confirmation=f"DELETE DKEK {share.name}",
            )
            with self.assertRaises(HTTPException) as invalid_reason:
                endpoint(
                    share.name,
                    blank_reason,
                    request_with_session(token, csrf, method="DELETE"),
                )
            self.assertEqual(invalid_reason.exception.status_code, 403)
            denied = [
                event
                for event in app.state.audit.list_events(limit=20)
                if event.action == "dkek_share_delete_denied"
            ]
            self.assertEqual(
                {event.details["guard"] for event in denied},
                {"typed_confirmation", "audit_reason"},
            )

            valid = DestructiveActionConfirmation(
                reason=_REASON,
                confirmation=f"DELETE DKEK {share.name}",
            )
            with mock.patch.object(
                Path,
                "unlink",
                side_effect=RuntimeError("do not persist this lower-layer error"),
            ):
                with self.assertRaises(RuntimeError):
                    endpoint(
                        share.name,
                        valid,
                        request_with_session(token, csrf, method="DELETE"),
                    )
            failure_event = self._event(app, "dkek_share_delete_failed")
            self.assertEqual(failure_event.details, {"reason": _REASON})
            self.assertNotIn("lower-layer error", json.dumps(failure_event.details))

    def test_hsm_key_and_dkek_operations_require_guard_and_audit_reason(self) -> None:
        with TemporaryDirectory() as tempdir:
            backend = _DeletableBackend()
            app, token, csrf, dkek_dir = self._admin_app(
                tempdir,
                backend=backend,
                backend_name="pkcs11",
            )

            long_unicode_label = "issuer-é-" + ("x" * 220)
            app.state.key_lifecycle.register_key(
                backend="pkcs11",
                key_ref=long_unicode_label,
                purpose="manual_hsm_key",
                ownership=KeyOwnership.MANAGED,
            )
            scheduled = route_endpoint(app, "/internal/hsm/keys/{label}", "DELETE")(
                long_unicode_label,
                DestructiveActionConfirmation(
                    reason=_REASON,
                    confirmation=f"DELETE KEY {long_unicode_label}",
                ),
                request_with_session(token, csrf, method="DELETE"),
            )
            self.assertEqual(backend.deleted, [])
            self.assertEqual(scheduled["destroyed"], 0)
            self.assertEqual(scheduled["status"], "orphaned")
            self.assertIsNotNone(scheduled["delete_after"])

            dkek_dir.mkdir(parents=True, exist_ok=True)
            share = dkek_dir / "share-1.pbe"
            share.write_bytes(b"encrypted-share")

            session, _ = app.state.auth_service.require_session(token)
            app.state.pin_vault.unlock(session.id, "secret-user-pin")
            partial_dkek = DKEKStatus(
                shares_total=2,
                shares_imported=1,
                complete=False,
            )
            with (
                mock.patch.object(
                    ScHsmCtl,
                    "dkek_status",
                    return_value=partial_dkek,
                ),
                mock.patch.object(
                    ScHsmCtl,
                    "import_dkek_share",
                    return_value=partial_dkek,
                ),
            ):
                route_endpoint(
                    app,
                    "/internal/hsm/dkek/shares/{filename}/import",
                    "POST",
                )(
                    share.name,
                    DKEKShareImport(
                        password="secret-share-password",
                        reason=_REASON,
                        confirmation=f"IMPORT DKEK {share.name}",
                    ),
                    request_with_session(token, csrf, method="POST"),
                )
            route_endpoint(
                app,
                "/internal/hsm/dkek/shares/{filename}",
                "DELETE",
            )(
                share.name,
                DestructiveActionConfirmation(
                    reason=_REASON,
                    confirmation=f"DELETE DKEK {share.name}",
                ),
                request_with_session(token, csrf, method="DELETE"),
            )
            self.assertFalse(share.exists())

            for action in (
                "hsm_key_delete",
                "dkek_share_import",
                "dkek_share_delete",
            ):
                event = self._event(app, action)
                self.assertEqual(event.details["reason"], _REASON)
                serialized = json.dumps(event.details)
                self.assertNotIn("secret-so-pin", serialized)
                self.assertNotIn("secret-user-pin", serialized)
                self.assertNotIn("secret-share-password", serialized)

    def test_runtime_removes_issuer_and_root_mutations(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _, _, _ = self._admin_app(tempdir)
            paths = {route.path for route in app.routes}
            dkek_share_routes = [
                route for route in app.routes if route.path == "/internal/hsm/dkek/shares"
            ]
        self.assertFalse(any(path.startswith("/internal/setup/") for path in paths))
        self.assertIn("/internal/admin/issuer", paths)
        self.assertIn("/internal/admin/root-certificate", paths)
        self.assertNotIn("/internal/hsm/initialize", paths)
        self.assertTrue(dkek_share_routes)
        self.assertTrue(all("POST" not in route.methods for route in dkek_share_routes))


if __name__ == "__main__":
    unittest.main()
