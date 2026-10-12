"""A locked HSM must ask the operator to unlock, never return a bare 500.

Before this, ``PKCS11Error`` subclassed ``RuntimeError`` while
``perform_issuance`` caught only ``(ApprovalPolicyError, RepositoryError,
ValueError)``, so a locked token escaped the route and Starlette rendered an
opaque 500. The token being locked is an operator-recoverable state, so it must
surface as structured, actionable data with the approval preserved.
"""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException

from myownca.ca_hsm.pkcs11 import HSMLockedError, PKCS11Error
from myownca.domain import CertificateProfile, CertificateTemplate, Role
from myownca.online.app import HSMPinUnlock, HSMPolicyUpdate, create_app
from tests.helpers import (
    add_login_ready_user,
    assign_request_holder,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
)

APPROVALS = "/internal/certificate-requests/{request_id}/approvals"


class LockedHSM:
    """A PKCS#11 token with no unlocked PIN: every key operation refuses."""

    def active_backend_name(self) -> str:
        return "pkcs11"

    def sign_certificate(self, *args, **kwargs):
        raise HSMLockedError()

    def sign_crl(self, *args, **kwargs):
        raise HSMLockedError()

    def sign_csr(self, *args, **kwargs):
        raise HSMLockedError()

    def public_key(self, *args, **kwargs):
        raise HSMLockedError()

    def private_key(self, *args, **kwargs):
        raise HSMLockedError()


class _Fixture:
    def __init__(self, tempdir: str, *, role: Role = Role.SUPERUSER) -> None:
        self.app = create_app(Path(tempdir) / "locked.sqlite3")
        secret = add_login_ready_user(
            self.app, user_id="u-1", email="u1@example.test", role=role
        )
        self.token, self.csrf = create_active_session(
            self.app, email="u1@example.test", totp_secret=secret
        )
        self.app.state.repository.add_template(
            CertificateTemplate(
                id="t-1",
                name="TLS",
                profile=CertificateProfile.HOST_TLS,
                first_issuance_approvals=1,
                renewal_approvals=1,
            )
        )

    def pending_request(self) -> str:
        created = self.app.state.service.submit_request(
            "t-1", make_csr("locked.test", dns_names=("locked.test",))
        )
        assign_request_holder(self.app, created.id)
        return created.id

    def lock_token(self) -> None:
        object.__setattr__(self.app.state.hsm, "_backend", LockedHSM())
        object.__setattr__(self.app.state.hsm, "_name", "pkcs11")

    def post(self, path: str, *args):
        endpoint = route_endpoint(self.app, path, "POST")
        return endpoint(*args, request_with_session(self.token, self.csrf, method="POST"))


class LockedTokenIssuanceTests(unittest.TestCase):
    def test_approval_reports_hsm_locked_instead_of_raising(self) -> None:
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            request_id = fixture.pending_request()
            fixture.lock_token()

            body = fixture.post(APPROVALS, request_id)

            self.assertFalse(body["auto_issued"])
            self.assertEqual(body["auto_issue_error"]["code"], "hsm_locked")
            self.assertIn("Unlock the HSM PIN", body["auto_issue_error"]["message"])

    def test_approval_is_preserved_so_the_request_can_be_retried(self) -> None:
        """The operator's approval must survive: they cannot approve twice."""
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            request_id = fixture.pending_request()
            fixture.lock_token()

            fixture.post(APPROVALS, request_id)

            approvals = fixture.app.state.repository.list_approvals(request_id)
            self.assertEqual(len(approvals), 1)
            self.assertEqual(
                fixture.app.state.repository.get_request(request_id).status.value, "pending"
            )

    def test_approving_with_an_open_token_issues_normally(self) -> None:
        """The intended path: the approval that meets the threshold issues."""
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            request_id = fixture.pending_request()

            body = fixture.post(APPROVALS, request_id)

            self.assertTrue(body["auto_issued"])
            self.assertIsNone(body["auto_issue_error"])
            self.assertIsNotNone(body["issued_certificate"])

    def test_manual_issue_endpoint_stays_absent(self) -> None:
        """Approval is the issuance trigger; there is no way to issue without one.

        Guarded here as well as in test_api_workflow so the locked-HSM work is
        not later "fixed" by reintroducing a manual issue path.
        """
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            with self.assertRaises(AssertionError):
                route_endpoint(
                    fixture.app,
                    "/internal/certificate-requests/{request_id}/issue",
                    "POST",
                )

    def test_locked_error_keeps_its_type_through_the_worker_boundary(self) -> None:
        """The worker reports the class name as its code; the subtype must survive."""
        from myownca.ca_hsm.pkcs11 import PKCS11HSM

        with self.assertRaises(HSMLockedError):
            PKCS11HSM._raise_worker_error(
                {"type": "pkcs11_error", "code": "HSMLockedError", "message": "locked"}
            )

    def test_a_generic_pkcs11_failure_is_not_mistaken_for_a_locked_token(self) -> None:
        from myownca.ca_hsm.pkcs11 import PKCS11HSM

        with self.assertRaises(PKCS11Error) as caught:
            PKCS11HSM._raise_worker_error(
                {"type": "pkcs11_error", "code": "PKCS11Error", "message": "device removed"}
            )
        self.assertNotIsInstance(caught.exception, HSMLockedError)


class OperatorPortalWiringTests(unittest.TestCase):
    """The portal must ask before the approval lands, not after."""

    def _asset(self, name: str) -> str:
        import myownca.online.app as app_module

        return (
            Path(app_module.__file__).parent / "static" / name
        ).read_text()

    def test_operator_portal_gates_the_final_approval_on_the_token(self) -> None:
        script = self._asset("superuser.js")
        self.assertIn("hsmReadyForIssuance", script)
        self.assertIn("willBeFinalApproval", script)
        # An approval that cannot issue would strand the request, so the check
        # must run before the approval POST, not after it.
        self.assertIn(
            "if (willBeFinalApproval(row) && !(await hsmReadyForIssuance())) return;",
            script,
        )
        self.assertIn("tpl-hsm-unlock-form", self._asset("superuser.html"))

    def test_operator_portal_has_no_manual_issue_path(self) -> None:
        script = self._asset("superuser.js")
        self.assertNotIn("/issue", script)
        self.assertNotIn('label: "Issue"', script)

    def test_admin_portal_exposes_the_unlock_policy(self) -> None:
        self.assertIn("hsm-operator-unlock", self._asset("admin.html"))
        self.assertIn("/internal/hsm/policy", self._asset("admin.js"))


class OperatorUnlockPolicyTests(unittest.TestCase):
    def _admin_session(self, fixture):
        if getattr(fixture, "_admin", None) is None:
            secret = add_login_ready_user(
                fixture.app, user_id="a-1", email="a1@example.test", role=Role.ADMIN
            )
            fixture._admin = create_active_session(
                fixture.app, email="a1@example.test", totp_secret=secret
            )
        return fixture._admin

    def _policy(self, fixture, allowed: bool):
        endpoint = route_endpoint(fixture.app, "/internal/hsm/policy", "PUT")
        token, csrf = self._admin_session(fixture)
        return endpoint(
            HSMPolicyUpdate(operator_unlock_allowed=allowed),
            request_with_session(token, csrf, method="PUT"),
        )

    def _unlock_as_operator(self, fixture):
        return route_endpoint(fixture.app, "/internal/hsm/pin/unlock", "POST")(
            HSMPinUnlock(pin="123456"),
            request_with_session(fixture.token, fixture.csrf, method="POST"),
        )

    def test_operator_can_unlock_by_default(self) -> None:
        """Issuing is the operator's job, so unlocking to sign is too."""
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)

            self.assertTrue(self._unlock_as_operator(fixture)["pin_unlocked"])

    def test_administrator_can_require_separation_of_duties(self) -> None:
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            self.assertFalse(self._policy(fixture, False)["operator_unlock_allowed"])

            with self.assertRaises(HTTPException) as caught:
                self._unlock_as_operator(fixture)

            self.assertEqual(caught.exception.status_code, 403)

    def test_the_policy_can_be_turned_back_on(self) -> None:
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            self._policy(fixture, False)
            self._policy(fixture, True)

            self.assertTrue(self._unlock_as_operator(fixture)["pin_unlocked"])

    def test_status_tells_the_operator_whether_they_may_unlock(self) -> None:
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            status = route_endpoint(fixture.app, "/internal/hsm/status", "GET")

            before = status(request_with_session(fixture.token))
            self.assertTrue(before["may_unlock"])
            # Token internals stay administrator-only.
            self.assertNotIn("token", before)

            self._policy(fixture, False)
            self.assertFalse(status(request_with_session(fixture.token))["may_unlock"])

    def test_an_administrator_may_always_unlock(self) -> None:
        """Turning the operator policy off must not lock administrators out."""
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            self._policy(fixture, False)
            token, csrf = self._admin_session(fixture)

            body = route_endpoint(fixture.app, "/internal/hsm/pin/unlock", "POST")(
                HSMPinUnlock(pin="123456"),
                request_with_session(token, csrf, method="POST"),
            )

            self.assertTrue(body["pin_unlocked"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class ModalContractTests(unittest.TestCase):
    """BB.modal returns {close, card}, not a DOM node.

    Treating it as an element (``dialog.addEventListener``) throws at runtime and
    would silently break the unlock prompt, so pin the contract the portal uses.
    """

    def _asset(self, name: str) -> str:
        import myownca.online.app as app_module

        return (Path(app_module.__file__).parent / "static" / name).read_text()

    def test_unlock_prompt_uses_the_onclose_callback(self) -> None:
        script = self._asset("superuser.js")
        self.assertIn("onClose: () => finish(false)", script)
        self.assertNotIn('dialog.addEventListener("close"', script)

    def test_shared_modal_still_returns_close_and_card(self) -> None:
        self.assertIn("return { close, card };", self._asset("app_shared.js"))
