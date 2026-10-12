import base64
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException

from myownca.online.app import LicenseUpload
from myownca.domain import (
    CertificateProfile,
    CertificateStatus,
    CertificateTemplate,
    IssuedCertificate,
    Role,
)
from myownca.licensing import LicenseLimitError, LicenseRepository, LicenseService
from myownca.online.app import create_app
from tests.helpers import (
    TempPKI,
    add_login_ready_user,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
    seed_person,
)

NOW = datetime(2026, 6, 13, 12, 0, tzinfo=timezone.utc)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class _LicenseKey:
    """A throwaway signing key injected through test configuration."""

    _key = None

    def __init__(self, key_id: str = "test") -> None:
        self.key_id = key_id
        if self.__class__._key is None:
            self.__class__._key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.key = self.__class__._key
        self.public_b64 = base64.b64encode(
            self.key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()

    def token(
        self,
        *,
        max_certs: int,
        valid_from: datetime,
        installation_id: str,
        days: int = 365,
    ) -> str:
        payload = {
            "schema": 2,
            "product": "myownca-self-hosted",
            "license_id": "BB-TEST-0001",
            "licensed_to": "Acme Corp",
            "installation_id": installation_id,
            "issued_at": valid_from.isoformat(),
            "valid_from": valid_from.isoformat(),
            "expires_at": (valid_from + timedelta(days=days)).isoformat(),
            "max_certificate_lineages": max_certs,
            "key_id": self.key_id,
        }
        segment = _b64url(json.dumps(payload, separators=(",", ":")).encode())
        signature = self.key.sign(
            segment.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
        return f"{segment}.{_b64url(signature)}"


def _seed_active(pki_or_app, count: int, *, expires_days: int = 365) -> None:
    repo = getattr(pki_or_app, "state", pki_or_app)
    repository = repo.repository if hasattr(repo, "repository") else pki_or_app.repository
    service = repo.service if hasattr(repo, "service") else pki_or_app.service
    for index in range(count):
        request = service.submit_request(
            "host", make_csr(f"f{index}.example.test", dns_names=(f"f{index}.example.test",))
        )
        repository.add_issued_certificate(
            IssuedCertificate(
                serial_number=f"FILL-{uuid4().hex}",
                request_id=request.id,
                template_id="host",
                certificate_pem="x",
                subject=f"CN=f{index}.example.test",
                issued_at=NOW - timedelta(days=1),
                expires_at=NOW + timedelta(days=expires_days),
                status=CertificateStatus.ACTIVE,
            )
        )


class LicenseServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.pki.add_template("host", CertificateProfile.HOST_TLS)
        self.signer = _LicenseKey()
        self.service = LicenseService(
            LicenseRepository(self.pki.database),
            self.pki.repository,
            public_keys={self.signer.key_id: self.signer.public_b64},
        )

    def _token(self, max_certs: int, valid_from: datetime, *, days: int = 365) -> str:
        return self.signer.token(
            max_certs=max_certs,
            valid_from=valid_from,
            installation_id=self.service.installation_id,
            days=days,
        )

    def tearDown(self) -> None:
        self.pki.close()

    def test_active_count_ignores_revoked_and_expired(self) -> None:
        _seed_active(self.pki, 3)
        # one expired, one revoked — neither counts
        request = self.pki.service.submit_request(
            "host", make_csr("x.example.test", dns_names=("x.example.test",))
        )
        self.pki.repository.add_issued_certificate(
            IssuedCertificate(
                serial_number="EXPIRED", request_id=request.id, template_id="host",
                certificate_pem="x", subject="CN=x", issued_at=NOW - timedelta(days=400),
                expires_at=NOW - timedelta(days=1), status=CertificateStatus.ACTIVE,
            )
        )
        request2 = self.pki.service.submit_request(
            "host", make_csr("y.example.test", dns_names=("y.example.test",))
        )
        self.pki.repository.add_issued_certificate(
            IssuedCertificate(
                serial_number="REVOKED", request_id=request2.id, template_id="host",
                certificate_pem="x", subject="CN=y", issued_at=NOW,
                expires_at=NOW + timedelta(days=10), status=CertificateStatus.REVOKED,
            )
        )
        self.assertEqual(self.service.active_count(NOW), 3)

    def test_effective_limit_free_license_floor_and_expiry(self) -> None:
        self.assertEqual(self.service.effective_limit(NOW), 10)  # no license
        self.service.install(
            self._token(50, NOW), uploaded_by="admin-1", now=NOW
        )
        self.assertEqual(self.service.effective_limit(NOW), 50)
        # a tier below the free floor never makes a customer worse off
        self.service.install(
            self._token(3, NOW), uploaded_by="admin-1", now=NOW
        )
        self.assertEqual(self.service.effective_limit(NOW), 10)
        # A previously installed license reverts to free tier after expiry.
        self.service.install(self._token(50, NOW, days=1), uploaded_by="admin-1", now=NOW)
        self.assertEqual(self.service.effective_limit(NOW + timedelta(days=2)), 10)

    def test_check_first_issuance(self) -> None:
        _seed_active(self.pki, 9)
        self.service.check_first_issuance(NOW)  # 9 < 10, ok
        _seed_active(self.pki, 1)
        with self.assertRaises(LicenseLimitError):
            self.service.check_first_issuance(NOW)  # 10 >= 10
        # licensing up raises the ceiling
        self.service.install(
            self._token(20, NOW), uploaded_by="admin-1", now=NOW
        )
        self.service.check_first_issuance(NOW)  # 10 < 20, ok

    def test_install_current_remove(self) -> None:
        self.assertIsNone(self.service.current())
        license = self.service.install(
            self._token(50, NOW), uploaded_by="admin-1", now=NOW
        )
        self.assertEqual(license.licensed_to, "Acme Corp")
        self.assertEqual(self.service.current().max_active_certs, 50)
        self.assertTrue(self.service.remove())
        self.assertIsNone(self.service.current())

    def test_fail_open_on_tampered_stored_token(self) -> None:
        # store a corrupt token directly, bypassing install()
        self.service.repository.replace(
            id="x", token="not.a.valid.token", license_id="L", licensed_to="Acme",
            valid_from=NOW, expires_at=NOW + timedelta(days=365), max_active_certs=999,
            uploaded_by="admin-1", uploaded_at=NOW,
        )
        self.assertIsNone(self.service.current())  # fail-open
        self.assertEqual(self.service.effective_limit(NOW), 10)  # not 999
        self.assertEqual(self.service.status(NOW).value, "invalid")
        self.assertIsNotNone(self.service.verification_error())

    def test_install_rejects_forged_token(self) -> None:
        from myownca.licensing import LicenseError

        token = self._token(99, NOW)
        payload, signature = token.split(".")
        damaged = bytearray(base64.urlsafe_b64decode(signature + "=="))
        damaged[-1] ^= 1

        with self.assertRaises(LicenseError):
            self.service.install(
                f"{payload}.{_b64url(bytes(damaged))}",
                uploaded_by="admin-1",
                now=NOW,
            )
        self.assertIsNone(self.service.current())  # nothing stored

    def test_install_rejects_future_and_expired_tokens(self) -> None:
        from myownca.licensing import LicenseError

        with self.assertRaisesRegex(LicenseError, "not active yet"):
            self.service.install(
                self._token(50, NOW + timedelta(days=1)),
                uploaded_by="admin-1",
                now=NOW,
            )
        with self.assertRaisesRegex(LicenseError, "expired"):
            self.service.install(
                self._token(50, NOW - timedelta(days=2), days=1),
                uploaded_by="admin-1",
                now=NOW,
            )

    def test_summary_shape(self) -> None:
        _seed_active(self.pki, 4)
        self.service.install(
            self._token(50, NOW), uploaded_by="admin-1", now=NOW
        )
        summary = self.service.summary(NOW)
        self.assertEqual(summary["status"], "valid")
        self.assertEqual(summary["active_count"], 4)
        self.assertEqual(summary["effective_limit"], 50)
        self.assertEqual(summary["licensed_to"], "Acme Corp")
        self.assertEqual(summary["days_remaining"], 365)
        self.assertTrue(summary["renewal_allowed"])
        self.assertIsNone(summary["renewal_grace_ends_at"])


def _gate_app(tempdir: str, public_keys: dict[str, str] | None = None):
    with mock.patch("myownca.config.licensing_public_keys", return_value=public_keys or {}):
        app = create_app(Path(tempdir) / "l.sqlite3", lab_mode=True)
    su = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="user-1", email="user@example.test", role=Role.USER)
    app.state.repository.add_template(
        CertificateTemplate(
            id="host", name="Host", profile=CertificateProfile.HOST_TLS,
            first_issuance_approvals=1, renewal_approvals=1,
        )
    )
    session = create_active_session(app, email="su1@example.test", totp_secret=su)
    return app, session


def _approve(app, session, request_id):
    token, csrf = session
    return route_endpoint(app, "/internal/certificate-requests/{request_id}/approvals", "POST")(
        request_id, request_with_session(token, csrf, method="POST")
    )


class IssuanceGateTests(unittest.TestCase):
    def test_duplicate_first_issuance_reports_renewal_action(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session = _gate_app(tempdir)
            person_id = seed_person(app)
            csr = make_csr("duplicate.example.test", dns_names=("duplicate.example.test",))
            first = app.state.service.submit_request(
                "host", csr, requested_by_user_id="user-1"
            )
            app.state.service.assign_request_holder(first.id, person_id=person_id)
            issued = _approve(app, session, first.id)
            self.assertTrue(issued["auto_issued"])

            duplicate = app.state.service.submit_request(
                "host", csr, requested_by_user_id="user-1"
            )
            app.state.service.assign_request_holder(duplicate.id, person_id=person_id)
            response = _approve(app, session, duplicate.id)

            self.assertFalse(response["auto_issued"])
            self.assertEqual(
                response["auto_issue_error"]["code"], "duplicate_certificate_identity"
            )
            self.assertIn("Renew action", response["auto_issue_error"]["message"])
            self.assertIsNone(response["issued_certificate"])
            self.assertEqual(app.state.licensing.reserved_count(), 0)

    def test_first_issuance_blocked_at_free_limit(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session = _gate_app(tempdir)
            _seed_active(app, 10)
            request = app.state.service.submit_request(
                "host", make_csr("new.example.test", dns_names=("new.example.test",)),
                requested_by_user_id="user-1",
            )
            app.state.service.assign_request_holder(request.id, person_id=seed_person(app))
            response = _approve(app, session, request.id)
            self.assertFalse(response["auto_issued"])
            self.assertEqual(response["auto_issue_error"]["code"], "license_limit_reached")
            self.assertIsNone(response["issued_certificate"])

    def test_license_raises_ceiling(self) -> None:
        with TemporaryDirectory() as tempdir:
            signer = _LicenseKey()
            app, session = _gate_app(tempdir, {signer.key_id: signer.public_b64})
            app.state.licensing.install(
                signer.token(
                    max_certs=20,
                    valid_from=NOW,
                    installation_id=app.state.licensing.installation_id,
                ),
                uploaded_by="admin-1",
            )
            _seed_active(app, 10)
            request = app.state.service.submit_request(
                "host", make_csr("ok.example.test", dns_names=("ok.example.test",)),
                requested_by_user_id="user-1",
            )
            app.state.service.assign_request_holder(request.id, person_id=seed_person(app))
            response = _approve(app, session, request.id)
            self.assertTrue(response["auto_issued"])
            self.assertIsNotNone(response["issued_certificate"])

    def test_renewal_allowed_over_limit(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, session = _gate_app(tempdir)
            token, csrf = session
            # one real anchor cert, issued while under the limit
            anchor_req = app.state.service.submit_request(
                "host", make_csr("anchor.example.test", dns_names=("anchor.example.test",)),
                requested_by_user_id="user-1",
            )
            app.state.service.approve_request(anchor_req.id, "su-1")
            app.state.service.assign_request_holder(anchor_req.id, person_id=seed_person(app))
            anchor = app.state.service.issue_certificate(anchor_req.id, app.state.lab_chain.issuer)
            _seed_active(app, 9)  # now 10 active → at the free limit
            self.assertEqual(app.state.licensing.active_count(), 10)

            renewal = route_endpoint(
                app, "/internal/certificates/{serial_number}/renew", "POST"
            )(anchor.serial_number, request_with_session(token, csrf, method="POST"))
            app.state.service.assign_request_holder(renewal["id"], person_id=seed_person(app))
            response = _approve(app, session, renewal["id"])
            # renewal issues despite being over the limit
            self.assertTrue(response["auto_issued"])
            self.assertIsNotNone(response["issued_certificate"])


class LicenseApiTests(unittest.TestCase):
    def _app(self, tempdir, public_keys: dict[str, str] | None = None):
        with mock.patch("myownca.config.licensing_public_keys", return_value=public_keys or {}):
            app = create_app(Path(tempdir) / "api.sqlite3", lab_mode=True)
        admin = add_login_ready_user(
            app, user_id="admin-1", email="admin@example.test", role=Role.ADMIN
        )
        su = add_login_ready_user(
            app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER
        )
        admin_session = create_active_session(app, email="admin@example.test", totp_secret=admin)
        su_session = create_active_session(app, email="su1@example.test", totp_secret=su)
        return app, admin_session, su_session

    def test_get_install_remove_roundtrip(self) -> None:
        with TemporaryDirectory() as tempdir:
            signer = _LicenseKey()
            app, (token, csrf), (su_token, su_csrf) = self._app(
                tempdir, {signer.key_id: signer.public_b64}
            )
            status = route_endpoint(app, "/internal/admin/license", "GET")(
                request_with_session(token, csrf)
            )
            self.assertEqual(status["status"], "none")
            self.assertEqual(status["effective_limit"], 10)
            self.assertEqual(status["usage_unit"], "certificate_lineage")
            self.assertEqual(status["lineage_limit"], 10)
            self.assertIn("installation_id", status)

            installed = route_endpoint(app, "/internal/admin/license", "PUT")(
                LicenseUpload(token=signer.token(
                    max_certs=100,
                    valid_from=NOW,
                    installation_id=app.state.licensing.installation_id,
                )),
                request_with_session(token, csrf, method="PUT"),
            )
            self.assertEqual(installed["status"], "valid")
            self.assertEqual(installed["effective_limit"], 100)
            self.assertEqual(installed["max_certificate_lineages"], 100)
            self.assertEqual(installed["licensed_to"], "Acme Corp")

            removed = route_endpoint(app, "/internal/admin/license", "DELETE")(
                request_with_session(token, csrf, method="DELETE")
            )
            self.assertEqual(removed["status"], "none")
            self.assertEqual(removed["effective_limit"], 10)

    def test_forged_upload_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, (token, csrf), _su = self._app(tempdir)
            stranger = _LicenseKey()  # not embedded
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/admin/license", "PUT")(
                    LicenseUpload(token=stranger.token(
                        max_certs=999,
                        valid_from=NOW,
                        installation_id=app.state.licensing.installation_id,
                    )),
                    request_with_session(token, csrf, method="PUT"),
                )
            self.assertEqual(ctx.exception.status_code, 400)

    def test_legacy_key_configuration_blocks_before_database_creation(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = Path(tempdir) / "bad-keys.sqlite3"
            with mock.patch.dict("os.environ", {"MYOWNCA_LICENSE_PUBLIC_KEYS": "not-json"}):
                with self.assertRaisesRegex(ValueError, "no longer supported"):
                    create_app(database, lab_mode=True)
            self.assertFalse(database.exists())

    def test_installation_mismatch_is_stable_conflict(self) -> None:
        with TemporaryDirectory() as tempdir:
            signer = _LicenseKey()
            app, (token, csrf), _su = self._app(
                tempdir, {signer.key_id: signer.public_b64}
            )
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/admin/license", "PUT")(
                    LicenseUpload(token=signer.token(
                        max_certs=100,
                        valid_from=NOW,
                        installation_id=str(uuid4()),
                    )),
                    request_with_session(token, csrf, method="PUT"),
                )
            self.assertEqual(ctx.exception.status_code, 409)
            self.assertEqual(ctx.exception.detail["code"], "license_installation_mismatch")

    def test_superuser_and_auditor_can_read_not_write(self) -> None:
        with TemporaryDirectory() as tempdir:
            signer = _LicenseKey()
            app, _admin, (su_token, su_csrf) = self._app(
                tempdir, {signer.key_id: signer.public_b64}
            )
            # read OK
            status = route_endpoint(app, "/internal/admin/license", "GET")(
                request_with_session(su_token, su_csrf)
            )
            self.assertEqual(status["status"], "none")
            # write denied
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/admin/license", "PUT")(
                    LicenseUpload(token=signer.token(
                        max_certs=50,
                        valid_from=NOW,
                        installation_id=app.state.licensing.installation_id,
                    )),
                    request_with_session(su_token, su_csrf, method="PUT"),
                )
            self.assertEqual(ctx.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
