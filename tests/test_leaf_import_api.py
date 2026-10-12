from __future__ import annotations

import base64
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import HTTPException

from myownca.domain import (
    CertificateProfile,
    CertificateStatus,
    CertificateTemplate,
    IssuerCRL,
    Person,
    RequestStatus,
    RevocationReason,
    Revocation,
    Role,
    SubCA,
)
from myownca.key_lifecycle import KeyLifecycleError, KeyStatus
from myownca.licensing import LicenseLimitError, LicenseStateError
from myownca.online.app import (
    CertificateArchive,
    CertificateRenewalCreate,
    DeviceCreate,
    LeafImportAnalyze,
    LeafImportCommit,
    PersonCreate,
    create_app,
)
from myownca.storage.repositories import RepositoryError
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _importable_leaf(
    app,
    common_name: str = "import.example.test",
    *,
    subject_alt_names: list[x509.GeneralName] | None = None,
):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    issuer = app.state.lab_chain.issuer
    certificate = app.state.hsm.sign_certificate(
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                subject_alt_names or [x509.DNSName(common_name)]
            ),
            critical=False,
        ),
        issuer.key_ref,
    )
    return certificate, key


class LeafImportAPITests(unittest.TestCase):
    def _app(self, tempdir: str):
        app = create_app(Path(tempdir) / "leaf-import.sqlite3", lab_mode=True)
        app.state.repository.add_template(
            CertificateTemplate(
                id="host",
                name="Host TLS",
                profile=CertificateProfile.HOST_TLS,
            )
        )
        admin_secret = add_login_ready_user(
            app,
            user_id="admin-1",
            email="admin@example.test",
            role=Role.ADMIN,
        )
        user_secret = add_login_ready_user(
            app,
            user_id="user-1",
            email="owner@example.test",
            role=Role.USER,
        )
        person = Person(
            id="person-owner",
            name="Leaf",
            surname="Owner",
            email="owner@example.test",
            created_at=datetime.now(timezone.utc),
        )
        app.state.repository.add_person(person)
        admin = create_active_session(
            app, email="admin@example.test", totp_secret=admin_secret
        )
        user = create_active_session(
            app, email="owner@example.test", totp_secret=user_secret
        )
        return app, admin, user

    def _payload(self, app, *, with_key: bool = True):
        certificate, key = _importable_leaf(app)
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        analyze = LeafImportAnalyze(
            bundle_b64=_b64(cert_pem),
            private_key_b64=_b64(key_pem) if with_key else None,
        )
        commit = LeafImportCommit(
            **analyze.model_dump(),
            template_id="host",
            person_id="person-owner",
        )
        return certificate, analyze, commit

    def test_analyze_commit_idempotency_and_inventory_id(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _admin, user = self._app(tempdir)
            certificate, analyze, commit = self._payload(app)
            token, csrf = user
            analyzed = route_endpoint(
                app, "/internal/certificates/import/analyze", "POST"
            )(analyze, request_with_session(token, csrf, method="POST"))
            self.assertEqual(analyzed["recommended_template_id"], "host")
            self.assertTrue(analyzed["has_private_key"])

            imported = route_endpoint(app, "/internal/certificates/import", "POST")(
                commit, request_with_session(token, csrf, method="POST")
            )
            repeated = route_endpoint(app, "/internal/certificates/import", "POST")(
                commit, request_with_session(token, csrf, method="POST")
            )
            self.assertEqual(imported["certificate_id"], repeated["certificate_id"])
            self.assertEqual(imported["source"], "imported")
            self.assertEqual(
                imported["serial_number"], format(certificate.serial_number, "x")
            )
            by_id = route_endpoint(
                app, "/internal/certificate-inventory/{certificate_id}", "GET"
            )(imported["certificate_id"], request_with_session(token))
            self.assertEqual(by_id["serial_number"], imported["serial_number"])

    def test_import_recovers_revocation_from_issuer_ledger(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _admin, user = self._app(tempdir)
            certificate, analyze, commit = self._payload(app)
            issuer = app.state.lab_chain.issuer
            issuer_id = issuer.certificate.fingerprint(hashes.SHA256()).hex()
            revoked_at = (
                datetime.now(timezone.utc) - timedelta(days=5)
            ).replace(microsecond=0)
            app.state.repository.import_issuer_crl(
                IssuerCRL(
                    issuer_subject=issuer.certificate.subject.rfc4514_string(),
                    number=14,
                    crl_pem="migration-placeholder",
                    generated_at=revoked_at,
                    issuer_id=issuer_id,
                    source="imported",
                ),
                [
                    Revocation(
                        serial_number=format(certificate.serial_number, "x"),
                        reason=RevocationReason.KEY_COMPROMISE,
                        revoked_at=revoked_at,
                    )
                ],
            )
            token, csrf = user

            analyzed = route_endpoint(
                app, "/internal/certificates/import/analyze", "POST"
            )(analyze, request_with_session(token, csrf, method="POST"))
            imported = route_endpoint(
                app, "/internal/certificates/import", "POST"
            )(commit, request_with_session(token, csrf, method="POST"))

            self.assertEqual(analyzed["revocation"]["status"], "revoked")
            self.assertEqual(
                analyzed["revocation"]["reason"],
                RevocationReason.KEY_COMPROMISE.value,
            )
            self.assertEqual(imported["status"], CertificateStatus.REVOKED.value)
            canonical = next(
                item
                for item in app.state.repository.list_revocations()
                if item.certificate_id == imported["certificate_id"]
            )
            self.assertEqual(canonical.reason, RevocationReason.KEY_COMPROMISE)
            self.assertEqual(canonical.revoked_at, revoked_at)

    def test_host_template_is_not_suggested_for_email_only_san(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _admin, user = self._app(tempdir)
            certificate, _ = _importable_leaf(
                app,
                subject_alt_names=[x509.RFC822Name("owner@example.test")],
            )
            analyze = LeafImportAnalyze(
                bundle_b64=_b64(certificate.public_bytes(serialization.Encoding.PEM))
            )
            token, csrf = user
            result = route_endpoint(
                app, "/internal/certificates/import/analyze", "POST"
            )(analyze, request_with_session(token, csrf, method="POST"))
            self.assertEqual(result["template_candidates"], [])
            self.assertTrue(result["requires_template"])

    def test_commit_rejects_template_disallowed_by_active_subca(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _admin, user = self._app(tempdir)
            issuer = app.state.lab_chain.issuer
            app.state.repository.add_sub_ca(
                SubCA(
                    id="restricted-subca",
                    certificate_pem=issuer.certificate.public_bytes(
                        serialization.Encoding.PEM
                    ).decode(),
                    key_ref=issuer.key_ref,
                    subject=issuer.certificate.subject.rfc4514_string(),
                    created_at=datetime.now(timezone.utc),
                    allowed_profiles=(CertificateProfile.USER_AUTH,),
                )
            )
            app.state.repository.set_active_sub_ca("restricted-subca")
            _certificate, analyze, commit = self._payload(app)
            token, csrf = user
            result = route_endpoint(
                app, "/internal/certificates/import/analyze", "POST"
            )(analyze, request_with_session(token, csrf, method="POST"))
            self.assertEqual(result["template_candidates"], [])
            with self.assertRaises(HTTPException) as rejected:
                route_endpoint(app, "/internal/certificates/import", "POST")(
                    commit,
                    request_with_session(token, csrf, method="POST"),
                )
            self.assertEqual(rejected.exception.status_code, 400)
            self.assertIn("active issuer policy", rejected.exception.detail)

    def test_idempotent_retry_does_not_consult_license_capacity(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _admin, user = self._app(tempdir)
            _certificate, _analyze, commit = self._payload(app)
            token, csrf = user
            imported = route_endpoint(app, "/internal/certificates/import", "POST")(
                commit, request_with_session(token, csrf, method="POST")
            )

            with mock.patch.object(
                app.state.licensing,
                "check_first_issuance",
                side_effect=AssertionError("idempotency must precede license checks"),
            ), mock.patch.object(
                app.state.licensing,
                "authorize_issuance",
                side_effect=AssertionError("idempotency must not reserve capacity"),
            ):
                repeated = route_endpoint(
                    app, "/internal/certificates/import", "POST"
                )(commit, request_with_session(token, csrf, method="POST"))

            self.assertEqual(repeated["certificate_id"], imported["certificate_id"])

    def test_atomic_new_device_retry_without_client_id_is_idempotent(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, admin, _user = self._app(tempdir)
            _certificate, _analyze, commit = self._payload(app)
            commit = commit.model_copy(
                update={
                    "person_id": None,
                    "new_device": DeviceCreate(
                        device_name="Imported gateway",
                        fqdn="gateway.example.test",
                        admin_id="person-owner",
                        comments="Created with certificate import",
                    ),
                }
            )
            token, csrf = admin

            imported = route_endpoint(app, "/internal/certificates/import", "POST")(
                commit, request_with_session(token, csrf, method="POST")
            )
            repeated = route_endpoint(app, "/internal/certificates/import", "POST")(
                commit, request_with_session(token, csrf, method="POST")
            )

            self.assertEqual(repeated["certificate_id"], imported["certificate_id"])
            self.assertEqual(len(app.state.repository.list_devices()), 1)
            self.assertEqual(
                repeated["holder"]["id"],
                app.state.repository.list_devices()[0].id,
            )

    def test_same_holder_template_and_identity_reuse_lineage(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _admin, user = self._app(tempdir)
            token, csrf = user
            _first_certificate, _first_analyze, first_commit = self._payload(app)
            _second_certificate, _second_analyze, second_commit = self._payload(app)

            first = route_endpoint(app, "/internal/certificates/import", "POST")(
                first_commit, request_with_session(token, csrf, method="POST")
            )
            second = route_endpoint(app, "/internal/certificates/import", "POST")(
                second_commit, request_with_session(token, csrf, method="POST")
            )

            first_row = app.state.repository.get_issued_certificate(
                first["serial_number"]
            )
            second_row = app.state.repository.get_issued_certificate(
                second["serial_number"]
            )
            self.assertEqual(first_row.lineage_id, second_row.lineage_id)
            self.assertEqual(app.state.licensing.active_count(), 1)

    def test_license_failures_roll_back_atomic_new_holder(self) -> None:
        for failure in (
            LicenseLimitError("capacity reached"),
            LicenseStateError("lineage state unavailable"),
        ):
            with self.subTest(failure=type(failure).__name__), TemporaryDirectory() as tempdir:
                app, admin, _user = self._app(tempdir)
                _certificate, _analyze, commit = self._payload(app)
                commit = commit.model_copy(
                    update={
                        "person_id": None,
                        "new_person": PersonCreate(
                            id="atomic-person",
                            name="Atomic",
                            surname="Owner",
                            email="atomic@example.test",
                        ),
                    }
                )
                token, csrf = admin
                with mock.patch.object(
                    app.state.licensing, "authorize_issuance", side_effect=failure
                ), self.assertRaises(HTTPException) as denied:
                    route_endpoint(app, "/internal/certificates/import", "POST")(
                        commit, request_with_session(token, csrf, method="POST")
                    )

                self.assertEqual(denied.exception.status_code, 409)
                with self.assertRaises(RepositoryError):
                    app.state.repository.get_person("atomic-person")
                self.assertEqual(app.state.repository.list_issued_certificates(), [])
                imported_requests = app.state.repository.list_requests(
                    include_imports=True
                )
                self.assertTrue(imported_requests)
                self.assertTrue(
                    all(item.status is RequestStatus.REJECTED for item in imported_requests)
                )
                self.assertEqual(app.state.licensing.reserved_count(), 0)

    def test_key_lifecycle_failure_orphans_stored_key_and_rolls_back_holder(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, admin, _user = self._app(tempdir)
            _certificate, _analyze, commit = self._payload(app)
            commit = commit.model_copy(
                update={
                    "person_id": None,
                    "new_person": PersonCreate(
                        id="key-failure-person",
                        name="Key",
                        surname="Failure",
                        email="key-failure@example.test",
                    ),
                }
            )
            original_bind = app.state.key_lifecycle.bind_key
            calls = 0

            def fail_certificate_binding(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise KeyLifecycleError("simulated lifecycle outage")
                return original_bind(*args, **kwargs)

            token, csrf = admin
            with mock.patch.object(
                app.state.key_lifecycle,
                "bind_key",
                side_effect=fail_certificate_binding,
            ), self.assertRaises(HTTPException) as denied:
                route_endpoint(app, "/internal/certificates/import", "POST")(
                    commit, request_with_session(token, csrf, method="POST")
                )

            self.assertEqual(denied.exception.status_code, 503)
            with self.assertRaises(RepositoryError):
                app.state.repository.get_person("key-failure-person")
            self.assertEqual(app.state.repository.list_issued_certificates(), [])
            imported_request = app.state.repository.list_requests(
                include_imports=True
            )[0]
            self.assertIs(imported_request.status, RequestStatus.REJECTED)
            key = app.state.key_lifecycle.repository.find(
                backend="request_vault", key_ref=imported_request.id
            )
            self.assertIsNotNone(key)
            self.assertIs(key.status, KeyStatus.ORPHANED)
            self.assertIsNotNone(key.delete_after)
            self.assertEqual(len(app.state.repository.list_request_private_keys()), 1)

    def test_finalize_failure_removes_staged_certificate_binding(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _admin, user = self._app(tempdir)
            _certificate, _analyze, commit = self._payload(app)
            token, csrf = user
            with mock.patch.object(
                app.state.repository,
                "finalize_issued_certificate",
                side_effect=RepositoryError("simulated commit failure"),
            ), self.assertRaises(HTTPException) as denied:
                route_endpoint(app, "/internal/certificates/import", "POST")(
                    commit, request_with_session(token, csrf, method="POST")
                )

            self.assertEqual(denied.exception.status_code, 400)
            self.assertEqual(app.state.repository.list_issued_certificates(), [])
            imported_request = app.state.repository.list_requests(
                include_imports=True
            )[0]
            self.assertIs(imported_request.status, RequestStatus.REJECTED)
            key = app.state.key_lifecycle.repository.find(
                backend="request_vault", key_ref=imported_request.id
            )
            self.assertIsNotNone(key)
            self.assertIs(key.status, KeyStatus.ORPHANED)
            self.assertEqual(app.state.key_lifecycle.repository.list_bindings(key.id), [])

    def test_certificate_only_renewal_rotates_key(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _admin, user = self._app(tempdir)
            _certificate, _analyze, commit = self._payload(app, with_key=False)
            token, csrf = user
            imported = route_endpoint(app, "/internal/certificates/import", "POST")(
                commit, request_with_session(token, csrf, method="POST")
            )
            renewal = route_endpoint(
                app, "/internal/certificates/{serial_number}/renew", "POST"
            )(
                imported["serial_number"],
                request_with_session(token, csrf, method="POST"),
            )
            self.assertTrue(renewal["server_key_held"])

    def test_successful_renewal_supersedes_anchor_and_keeps_reused_key_bound(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _admin, user = self._app(tempdir)
            superuser_secret = add_login_ready_user(
                app,
                user_id="superuser-1",
                email="superuser@example.test",
                role=Role.SUPERUSER,
            )
            superuser = create_active_session(
                app,
                email="superuser@example.test",
                totp_secret=superuser_secret,
            )
            _certificate, _analyze, commit = self._payload(app)
            token, csrf = user
            imported = route_endpoint(app, "/internal/certificates/import", "POST")(
                commit, request_with_session(token, csrf, method="POST")
            )
            anchor = app.state.repository.get_issued_certificate(
                imported["serial_number"]
            )
            old_key_id = anchor.key_registry_id
            self.assertIsNotNone(old_key_id)

            renewal = route_endpoint(
                app, "/internal/certificates/{serial_number}/renew", "POST"
            )(
                anchor.serial_number,
                request_with_session(token, csrf, method="POST"),
                CertificateRenewalCreate(mode="reuse"),
            )
            superuser_token, superuser_csrf = superuser
            approved = route_endpoint(
                app,
                "/internal/certificate-requests/{request_id}/approvals",
                "POST",
            )(
                renewal["id"],
                request_with_session(
                    superuser_token, superuser_csrf, method="POST"
                ),
            )

            self.assertTrue(approved["auto_issued"])
            replacement = app.state.repository.get_issued_certificate_by_request_id(
                renewal["id"]
            )
            self.assertIsNotNone(replacement)
            self.assertIs(replacement.status, CertificateStatus.ACTIVE)
            old = app.state.repository.get_issued_certificate(anchor.serial_number)
            self.assertIs(old.status, CertificateStatus.REVOKED)
            revocation = next(
                item
                for item in app.state.repository.list_revocations()
                if item.serial_number == anchor.serial_number
            )
            self.assertIs(revocation.reason, RevocationReason.SUPERSEDED)
            self.assertEqual(replacement.key_registry_id, old_key_id)
            new_key = app.state.key_lifecycle.repository.get(
                replacement.key_registry_id
            )
            self.assertIs(new_key.status, KeyStatus.ACTIVE)
            bindings = app.state.key_lifecycle.repository.list_bindings(new_key.id)
            self.assertEqual(
                {
                    (binding.resource_type, binding.resource_id)
                    for binding in bindings
                },
                {("certificate", replacement.certificate_id)},
            )

            rotated_request = route_endpoint(
                app, "/internal/certificates/{serial_number}/renew", "POST"
            )(
                replacement.serial_number,
                request_with_session(token, csrf, method="POST"),
                CertificateRenewalCreate(mode="rotate"),
            )
            rotated_approval = route_endpoint(
                app,
                "/internal/certificate-requests/{request_id}/approvals",
                "POST",
            )(
                rotated_request["id"],
                request_with_session(
                    superuser_token, superuser_csrf, method="POST"
                ),
            )
            self.assertTrue(rotated_approval["auto_issued"])
            rotated = app.state.repository.get_issued_certificate_by_request_id(
                rotated_request["id"]
            )
            self.assertIsNotNone(rotated)
            self.assertNotEqual(rotated.key_registry_id, old_key_id)
            self.assertIs(
                app.state.key_lifecycle.repository.get(old_key_id).status,
                KeyStatus.ORPHANED,
            )
            self.assertIs(
                app.state.key_lifecycle.repository.get(
                    rotated.key_registry_id
                ).status,
                KeyStatus.ACTIVE,
            )
            orphaned = app.state.key_lifecycle.repository.get(old_key_id)
            app.state.key_lifecycle.cleanup_due(now=orphaned.delete_after)
            remaining_request_ids = {
                row["request_id"]
                for row in app.state.repository.list_request_private_keys()
            }
            self.assertNotIn(anchor.request_id, remaining_request_ids)
            self.assertNotIn(replacement.request_id, remaining_request_ids)
            self.assertIn(rotated.request_id, remaining_request_ids)

    def test_archive_keeps_key_material_during_grace_period(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _admin, user = self._app(tempdir)
            _certificate, _analyze, commit = self._payload(app)
            token, csrf = user
            imported = route_endpoint(app, "/internal/certificates/import", "POST")(
                commit, request_with_session(token, csrf, method="POST")
            )
            app.state.auth_service.reauthenticate_password(
                token, "very-long-test-password"
            )
            archived = route_endpoint(
                app, "/internal/certificates/{serial_number}", "DELETE"
            )(
                imported["serial_number"],
                CertificateArchive(
                    reason="Certificate is no longer needed by its owner",
                    confirmation=f"ARCHIVE CERTIFICATE {imported['serial_number']}",
                ),
                request_with_session(token, csrf, method="DELETE"),
            )
            self.assertIsNotNone(archived["archived_at"])
            self.assertEqual(archived["status"], "revoked")
            rows = app.state.repository.list_request_private_keys()
            self.assertEqual(len(rows), 1)
            key = app.state.key_lifecycle.repository.find(
                backend="request_vault", key_ref=archived["request_id"]
            )
            self.assertIsNotNone(key)
            self.assertEqual(key.status.value, "orphaned")
            self.assertEqual(key.delete_after - key.orphaned_at, timedelta(days=30))

    def test_user_cannot_import_for_another_person(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _admin, user = self._app(tempdir)
            app.state.repository.add_person(
                Person(
                    id="other-person",
                    name="Other",
                    surname="Owner",
                    email="other@example.test",
                    created_at=datetime.now(timezone.utc),
                )
            )
            _certificate, _analyze, commit = self._payload(app)
            commit = commit.model_copy(
                update={"person_id": "other-person"}
            )
            token, csrf = user
            with self.assertRaises(HTTPException) as denied:
                route_endpoint(app, "/internal/certificates/import", "POST")(
                    commit, request_with_session(token, csrf, method="POST")
                )
            self.assertEqual(denied.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
