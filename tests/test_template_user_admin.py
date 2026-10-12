from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException

from myownca.ca_auth.service import AuthenticationError
from myownca.domain import CertificateProfile, CertificateTemplate, Role
from myownca.online.app import TemplateCreate, TemplateUpdate, create_app
from myownca.storage.database import Database
from myownca.storage.repositories import PKIRepository
from myownca.storage.repositories import RepositoryError
from tests.helpers import (
    TempPKI,
    add_login_ready_user,
    create_active_session,
    make_csr,
    request_with_session,
    route_endpoint,
)


class TemplateAdminRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.pki.add_template("host", CertificateProfile.HOST_TLS)

    def tearDown(self) -> None:
        self.pki.close()

    def test_update_template_changes_fields(self) -> None:
        self.pki.repository.update_template(
            CertificateTemplate(
                id="host",
                name="Host TLS v2",
                profile=CertificateProfile.HOST_TLS,
                validity_days=730,
                first_issuance_approvals=3,
                renewal_approvals=2,
            )
        )
        updated = self.pki.repository.get_template("host")
        self.assertEqual(updated.name, "Host TLS v2")
        self.assertEqual(updated.validity_days, 730)
        self.assertEqual(updated.first_issuance_approvals, 3)

    def test_key_algorithm_policy_round_trips_and_rejects_invalid_sets(self) -> None:
        constrained = CertificateTemplate(
            id="host",
            name="Host TLS v2",
            profile=CertificateProfile.HOST_TLS,
            allowed_key_algorithms=("rsa-2048", "rsa-4096"),
        )
        self.pki.repository.update_template(constrained)
        self.assertEqual(
            self.pki.repository.get_template("host").allowed_key_algorithms,
            ("rsa-2048", "rsa-4096"),
        )
        for algorithms in ((), ("rsa-2048", "rsa-2048"), ("unsupported",)):
            with self.subTest(algorithms=algorithms):
                with self.assertRaises(ValueError):
                    CertificateTemplate(
                        id="invalid",
                        name="Invalid",
                        profile=CertificateProfile.HOST_TLS,
                        allowed_key_algorithms=algorithms,
                    )

    def test_policy_migration_defaults_existing_templates_to_full_catalog(self) -> None:
        migrations = Path(__file__).parents[1] / "src/myownca/storage/migrations"
        with TemporaryDirectory() as tempdir:
            database = Database(Path(tempdir) / "legacy-templates.sqlite3")
            with database.connect() as connection:
                connection.executescript(
                    "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY)"
                )
                for migration in sorted(migrations.glob("*.sql")):
                    if migration.name >= "0041_template_allowed_key_algorithms.sql":
                        break
                    connection.executescript(migration.read_text())
                    connection.execute(
                        "INSERT INTO schema_migrations(version) VALUES (?)",
                        (migration.name,),
                    )
                connection.execute(
                    """
                    INSERT INTO certificate_templates(
                        id, name, profile, validity_days,
                        first_issuance_approvals, renewal_approvals,
                        key_usages_json, extended_key_usages_json,
                        key_usage_critical, extended_key_usage_critical
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "legacy-host",
                        "Legacy host",
                        CertificateProfile.HOST_TLS.value,
                        365,
                        2,
                        1,
                        '["digital_signature", "key_encipherment"]',
                        '["server_auth"]',
                        1,
                        0,
                    ),
                )
            database.migrate()
            self.assertEqual(
                PKIRepository(database).get_template("legacy-host").allowed_key_algorithms,
                (
                    "rsa-2048",
                    "rsa-3072",
                    "rsa-4096",
                    "ecdsa-p256",
                    "ecdsa-p384",
                    "ecdsa-p521",
                ),
            )

    def test_update_unknown_template_raises(self) -> None:
        with self.assertRaises(RepositoryError):
            self.pki.repository.update_template(
                CertificateTemplate(id="ghost", name="x", profile=CertificateProfile.HOST_TLS)
            )

    def test_delete_template_removes_it(self) -> None:
        self.pki.repository.delete_template("host")
        with self.assertRaises(RepositoryError):
            self.pki.repository.get_template("host")

    def test_delete_unknown_template_raises(self) -> None:
        with self.assertRaises(RepositoryError):
            self.pki.repository.delete_template("ghost")

    def test_delete_referenced_template_blocked(self) -> None:
        self.pki.service.submit_request("host", make_csr("host.example.test", dns_names=("host.example.test",)))
        with self.assertRaises(RepositoryError):
            self.pki.repository.delete_template("host")


def _admin_app(tempdir: str):
    app = create_app(Path(tempdir) / "admin.sqlite3")
    admin = add_login_ready_user(app, user_id="admin-1", email="admin1@example.test", role=Role.ADMIN)
    admin2 = add_login_ready_user(app, user_id="admin-2", email="admin2@example.test", role=Role.ADMIN)
    su = add_login_ready_user(app, user_id="su-1", email="su1@example.test", role=Role.SUPERUSER)
    add_login_ready_user(app, user_id="user-1", email="user@example.test", role=Role.USER)
    tokens = {
        "admin": create_active_session(app, email="admin1@example.test", totp_secret=admin),
        "admin2": create_active_session(app, email="admin2@example.test", totp_secret=admin2),
        "su": create_active_session(app, email="su1@example.test", totp_secret=su),
        "user": create_active_session(app, email="user@example.test"),
    }
    return app, tokens


class TemplateAdminAPITests(unittest.TestCase):
    def test_update_template_via_put(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _admin_app(tempdir)
            token, csrf = tokens["admin"]
            app.state.repository.add_template(
                CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)
            )
            response = route_endpoint(app, "/internal/templates/{template_id}", "PUT")(
                "host",
                TemplateUpdate(name="Host v2", profile=CertificateProfile.HOST_TLS, validity_days=730),
                request_with_session(token, csrf, method="PUT"),
            )
            self.assertEqual(response["name"], "Host v2")
            self.assertEqual(response["validity_days"], 730)
            self.assertEqual(len(response["allowed_key_algorithms"]), 6)

    def test_template_api_persists_algorithm_policy(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _admin_app(tempdir)
            token, csrf = tokens["admin"]
            created = route_endpoint(app, "/internal/templates", "POST")(
                TemplateCreate(
                    id="host",
                    name="Host",
                    profile=CertificateProfile.HOST_TLS,
                    allowed_key_algorithms=["rsa-2048", "ecdsa-p384"],
                ),
                request_with_session(token, csrf, method="POST"),
            )
            self.assertEqual(created, {"id": "host"})
            template = route_endpoint(app, "/internal/templates", "GET")(
                request_with_session(token)
            )[0]
            self.assertEqual(template["allowed_key_algorithms"], ["rsa-2048", "ecdsa-p384"])

    def test_update_unknown_template_returns_404(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _admin_app(tempdir)
            token, csrf = tokens["admin"]
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/templates/{template_id}", "PUT")(
                    "ghost",
                    TemplateUpdate(name="x", profile=CertificateProfile.HOST_TLS),
                    request_with_session(token, csrf, method="PUT"),
                )
            self.assertEqual(ctx.exception.status_code, 404)

    def test_update_template_rejected_for_ordinary_user(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _admin_app(tempdir)
            token, csrf = tokens["user"]
            app.state.repository.add_template(
                CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)
            )
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/templates/{template_id}", "PUT")(
                    "host",
                    TemplateUpdate(name="Nope", profile=CertificateProfile.HOST_TLS),
                    request_with_session(token, csrf, method="PUT"),
                )
            self.assertEqual(ctx.exception.status_code, 403)

    def test_delete_template_and_referenced_guard(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _admin_app(tempdir)
            token, csrf = tokens["admin"]
            app.state.repository.add_template(
                CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)
            )
            app.state.repository.add_template(
                CertificateTemplate(id="used", name="Used", profile=CertificateProfile.HOST_TLS)
            )
            app.state.service.submit_request("used", make_csr("x.example.test", dns_names=("x.example.test",)))

            # Unreferenced template deletes cleanly.
            deleted = route_endpoint(app, "/internal/templates/{template_id}", "DELETE")(
                "host", request_with_session(token, csrf, method="DELETE")
            )
            self.assertEqual(deleted["id"], "host")

            # Referenced template is blocked with a 409.
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/templates/{template_id}", "DELETE")(
                    "used", request_with_session(token, csrf, method="DELETE")
                )
            self.assertEqual(ctx.exception.status_code, 409)

            # Unknown template delete is a 404.
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/templates/{template_id}", "DELETE")(
                    "ghost", request_with_session(token, csrf, method="DELETE")
                )
            self.assertEqual(ctx.exception.status_code, 404)


class UserLifecycleAPITests(unittest.TestCase):
    def test_deactivate_blocks_login_then_reactivate_restores(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _admin_app(tempdir)
            token, csrf = tokens["admin"]

            route_endpoint(app, "/internal/users/{user_id}/deactivate", "POST")(
                "user-1", request_with_session(token, csrf, method="POST")
            )
            with self.assertRaises(AuthenticationError):
                app.state.auth_service.login("user@example.test", "very-long-test-password")

            response = route_endpoint(app, "/internal/users/{user_id}/reactivate", "POST")(
                "user-1", request_with_session(token, csrf, method="POST")
            )
            self.assertTrue(response["is_active"])
            # Login works again.
            created = app.state.auth_service.login("user@example.test", "very-long-test-password")
            self.assertEqual(created.session.stage.value, "active")

    def test_cannot_deactivate_self(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _admin_app(tempdir)
            token, csrf = tokens["admin"]
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/users/{user_id}/deactivate", "POST")(
                    "admin-1", request_with_session(token, csrf, method="POST")
                )
            self.assertEqual(ctx.exception.status_code, 400)

    def test_superuser_cannot_deactivate_admin(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _admin_app(tempdir)
            token, csrf = tokens["su"]
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/users/{user_id}/deactivate", "POST")(
                    "admin-1", request_with_session(token, csrf, method="POST")
                )
            self.assertEqual(ctx.exception.status_code, 400)

    def test_unknown_user_returns_404(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _admin_app(tempdir)
            token, csrf = tokens["admin"]
            with self.assertRaises(HTTPException) as ctx:
                route_endpoint(app, "/internal/users/{user_id}/deactivate", "POST")(
                    "ghost", request_with_session(token, csrf, method="POST")
                )
            self.assertEqual(ctx.exception.status_code, 404)

    def test_dual_control_keeps_two_active_admins(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, _ = _admin_app(tempdir)
            actor = app.state.auth_repository.get_user("admin-1")
            with self.assertRaises(Exception) as ctx:
                app.state.auth_service.set_user_active(
                    actor,
                    target_user_id="admin-2",
                    active=False,
                )
            self.assertIn("two active administrators", str(ctx.exception))


class TemplateWritesAreAdminOnlyTests(unittest.TestCase):
    def test_superuser_cannot_create_update_or_delete_template(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _admin_app(tempdir)
            su_token, su_csrf = tokens["su"]
            app.state.repository.add_template(
                CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)
            )
            with self.assertRaises(HTTPException) as create_ctx:
                route_endpoint(app, "/internal/templates", "POST")(
                    TemplateCreate(id="new", name="New", profile="host_tls"),
                    request_with_session(su_token, su_csrf, method="POST"),
                )
            self.assertEqual(create_ctx.exception.status_code, 403)
            with self.assertRaises(HTTPException) as update_ctx:
                route_endpoint(app, "/internal/templates/{template_id}", "PUT")(
                    "host",
                    TemplateUpdate(name="Nope", profile=CertificateProfile.HOST_TLS),
                    request_with_session(su_token, su_csrf, method="PUT"),
                )
            self.assertEqual(update_ctx.exception.status_code, 403)
            with self.assertRaises(HTTPException) as delete_ctx:
                route_endpoint(app, "/internal/templates/{template_id}", "DELETE")(
                    "host", request_with_session(su_token, su_csrf, method="DELETE")
                )
            self.assertEqual(delete_ctx.exception.status_code, 403)

    def test_admin_can_create_template_and_superuser_can_read(self) -> None:
        with TemporaryDirectory() as tempdir:
            app, tokens = _admin_app(tempdir)
            admin_token, admin_csrf = tokens["admin"]
            su_token, su_csrf = tokens["su"]
            created = route_endpoint(app, "/internal/templates", "POST")(
                TemplateCreate(id="host", name="Host TLS", profile="host_tls"),
                request_with_session(admin_token, admin_csrf, method="POST"),
            )
            self.assertEqual(created, {"id": "host"})
            listed = route_endpoint(app, "/internal/templates", "GET")(
                request_with_session(su_token)
            )
            self.assertIn("host", {row["id"] for row in listed})


if __name__ == "__main__":
    unittest.main()
