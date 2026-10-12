from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from myownca.config import Settings
from myownca.setup.config_writer import read_config_env, read_secrets
from myownca.setup.orchestrator import SetupError, SetupOrchestrator
from myownca.setup.state import load_setup_state, save_setup_state


def _self_signed_root_pem() -> str:
    from myownca.ca_hsm import SoftwareHSM
    from myownca.ca_main.crypto import certificate_to_pem, create_lab_ca_chain

    return certificate_to_pem(create_lab_ca_chain(SoftwareHSM()).root.certificate)


def _write_tls_pair(directory: str | Path, *, matching: bool = True) -> tuple[str, str]:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    key_for_file = key if matching else ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "portal.example.test")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    certificate_path = Path(directory) / "portal.crt"
    key_path = Path(directory) / "portal.key"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key_for_file.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(certificate_path), str(key_path)


def _root_variant_pem(
    *,
    self_issued: bool = True,
    valid: bool = True,
    basic_constraints: bool = True,
    ca: bool = True,
    key_usage: bool = True,
    key_cert_sign: bool = True,
    valid_signature: bool = True,
) -> str:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = key if valid_signature else rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=1) if valid else now - timedelta(days=3)
    not_after = now + timedelta(days=30) if valid else now - timedelta(days=1)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")])
    issuer = subject if self_issued else x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Different Issuer")]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=1 if ca else None), critical=True
        )
    if key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    certificate = builder.sign(signer, hashes.SHA256())
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


_ADMIN_1 = {"id": "admin-1", "email": "a1@example.test", "password": "p" * 16}
_ADMIN_2 = {"id": "admin-2", "email": "a2@example.test", "password": "q" * 16}


def _set_required_admins(orchestrator: SetupOrchestrator) -> None:
    if orchestrator.snapshot()["governance_mode"] is None:
        orchestrator.set_governance_mode("dual_control")
    if orchestrator.snapshot()["listener"] is None:
        orchestrator.set_listener(topology="proxy")
    orchestrator.set_admins(dict(_ADMIN_1), dict(_ADMIN_2))


def _finalize_with_configured_issuer(orchestrator: SetupOrchestrator) -> None:
    """Unit-test non-issuer finalization fields with a persisted issuer stub."""

    with mock.patch(
        "myownca.setup.provisioning.SetupProvisioningService"
    ) as provisioning_type:
        provisioning = provisioning_type.return_value
        provisioning.status.return_value = {"configured": True, "pending": []}
        provisioning.repository.list_sub_cas.return_value = [object()]
        provisioning.assert_finalizable = mock.Mock(
            return_value={"configured": True, "pending": []}
        )
        orchestrator.finalize()


class OrchestratorStateTests(unittest.TestCase):
    def test_fresh_snapshot_is_incomplete_and_empty(self) -> None:
        with TemporaryDirectory() as tempdir:
            snapshot = SetupOrchestrator(tempdir).snapshot()
        self.assertFalse(snapshot["complete"])
        self.assertEqual(snapshot["steps"], {})
        self.assertIsNone(snapshot["install_type"])

    def test_set_install_type_persists_and_marks_step(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            snapshot = SetupOrchestrator(tempdir).snapshot()  # reload from disk
        self.assertEqual(snapshot["install_type"], "lab")
        self.assertEqual(snapshot["steps"]["install_type"], "done")
        # Marking a step done must NOT mark the whole setup complete.
        self.assertFalse(snapshot["complete"])

    def test_set_direct_listener_persists_ipv4_ipv6_and_loopback_values(self) -> None:
        cases = (
            ("127.0.0.1", 8000),
            ("172.21.220.42", 8443),
            ("::1", 8001),
            ("::", 8002),
            ("localhost", 8003),
        )
        for host, port in cases:
            with self.subTest(host=host):
                with TemporaryDirectory() as tempdir:
                    orchestrator = SetupOrchestrator(tempdir)
                    orchestrator.set_listener(
                        topology="direct", bind_host=host, bind_port=port
                    )
                    snapshot = SetupOrchestrator(tempdir).snapshot()
                self.assertEqual(
                    snapshot["listener"],
                    {"topology": "direct", "bind_host": host, "bind_port": port},
                )

    def test_set_direct_listener_persists_validated_tls_paths(self) -> None:
        with TemporaryDirectory() as tempdir:
            certificate_path, key_path = _write_tls_pair(tempdir)
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_listener(
                topology="direct",
                bind_host="127.0.0.1",
                bind_port=8443,
                tls_enabled=True,
                tls_cert=certificate_path,
                tls_key=key_path,
            )
            snapshot = orchestrator.snapshot()
        self.assertEqual(
            snapshot["listener"],
            {
                "topology": "direct",
                "bind_host": "127.0.0.1",
                "bind_port": 8443,
                "tls_enabled": True,
                "tls_cert": certificate_path,
                "tls_key": key_path,
            },
        )

    def test_direct_tls_rejects_missing_relative_and_mismatched_paths(self) -> None:
        with TemporaryDirectory() as tempdir:
            certificate_path, key_path = _write_tls_pair(tempdir, matching=False)
            orchestrator = SetupOrchestrator(tempdir)
            with self.assertRaisesRegex(SetupError, "path must be absolute"):
                orchestrator.set_listener(
                    topology="direct",
                    bind_host="127.0.0.1",
                    bind_port=8443,
                    tls_enabled=True,
                    tls_cert="portal.crt",
                    tls_key=key_path,
                )
            with self.assertRaisesRegex(SetupError, "does not exist or"):
                orchestrator.set_listener(
                    topology="direct",
                    bind_host="127.0.0.1",
                    bind_port=8443,
                    tls_enabled=True,
                    tls_cert=str(Path(tempdir) / "missing.crt"),
                    tls_key=key_path,
                )
            with self.assertRaisesRegex(SetupError, "do not match"):
                orchestrator.set_listener(
                    topology="direct",
                    bind_host="127.0.0.1",
                    bind_port=8443,
                    tls_enabled=True,
                    tls_cert=certificate_path,
                    tls_key=key_path,
                )

    def test_listener_rejects_invalid_topology_host_and_port(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            with self.assertRaisesRegex(SetupError, "Direct service"):
                orchestrator.set_listener(topology="unknown")
            for host in ("", "ca.example.test", "172.21.220"):
                with self.subTest(host=host), self.assertRaisesRegex(SetupError, "Bind address"):
                    orchestrator.set_listener(
                        topology="direct", bind_host=host, bind_port=8000
                    )
            for port in (None, 0, 65536):
                with self.subTest(port=port), self.assertRaisesRegex(SetupError, "Bind port"):
                    orchestrator.set_listener(
                        topology="direct", bind_host="127.0.0.1", bind_port=port
                    )

    def test_set_proxy_listener_drops_direct_bind_values(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_listener(
                topology="direct", bind_host="127.0.0.1", bind_port=8000
            )
            orchestrator.set_listener(
                topology="proxy", bind_host="172.21.220.42", bind_port=8443
            )
            snapshot = orchestrator.snapshot()
        self.assertEqual(snapshot["listener"], {"topology": "proxy"})

    def test_switching_to_lab_clears_imported_production_root(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("production")
            orchestrator.set_root_certificate(_self_signed_root_pem())
            root_path = Path(tempdir) / "setup" / "root-ca.pem"
            root_path.parent.mkdir(parents=True, exist_ok=True)
            root_path.write_text("imported production root")

            orchestrator.set_install_type("lab")
            snapshot = SetupOrchestrator(tempdir).snapshot()

        self.assertFalse(snapshot["root_captured"])
        self.assertNotIn("root_certificate", snapshot["steps"])
        self.assertFalse(root_path.exists())

    def test_unknown_install_type_rejected_without_mutating_state(self) -> None:
        with TemporaryDirectory() as tempdir:
            with self.assertRaises(SetupError):
                SetupOrchestrator(tempdir).set_install_type("banana")
            # State must be pristine — validation happens before any write.
            snapshot = SetupOrchestrator(tempdir).snapshot()
        self.assertEqual(snapshot["steps"], {})
        self.assertIsNone(snapshot["install_type"])

    def test_set_hsm_software_persists_default_choice(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm("software")
            snapshot = SetupOrchestrator(tempdir).snapshot()
        self.assertEqual(snapshot["hsm"]["backend"], "software")
        self.assertEqual(snapshot["hsm"]["pkcs11_lib"], "")
        self.assertEqual(snapshot["hsm"]["token_label"], "myOwnCA")
        self.assertEqual(snapshot["steps"]["hsm"], "done")

    def test_set_hsm_pkcs11_persists_module_and_label(self) -> None:
        with TemporaryDirectory() as tempdir:
            module = Path(tempdir) / "opensc-pkcs11.dll"
            module.write_text("fake")
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm("pkcs11", pkcs11_lib=str(module), token_label="Token A")
            snapshot = SetupOrchestrator(tempdir).snapshot()
        self.assertEqual(snapshot["hsm"]["backend"], "pkcs11")
        self.assertEqual(snapshot["hsm"]["pkcs11_lib"], str(module))
        self.assertEqual(snapshot["hsm"]["token_label"], "Token A")

    def test_set_hsm_pkcs11_requires_existing_module_path(self) -> None:
        with TemporaryDirectory() as tempdir:
            with self.assertRaises(SetupError) as caught:
                SetupOrchestrator(tempdir).set_hsm(
                    "pkcs11", pkcs11_lib=str(Path(tempdir) / "missing.dll")
                )
        self.assertIn("PKCS#11 module was not found", str(caught.exception))


class OrchestratorFinalizeTests(unittest.TestCase):
    def test_finalize_requires_install_type(self) -> None:
        with TemporaryDirectory() as tempdir:
            with self.assertRaises(SetupError):
                SetupOrchestrator(tempdir).finalize()

    def test_finalize_writes_config_secrets_and_latch(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            _set_required_admins(orchestrator)
            orchestrator.finalize()

            # Latch dropped, snapshot reports complete.
            self.assertTrue(SetupOrchestrator(tempdir).snapshot()["complete"])

            # Generated secrets exist and are 0600.
            secrets_path = Path(tempdir) / "secrets" / "secrets.env"
            self.assertEqual(secrets_path.stat().st_mode & 0o777, 0o600)
            loaded_secrets = read_secrets(tempdir)
            self.assertTrue(loaded_secrets["MYOWNCA_AUTH_ENCRYPTION_SECRET"])
            self.assertNotEqual(
                loaded_secrets["MYOWNCA_AUTH_ENCRYPTION_SECRET"],
                "change-me-for-local-testing",
            )

            # Settings.load reflects the lab install.
            settings = Settings.load(tempdir, environ={})
            self.assertTrue(settings.lab_mode)
            self.assertEqual(settings.hsm_backend, "software")
            self.assertEqual(
                settings.auth_encryption_secret,
                loaded_secrets["MYOWNCA_AUTH_ENCRYPTION_SECRET"],
            )

    def test_finalize_production_sets_lab_mode_false(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("production")
            _set_required_admins(orchestrator)
            orchestrator.set_root_certificate(_self_signed_root_pem())
            _finalize_with_configured_issuer(orchestrator)
            self.assertFalse(Settings.load(tempdir, environ={}).lab_mode)

    def test_finalize_writes_pkcs11_hsm_config(self) -> None:
        with TemporaryDirectory() as tempdir:
            module = Path(tempdir) / "opensc-pkcs11.dll"
            module.write_text("fake")
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            orchestrator.set_hsm(
                "pkcs11",
                pkcs11_lib=str(module),
                token_label="Token A",
                reader="Reader A",
            )
            orchestrator.record_pkcs11_ready(
                mode="existing",
                token_serial="SERIAL-A",
                dkek_mode="shares",
                kcv="A1B2C3",
            )
            _set_required_admins(orchestrator)
            _finalize_with_configured_issuer(orchestrator)
            config = read_config_env(tempdir)
        self.assertEqual(config["MYOWNCA_HSM_BACKEND"], "pkcs11")
        self.assertEqual(config["MYOWNCA_PKCS11_LIB"], str(module))
        self.assertEqual(config["MYOWNCA_PKCS11_TOKEN_LABEL"], "Token A")
        self.assertEqual(config["MYOWNCA_SC_HSM_READER"], "Reader A")

    def test_pkcs11_readiness_requires_explicit_dkek_mode(self) -> None:
        with TemporaryDirectory() as tempdir:
            module = Path(tempdir) / "opensc-pkcs11.so"
            module.write_text("fake")
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            orchestrator.set_hsm(
                "pkcs11",
                pkcs11_lib=str(module),
                token_label="Token A",
            )
            orchestrator.record_pkcs11_ready(
                mode="initialized",
                token_serial="SERIAL-A",
                dkek_mode="disabled",
                kcv=None,
            )
            self.assertTrue(orchestrator.snapshot()["hsm"]["ready"])

            state = load_setup_state(tempdir)
            del state.data["pkcs11_hsm_ready"]["dkek_mode"]
            save_setup_state(tempdir, state)

            self.assertFalse(orchestrator.snapshot()["hsm"]["ready"])

    def test_finalize_rejects_pkcs11_hsm_config_without_module(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            _set_required_admins(orchestrator)
            state = orchestrator.snapshot()
            state["hsm"]["backend"] = "pkcs11"
            state["hsm"]["pkcs11_lib"] = str(Path(tempdir) / "missing.dll")

            raw_state = load_setup_state(tempdir)
            raw_state.data["hsm"] = state["hsm"]
            save_setup_state(tempdir, raw_state)

            with self.assertRaises(SetupError) as caught:
                orchestrator.finalize()
        self.assertIn("PKCS#11 module was not found", str(caught.exception))

    def test_finalize_requires_admins(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            with self.assertRaises(SetupError) as caught:
                orchestrator.finalize()
            self.assertIn("bootstrap administrator account", str(caught.exception))
            self.assertFalse(SetupOrchestrator(tempdir).snapshot()["complete"])

    def test_set_install_type_rejected_after_finalize(self) -> None:
        # Once finalized, step setters must not mutate state under a live system.
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            _set_required_admins(orchestrator)
            orchestrator.finalize()
            with self.assertRaises(SetupError):
                orchestrator.set_install_type("production")

    def test_finalize_twice_is_rejected(self) -> None:
        # The latch is the point of no return; a second finalize must not
        # silently rotate the generated secrets.
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            _set_required_admins(orchestrator)
            orchestrator.finalize()
            with self.assertRaises(SetupError):
                orchestrator.finalize()


class OrchestratorGuardTests(unittest.TestCase):
    def test_ensure_not_complete_raises_after_finalize(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            _set_required_admins(orchestrator)
            orchestrator.finalize()
            with self.assertRaises(SetupError):
                orchestrator._ensure_not_complete()

    def test_ensure_not_complete_noop_before_finalize(self) -> None:
        with TemporaryDirectory() as tempdir:
            SetupOrchestrator(tempdir)._ensure_not_complete()  # must not raise


class OrchestratorDatabaseTests(unittest.TestCase):
    def test_sqlite_is_the_simple_default(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_database("sqlite")
            self.assertIsNone(o.database_url())
            self.assertEqual(o.snapshot()["database"], {"kind": "sqlite"})

    def test_mariadb_builds_credential_safe_url(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_database(
                "mariadb",
                host="db.example.test",
                port=3307,
                name="ca",
                user="ca_user",
                password="p@ss/word:99",
            )
            url = o.database_url()
            self.assertTrue(url.startswith("mysql+pymysql://ca_user:"))
            # Special characters are percent-encoded, not left raw.
            self.assertIn("p%40ss%2Fword%3A99", url)
            self.assertIn("@db.example.test:3307/ca", url)

    def test_unknown_kind_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            with self.assertRaises(SetupError):
                SetupOrchestrator(tempdir).set_database("postgres")

    def test_mariadb_requires_connection_fields(self) -> None:
        with TemporaryDirectory() as tempdir:
            with self.assertRaises(SetupError) as caught:
                SetupOrchestrator(tempdir).set_database("mariadb", host="h")
            # The error names the missing fields.
            self.assertIn("name", str(caught.exception))

    def test_mariadb_db_name_is_url_encoded(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_database("mariadb", host="h", name="ca/extra", user="u", password="p")
            self.assertIn("/ca%2Fextra", o.database_url())

    def test_set_database_rejected_after_finalize(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_install_type("lab")
            _set_required_admins(o)
            o.finalize()
            with self.assertRaises(SetupError):
                o.set_database("sqlite")

    def test_snapshot_redacts_database_password(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_database("mariadb", host="h", name="ca", user="u", password="secretpw")
            db = o.snapshot()["database"]
            self.assertNotIn("password", db)
            self.assertEqual(db["user"], "u")
            # database_url() still builds with the real password (reads state, not snapshot).
            self.assertIn("secretpw", o.database_url())


class OrchestratorDatabaseConnectivityTests(unittest.TestCase):
    def test_sqlite_default_connects(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_database("sqlite")
            o.test_database()  # must not raise — connects to the state-dir sqlite file

    def test_unreachable_sqlite_path_raises_setup_error(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            # Point the probe at a path under a file, so the sqlite file cannot be created.
            blocker = Path(tempdir) / "blocker"
            blocker.write_text("x")
            o.set_database("sqlite")
            with mock.patch.object(o, "_sqlite_probe_path", return_value=blocker / "x.sqlite3"):
                with self.assertRaises(SetupError):
                    o.test_database()


class OrchestratorUrlStepsTests(unittest.TestCase):
    def test_service_urls_persist_and_snapshot(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_service_urls(
                admin="https://ca-admin.example.test",
                superuser="https://ca-ops.example.test",
                frontend="https://ca.example.test",
            )
            urls = SetupOrchestrator(tempdir).snapshot()["service_urls"]
            self.assertEqual(urls["admin"], "https://ca-admin.example.test")
            self.assertEqual(urls["frontend"], "https://ca.example.test")

    def test_issuance_endpoints_persist_and_snapshot(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_issuance_endpoints(
                crl="https://ca.example.test/crl/issuer.crl",
                aia="https://ca.example.test/aia/issuer.crt",
                ocsp="https://ca.example.test/ocsp",
            )
            endpoints = SetupOrchestrator(tempdir).snapshot()["issuance_endpoints"]
            self.assertEqual(endpoints["ocsp"], "https://ca.example.test/ocsp")

    def test_url_steps_rejected_after_finalize(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_install_type("lab")
            _set_required_admins(o)
            o.finalize()
            with self.assertRaises(SetupError):
                o.set_service_urls(admin="x", superuser="y", frontend="z")
            with self.assertRaises(SetupError):
                o.set_issuance_endpoints(crl="x", aia="y", ocsp="z")


class OrchestratorFinalizeConfigStepsTests(unittest.TestCase):
    def test_finalize_requires_an_explicit_listener_topology(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_install_type("lab")
            o.set_admins(dict(_ADMIN_1))
            with self.assertRaisesRegex(SetupError, "deployment topology"):
                o.finalize()

    def test_finalize_writes_service_urls_and_endpoints_to_config(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_install_type("production")
            _set_required_admins(o)
            o.set_root_certificate(_self_signed_root_pem())
            certificate_path, key_path = _write_tls_pair(tempdir)
            o.set_listener(
                topology="direct",
                bind_host="172.21.220.42",
                bind_port=8443,
                tls_enabled=True,
                tls_cert=certificate_path,
                tls_key=key_path,
            )
            o.set_service_urls(
                admin="https://admin.example.test",
                superuser="https://ops.example.test",
                frontend="https://ca.example.test",
            )
            o.set_issuance_endpoints(
                crl="https://ca.example.test/crl",
                aia="https://ca.example.test/aia",
                ocsp="https://ca.example.test/ocsp",
            )
            _finalize_with_configured_issuer(o)
            config = read_config_env(tempdir)
        self.assertEqual(config["MYOWNCA_ADMIN_BASE_URL"], "https://admin.example.test")
        self.assertEqual(config["MYOWNCA_SUPERUSER_BASE_URL"], "https://ops.example.test")
        self.assertEqual(config["MYOWNCA_FRONTEND_BASE_URL"], "https://ca.example.test")
        self.assertEqual(config["MYOWNCA_CRL_URL"], "https://ca.example.test/crl")
        self.assertEqual(config["MYOWNCA_AIA_URL"], "https://ca.example.test/aia")
        self.assertEqual(config["MYOWNCA_OCSP_URL"], "https://ca.example.test/ocsp")
        self.assertEqual(config["MYOWNCA_BIND_HOST"], "172.21.220.42")
        self.assertEqual(config["MYOWNCA_BIND_PORT"], "8443")
        self.assertEqual(config["MYOWNCA_TLS_CERT"], certificate_path)
        self.assertEqual(config["MYOWNCA_TLS_KEY"], key_path)
        self.assertEqual(config["MYOWNCA_SESSION_COOKIE_SECURE"], "true")

    def test_finalize_proxy_listener_writes_no_bind_settings(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_install_type("lab")
            _set_required_admins(o)
            o.set_listener(topology="proxy")
            o.finalize()
            config = read_config_env(tempdir)
        self.assertNotIn("MYOWNCA_BIND_HOST", config)
        self.assertNotIn("MYOWNCA_BIND_PORT", config)
        self.assertNotIn("MYOWNCA_TLS_CERT", config)
        self.assertNotIn("MYOWNCA_TLS_KEY", config)
        self.assertNotIn("MYOWNCA_SESSION_COOKIE_SECURE", config)

    def test_finalize_writes_mariadb_url_to_secrets_not_config(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_install_type("production")
            _set_required_admins(o)
            o.set_root_certificate(_self_signed_root_pem())
            o.set_database(
                "mariadb", host="db", name="ca", user="u", password="secretpw"
            )
            _finalize_with_configured_issuer(o)
            secrets_map = read_secrets(tempdir)
            config = read_config_env(tempdir)
        # The credential-bearing URL lives in the 0600 secrets file only.
        self.assertIn("MYOWNCA_DATABASE_URL", secrets_map)
        self.assertIn("secretpw", secrets_map["MYOWNCA_DATABASE_URL"])
        self.assertNotIn("MYOWNCA_DATABASE_URL", config)

    def test_finalize_sqlite_writes_no_database_url(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_install_type("lab")
            _set_required_admins(o)
            o.set_database("sqlite")
            o.finalize()
            self.assertNotIn("MYOWNCA_DATABASE_URL", read_secrets(tempdir))


class OrchestratorRootCertificateTests(unittest.TestCase):
    def test_capture_valid_root(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_root_certificate(_self_signed_root_pem())
            self.assertTrue(SetupOrchestrator(tempdir).snapshot()["root_captured"])

    def test_garbage_pem_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            with self.assertRaises(SetupError):
                SetupOrchestrator(tempdir).set_root_certificate("not a certificate")

    def test_verify_root_returns_summary_without_saving(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            result = orchestrator.verify_root_certificate(_self_signed_root_pem())
            self.assertTrue(result["verified"])
            self.assertIn("fingerprint_sha256", result)
            self.assertNotIn("root_certificate", load_setup_state(tempdir).data)

    def test_verify_root_rejects_required_policy_failures(self) -> None:
        cases = (
            ({"self_issued": False}, "self-issued"),
            ({"valid_signature": False}, "signature"),
            ({"valid": False}, "currently valid"),
            ({"basic_constraints": False}, "BasicConstraints"),
            ({"ca": False}, "CA=true"),
            ({"key_usage": False}, "KeyUsage"),
            ({"key_cert_sign": False}, "keyCertSign"),
        )
        for options, message in cases:
            with self.subTest(message=message), TemporaryDirectory() as tempdir:
                with self.assertRaisesRegex(SetupError, message):
                    SetupOrchestrator(tempdir).verify_root_certificate(
                        _root_variant_pem(**options)
                    )

    def test_non_self_signed_rejected(self) -> None:
        # A leaf/issuer cert (issuer != subject) is not a valid root.
        from myownca.ca_hsm import SoftwareHSM
        from myownca.ca_main.crypto import certificate_to_pem, create_lab_ca_chain

        issuer_pem = certificate_to_pem(create_lab_ca_chain(SoftwareHSM()).issuer.certificate)
        with TemporaryDirectory() as tempdir:
            with self.assertRaises(SetupError):
                SetupOrchestrator(tempdir).set_root_certificate(issuer_pem)

    def test_root_rejected_after_finalize(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_install_type("lab")
            _set_required_admins(o)
            o.finalize()
            with self.assertRaises(SetupError):
                o.set_root_certificate(_self_signed_root_pem())


class OrchestratorFinalizeRootTests(unittest.TestCase):
    def test_finalize_writes_pending_root_file(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_install_type("production")
            _set_required_admins(o)
            root_pem = _self_signed_root_pem()
            o.set_root_certificate(root_pem)
            _finalize_with_configured_issuer(o)
            pending = Path(tempdir) / "setup" / "root-ca.pem"
            self.assertTrue(pending.exists())
            self.assertEqual(pending.read_text(), root_pem.strip() + "\n")

    def test_finalize_without_root_writes_no_pending_file(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_install_type("lab")
            _set_required_admins(o)
            o.finalize()
            self.assertFalse((Path(tempdir) / "setup" / "root-ca.pem").exists())


class OrchestratorAdminsTests(unittest.TestCase):
    _A = {"id": "admin-1", "email": "a1@example.test", "password": "x" * 16}
    _B = {"id": "admin-2", "email": "a2@example.test", "password": "y" * 16}

    def test_capture_admins_redacts_passwords_in_snapshot(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            orchestrator.set_admins(self._A, self._B)
            admins = orchestrator.snapshot()["admins"]
        self.assertEqual([a["email"] for a in admins], [self._A["email"], self._B["email"]])
        self.assertNotIn("password", admins[0])

    def test_admin_emails_are_normalized(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            orchestrator.set_admins(
                {"id": "admin-1", "email": " A1@Example.TEST ", "password": "x" * 16},
                {"id": "admin-2", "email": " A2@Example.TEST ", "password": "y" * 16},
            )
            admins = orchestrator.snapshot()["admins"]
        self.assertEqual([a["email"] for a in admins], ["a1@example.test", "a2@example.test"])

    def test_malformed_admin_email_rejected(self) -> None:
        bad_emails = ["missing-at.test", "@example.test", "admin@", "a@@example.test", "a b@example.test", "a@example"]
        for email in bad_emails:
            with self.subTest(email=email), TemporaryDirectory() as tempdir:
                orchestrator = SetupOrchestrator(tempdir)
                orchestrator.set_install_type("lab")
                with self.assertRaises(SetupError):
                    orchestrator.set_admins(
                        {"id": "a", "email": email, "password": "z" * 16}, self._B
                    )

    def test_short_password_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            with self.assertRaises(SetupError):
                orchestrator.set_admins(
                    {"id": "a", "email": "a@x.test", "password": "tooshort"}, self._B
                )

    def test_duplicate_admins_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            with self.assertRaises(SetupError):
                orchestrator.set_admins(self._A, dict(self._A))

    def test_admin_emails_must_be_distinct_case_insensitively(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            with self.assertRaises(SetupError):
                orchestrator.set_admins(
                    {
                        "id": "admin-1",
                        "email": "Admin@Example.test",
                        "password": "x" * 16,
                    },
                    {
                        "id": "admin-2",
                        "email": "admin@example.test",
                        "password": "y" * 16,
                    },
                )

    def test_missing_field_rejected(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_install_type("lab")
            with self.assertRaises(SetupError):
                orchestrator.set_admins(
                    {"id": "a", "email": "", "password": "z" * 16},
                    self._B,
                )

    def test_admins_rejected_after_finalize(self) -> None:
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_install_type("lab")
            _set_required_admins(o)
            o.finalize()
            with self.assertRaises(SetupError):
                o.set_admins(self._A, self._B)


class OrchestratorFinalizeAdminsTests(unittest.TestCase):
    def test_finalize_writes_pending_admins_0600(self) -> None:
        admins = [
            {"id": "admin-1", "email": "a1@example.test", "password": "p" * 16},
            {"id": "admin-2", "email": "a2@example.test", "password": "q" * 16},
        ]
        with TemporaryDirectory() as tempdir:
            o = SetupOrchestrator(tempdir)
            o.set_install_type("production")
            o.set_governance_mode("dual_control")
            o.set_listener(topology="proxy")
            o.set_admins(admins[0], admins[1])
            o.set_root_certificate(_self_signed_root_pem())
            _finalize_with_configured_issuer(o)
            pending = Path(tempdir) / "secrets" / "pending-admins.json"
            self.assertEqual(pending.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(pending.read_text()), admins)
