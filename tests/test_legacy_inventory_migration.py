from __future__ import annotations

import hashlib
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from myownca.key_lifecycle import KeyOwnership, KeyStatus
from myownca.online.app import create_app
from myownca_core.storage.database import Database as CoreDatabase


MIGRATIONS = Path(__file__).parents[1] / "src/myownca/storage/migrations"
NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)


def _legacy_certificate_and_csr() -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy.example.test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x1234)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("legacy.example.test")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("legacy.example.test")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        csr.public_bytes(serialization.Encoding.PEM).decode(),
    )


def test_pre_registry_database_backfills_inventory_and_known_key_bindings() -> None:
    """Upgrade a realistic pre-0031 database without discovering unknown HSM keys."""

    with TemporaryDirectory() as tempdir:
        root = Path(tempdir)
        database_path = root / "legacy.sqlite3"
        old_migrations = root / "old-migrations"
        old_migrations.mkdir()
        for source in sorted(MIGRATIONS.glob("*.sql")):
            if source.name < "0031_key_lifecycle.sql":
                shutil.copy(source, old_migrations / source.name)

        legacy = CoreDatabase(database_path)
        legacy.migrate(old_migrations)
        certificate_pem, csr_pem = _legacy_certificate_and_csr()
        timestamp = NOW.isoformat()
        cloud_ref = "arn:aws:kms:eu-test-1:123456789012:key/legacy-cloud"
        with legacy.connect() as connection:
            connection.execute(
                "INSERT INTO certificate_templates("
                "id, name, profile, validity_days, first_issuance_approvals, "
                "renewal_approvals) VALUES (?, ?, ?, ?, ?, ?)",
                ("legacy-host", "Legacy host", "host_tls", 365, 0, 0),
            )
            connection.execute(
                "INSERT INTO people(id, name, surname, email, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                ("legacy-person", "Legacy", "Holder", "legacy@example.test", timestamp),
            )
            connection.execute(
                "INSERT INTO certificate_requests("
                "id, template_id, csr_pem, kind, status, created_at, holder_person_id"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "legacy-request",
                    "legacy-host",
                    csr_pem,
                    "first_issuance",
                    "issued",
                    timestamp,
                    "legacy-person",
                ),
            )
            connection.execute(
                "INSERT INTO issued_certificates("
                "serial_number, request_id, template_id, certificate_pem, subject, "
                "issued_at, expires_at, status, holder_person_id"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "1234",
                    "legacy-request",
                    "legacy-host",
                    certificate_pem,
                    "CN=legacy.example.test",
                    timestamp,
                    (NOW + timedelta(days=365)).isoformat(),
                    "active",
                    "legacy-person",
                ),
            )
            connection.execute(
                "INSERT INTO request_private_keys("
                "request_id, key_pem_encrypted, algorithm, created_at"
                ") VALUES (?, ?, ?, ?)",
                ("legacy-request", "opaque-legacy-ciphertext", "ecdsa-p256", timestamp),
            )
            connection.execute(
                "INSERT INTO sub_cas("
                "id, certificate_pem, key_ref, subject, created_at"
                ") VALUES (?, ?, ?, ?, ?)",
                (
                    "legacy-subca",
                    certificate_pem,
                    "legacy-subca-key",
                    "CN=Legacy Sub CA",
                    timestamp,
                ),
            )
            connection.execute(
                "INSERT INTO service_certificates("
                "id, name, source, status, key_backend, key_ref, csr_pem, "
                "created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "legacy-service",
                    "legacy-service",
                    "csr_external",
                    "pending",
                    "software",
                    "legacy-service-key",
                    csr_pem,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                "INSERT INTO cloud_keys("
                "id, provider, key_ref, key_ref_digest, label, algorithm, purpose, "
                "ownership, status, created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "legacy-cloud",
                    "aws_kms",
                    cloud_ref,
                    hashlib.sha256(cloud_ref.encode()).hexdigest(),
                    "legacy-cloud",
                    "ecdsa-p256",
                    "subca",
                    "managed",
                    "active",
                    timestamp,
                    timestamp,
                ),
            )

        with mock.patch.dict(
            "os.environ",
            {
                "MYOWNCA_STATE_DIR": str(root / "state"),
                "MYOWNCA_HSM_BACKEND": "software",
                "MYOWNCA_ONLINE_KEY_PASSPHRASE": "migration-test-passphrase",
            },
        ):
            app = create_app(
                database_path,
                lab_mode=True,
                online_key_dir=root / "online-keys",
            )

        inventory = app.state.repository.get_certificate_by_id("1234")
        assert inventory.serial_number == "1234"
        assert inventory.source.value == "issued"

        request_key_id = app.state.repository.get_request(
            "legacy-request"
        ).key_registry_id
        assert request_key_id is not None
        request_key = app.state.key_lifecycle.repository.get(request_key_id)
        assert request_key.backend == "request_vault"
        assert request_key.ownership is KeyOwnership.MANAGED
        assert request_key.status is KeyStatus.ACTIVE
        assert {
            (binding.resource_type, binding.resource_id)
            for binding in app.state.key_lifecycle.repository.list_bindings(
                request_key.id
            )
        } == {("certificate", "1234")}

        expected = {
            ("software", "legacy-subca-key"): (
                KeyOwnership.ATTACHED,
                ("sub_ca", "legacy-subca"),
            ),
            ("software", "legacy-service-key"): (
                KeyOwnership.MANAGED,
                ("service_certificate", "legacy-service"),
            ),
            ("aws_kms", cloud_ref): (
                KeyOwnership.MANAGED,
                ("cloud_key", "legacy-cloud"),
            ),
        }
        for (backend, key_ref), (ownership, binding) in expected.items():
            registered = app.state.key_lifecycle.repository.find(
                backend=backend,
                key_ref=key_ref,
            )
            assert registered is not None
            assert registered.ownership is ownership
            assert registered.status is KeyStatus.ACTIVE
            assert binding in {
                (item.resource_type, item.resource_id)
                for item in app.state.key_lifecycle.repository.list_bindings(
                    registered.id
                )
            }

        assert app.state.key_lifecycle.repository.find(
            backend="software",
            key_ref="unmanaged-token-key-never-discovered",
        ) is None
