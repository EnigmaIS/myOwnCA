from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ObjectIdentifier

from myownca.ca_hsm import SoftwareHSM
from myownca.ca_main.crl_import import CRLImportError, analyze_crl_migration
from myownca.ca_main.crypto import build_crl, create_lab_ca_chain
from myownca.ca_main.service import CAMainService
from myownca.domain import (
    CertificateProfile,
    CertificateSource,
    CertificateStatus,
    CertificateTemplate,
    IssuedCertificate,
    IssuerCRL,
    Person,
    Revocation,
    RevocationReason,
    Role,
    User,
)
from myownca.online.crl_worker import CRLMaintenanceWorker
from myownca.storage.database import Database
from myownca.storage.repositories import PKIRepository
from tests.helpers import TempPKI, make_csr


def _migration_crl(
    hsm: SoftwareHSM,
    *,
    issuer=None,
    number: int = 7,
    revocations: list[Revocation] | None = None,
    now: datetime | None = None,
) -> tuple[object, x509.CertificateRevocationList]:
    selected = issuer or create_lab_ca_chain(hsm).issuer
    crl = build_crl(
        selected,
        revocations
        or [
            Revocation(
                serial_number="a11ce",
                reason=RevocationReason.KEY_COMPROMISE,
                revoked_at=(now or datetime.now(timezone.utc)) - timedelta(days=1),
            )
        ],
        number,
        hsm,
        now=now,
    )
    return selected, crl


@pytest.mark.parametrize("encoding", [serialization.Encoding.PEM, serialization.Encoding.DER])
def test_crl_migration_accepts_pem_and_der(encoding) -> None:
    hsm = SoftwareHSM()
    issuer, crl = _migration_crl(hsm)

    analysis = analyze_crl_migration(
        issuer.certificate,
        prior_crl_state="crl",
        crl_b64=base64.b64encode(crl.public_bytes(encoding)).decode(),
    )

    assert analysis.number == 7
    assert analysis.revocations[0].serial_number == "a11ce"
    assert analysis.revocations[0].reason is RevocationReason.KEY_COMPROMISE


def test_never_issued_crl_starts_at_zero_without_an_upload() -> None:
    issuer = create_lab_ca_chain(SoftwareHSM()).issuer
    analysis = analyze_crl_migration(
        issuer.certificate,
        prior_crl_state="never_issued_crl",
        crl_b64=None,
    )
    assert analysis.number == 0
    assert analysis.revocations == ()


def test_crl_migration_rejects_wrong_signature_and_missing_number() -> None:
    issuer_hsm = SoftwareHSM()
    issuer = create_lab_ca_chain(issuer_hsm).issuer
    foreign_hsm = SoftwareHSM()
    foreign = create_lab_ca_chain(foreign_hsm).issuer
    wrong_signature = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.certificate.subject)
        .last_update(datetime.now(timezone.utc))
        .next_update(datetime.now(timezone.utc) + timedelta(days=7))
        .add_extension(x509.CRLNumber(3), critical=False)
    )
    signed_by_foreign = foreign_hsm.sign_crl(wrong_signature, foreign.key_ref)
    with pytest.raises(CRLImportError, match="signature"):
        analyze_crl_migration(
            issuer.certificate,
            prior_crl_state="crl",
            crl_b64=base64.b64encode(
                signed_by_foreign.public_bytes(serialization.Encoding.DER)
            ).decode(),
        )

    missing_number = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.certificate.subject)
        .last_update(datetime.now(timezone.utc))
        .next_update(datetime.now(timezone.utc) + timedelta(days=7))
    )
    signed = issuer_hsm.sign_crl(missing_number, issuer.key_ref)
    with pytest.raises(CRLImportError, match="CRLNumber"):
        analyze_crl_migration(
            issuer.certificate,
            prior_crl_state="crl",
            crl_b64=base64.b64encode(
                signed.public_bytes(serialization.Encoding.DER)
            ).decode(),
        )


@pytest.mark.parametrize(
    ("extension", "message"),
    [
        (x509.DeltaCRLIndicator(6), "Delta"),
        (
            x509.IssuingDistributionPoint(
                full_name=None,
                relative_name=None,
                only_contains_user_certs=False,
                only_contains_ca_certs=False,
                only_some_reasons=None,
                indirect_crl=True,
                only_contains_attribute_certs=False,
            ),
            "Indirect or partitioned",
        ),
        (
            x509.IssuingDistributionPoint(
                full_name=[x509.UniformResourceIdentifier("https://ca.test/part-1")],
                relative_name=None,
                only_contains_user_certs=False,
                only_contains_ca_certs=False,
                only_some_reasons=None,
                indirect_crl=False,
                only_contains_attribute_certs=False,
            ),
            "Indirect or partitioned",
        ),
    ],
)
def test_crl_migration_rejects_delta_indirect_and_partitioned(
    extension,
    message: str,
) -> None:
    hsm = SoftwareHSM()
    issuer = create_lab_ca_chain(hsm).issuer
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.certificate.subject)
        .last_update(datetime.now(timezone.utc))
        .next_update(datetime.now(timezone.utc) + timedelta(days=7))
        .add_extension(x509.CRLNumber(7), critical=False)
        .add_extension(extension, critical=True)
    )
    crl = hsm.sign_crl(builder, issuer.key_ref)
    with pytest.raises(CRLImportError, match=message):
        analyze_crl_migration(
            issuer.certificate,
            prior_crl_state="crl",
            crl_b64=base64.b64encode(
                crl.public_bytes(serialization.Encoding.DER)
            ).decode(),
        )


def test_crl_migration_rejects_wrong_aki_and_unknown_critical_extension() -> None:
    hsm = SoftwareHSM()
    issuer = create_lab_ca_chain(hsm).issuer
    base = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.certificate.subject)
        .last_update(datetime.now(timezone.utc))
        .next_update(datetime.now(timezone.utc) + timedelta(days=7))
        .add_extension(x509.CRLNumber(9), critical=False)
    )
    wrong_aki = hsm.sign_crl(
        base.add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=b"\x01" * 20,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        ),
        issuer.key_ref,
    )
    with pytest.raises(CRLImportError, match="AuthorityKeyIdentifier"):
        analyze_crl_migration(
            issuer.certificate,
            prior_crl_state="crl",
            crl_b64=base64.b64encode(
                wrong_aki.public_bytes(serialization.Encoding.DER)
            ).decode(),
        )

    unsupported = hsm.sign_crl(
        base.add_extension(
            x509.UnrecognizedExtension(
                ObjectIdentifier("1.3.6.1.4.1.55555.9.1"),
                b"\x05\x00",
            ),
            critical=True,
        ),
        issuer.key_ref,
    )
    with pytest.raises(CRLImportError, match="Unsupported critical"):
        analyze_crl_migration(
            issuer.certificate,
            prior_crl_state="crl",
            crl_b64=base64.b64encode(
                unsupported.public_bytes(serialization.Encoding.DER)
            ).decode(),
        )


def test_expired_crl_is_accepted_with_a_migration_warning() -> None:
    hsm = SoftwareHSM()
    now = datetime.now(timezone.utc)
    issuer, crl = _migration_crl(hsm, now=now - timedelta(days=8))
    analysis = analyze_crl_migration(
        issuer.certificate,
        prior_crl_state="crl",
        crl_b64=base64.b64encode(
            crl.public_bytes(serialization.Encoding.DER)
        ).decode(),
        now=now,
    )
    assert any("expired" in warning for warning in analysis.warnings)


def test_crl_migration_rejects_malformed_der() -> None:
    issuer = create_lab_ca_chain(SoftwareHSM()).issuer
    with pytest.raises(CRLImportError, match="neither valid PEM nor DER"):
        analyze_crl_migration(
            issuer.certificate,
            prior_crl_state="crl",
            crl_b64=base64.b64encode(b"not-a-crl").decode(),
        )


def test_crl_migration_rejects_inconsistent_revoked_entry_dates() -> None:
    hsm = SoftwareHSM()
    issuer = create_lab_ca_chain(hsm).issuer
    now = datetime.now(timezone.utc).replace(microsecond=0)
    entry = (
        x509.RevokedCertificateBuilder()
        .serial_number(123)
        .revocation_date(now + timedelta(hours=1))
        .build()
    )
    crl = hsm.sign_crl(
        (
            x509.CertificateRevocationListBuilder()
            .issuer_name(issuer.certificate.subject)
            .last_update(now)
            .next_update(now + timedelta(days=7))
            .add_extension(x509.CRLNumber(2), critical=False)
            .add_revoked_certificate(entry)
        ),
        issuer.key_ref,
    )
    with pytest.raises(CRLImportError, match="revocation date"):
        analyze_crl_migration(
            issuer.certificate,
            prior_crl_state="crl",
            crl_b64=base64.b64encode(
                crl.public_bytes(serialization.Encoding.DER)
            ).decode(),
            now=now,
        )


def test_imported_crl_seeds_ledger_and_local_successor_preserves_unknown_serial() -> None:
    pki = TempPKI()
    try:
        now = datetime.now(timezone.utc)
        issuer, crl = _migration_crl(
            pki.hsm,
            issuer=pki.lab_chain.issuer,
            number=12,
            now=now,
        )
        analysis = analyze_crl_migration(
            issuer.certificate,
            prior_crl_state="crl",
            crl_b64=base64.b64encode(
                crl.public_bytes(serialization.Encoding.DER)
            ).decode(),
            now=now,
        )
        issuer_id = issuer.certificate.fingerprint(hashes.SHA256()).hex()
        pki.repository.import_issuer_crl(
            IssuerCRL(
                issuer_subject=issuer.certificate.subject.rfc4514_string(),
                number=analysis.number,
                crl_pem=analysis.crl_pem or "",
                generated_at=analysis.this_update or now,
                issuer_id=issuer_id,
                this_update=analysis.this_update,
                next_update=analysis.next_update,
                source="imported",
                sha256=analysis.sha256 or "",
            ),
            analysis.revocations,
        )

        local = pki.service.generate_crl(issuer, crl_number=analysis.number + 1)
        parsed = x509.load_pem_x509_crl(local.crl_pem.encode())

        assert local.number == 13
        assert local.source == "local"
        assert {format(entry.serial_number, "x") for entry in parsed} == {"a11ce"}
    finally:
        pki.close()


def test_legacy_crl_history_is_linked_to_verified_issuer_on_migration() -> None:
    pki = TempPKI()
    try:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        crl = build_crl(
            pki.lab_chain.issuer,
            [],
            5,
            pki.hsm,
            now=now,
        )
        subject = pki.lab_chain.issuer.certificate.subject.rfc4514_string()
        pki.repository.add_issuer_crl(
            IssuerCRL(
                issuer_subject=subject,
                number=5,
                crl_pem=crl.public_bytes(serialization.Encoding.PEM).decode(),
                generated_at=now,
            )
        )

        assert (
            pki.repository.reconcile_issuer_crl_history(
                pki.lab_chain.issuer.certificate
            )
            == 1
        )

        issuer_id = pki.lab_chain.issuer.certificate.fingerprint(
            hashes.SHA256()
        ).hex()
        migrated = pki.repository.get_issuer_crl_by_number(subject, issuer_id, 5)
        assert migrated is not None
        assert migrated.issuer_id == issuer_id
        assert migrated.this_update == now
        assert migrated.next_update == now + timedelta(days=7)
        assert len(migrated.sha256) == 64
    finally:
        pki.close()


def test_database_migration_preserves_existing_revocations_and_crl_history() -> None:
    with TemporaryDirectory() as tempdir:
        database = Database(Path(tempdir) / "pre-crl-ledger.sqlite3")
        migrations = (
            Path(__file__).parents[1] / "src/myownca/storage/migrations"
        )
        with database.connect() as connection:
            connection.executescript(
                "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY)"
            )
            for migration in sorted(migrations.glob("*.sql")):
                if migration.name >= "0037_crl_lifecycle.sql":
                    break
                connection.executescript(migration.read_text())
                connection.execute(
                    "INSERT INTO schema_migrations(version) VALUES (?)",
                    (migration.name,),
                )
            # This fixture intentionally retains the pre-CRL-ledger schema so
            # it can exercise migration 0037 below. Its setup uses the current
            # repository, which requires the later template-policy column.
            policy_migration = migrations / "0041_template_allowed_key_algorithms.sql"
            connection.executescript(policy_migration.read_text())
            connection.execute(
                "INSERT INTO schema_migrations(version) VALUES (?)",
                (policy_migration.name,),
            )
        repository = PKIRepository(database)
        hsm = SoftwareHSM()
        service = CAMainService(repository, hsm)
        chain = create_lab_ca_chain(hsm)
        repository.add_user(
            User(id="legacy-su-1", email="su1@example.test", role=Role.SUPERUSER)
        )
        repository.add_user(
            User(id="legacy-su-2", email="su2@example.test", role=Role.SUPERUSER)
        )
        repository.add_template(
            CertificateTemplate(
                id="legacy-host",
                name="Legacy host",
                profile=CertificateProfile.HOST_TLS,
            )
        )
        repository.add_person(
            Person(
                id="legacy-holder",
                name="Legacy",
                surname="Holder",
                email="holder@example.test",
                created_at=datetime.now(timezone.utc),
            )
        )
        request = service.submit_request(
            "legacy-host",
            make_csr("legacy.example.test", dns_names=("legacy.example.test",)),
        )
        service.approve_request(request.id, "legacy-su-1")
        service.approve_request(request.id, "legacy-su-2")
        service.assign_request_holder(request.id, person_id="legacy-holder")
        issued = service.issue_certificate(request.id, chain.issuer)
        revoked_at = datetime.now(timezone.utc).replace(microsecond=0)
        with database.connect() as connection:
            connection.execute(
                "INSERT INTO certificate_revocations("
                "certificate_id, serial_number, reason, revoked_at"
                ") VALUES (?, ?, ?, ?)",
                (
                    issued.certificate_id,
                    issued.serial_number,
                    RevocationReason.KEY_COMPROMISE.value,
                    revoked_at.isoformat(),
                ),
            )
            connection.execute(
                "UPDATE certificate_inventory SET status = ? "
                "WHERE certificate_id = ?",
                (CertificateStatus.REVOKED.value, issued.certificate_id),
            )
            connection.execute(
                "UPDATE issued_certificates SET status = ? "
                "WHERE certificate_id = ?",
                (CertificateStatus.REVOKED.value, issued.certificate_id),
            )
        legacy_crl = build_crl(
            chain.issuer,
            [
                Revocation(
                    serial_number=issued.serial_number,
                    reason=RevocationReason.KEY_COMPROMISE,
                    revoked_at=revoked_at,
                )
            ],
            4,
            hsm,
            now=revoked_at + timedelta(minutes=1),
        )
        with database.connect() as connection:
            connection.execute(
                "INSERT INTO issuer_crls("
                "issuer_subject, number, crl_pem, generated_at"
                ") VALUES (?, ?, ?, ?)",
                (
                    chain.issuer.certificate.subject.rfc4514_string(),
                    4,
                    legacy_crl.public_bytes(serialization.Encoding.PEM).decode(),
                    (revoked_at + timedelta(minutes=1)).isoformat(),
                ),
            )

        database.migrate()
        migrated = PKIRepository(database)
        issuer_id = chain.issuer.certificate.fingerprint(hashes.SHA256()).hex()
        assert migrated.get_issuer_revocation(
            issuer_id,
            issued.serial_number,
        ).reason is RevocationReason.KEY_COMPROMISE
        assert migrated.reconcile_issuer_crl_history(chain.issuer.certificate) == 1
        history = migrated.get_issuer_crl_by_number(
            chain.issuer.certificate.subject.rfc4514_string(),
            issuer_id,
            4,
        )
        assert history is not None
        assert history.issuer_id == issuer_id
        assert history.sha256


def test_revoke_atomically_queues_and_worker_generates_one_deduplicated_crl() -> None:
    pki = TempPKI()
    try:
        pki.add_default_users()
        pki.add_template("host", profile=CertificateProfile.HOST_TLS)
        request = pki.service.submit_request(
            "host",
            make_csr("event.example.test", dns_names=("event.example.test",)),
        )
        pki.service.approve_request(request.id, "su-1")
        pki.service.approve_request(request.id, "su-2")
        pki.assign_holder(request.id)
        issued = pki.service.issue_certificate(request.id, pki.lab_chain.issuer)
        worker = CRLMaintenanceWorker(
            pki.repository,
            pki.service,
            lambda: pki.lab_chain.issuer,
        )
        pki.service.crl_change_listener = worker.kick

        pki.service.revoke_certificate(
            issued.serial_number,
            RevocationReason.CESSATION_OF_OPERATION,
        )
        issuer_id = pki.lab_chain.issuer.certificate.fingerprint(
            hashes.SHA256()
        ).hex()
        first_job = pki.repository.get_crl_job(issuer_id)
        assert first_job is not None
        pki.repository.enqueue_crl_refresh(
            issuer_id,
            pki.lab_chain.issuer.certificate.subject.rfc4514_string(),
        )
        crl = worker.run_once()

        assert crl is not None
        assert crl.number == 1
        assert pki.repository.get_crl_job(issuer_id).status == "complete"
        parsed = x509.load_pem_x509_crl(crl.crl_pem.encode())
        assert {format(entry.serial_number, "x") for entry in parsed} == {
            issued.serial_number
        }
    finally:
        pki.close()


def test_revoke_rolls_back_if_durable_crl_enqueue_fails() -> None:
    pki = TempPKI()
    try:
        pki.add_default_users()
        pki.add_template("host", CertificateProfile.HOST_TLS)
        request = pki.service.submit_request(
            "host",
            make_csr("atomic.example.test", dns_names=("atomic.example.test",)),
        )
        pki.service.approve_request(request.id, "su-1")
        pki.service.approve_request(request.id, "su-2")
        pki.assign_holder(request.id)
        issued = pki.service.issue_certificate(request.id, pki.lab_chain.issuer)

        with (
            mock.patch(
                "myownca.storage.repositories._enqueue_crl_job",
                side_effect=RuntimeError("queue unavailable"),
            ),
            pytest.raises(RuntimeError, match="queue unavailable"),
        ):
            pki.service.revoke_certificate(issued.serial_number)

        assert (
            pki.repository.get_certificate_by_id(issued.certificate_id).status
            is CertificateStatus.ACTIVE
        )
        assert pki.repository.list_revocations() == []
    finally:
        pki.close()


class _UnavailableHSM:
    def __init__(self, delegate: SoftwareHSM) -> None:
        self.delegate = delegate

    def sign_crl(self, _builder, _key_ref):
        raise RuntimeError("HSM unavailable with sensitive provider details")


def test_unavailable_hsm_keeps_revocation_and_schedules_retry() -> None:
    pki = TempPKI()
    try:
        issuer_id = pki.lab_chain.issuer.certificate.fingerprint(
            hashes.SHA256()
        ).hex()
        revoked_at = datetime.now(timezone.utc)
        pki.repository.import_issuer_crl(
            IssuerCRL(
                issuer_subject=pki.lab_chain.issuer.certificate.subject.rfc4514_string(),
                number=4,
                crl_pem="migration-placeholder",
                generated_at=revoked_at,
                issuer_id=issuer_id,
                source="imported",
            ),
            [
                Revocation(
                    serial_number="beef",
                    reason=RevocationReason.CA_COMPROMISE,
                    revoked_at=revoked_at,
                )
            ],
        )
        pki.repository.enqueue_crl_refresh(
            issuer_id,
            pki.lab_chain.issuer.certificate.subject.rfc4514_string(),
            now=revoked_at,
        )
        worker = CRLMaintenanceWorker(
            pki.repository,
            CAMainService(pki.repository, _UnavailableHSM(pki.hsm)),
            lambda: pki.lab_chain.issuer,
        )

        assert worker.run_once(revoked_at) is None
        job = pki.repository.get_crl_job(issuer_id)
        assert job is not None
        assert job.status == "pending"
        assert job.next_attempt_at > revoked_at
        assert job.last_error == "CRL generation failed (RuntimeError)"
        assert pki.repository.get_issuer_revocation(issuer_id, "beef") is not None
    finally:
        pki.close()


def test_later_imported_leaf_recovers_historical_revocation_by_issuer() -> None:
    pki = TempPKI()
    try:
        pki.add_default_users()
        pki.add_template("host", CertificateProfile.HOST_TLS)
        request = pki.service.submit_request(
            "host",
            make_csr("historical.example.test", dns_names=("historical.example.test",)),
        )
        revoked_at = datetime.now(timezone.utc).replace(microsecond=0)
        issuer_id = pki.lab_chain.issuer.certificate.fingerprint(
            hashes.SHA256()
        ).hex()
        pki.repository.import_issuer_crl(
            IssuerCRL(
                issuer_subject=pki.lab_chain.issuer.certificate.subject.rfc4514_string(),
                number=3,
                crl_pem="migration-placeholder",
                generated_at=revoked_at,
                issuer_id=issuer_id,
                source="imported",
            ),
            [
                Revocation(
                    serial_number="feed",
                    reason=RevocationReason.AFFILIATION_CHANGED,
                    revoked_at=revoked_at,
                )
            ],
        )
        imported = IssuedCertificate(
            serial_number="feed",
            request_id=request.id,
            template_id="host",
            certificate_pem="historical-leaf-placeholder",
            subject="CN=historical.example.test",
            issued_at=revoked_at - timedelta(days=30),
            expires_at=revoked_at + timedelta(days=300),
            status=CertificateStatus.REVOKED,
            certificate_id="historical-feed",
            source=CertificateSource.IMPORTED,
            issuer_id=issuer_id,
        )

        pki.repository.finalize_issued_certificate(imported)

        stored = pki.repository.get_certificate_by_id("historical-feed")
        canonical = next(
            item
            for item in pki.repository.list_revocations()
            if item.certificate_id == "historical-feed"
        )
        assert stored.status is CertificateStatus.REVOKED
        assert canonical.reason is RevocationReason.AFFILIATION_CHANGED
        assert canonical.revoked_at == revoked_at
        assert pki.repository.get_issuer_revocation("different-issuer", "feed") is None
    finally:
        pki.close()


def test_expired_lease_is_recovered_and_competing_worker_does_not_resign() -> None:
    pki = TempPKI()
    try:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        issuer = pki.lab_chain.issuer
        issuer_id = issuer.certificate.fingerprint(hashes.SHA256()).hex()
        pki.repository.enqueue_crl_refresh(
            issuer_id,
            issuer.certificate.subject.rfc4514_string(),
            now=now,
        )
        claimed = pki.repository.claim_crl_job(
            issuer_id,
            lease_owner="crashed-instance",
            now=now,
            lease_seconds=1,
        )
        assert claimed is not None
        assert (
            pki.repository.claim_crl_job(
                issuer_id,
                lease_owner="competing-instance",
                now=now,
            )
            is None
        )
        recovered = CRLMaintenanceWorker(
            pki.repository,
            pki.service,
            lambda: issuer,
        )
        competitor = CRLMaintenanceWorker(
            pki.repository,
            pki.service,
            lambda: issuer,
        )

        first = recovered.run_once(now + timedelta(seconds=2))
        second = competitor.run_once(now + timedelta(seconds=2))

        assert first is not None
        assert first.number == 1
        assert second is None
        with pki.database.connect() as connection:
            count = connection.execute(
                "SELECT COUNT(*) AS count FROM issuer_crls WHERE issuer_id = ?",
                (issuer_id,),
            ).fetchone()["count"]
        assert count == 1
    finally:
        pki.close()


def test_recovery_after_crl_persisted_does_not_sign_reserved_number_twice() -> None:
    pki = TempPKI()
    try:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        issuer = pki.lab_chain.issuer
        issuer_id = issuer.certificate.fingerprint(hashes.SHA256()).hex()
        pki.repository.enqueue_crl_refresh(
            issuer_id,
            issuer.certificate.subject.rfc4514_string(),
            now=now,
        )
        claimed = pki.repository.claim_crl_job(
            issuer_id,
            lease_owner="crashed-after-persist",
            now=now,
            lease_seconds=1,
        )
        assert claimed is not None
        persisted = pki.service.generate_crl(
            issuer,
            now=now,
            crl_number=claimed.reserved_number,
        )
        worker = CRLMaintenanceWorker(
            pki.repository,
            pki.service,
            lambda: issuer,
        )

        recovered = worker.run_once(now + timedelta(seconds=2))

        assert recovered == persisted
        assert pki.repository.get_crl_job(issuer_id).status == "complete"
        with pki.database.connect() as connection:
            count = connection.execute(
                "SELECT COUNT(*) AS count FROM issuer_crls WHERE issuer_id = ?",
                (issuer_id,),
            ).fetchone()["count"]
        assert count == 1
    finally:
        pki.close()


def test_worker_renews_crl_inside_24_hour_window() -> None:
    pki = TempPKI()
    try:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        old = pki.service.generate_crl(
            pki.lab_chain.issuer,
            now=now - timedelta(days=6, hours=1),
        )
        worker = CRLMaintenanceWorker(
            pki.repository,
            pki.service,
            lambda: pki.lab_chain.issuer,
        )

        renewed = worker.run_once(now)

        assert old.number == 1
        assert renewed is not None
        assert renewed.number == 2
        assert renewed.next_update == now + timedelta(days=7)
        assert worker.safety_reconciliation_seconds == 300
    finally:
        pki.close()
