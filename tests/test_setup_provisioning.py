from __future__ import annotations

import base64
import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request

from myownca.audit import AuditRepository
from myownca.ca_hsm import SoftwareHSM
from myownca.ca_main.crypto import (
    build_crl,
    build_sub_ca_certificate,
    build_sub_ca_csr,
    certificate_to_pem,
    create_lab_ca_chain,
    create_root_ca,
)
from myownca.domain import CertificateProfile, Revocation, RevocationReason
from myownca.key_lifecycle import KeyOwnership, KeyStatus
from myownca.offline import OfflineRootService, OfflineStateRepository
from myownca.online.app import create_app
from myownca.setup.app import (
    DatabasePayload,
    InstallTypePayload,
    LabIssuerPayload,
    create_setup_app,
)
from myownca.setup.config_writer import read_secrets
from myownca.setup.orchestrator import SetupError, SetupOrchestrator
from myownca.setup.provisioning import (
    SetupProvisioningError,
    SetupProvisioningService,
)
from myownca.setup.state import is_setup_complete, load_setup_state
from myownca.setup.token import SetupAuth
from tests.helpers import route_endpoint


_ADMIN = {
    "id": "admin-1",
    "email": "admin@example.test",
    "password": "p" * 16,
}
_ADMIN_2 = {
    "id": "admin-2",
    "email": "admin2@example.test",
    "password": "q" * 16,
}


def _prepare_lab(state_dir: str | Path) -> tuple[SetupOrchestrator, SetupProvisioningService]:
    orchestrator = SetupOrchestrator(state_dir)
    orchestrator.set_install_type("lab")
    orchestrator.set_listener(topology="proxy")
    orchestrator.prepare_runtime()
    return orchestrator, SetupProvisioningService(state_dir)


def _prepare_production(
    state_dir: str | Path,
    root_pem: str,
) -> tuple[SetupOrchestrator, SetupProvisioningService]:
    orchestrator = SetupOrchestrator(state_dir)
    orchestrator.set_install_type("production")
    orchestrator.set_governance_mode("dual_control")
    orchestrator.set_listener(topology="proxy")
    orchestrator.set_root_certificate(root_pem)
    orchestrator.prepare_runtime()
    return orchestrator, SetupProvisioningService(state_dir)


def _prepare_pkcs11_request_service(
    state_dir: str | Path,
    *,
    mode: str,
) -> tuple[SetupProvisioningService, SoftwareHSM, str, object, SoftwareHSM]:
    root_hsm = SoftwareHSM()
    root = create_root_ca(root_hsm, "PKCS11 Request Root")
    module = Path(state_dir) / "fake-pkcs11.so"
    module.parent.mkdir(parents=True, exist_ok=True)
    module.write_text("test")
    orchestrator = SetupOrchestrator(state_dir)
    orchestrator.set_install_type("production")
    orchestrator.set_governance_mode("single_admin")
    orchestrator.set_listener(topology="proxy")
    orchestrator.set_hsm(
        "pkcs11",
        pkcs11_lib=str(module),
        token_label="Prepared HSM",
    )
    orchestrator.record_pkcs11_ready(
        mode=mode,
        token_serial="PREPARED-HSM-SERIAL",
        dkek_mode="shares",
        kcv="A1B2C3",
    )
    orchestrator.set_root_certificate(root.certificate_pem)
    orchestrator.prepare_runtime()

    backend = SoftwareHSM()
    existing_key_ref = backend.generate_key("prepared-issuer", "ecdsa-p384")
    with mock.patch(
        "myownca.setup.provisioning.create_hsm",
        return_value=(backend, "pkcs11"),
    ):
        service = SetupProvisioningService(state_dir, user_pin="123456")
    return service, backend, existing_key_ref, root, root_hsm


def _p12(chain, hsm: SoftwareHSM, password: bytes = b"bundle-password") -> str:
    payload = pkcs12.serialize_key_and_certificates(
        name=b"initial-sub-ca",
        key=hsm.private_key(chain.issuer.key_ref),
        cert=chain.issuer.certificate,
        cas=[chain.root.certificate],
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    return base64.b64encode(payload).decode()


def _never_crl() -> dict[str, object]:
    return {
        "prior_crl_state": "never_issued_crl",
        "crl_b64": None,
    }


def _subca_certificate(
    key_hsm: SoftwareHSM,
    key_ref: str,
    root,
    root_hsm: SoftwareHSM,
    *,
    ca: bool = True,
    path_length: int | None = 0,
    key_cert_sign: bool = True,
    crl_sign: bool = True,
    expired: bool = False,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    not_before = not_before or (
        now - timedelta(days=30) if expired else root.material.certificate.not_valid_before_utc
    )
    not_after = not_after or (now - timedelta(days=1) if expired else now + timedelta(days=365))
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Imported Issuing CA")]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root.material.certificate.subject)
        .public_key(key_hsm.public_key(key_ref))
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length if ca else None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=crl_sign,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    )
    return root_hsm.sign_certificate(builder, root.material.key_ref)


def _setup_request(
    *,
    session: str | None = None,
    csrf: str | None = None,
    method: str = "GET",
) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if session is not None:
        headers.append((b"cookie", f"myownca_setup={session}".encode()))
    if csrf is not None:
        headers.append((b"x-csrf-token", csrf.encode()))
    return Request(
        {"type": "http", "method": method, "path": "/", "headers": headers}
    )


def test_offline_ceremony_survives_restart_and_finalize_preserves_secrets() -> None:
    with TemporaryDirectory() as tempdir:
        state_dir = Path(tempdir) / "online"
        offline_hsm = SoftwareHSM(Path(tempdir) / "offline-keys")
        offline = OfflineRootService(
            OfflineStateRepository(Path(tempdir) / "offline.sqlite3"),
            offline_hsm,
        )
        root = offline.create_root("Offline Production Root")
        orchestrator, provisioning = _prepare_production(
            state_dir,
            root.root_certificate_pem,
        )
        secrets_before = read_secrets(state_dir)

        created = provisioning.create_request(
            common_name="Production Issuing CA",
            allowed_profiles=list(CertificateProfile),
            algorithm="ecdsa-p384",
        )
        assert created["pending_id"]
        assert created["csr_pem"].startswith(
            "-----BEGIN CERTIFICATE REQUEST-----"
        )
        signed = offline.sign_sub_ca_csr(
            created["csr_pem"],
            validity_days=365,
            permitted_dns_suffixes=("example.test",),
        )

        restarted_pending = SetupProvisioningService(state_dir)
        pending_status = restarted_pending.status()["pending"]
        assert len(pending_status) == 1
        assert pending_status[0]["csr_pem"] == created["csr_pem"]
        activated = restarted_pending.import_response(
            certificate_pem=signed.certificate_pem,
        )
        issuer_id = activated["issuer"]["id"]

        restarted_active = SetupProvisioningService(state_dir)
        assert restarted_active.status()["issuer"]["id"] == issuer_id
        orchestrator.set_admins(_ADMIN, _ADMIN_2)
        orchestrator.finalize()

        assert is_setup_complete(state_dir)
        assert read_secrets(state_dir) == secrets_before
        with mock.patch.dict(
            os.environ,
            {"MYOWNCA_STATE_DIR": str(state_dir)},
            clear=True,
        ):
            runtime = create_app()
        active = runtime.state.repository.get_active_sub_ca()
        assert active is not None
        assert active.id == issuer_id
        runtime.state.hsm.public_key(active.key_ref)


def test_adopted_pkcs11_hsm_creates_csr_with_selected_attached_key() -> None:
    with TemporaryDirectory() as tempdir:
        service, backend, key_ref, root, root_hsm = _prepare_pkcs11_request_service(
            tempdir,
            mode="existing",
        )
        inventory_before = backend.list_keys()

        created = service.create_request(
            common_name="Prepared HSM Issuing CA",
            allowed_profiles=[CertificateProfile.HOST_TLS],
            algorithm="rsa-2048",
            existing_key_ref=key_ref,
        )

        csr = x509.load_pem_x509_csr(created["csr_pem"].encode())
        assert csr.is_signature_valid
        assert csr.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ) == backend.public_key(key_ref).public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert backend.list_keys() == inventory_before
        assert created["key_ref"] == key_ref
        assert created["algorithm"] == "ecdsa-p384"
        assert created["ownership"] == KeyOwnership.ATTACHED.value

        registered = service.key_lifecycle_repository.find(
            backend="pkcs11",
            key_ref=key_ref,
        )
        assert registered is not None
        assert registered.ownership is KeyOwnership.ATTACHED

        certificate = build_sub_ca_certificate(csr, root.material, root_hsm)
        activated = service.import_response(
            certificate_pem=certificate_to_pem(certificate),
        )
        assert activated["issuer"]["key_ref"] == key_ref
        assert load_setup_state(tempdir).data["issuer_keys"] == [
            {
                "backend": "pkcs11",
                "key_ref": key_ref,
                "ownership": KeyOwnership.ATTACHED.value,
            }
        ]

        service.reset()

        backend.public_key(key_ref)
        assert (
            service.key_lifecycle_repository.get(registered.id).status
            is KeyStatus.DETACHED
        )


def test_pkcs11_adopted_hsm_still_generates_a_new_subca_key() -> None:
    with TemporaryDirectory() as existing_dir:
        existing_service, _backend, _key_ref, _root, _root_hsm = (
            _prepare_pkcs11_request_service(
            existing_dir,
            mode="existing",
            )
        )
        count_before = len(_backend.list_keys())
        created = existing_service.create_request(
            common_name="New Key On Adopted HSM",
            allowed_profiles=[CertificateProfile.HOST_TLS],
            algorithm="ecdsa-p384",
        )
        assert len(_backend.list_keys()) == count_before + 1
        assert created["ownership"] == KeyOwnership.MANAGED.value

    with TemporaryDirectory() as initialized_dir:
        initialized_service, backend, key_ref, _root, _root_hsm = (
            _prepare_pkcs11_request_service(
                initialized_dir,
                mode="initialized",
            )
        )
        with pytest.raises(SetupProvisioningError, match="only be selected"):
            initialized_service.create_request(
                common_name="Wrong Existing Key",
                allowed_profiles=[CertificateProfile.HOST_TLS],
                algorithm="ecdsa-p384",
                existing_key_ref=key_ref,
            )

        count_before = len(backend.list_keys())
        created = initialized_service.create_request(
            common_name="New Managed Key",
            allowed_profiles=[CertificateProfile.HOST_TLS],
            algorithm="ecdsa-p256",
        )
        assert len(backend.list_keys()) == count_before + 1
        assert created["ownership"] == KeyOwnership.MANAGED.value
        registered = initialized_service.key_lifecycle_repository.find(
            backend="pkcs11",
            key_ref=created["key_ref"],
        )
        assert registered is not None
        assert registered.ownership is KeyOwnership.MANAGED


def test_p12_import_requires_configured_root_and_persists_one_active_issuer() -> None:
    with TemporaryDirectory() as tempdir:
        source_hsm = SoftwareHSM()
        chain = create_lab_ca_chain(source_hsm, "Imported Issuing CA")
        _, provisioning = _prepare_production(
            tempdir,
            certificate_to_pem(chain.root.certificate),
        )
        analyzed = provisioning.analyze_file(
            bundle_b64=_p12(chain, source_hsm),
            private_key_b64=None,
            password="bundle-password",
            key_label="imported-initial-issuer",
            allowed_profiles=[CertificateProfile.HOST_TLS],
            **_never_crl(),
        )
        assert analyzed["source_format"] == "pkcs12"

        activated = provisioning.commit_file(
            bundle_b64=_p12(chain, source_hsm),
            private_key_b64=None,
            password="bundle-password",
            key_label="imported-initial-issuer",
            allowed_profiles=[CertificateProfile.HOST_TLS],
            **_never_crl(),
        )
        assert activated["configured"] is True
        assert len(provisioning.repository.list_sub_cas()) == 1
        event = next(
            event
            for event in AuditRepository(provisioning.database).list_events(
                actor_id="bootstrap/setup"
            )
            if event.action == "setup_subca_file_import"
        )
        assert "legacy_path_length_missing" not in event.details
        with pytest.raises(SetupProvisioningError, match="already configured"):
            provisioning.commit_file(
                bundle_b64=_p12(chain, source_hsm),
                private_key_b64=None,
                password="bundle-password",
                key_label="second-issuer",
                allowed_profiles=[CertificateProfile.HOST_TLS],
                **_never_crl(),
            )


def test_p12_import_migrates_crl_and_generates_local_successor() -> None:
    with TemporaryDirectory() as tempdir:
        source_hsm = SoftwareHSM()
        chain = create_lab_ca_chain(source_hsm, "Migrated CRL Issuer")
        _, provisioning = _prepare_production(
            tempdir,
            certificate_to_pem(chain.root.certificate),
        )
        revoked_at = (datetime.now(timezone.utc) - timedelta(days=2)).replace(
            microsecond=0
        )
        source_crl = build_crl(
            chain.issuer,
            [
                Revocation(
                    serial_number="cafe",
                    reason=RevocationReason.KEY_COMPROMISE,
                    revoked_at=revoked_at,
                )
            ],
            8,
            source_hsm,
        )
        crl_b64 = base64.b64encode(
            source_crl.public_bytes(serialization.Encoding.DER)
        ).decode()

        analysis = provisioning.analyze_file(
            bundle_b64=_p12(chain, source_hsm),
            private_key_b64=None,
            password="bundle-password",
            key_label="crl-migrated-issuer",
            allowed_profiles=[CertificateProfile.HOST_TLS],
            prior_crl_state="crl",
            crl_b64=crl_b64,
        )
        assert analysis["crl_migration"]["number"] == 8
        assert analysis["crl_migration"]["revocation_count"] == 1

        activated = provisioning.commit_file(
            bundle_b64=_p12(chain, source_hsm),
            private_key_b64=None,
            password="bundle-password",
            key_label="crl-migrated-issuer",
            allowed_profiles=[CertificateProfile.HOST_TLS],
            prior_crl_state="crl",
            crl_b64=crl_b64,
        )
        issuer = activated["issuer"]
        assert issuer["crl"]["number"] == 9
        assert issuer["crl"]["source"] == "local"
        assert provisioning.repository.get_issuer_revocation(
            issuer["certificate_sha256"],
            "cafe",
        ).revoked_at == revoked_at
        with provisioning.database.connect() as connection:
            history = connection.execute(
                "SELECT number, source FROM issuer_crls "
                "WHERE issuer_id = ? ORDER BY number",
                (issuer["certificate_sha256"],),
            ).fetchall()
        assert history == [
            {"number": 8, "source": "imported"},
            {"number": 9, "source": "local"},
        ]
        assert provisioning.assert_finalizable()["configured"] is True


def test_never_issued_crl_does_not_require_explicit_confirmation() -> None:
    with TemporaryDirectory() as tempdir:
        source_hsm = SoftwareHSM()
        chain = create_lab_ca_chain(source_hsm, "Unconfirmed CRL Issuer")
        _, provisioning = _prepare_production(
            tempdir,
            certificate_to_pem(chain.root.certificate),
        )
        analysis = provisioning.analyze_file(
            bundle_b64=_p12(chain, source_hsm),
            private_key_b64=None,
            password="bundle-password",
            key_label="unconfirmed-crl-state",
            allowed_profiles=[CertificateProfile.HOST_TLS],
            prior_crl_state="never_issued_crl",
            crl_b64=None,
        )
        assert analysis["crl_migration"]["prior_crl_state"] == "never_issued_crl"


def test_setup_rolls_back_when_first_local_crl_cannot_be_signed() -> None:
    with TemporaryDirectory() as tempdir:
        source_hsm = SoftwareHSM()
        chain = create_lab_ca_chain(source_hsm, "CRL Signing Failure Issuer")
        _, provisioning = _prepare_production(
            tempdir,
            certificate_to_pem(chain.root.certificate),
        )
        with (
            mock.patch(
                "myownca.setup.provisioning.CAMainService.generate_crl",
                side_effect=RuntimeError("CRL signing failed"),
            ),
            pytest.raises(SetupProvisioningError, match="CRL signing failed"),
        ):
            provisioning.commit_file(
                bundle_b64=_p12(chain, source_hsm),
                private_key_b64=None,
                password="bundle-password",
                key_label="failed-crl-signing",
                allowed_profiles=[CertificateProfile.HOST_TLS],
                **_never_crl(),
            )
        assert provisioning.repository.get_active_sub_ca() is None
        with provisioning.database.connect() as connection:
            assert connection.execute("SELECT * FROM issuer_crls").fetchall() == []
            assert connection.execute("SELECT * FROM issuer_revocations").fetchall() == []


def test_combined_pem_import_persists_the_matching_private_key() -> None:
    with TemporaryDirectory() as tempdir:
        source_hsm = SoftwareHSM()
        chain = create_lab_ca_chain(source_hsm, "PEM Imported Issuer")
        _, provisioning = _prepare_production(
            tempdir,
            certificate_to_pem(chain.root.certificate),
        )
        combined = (
            certificate_to_pem(chain.issuer.certificate).encode()
            + certificate_to_pem(chain.root.certificate).encode()
            + source_hsm.private_key(chain.issuer.key_ref).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        encoded = base64.b64encode(combined).decode()
        analysis = provisioning.analyze_file(
            bundle_b64=encoded,
            private_key_b64=None,
            password=None,
            key_label="pem-initial-issuer",
            allowed_profiles=[CertificateProfile.HOST_TLS],
            **_never_crl(),
        )
        assert analysis["source_format"] == "pem"

        activated = provisioning.commit_file(
            bundle_b64=encoded,
            private_key_b64=None,
            password=None,
            key_label="pem-initial-issuer",
            allowed_profiles=[CertificateProfile.HOST_TLS],
            **_never_crl(),
        )
        assert activated["configured"] is True
        provisioning.backend.public_key("pem-initial-issuer")


def test_import_rejects_foreign_root_and_empty_profiles() -> None:
    with TemporaryDirectory() as tempdir:
        source_hsm = SoftwareHSM()
        source = create_lab_ca_chain(source_hsm, "Source Issuer")
        foreign = create_lab_ca_chain(SoftwareHSM(), "Foreign Issuer")
        _, provisioning = _prepare_production(
            tempdir,
            certificate_to_pem(foreign.root.certificate),
        )
        with pytest.raises(SetupProvisioningError):
            provisioning.analyze_file(
                bundle_b64=_p12(source, source_hsm),
                private_key_b64=None,
                password="bundle-password",
                key_label="foreign-root",
                allowed_profiles=[CertificateProfile.HOST_TLS],
                **_never_crl(),
            )
        with pytest.raises(SetupProvisioningError, match="at least one"):
            provisioning.analyze_file(
                bundle_b64=_p12(source, source_hsm),
                private_key_b64=None,
                password="bundle-password",
                key_label="no-profiles",
                allowed_profiles=[],
                **_never_crl(),
            )


def test_existing_key_import_rejects_mismatch_algorithm_constraints_and_expiry() -> None:
    with TemporaryDirectory() as tempdir:
        root_hsm = SoftwareHSM()
        root = create_root_ca(root_hsm, "Validation Root")
        _, provisioning = _prepare_production(tempdir, root.certificate_pem)
        selected_ref = provisioning.backend.generate_key(
            "selected-existing-key",
            "ecdsa-p384",
        )
        other_ref = provisioning.backend.generate_key(
            "other-existing-key",
            "ecdsa-p384",
        )
        valid_for_other = _subca_certificate(
            provisioning.backend,
            other_ref,
            root,
            root_hsm,
        )
        with pytest.raises(SetupProvisioningError, match="does not match"):
            provisioning.commit_existing_key(
                key_ref=selected_ref,
                certificate_pem=certificate_to_pem(valid_for_other),
                allowed_profiles=[CertificateProfile.HOST_TLS],
                algorithm="ecdsa-p384",
                **_never_crl(),
            )

        valid = _subca_certificate(
            provisioning.backend,
            selected_ref,
            root,
            root_hsm,
        )
        with pytest.raises(SetupProvisioningError, match="algorithm"):
            provisioning.commit_existing_key(
                key_ref=selected_ref,
                certificate_pem=certificate_to_pem(valid),
                allowed_profiles=[CertificateProfile.HOST_TLS],
                algorithm="rsa-2048",
                **_never_crl(),
            )

        invalid_constraints = _subca_certificate(
            provisioning.backend,
            selected_ref,
            root,
            root_hsm,
            ca=False,
        )
        with pytest.raises(SetupProvisioningError, match="CA=true"):
            provisioning.commit_existing_key(
                key_ref=selected_ref,
                certificate_pem=certificate_to_pem(invalid_constraints),
                allowed_profiles=[CertificateProfile.HOST_TLS],
                algorithm="ecdsa-p384",
                **_never_crl(),
            )

        nested_ca = _subca_certificate(
            provisioning.backend,
            selected_ref,
            root,
            root_hsm,
            path_length=1,
        )
        with pytest.raises(SetupProvisioningError, match="pathLength=0"):
            provisioning.analyze_existing_key(
                key_ref=selected_ref,
                certificate_pem=certificate_to_pem(nested_ca),
                allowed_profiles=[CertificateProfile.HOST_TLS],
                algorithm="ecdsa-p384",
                **_never_crl(),
            )

        invalid_usage = _subca_certificate(
            provisioning.backend,
            selected_ref,
            root,
            root_hsm,
            key_cert_sign=False,
        )
        with pytest.raises(SetupProvisioningError, match="keyCertSign"):
            provisioning.commit_existing_key(
                key_ref=selected_ref,
                certificate_pem=certificate_to_pem(invalid_usage),
                allowed_profiles=[CertificateProfile.HOST_TLS],
                algorithm="ecdsa-p384",
                **_never_crl(),
            )

        expired = _subca_certificate(
            provisioning.backend,
            selected_ref,
            root,
            root_hsm,
            expired=True,
        )
        with pytest.raises(SetupProvisioningError, match="not currently valid"):
            provisioning.commit_existing_key(
                key_ref=selected_ref,
                certificate_pem=certificate_to_pem(expired),
                allowed_profiles=[CertificateProfile.HOST_TLS],
                algorithm="ecdsa-p384",
                **_never_crl(),
            )


def test_existing_key_import_accepts_legacy_missing_path_length_and_audits_it() -> None:
    with TemporaryDirectory() as tempdir:
        root_hsm = SoftwareHSM()
        root = create_root_ca(root_hsm, "Legacy Compatibility Root")
        _, provisioning = _prepare_production(tempdir, root.certificate_pem)
        key_ref = provisioning.backend.generate_key("legacy-existing-key", "ecdsa-p384")
        legacy = _subca_certificate(
            provisioning.backend,
            key_ref,
            root,
            root_hsm,
            path_length=None,
        )

        analysis = provisioning.analyze_existing_key(
            key_ref=key_ref,
            certificate_pem=certificate_to_pem(legacy),
            allowed_profiles=[CertificateProfile.HOST_TLS],
            algorithm="ecdsa-p384",
            **_never_crl(),
        )
        assert analysis["legacy_path_length_missing"] is True
        assert "does not enforce a zero CA path length" in analysis["warnings"][0]

        assert provisioning.commit_existing_key(
            key_ref=key_ref,
            certificate_pem=certificate_to_pem(legacy),
            allowed_profiles=[CertificateProfile.HOST_TLS],
            algorithm="ecdsa-p384",
            **_never_crl(),
        )["configured"] is True
        assert provisioning.assert_finalizable()["configured"] is True
        event = next(
            event
            for event in AuditRepository(provisioning.database).list_events(
                actor_id="bootstrap/setup"
            )
            if event.action == "setup_subca_existing_key_import"
        )
        assert event.details["legacy_path_length_missing"] is True


def test_p12_import_accepts_legacy_missing_path_length_and_audits_it() -> None:
    with TemporaryDirectory() as tempdir:
        root_hsm = SoftwareHSM()
        root = create_root_ca(root_hsm, "Legacy P12 Root")
        source_hsm = SoftwareHSM()
        key_ref = source_hsm.generate_key("legacy-p12-key", "ecdsa-p384")
        legacy = _subca_certificate(
            source_hsm,
            key_ref,
            root,
            root_hsm,
            path_length=None,
        )
        bundle = pkcs12.serialize_key_and_certificates(
            name=b"legacy-sub-ca",
            key=source_hsm.private_key(key_ref),
            cert=legacy,
            cas=[root.material.certificate],
            encryption_algorithm=serialization.BestAvailableEncryption(b"bundle-password"),
        )
        _, provisioning = _prepare_production(tempdir, root.certificate_pem)

        analysis = provisioning.analyze_file(
            bundle_b64=base64.b64encode(bundle).decode(),
            private_key_b64=None,
            password="bundle-password",
            key_label="legacy-p12-import",
            allowed_profiles=[CertificateProfile.HOST_TLS],
            **_never_crl(),
        )
        assert analysis["legacy_path_length_missing"] is True

        assert provisioning.commit_file(
            bundle_b64=base64.b64encode(bundle).decode(),
            private_key_b64=None,
            password="bundle-password",
            key_label="legacy-p12-import",
            allowed_profiles=[CertificateProfile.HOST_TLS],
            **_never_crl(),
        )["configured"] is True
        event = next(
            event
            for event in AuditRepository(provisioning.database).list_events(
                actor_id="bootstrap/setup"
            )
            if event.action == "setup_subca_file_import"
        )
        assert event.details["legacy_path_length_missing"] is True


def test_new_subca_response_rejects_missing_path_length() -> None:
    with TemporaryDirectory() as tempdir:
        root_hsm = SoftwareHSM()
        root = create_root_ca(root_hsm, "Strict New Sub CA Root")
        _, provisioning = _prepare_production(tempdir, root.certificate_pem)
        created = provisioning.create_request(
            common_name="Strict New Sub CA",
            allowed_profiles=[CertificateProfile.HOST_TLS],
            algorithm="ecdsa-p384",
        )
        legacy = _subca_certificate(
            provisioning.backend,
            str(created["key_ref"]),
            root,
            root_hsm,
            path_length=None,
        )

        with pytest.raises(SetupProvisioningError, match="pathLength=0"):
            provisioning.import_response(certificate_pem=certificate_to_pem(legacy))


def test_existing_key_import_rejects_unknown_key_reference() -> None:
    with TemporaryDirectory() as tempdir:
        root_hsm = SoftwareHSM()
        root = create_root_ca(root_hsm, "Unknown Key Root")
        _, provisioning = _prepare_production(tempdir, root.certificate_pem)
        existing_ref = provisioning.backend.generate_key(
            "existing-issuer",
            "ecdsa-p384",
        )
        certificate = _subca_certificate(
            provisioning.backend,
            existing_ref,
            root,
            root_hsm,
        )

        with pytest.raises(
            SetupProvisioningError,
            match="selected key reference does not exist",
        ):
            provisioning.analyze_existing_key(
                key_ref="missing-key-reference",
                certificate_pem=certificate_to_pem(certificate),
                allowed_profiles=[CertificateProfile.HOST_TLS],
                algorithm="ecdsa-p384",
                **_never_crl(),
            )


def test_file_import_enforces_upload_limit_and_rolls_back_managed_key() -> None:
    with TemporaryDirectory() as tempdir:
        source_hsm = SoftwareHSM()
        chain = create_lab_ca_chain(source_hsm, "Rollback Issuer")
        _, provisioning = _prepare_production(
            tempdir,
            certificate_to_pem(chain.root.certificate),
        )
        with pytest.raises(SetupProvisioningError, match="upload limit"):
            provisioning.analyze_file(
                bundle_b64=base64.b64encode(
                    b"x" * (5 * 1024 * 1024 + 1)
                ).decode(),
                private_key_b64=None,
                password=None,
                key_label="oversized",
                allowed_profiles=[CertificateProfile.HOST_TLS],
                **_never_crl(),
            )

        with (
            mock.patch.object(
                provisioning.ceremony,
                "import_existing_sub_ca",
                side_effect=RuntimeError("persistence failed"),
            ),
            pytest.raises(SetupProvisioningError, match="persistence failed"),
        ):
            provisioning.commit_file(
                bundle_b64=_p12(chain, source_hsm),
                private_key_b64=None,
                password="bundle-password",
                key_label="rollback-import",
                allowed_profiles=[CertificateProfile.HOST_TLS],
                **_never_crl(),
            )
        registered = provisioning.key_lifecycle_repository.find(
            backend="software",
            key_ref="rollback-import",
        )
        assert registered is not None
        assert registered.status is KeyStatus.DELETED
        assert provisioning.status()["configured"] is False
        with pytest.raises(KeyError):
            provisioning.backend.public_key("rollback-import")


def test_reset_deletes_managed_keys_unlocks_foundation_and_allows_recreate() -> None:
    with TemporaryDirectory() as tempdir:
        orchestrator, provisioning = _prepare_lab(tempdir)
        provisioning.provision_lab()
        root_key = provisioning.key_lifecycle_repository.find(
            backend="software",
            key_ref="lab-root",
        )
        issuer_key = provisioning.key_lifecycle_repository.find(
            backend="software",
            key_ref="lab-issuer",
        )
        assert root_key is not None and issuer_key is not None

        reset = provisioning.reset()
        assert reset["configured"] is False
        assert reset["locked"] is False
        assert provisioning.key_lifecycle_repository.get(root_key.id).status is KeyStatus.DELETED
        assert provisioning.key_lifecycle_repository.get(issuer_key.id).status is KeyStatus.DELETED
        with pytest.raises(KeyError):
            provisioning.backend.public_key("lab-root")
        with pytest.raises(KeyError):
            provisioning.backend.public_key("lab-issuer")

        orchestrator.set_database("sqlite")
        recreated = SetupProvisioningService(tempdir).provision_lab()
        assert recreated["configured"] is True
        assert (
            SetupProvisioningService(tempdir)
            .key_lifecycle_repository.get(root_key.id)
            .status
            is KeyStatus.ACTIVE
        )


def test_reset_stays_locked_when_managed_key_cleanup_fails() -> None:
    with TemporaryDirectory() as tempdir:
        _, provisioning = _prepare_lab(tempdir)
        provisioning.provision_lab()
        with (
            mock.patch.object(
                provisioning.backend,
                "delete_key",
                side_effect=RuntimeError("token unavailable"),
            ),
            pytest.raises(SetupProvisioningError, match="cleanup failed"),
        ):
            provisioning.reset()
        assert provisioning.status()["configured"] is True
        assert provisioning.status()["locked"] is True

        assert provisioning.reset()["configured"] is False


def test_reset_detaches_existing_key_without_provider_deletion() -> None:
    with TemporaryDirectory() as tempdir:
        root_hsm = SoftwareHSM()
        root = create_root_ca(root_hsm, "External-key Root")
        _, provisioning = _prepare_production(tempdir, root.certificate_pem)
        key_ref = provisioning.backend.generate_key("provider-owned-key", "ecdsa-p384")
        csr = build_sub_ca_csr(
            provisioning.backend,
            key_ref,
            "Provider-owned Issuing CA",
        )
        certificate = build_sub_ca_certificate(csr, root.material, root_hsm)
        provisioning.commit_existing_key(
            key_ref=key_ref,
            certificate_pem=certificate_to_pem(certificate),
            allowed_profiles=[CertificateProfile.HOST_TLS],
            algorithm="ecdsa-p384",
            **_never_crl(),
        )
        registered = provisioning.key_lifecycle_repository.find(
            backend="software",
            key_ref=key_ref,
        )
        assert registered is not None
        assert registered.ownership is KeyOwnership.ATTACHED

        provisioning.reset()

        provisioning.backend.public_key(key_ref)
        assert (
            provisioning.key_lifecycle_repository.get(registered.id).status
            is KeyStatus.DETACHED
        )


def test_existing_cloud_key_is_attached_and_never_deleted_by_reset() -> None:
    class AttachedCloudBackend:
        def __init__(self, private_key) -> None:
            self.private_key = private_key
            self.attached: list[tuple[str, str | None]] = []
            self.deleted: list[str] = []

        def attach_key(self, key_ref: str, expected_algorithm: str | None = None):
            self.attached.append((key_ref, expected_algorithm))
            return key_ref

        def public_key(self, _key_ref: str):
            return self.private_key.public_key()

        def sign_certificate(self, builder, _key_ref: str):
            return builder.sign(self.private_key, hashes.SHA384())

        def sign_crl(self, builder, _key_ref: str):
            return builder.sign(self.private_key, hashes.SHA384())

        def delete_key(self, key_ref: str):
            self.deleted.append(key_ref)

    with TemporaryDirectory() as tempdir:
        root_hsm = SoftwareHSM()
        root = create_root_ca(root_hsm, "Cloud-key Root")
        provider_hsm = SoftwareHSM()
        provider_ref = provider_hsm.generate_key("provider-key", "ecdsa-p384")
        csr = build_sub_ca_csr(provider_hsm, provider_ref, "Cloud Issuing CA")
        certificate = build_sub_ca_certificate(csr, root.material, root_hsm)
        _, provisioning = _prepare_production(tempdir, root.certificate_pem)
        cloud = AttachedCloudBackend(provider_hsm.private_key(provider_ref))
        provisioning.backend = cloud
        provisioning.backend_name = "aws_kms"
        provisioning.ceremony.hsm = cloud

        activated = provisioning.commit_existing_key(
            key_ref="arn:aws:kms:eu-test-1:123456789012:key/customer-owned",
            certificate_pem=certificate_to_pem(certificate),
            allowed_profiles=[CertificateProfile.HOST_TLS],
            algorithm="ecdsa-p384",
            **_never_crl(),
        )
        assert activated["issuer"]["key_backend"] == "aws_kms"
        assert cloud.attached == [
            (
                "arn:aws:kms:eu-test-1:123456789012:key/customer-owned",
                "ecdsa-p384",
            ),
        ]
        registered_cloud = provisioning.cloud_keys.find(
            provider="aws_kms",
            key_ref="arn:aws:kms:eu-test-1:123456789012:key/customer-owned",
        )
        assert registered_cloud is not None
        assert registered_cloud.ownership.value == "attached"

        provisioning.reset()
        assert cloud.deleted == []
        assert (
            provisioning.cloud_keys.get(registered_cloud.id).status.value
            == "deleted"
        )


def test_completed_setup_rejects_reset_of_active_trust_chain() -> None:
    with TemporaryDirectory() as tempdir:
        orchestrator, provisioning = _prepare_lab(tempdir)
        provisioning.provision_lab()
        orchestrator.set_admins(_ADMIN)
        orchestrator.finalize()
        with pytest.raises(SetupProvisioningError, match="immutable"):
            SetupProvisioningService(tempdir).reset()


def test_setup_api_requires_session_csrf_phrase_and_redacts_rejected_input() -> None:
    with TemporaryDirectory() as tempdir:
        auth = SetupAuth("one-time-token")
        app = create_setup_app(tempdir, auth)
        lab_endpoint = route_endpoint(app, "/setup/issuer/lab", "POST")
        valid_lab = LabIssuerPayload(
            confirmation="CREATE LAB CA",
            reason="Create the initial lab issuer",
        )
        with pytest.raises(HTTPException) as no_session:
            lab_endpoint(valid_lab, _setup_request(method="POST"))
        assert no_session.value.status_code == 401

        session, csrf = auth.open_session()
        route_endpoint(app, "/setup/install-type", "POST")(
            InstallTypePayload(value="lab"),
            _setup_request(session=session, csrf=csrf, method="POST"),
        )
        with pytest.raises(HTTPException) as wrong_phrase:
            lab_endpoint(
                LabIssuerPayload(
                    confirmation="WRONG",
                    reason="Create the initial lab issuer",
                ),
                _setup_request(session=session, csrf=csrf, method="POST"),
            )
        assert wrong_phrase.value.status_code == 400
        with pytest.raises(HTTPException) as no_csrf:
            lab_endpoint(
                valid_lab,
                _setup_request(session=session, method="POST"),
            )
        assert no_csrf.value.status_code == 403

        created = lab_endpoint(
            valid_lab,
            _setup_request(session=session, csrf=csrf, method="POST"),
        )
        assert created["configured"] is True
        with pytest.raises(HTTPException) as locked_database:
            route_endpoint(app, "/setup/database", "POST")(
                DatabasePayload(kind="sqlite"),
                _setup_request(session=session, csrf=csrf, method="POST"),
            )
        assert locked_database.value.status_code == 400

        secret = "PIN-MUST-NOT-BE-REFLECTED"
        validation_error = RequestValidationError(
            [
                {
                    "type": "string_too_short",
                    "loc": ("body", "reason"),
                    "msg": "String should have at least 10 characters",
                    "input": secret,
                    "ctx": {"min_length": 10},
                }
            ]
        )
        handler = app.exception_handlers[RequestValidationError]
        response = asyncio.run(handler(_setup_request(), validation_error))
        assert response.status_code == 422
        assert secret not in response.body.decode()
        assert json.loads(response.body)["detail"][0]["loc"] == ["body", "reason"]

        events = AuditRepository(
            SetupProvisioningService(tempdir).database
        ).list_events(actor_id="bootstrap/setup")
        lab_event = next(
            event
            for event in events
            if event.action == "setup_lab_issuer_create"
        )
        assert lab_event.details["reason"] == "Create the initial lab issuer"
        assert all(secret not in str(event.details) for event in events)


def test_runtime_exposes_no_legacy_setup_mutations() -> None:
    with TemporaryDirectory() as tempdir, mock.patch.dict(
        os.environ,
        {"MYOWNCA_STATE_DIR": tempdir},
        clear=True,
    ):
        runtime = create_app(
            Path(tempdir) / "runtime.sqlite3",
            lab_mode=False,
            online_key_dir=Path(tempdir) / "keys",
        )
    routes = {
        (method, route.path)
        for route in runtime.routes
        for method in getattr(route, "methods", set())
    }
    assert not any(path.startswith("/internal/setup/") for _, path in routes)
    assert ("GET", "/internal/admin/issuer") in routes
    assert ("GET", "/internal/admin/root-certificate") in routes
    assert not any(
        path in {
            "/internal/admin/issuer",
            "/internal/admin/root-certificate",
        }
        and method != "GET"
        for method, path in routes
    )


def test_finalize_requires_active_issuer() -> None:
    with TemporaryDirectory() as tempdir:
        root = create_root_ca(SoftwareHSM(), "Production Root")
        orchestrator = SetupOrchestrator(tempdir)
        orchestrator.set_install_type("production")
        orchestrator.set_governance_mode("dual_control")
        orchestrator.set_listener(topology="proxy")
        orchestrator.set_root_certificate(root.certificate_pem)
        orchestrator.set_admins(_ADMIN, _ADMIN_2)
        with pytest.raises(SetupError, match="activate the issuing Sub CA"):
            orchestrator.finalize()


def test_finalize_rejects_an_inaccessible_active_issuer_key() -> None:
    with TemporaryDirectory() as tempdir:
        orchestrator, provisioning = _prepare_lab(tempdir)
        provisioning.provision_lab()
        provisioning.backend.delete_key("lab-issuer")
        orchestrator.set_admins(_ADMIN)
        with pytest.raises(SetupError, match="not accessible"):
            orchestrator.finalize()
