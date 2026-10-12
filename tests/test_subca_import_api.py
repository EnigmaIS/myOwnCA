from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from cryptography import x509

from myownca.audit import AuditRepository
from myownca.ca_hsm import SoftwareHSM
from myownca.ca_hsm.scctl import DKEKStatus
from myownca.ca_main.crypto import certificate_to_pem, create_lab_ca_chain
from myownca.domain import CertificateProfile
from myownca.key_lifecycle import KeyOwnership, KeyStatus
from myownca.setup.orchestrator import SetupOrchestrator
from myownca.setup.provisioning import (
    SetupProvisioningError,
    SetupProvisioningService,
)


class _RestoredBackend(SoftwareHSM):
    def __init__(self, key, certificate) -> None:
        super().__init__()
        self.import_key("restored-subca", key, certificate)
        self.restored_visible = False

    def list_keys(self):
        if not self.restored_visible:
            return []
        return [
            {
                "label": "restored-subca",
                "id": "10",
                "key_reference": 16,
                "key_type": "EC",
                "key_size": 256,
            }
        ]

    def reveal_restored_key(self, *_args, **_kwargs) -> None:
        self.restored_visible = True

    def delete_key(self, label: str) -> int:
        self.restored_visible = False
        return super().delete_key(label)


def _service(tempdir: str, *, user_pin: str | None = None):
    source_hsm = SoftwareHSM()
    chain = create_lab_ca_chain(
        source_hsm,
        common_name="Recovered Issuing CA",
        root_key_ref="source-root",
        issuer_key_ref="source-issuer",
    )
    module = Path(tempdir) / "fake-pkcs11.so"
    module.write_text("test")
    orchestrator = SetupOrchestrator(tempdir)
    orchestrator.set_install_type("production")
    orchestrator.set_governance_mode("single_admin")
    orchestrator.set_hsm(
        "pkcs11",
        pkcs11_lib=str(module),
        token_label="Recovery Token",
    )
    orchestrator.record_pkcs11_ready(
        mode="initialized",
        token_serial="RECOVERY-TOKEN",
        dkek_mode="shares",
        kcv="A1B2C3",
    )
    orchestrator.set_root_certificate(certificate_to_pem(chain.root.certificate))
    orchestrator.prepare_runtime()
    backend = _RestoredBackend(
        source_hsm.private_key(chain.issuer.key_ref),
        chain.issuer.certificate,
    )
    scctl = mock.Mock()
    with mock.patch(
        "myownca.setup.provisioning.create_hsm",
        return_value=(backend, "pkcs11"),
    ):
        service = SetupProvisioningService(
            tempdir,
            user_pin=user_pin,
            scctl=scctl,
        )
    return service, backend, scctl, chain, source_hsm


def _legacy_subca_certificate(source_hsm: SoftwareHSM, chain) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(chain.issuer.certificate.subject)
        .issuer_name(chain.root.certificate.subject)
        .public_key(chain.issuer.certificate.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(chain.root.certificate.not_valid_before_utc)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    )
    return source_hsm.sign_certificate(builder, chain.root.key_ref)


def test_dkek_analysis_is_read_only_and_requires_ready_hsm() -> None:
    with TemporaryDirectory() as tempdir:
        service, _backend, scctl, chain, _source_hsm = _service(tempdir, user_pin="123456")
        scctl.dkek_status.return_value = DKEKStatus(2, 2, True, "A1B2C3")
        analysis = service.analyze_dkek(
            wrapped_key_b64=base64.b64encode(b"wrapped key").decode(),
            key_reference="0x10",
            certificate_pem=certificate_to_pem(chain.issuer.certificate),
            allowed_profiles=[CertificateProfile.HOST_TLS],
            prior_crl_state="never_issued_crl",
            crl_b64=None,
        )
    assert analysis["method"] == "dkek_restore"
    assert analysis["dkek_shares_imported"] == 2
    scctl.import_dkek_share.assert_not_called()
    scctl.unwrap_key.assert_not_called()


def test_dkek_restore_activates_managed_key_without_persisting_secrets() -> None:
    with TemporaryDirectory() as tempdir:
        service, backend, scctl, chain, source_hsm = _service(tempdir, user_pin="123456")
        legacy = _legacy_subca_certificate(source_hsm, chain)
        complete = DKEKStatus(2, 2, True, "A1B2C3")
        scctl.dkek_status.return_value = complete
        scctl.unwrap_key.side_effect = backend.reveal_restored_key

        analysis = service.analyze_dkek(
            wrapped_key_b64=base64.b64encode(b"wrapped key bundle").decode(),
            key_reference="0x10",
            certificate_pem=certificate_to_pem(legacy),
            allowed_profiles=[CertificateProfile.HOST_TLS],
            prior_crl_state="never_issued_crl",
            crl_b64=None,
        )
        assert analysis["legacy_path_length_missing"] is True

        restored = service.restore_dkek(
            wrapped_key_b64=base64.b64encode(b"wrapped key bundle").decode(),
            key_reference="0x10",
            certificate_pem=certificate_to_pem(legacy),
            allowed_profiles=[CertificateProfile.HOST_TLS],
            prior_crl_state="never_issued_crl",
            crl_b64=None,
        )

        assert restored["configured"] is True
        issuer = service.repository.get_active_sub_ca()
        assert issuer is not None
        assert issuer.key_ref == "restored-subca"
        assert issuer.key_backend == "pkcs11"
        registered = service.key_lifecycle_repository.find(
            backend="pkcs11",
            key_ref="restored-subca",
        )
        assert registered is not None
        assert registered.ownership is KeyOwnership.MANAGED
        event = next(
            event
            for event in AuditRepository(service.database).list_events(actor_id="bootstrap/setup")
            if event.action == "setup_subca_dkek_restore"
        )
        assert event.details["legacy_path_length_missing"] is True
        scctl.unwrap_key.assert_called_once_with(
            b"wrapped key bundle",
            user_pin="123456",
            key_reference=16,
            force=False,
        )
        scctl.import_dkek_share.assert_not_called()

        database_bytes = (Path(tempdir) / "myownca.sqlite3").read_bytes()
        for secret in (
            b"123456",
            b"wrapped key bundle",
        ):
            assert secret not in database_bytes

        reset = service.reset()
        assert reset["configured"] is False
        assert service.key_lifecycle_repository.get(registered.id).status is KeyStatus.DELETED


def test_dkek_restore_rolls_back_hsm_key_after_lifecycle_failure() -> None:
    with TemporaryDirectory() as tempdir:
        service, backend, scctl, chain, _source_hsm = _service(tempdir, user_pin="123456")
        complete = DKEKStatus(2, 2, True, "A1B2C3")
        scctl.dkek_status.side_effect = [complete, complete]
        scctl.unwrap_key.side_effect = backend.reveal_restored_key

        with (
            mock.patch.object(
                service,
                "_register_key",
                side_effect=RuntimeError("lifecycle write failed"),
            ),
            pytest.raises(SetupProvisioningError, match="lifecycle write failed"),
        ):
            service.restore_dkek(
                wrapped_key_b64=base64.b64encode(b"wrapped key bundle").decode(),
                key_reference="0x10",
                certificate_pem=certificate_to_pem(chain.issuer.certificate),
            allowed_profiles=[CertificateProfile.HOST_TLS],
            prior_crl_state="never_issued_crl",
            crl_b64=None,
            )

        assert backend.list_keys() == []
        assert service.repository.get_active_sub_ca() is None
