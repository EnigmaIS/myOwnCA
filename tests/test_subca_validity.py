"""Root/Sub-CA interval containment at every setup acceptance boundary."""

import base64
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi import HTTPException

from myownca.ca_hsm import SoftwareHSM
from myownca.ca_main.crypto import certificate_to_pem, create_root_ca
from myownca.domain import CertificateProfile, SubCA
from myownca.online.ceremony import _validate_sub_ca_chain
from myownca.setup.app import ResponseImportPayload, create_setup_app
from myownca.setup.orchestrator import SetupError
from myownca.setup.provisioning import SetupProvisioningError
from myownca.setup.state import is_setup_complete, load_setup_state
from myownca.setup.token import SetupAuth
from tests.helpers import route_endpoint
from tests.test_setup_provisioning import (
    _ADMIN, _ADMIN_2, _never_crl, _prepare_production, _setup_request, _subca_certificate,
)


@pytest.fixture
def material(tmp_path):
    root_hsm = SoftwareHSM()
    root = create_root_ca(root_hsm, "Validity Root")
    orchestrator, service = _prepare_production(tmp_path, root.certificate_pem)
    key_ref = service.backend.generate_key("existing-subca", "ecdsa-p384")
    return orchestrator, service, root, root_hsm, key_ref


def _certificate(material, boundary, *, key_ref=None, path_length=0):
    _, service, root, root_hsm, default_key_ref = material
    parent = root.material.certificate
    starts_at = parent.not_valid_before_utc
    expires_at = parent.not_valid_after_utc
    return _subca_certificate(
        service.backend, key_ref or default_key_ref, root, root_hsm,
        not_before=starts_at + timedelta(seconds={
            "contained": 1, "equal_start": 0, "equal_end": 1,
            "equal_both": 0, "early_start": -1, "late_end": 0,
        }[boundary]),
        not_after=expires_at + timedelta(seconds={
            "contained": -1, "equal_start": -1, "equal_end": 0,
            "equal_both": 0, "early_start": -1, "late_end": 1,
        }[boundary]),
        path_length=path_length,
    )


@pytest.mark.parametrize("boundary", ["contained", "equal_start", "equal_end", "equal_both"])
def test_chain_accepts_containment_and_equal_boundaries(material, boundary):
    certificate = _certificate(material, boundary)
    _validate_sub_ca_chain(certificate, material[2].material.certificate,
                           now=datetime.now(timezone.utc))


@pytest.mark.parametrize("boundary", ["early_start", "late_end"])
@pytest.mark.parametrize("legacy", [False, True])
def test_chain_rejects_one_second_outside_root_even_for_legacy_imports(material, boundary, legacy):
    certificate = _certificate(material, boundary, path_length=None if legacy else 0)
    root = material[2].material.certificate
    with pytest.raises(ValueError, match="corrected Root-signed") as error:
        _validate_sub_ca_chain(certificate, root, now=datetime.now(timezone.utc),
                               allow_legacy_missing_path_length=legacy)
    child_time = certificate.not_valid_before_utc if boundary == "early_start" else (
        certificate.not_valid_after_utc
    )
    root_time = root.not_valid_before_utc if boundary == "early_start" else root.not_valid_after_utc
    assert child_time.isoformat() in str(error.value)
    assert root_time.isoformat() in str(error.value)


@pytest.mark.parametrize("boundary", ["early_start", "late_end"])
@pytest.mark.parametrize("operation", [
    "analyze_existing_key", "commit_existing_key",
    "analyze_pem", "commit_pem", "analyze_p12", "commit_p12",
    "analyze_dkek", "restore_dkek",
])
def test_setup_rejects_before_key_mutation_or_activation(material, boundary, operation):
    _, service, root, _, key_ref = material
    certificate = _certificate(material, boundary)
    kwargs = {"allowed_profiles": [CertificateProfile.HOST_TLS], **_never_crl()}
    method = operation
    if operation.endswith("existing_key"):
        kwargs.update(key_ref=key_ref, certificate_pem=certificate_to_pem(certificate),
                      algorithm="ecdsa-p384")
    elif operation.endswith("dkek"):
        service.backend_name = "pkcs11"
        kwargs.update(wrapped_key_b64=base64.b64encode(b"wrapped key").decode(),
                      key_reference="1", certificate_pem=certificate_to_pem(certificate))
    else:
        key = service.backend.private_key(key_ref)
        if operation.endswith("p12"):
            bundle = pkcs12.serialize_key_and_certificates(
                b"subca", key, certificate, [root.material.certificate],
                serialization.NoEncryption(),
            )
        else:
            bundle = certificate_to_pem(certificate).encode() + key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        kwargs.update(bundle_b64=base64.b64encode(bundle).decode(), private_key_b64=None,
                      password=None, key_label="new-import")
        method = operation.split("_")[0] + "_file"
    state_before = load_setup_state(service.state_dir)
    with (
        mock.patch.object(service.backend, "import_key") as import_key,
        mock.patch.object(service.backend, "delete_key") as delete_key,
        mock.patch.object(service.hsm_recovery, "inspect_restore_target") as inspect,
        mock.patch.object(service.hsm_recovery, "restore_key") as restore,
    ):
        with pytest.raises(SetupProvisioningError, match="corrected Root-signed"):
            getattr(service, method)(**kwargs)
    import_key.assert_not_called()
    delete_key.assert_not_called()
    inspect.assert_not_called()
    restore.assert_not_called()
    assert service.repository.list_sub_cas() == []
    assert service.repository.list_pending_sub_cas() == []
    assert load_setup_state(service.state_dir) == state_before
    service.backend.public_key(key_ref)


@pytest.mark.parametrize("boundary", ["early_start", "late_end"])
def test_csr_response_http_error_preserves_pending_request_and_key(material, boundary):
    _, service, _, _, _ = material
    service.create_request(common_name="Imported Issuing CA",
                           allowed_profiles=[CertificateProfile.HOST_TLS], algorithm="ecdsa-p384")
    pending = service.repository.list_pending_sub_cas()[0]
    rejected_pem = certificate_to_pem(_certificate(material, boundary, key_ref=pending.key_ref))
    auth = SetupAuth()
    app = create_setup_app(service.state_dir, auth)
    session, csrf = auth.open_session()
    endpoint = route_endpoint(app, "/setup/issuer/response/import", "POST")
    payload = ResponseImportPayload(certificate_pem=rejected_pem, confirmation="ACTIVATE SUBCA",
                                    reason="Validate issuer lifetime")
    with pytest.raises(HTTPException) as error:
        endpoint(payload, _setup_request(session=session, csrf=csrf, method="POST"))
    assert error.value.status_code == 400
    assert "corrected Root-signed Sub-CA certificate" in error.value.detail
    assert service.repository.list_pending_sub_cas() == [pending]
    assert service.repository.get_active_sub_ca() is None
    service.backend.public_key(pending.key_ref)
    assert not is_setup_complete(service.state_dir)

    # The same CSR/key can be retried with a corrected certificate, including equal bounds.
    corrected = _certificate(material, "equal_both", key_ref=pending.key_ref)
    result = service.import_response(certificate_pem=certificate_to_pem(corrected))
    assert result["configured"] is True
    assert service.repository.list_pending_sub_cas() == []


@pytest.mark.parametrize("boundary", ["early_start", "late_end"])
def test_finalization_rechecks_previously_persisted_issuer(material, boundary):
    orchestrator, service, root, _, key_ref = material
    certificate = _certificate(material, boundary)
    # Simulate an unfinished setup populated before interval enforcement existed.
    service.repository.add_sub_ca(
        SubCA(id="legacy-issuer", certificate_pem=certificate_to_pem(certificate),
              key_ref=key_ref, subject=certificate.subject.rfc4514_string(),
              created_at=datetime.now(timezone.utc),
              allowed_profiles=(CertificateProfile.HOST_TLS,), key_backend="software"),
        root_certificate_pem=root.certificate_pem, activate=True,
    )
    orchestrator.set_admins(_ADMIN, _ADMIN_2)
    with pytest.raises(SetupError, match="corrected Root-signed"):
        orchestrator.finalize()
    assert not is_setup_complete(service.state_dir)
    assert load_setup_state(service.state_dir).steps.get("finalize") != "done"
    assert service.repository.get_active_sub_ca().id == "legacy-issuer"
    service.backend.public_key(key_ref)
