"""Issuer lifetime enforcement across transactions, APIs, and readiness."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from myownca.domain import CertificateProfile, CertificateTemplate, RequestStatus, Role
from myownca.online.app import RequestHolderAssign, _auto_issue_error_from_exception
from myownca.online.operations import OperationsService
from myownca_core.leaf import IssuerValidityError
from tests.helpers import add_login_ready_user, create_active_session, request_with_session
from tests.helpers import route_endpoint, assign_request_holder, make_csr
from tests.test_claim_renewal import _app_with_renewal_link, _mtls_request, _renew
from tests.test_cloud_app_integration import _cloud_app, _login
from tests.test_leaf import _issuer
from tests.test_production_licensing import _app, _pending_first


def test_claim_page_displays_actionable_errors_and_preserves_queued_and_success_states():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the claim-page behavior check")
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [node, str(root / "tests/js/issuer_validity.cjs"),
         str(root / "src/myownca/online/static/holder.js")],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("phase", ["before_sign", "after_sign"])
def test_claim_renewal_reports_rejection_without_retiring_original(tmp_path, phase):
    app, original, _link, token, _session = _app_with_renewal_link(str(tmp_path))
    expiry = app.state.lab_chain.issuer.certificate.not_valid_after_utc
    start = expiry - timedelta(days=365 if phase == "after_sign" else 1)
    app.state.service.clock = mock.Mock(side_effect=[start, expiry])
    keys_before = app.state.key_vault.held(original.request_id)
    with mock.patch.object(app.state.service, "_notify_cert_change") as notify:
        result = _renew(app, token, _mtls_request(original.certificate_pem), mode="rotate")
    assert result["issued_serial_number"] is None
    assert result["auto_issue_error"]["code"] == (
        "issuer_expired" if phase == "after_sign" else "issuer_validity_exceeded"
    )
    assert app.state.repository.get_issued_certificate(original.serial_number) == original
    assert app.state.key_vault.held(original.request_id) == keys_before
    assert app.state.key_vault.held(result["request_id"])
    assert app.state.repository.get_request(result["request_id"]).status is RequestStatus.PENDING
    assert app.state.repository.list_revocations() == []
    assert app.state.licensing.reserved_count(start) == 0
    notify.assert_not_called()


@pytest.mark.parametrize("phase,code", [
    ("enqueue", "issuer_validity_exceeded"),
    ("queue_wait", "issuer_validity_exceeded"),
    ("queue_expired", "issuer_expired"),
    ("queue_not_yet_valid", "issuer_not_yet_valid"),
    ("after_sign", "issuer_expired"),
    ("success", None),
])
def test_cloud_lifetime_checks_and_permanent_errors(tmp_path, phase, code):
    from myownca.ca_hsm import SoftwareHSM
    from myownca.offline import OfflineRootService, OfflineStateRepository

    with _cloud_app(str(tmp_path)) as (app, _key, _client):
        offline = OfflineRootService(OfflineStateRepository(tmp_path / "offline.sqlite3"),
                                     SoftwareHSM())
        root = offline.create_root("Validity Test Root")
        pending = app.state.ceremony.create_sub_ca_request(
            common_name="Cloud Issuer", allowed_profiles=(CertificateProfile.HOST_TLS,),
            algorithm="ecdsa-p384", key_backend="aws_kms",
        )
        signed = offline.sign_sub_ca_csr(pending.csr_pem,
                                         allowed_profiles=(CertificateProfile.HOST_TLS,))
        app.state.ceremony.import_sub_ca_certificate(
            signed.certificate_pem, root_certificate_pem=root.root_certificate_pem,
            pending_id=pending.id,
        )
        issuer = app.state.ceremony.issuer_material(pending.id)
        operator = _login(app, user_id="operator", email="op@example.test", role=Role.SUPERUSER)
        app.state.repository.add_template(CertificateTemplate(
            id="host", name="Host", profile=CertificateProfile.HOST_TLS,
            first_issuance_approvals=1, validity_days=3000 if phase == "enqueue" else 365,
        ))
        request = app.state.service.submit_request(
            "host", make_csr("cloud.example.test", dns_names=("cloud.example.test",)),
            requested_by_user_id="operator",
        )
        assign_request_holder(app, request.id)
        result = route_endpoint(
            app, "/internal/certificate-requests/{request_id}/approvals", "POST"
        )(request.id, operator)
        if phase == "enqueue":
            assert result["auto_issue_error"]["code"] == code
            assert app.state.signing_jobs.list_all() == []
            assert len(app.state.repository.list_approvals(request.id)) == 1
            assert app.state.licensing.reserved_count() == 0
            return
        assert result["auto_issue_error"]["code"] == "cloud_signing_queued"
        expiry = issuer.certificate.not_valid_after_utc
        start = {
            "queue_wait": expiry - timedelta(days=1),
            "queue_expired": expiry,
            "queue_not_yet_valid": issuer.certificate.not_valid_before_utc - timedelta(seconds=1),
            "after_sign": expiry - timedelta(days=365),
            "success": expiry - timedelta(days=365),
        }[phase]
        completion = expiry if phase == "after_sign" else start + timedelta(seconds=1)
        app.state.service.clock = mock.Mock(side_effect=[start, completion])
        with mock.patch.object(app.state.service.hsm.backend, "sign_certificate",
                               wraps=app.state.service.hsm.backend.sign_certificate) as sign:
            job = app.state.cloud_signing_worker.run_once()
        assert job.id == result["auto_issue_error"]["job_id"]
        assert len(app.state.repository.list_approvals(request.id)) == 1
        assert app.state.licensing.reserved_count(start) == 0
        if phase == "success":
            assert job.status.value == "succeeded"
            issued = app.state.repository.get_issued_certificate_by_request_id(request.id)
            assert issued.expires_at == expiry
            assert job.result["serial_number"] == issued.serial_number
            replay = app.state.signing_jobs.enqueue(
                cloud_key_id=job.cloud_key_id, operation=job.operation,
                resource_type=job.resource_type, resource_id=job.resource_id,
                payload=job.payload, deduplication_key=request.id,
            ).job
            app.state.service.clock = mock.Mock(side_effect=AssertionError("Must not reissue"))
            replayed = app.state.cloud_signing_worker.run_once()
            assert replayed.id == replay.id
            assert replayed.status.value == "succeeded"
            assert replayed.result == job.result
        else:
            assert job.status.value == "failed"
            assert job.last_error_code == code
            assert "CA" in job.last_error_message
            response = route_endpoint(app, "/internal/cloud/signing-jobs/{job_id}", "GET")(
                job.id, operator,
            )
            assert response["last_error_code"] == code
            assert response["last_error_message"] == job.last_error_message
            assert sign.call_count == (1 if phase == "after_sign" else 0)
            assert app.state.repository.get_issued_certificate_by_request_id(request.id) is None
            assert app.state.repository.get_request(request.id).status is RequestStatus.PENDING
            assert app.state.cloud_signing_worker.run_once() is None


@pytest.mark.parametrize("phase", ["before_sign", "after_sign"])
def test_service_rejection_releases_license_reservation_and_preserves_request(tmp_path, phase):
    app = _app(str(tmp_path))
    request = _pending_first(app, "lifetime.example.test")
    issuer = app.state.lab_chain.issuer
    expiry = issuer.certificate.not_valid_after_utc
    start = expiry - timedelta(days=365 if phase == "after_sign" else 1)
    app.state.service.clock = mock.Mock(side_effect=[start, expiry])
    with (
        mock.patch.object(app.state.service.hsm.backend, "sign_certificate",
                          wraps=app.state.service.hsm.backend.sign_certificate) as sign,
        mock.patch.object(app.state.licensing, "release_issuance",
                          wraps=app.state.licensing.release_issuance) as release,
        mock.patch.object(app.state.service, "_notify_cert_change") as notify,
    ):
        with pytest.raises(IssuerValidityError) as error:
            app.state.service.issue_certificate(request.id, issuer)
    assert error.value.code == (
        "issuer_expired" if phase == "after_sign" else "issuer_validity_exceeded"
    )
    assert sign.call_count == (1 if phase == "after_sign" else 0)
    release.assert_called_once()
    notify.assert_not_called()
    assert app.state.licensing.reserved_count(start) == 0
    assert app.state.repository.get_request(request.id).status is RequestStatus.PENDING
    assert app.state.repository.get_issued_certificate_by_request_id(request.id) is None


def test_holder_api_preserves_approval_and_exposes_issuer_error(tmp_path):
    app = _app(str(tmp_path))
    request = _pending_first(app, "holder.example.test")
    secret = add_login_ready_user(app, user_id="operator", email="op@example.test",
                                  role=Role.SUPERUSER)
    app.state.service.approve_request(request.id, "operator")
    token, csrf = create_active_session(app, email="op@example.test", totp_secret=secret)
    app.state.service.clock = lambda: app.state.lab_chain.issuer.certificate.not_valid_after_utc
    result = route_endpoint(app, "/internal/certificate-requests/{request_id}/holder", "POST")(
        request.id, RequestHolderAssign(person_id=request.holder_person_id),
        request_with_session(token, csrf, method="POST"),
    )
    assert result["auto_issue_error"]["code"] == "issuer_expired"
    assert "CA administrator" in result["auto_issue_error"]["message"]
    assert not result["auto_issued"]
    assert len(app.state.repository.list_approvals(request.id)) == 1
    assert app.state.licensing.reserved_count() == 0


@pytest.mark.parametrize("code", [
    "issuer_not_yet_valid", "issuer_expired", "issuer_validity_exceeded",
])
def test_issuer_errors_are_not_misclassified_as_csr_or_renewal_errors(code):
    assert _auto_issue_error_from_exception(IssuerValidityError(code, "Review renewal validity")) == {
        "code": code, "message": "Review renewal validity",
    }


_NOW = datetime(2026, 9, 16, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize("days,seconds,status,text", [
    (396, 0, "pass", "configured through"),
    (395, 1, "pass", "configured through"),
    (395, 0, "warn", "cutoff within 30 days: Host"),
    (365, 0, "warn", "cutoff within 30 days: Host"),
    (365, -1, "warn", "no longer fit: Host"),
    (0, 0, "fail", "expired"),
])
def test_readiness_warns_before_template_lifetime_cutoff(days, seconds, status, text):
    certificate, _ = _issuer(starts_at=_NOW - timedelta(days=1),
                             expires_at=_NOW + timedelta(days=days, seconds=seconds))
    template = CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)
    service = SimpleNamespace(
        issuer_provider=lambda: SimpleNamespace(certificate=certificate, allowed_profiles=None),
        repository=SimpleNamespace(list_templates=lambda: [template]), lab_mode=False,
    )
    item = OperationsService._issuer_item(service, _NOW)
    assert item["status"] == status
    assert text in item["summary"]


@pytest.mark.parametrize("lab", [False, True])
def test_readiness_warning_precedes_lab_info_and_ignores_disallowed_profiles(lab):
    certificate, _ = _issuer(starts_at=_NOW, expires_at=_NOW + timedelta(days=90))
    issuer = SimpleNamespace(certificate=certificate, allowed_profiles=(CertificateProfile.SMIME,))
    templates = [CertificateTemplate(id="host", name="Host", profile=CertificateProfile.HOST_TLS)]
    service = SimpleNamespace(issuer_provider=lambda: issuer,
                              repository=SimpleNamespace(list_templates=lambda: templates),
                              lab_mode=lab)
    item = OperationsService._issuer_item(service, _NOW)
    assert item["severity"] == ("info" if lab else "none")
    item = OperationsService._issuer_item(service, _NOW + timedelta(days=60))
    assert item["severity"] == "warning"
    assert "Host" not in item["summary"]
    item = OperationsService._issuer_item(service, _NOW - timedelta(seconds=1))
    assert item["status"] == "fail"
    assert "not valid until" in item["summary"]
