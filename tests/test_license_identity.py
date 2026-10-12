"""The recipient displayed in every portal comes only from verified licence state."""

from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest
from fastapi import HTTPException

from myownca.domain import Role, SessionStage
from myownca.licensing import LicenseService
from myownca.online.app import create_app
from tests.helpers import add_login_ready_user, create_active_session, request_with_session
from tests.helpers import route_endpoint
from tests.test_claim_api import _app_with_link, _open_session, _state
from tests.test_claim_renewal import _app_with_renewal_link, _mtls_request
from tests.test_enrollment import _app as enrollment_app, _enrollment_link
from tests.test_production_licensing import Signer


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr("myownca.config.licensing_public_keys", lambda: {})
    return create_app(tmp_path / "identity.sqlite3", lab_mode=True)


def install_named_license(app, company="Acme Corp"):
    signer = Signer()
    service = app.state.licensing
    service.public_keys = {signer.key_id: signer.public_b64}
    service.key_configuration_error = None
    now = datetime.now(timezone.utc)
    payload = signer.payload(service.installation_id, valid_from=now)
    payload["licensed_to"] = company
    service.install(signer.sign(payload), uploaded_by="test", now=now)
    return now


@pytest.mark.parametrize("days,status", [(0, "valid"), (365, "expired"), (-1, "not_yet_valid")])
def test_verified_identity_window_and_metadata(app, days, status):
    now = install_named_license(app, "Żółć & 株式会社")
    service = app.state.licensing
    with service.repository.database.connect() as connection:
        connection.execute("UPDATE licenses SET licensed_to = ?", ("Unsigned replacement",))
    with mock.patch.object(service, "active_count", side_effect=AssertionError("quota read")):
        assert service.identity(now + timedelta(days=days)) == {
            "licensed_to": "Żółć & 株式会社",
            "status": status,
            "verification_warning": False,
        }


def test_identity_replacement_and_removal(app):
    assert app.state.licensing.identity() == {
        "licensed_to": None, "status": "none", "verification_warning": False,
    }
    install_named_license(app)
    install_named_license(app, "Second company")
    assert app.state.licensing.identity()["licensed_to"] == "Second company"
    app.state.licensing.remove()
    assert app.state.licensing.identity() == {
        "licensed_to": None, "status": "none", "verification_warning": False,
    }


@pytest.mark.parametrize("failure", ["storage", "token"])
def test_identity_uses_only_verified_cache_and_warns(app, failure):
    install_named_license(app)
    service = app.state.licensing
    if failure == "storage":
        context = mock.patch.object(service.repository, "get", side_effect=OSError("private detail"))
    else:
        with service.repository.database.connect() as connection:
            connection.execute("UPDATE licenses SET token = ?, licensed_to = ?", ("bad", "Forged"))
        context = mock.patch.object(service.repository, "get", wraps=service.repository.get)
    with context:
        assert service.identity() == {
            "licensed_to": "Acme Corp", "status": "valid", "verification_warning": True,
        }
        # A cold service has no verified identity to fall back to.
        cold = LicenseService(service.repository, app.state.repository, public_keys=service.public_keys)
        assert cold.identity() == {
            "licensed_to": None, "status": "invalid", "verification_warning": True,
        }


@pytest.mark.parametrize("role", list(Role))
def test_identity_available_to_all_roles_without_management_access(app, role):
    install_named_license(app)
    email = f"{role.value}@example.test"
    factor = add_login_ready_user(app, user_id=role.value, email=email, role=role)
    token, csrf = create_active_session(app, email=email, totp_secret=factor)
    identity = route_endpoint(app, "/internal/license/identity", "GET")
    assert identity(request_with_session(token)) == app.state.licensing.identity()
    if role is Role.USER:
        with pytest.raises(HTTPException) as denied:
            route_endpoint(app, "/internal/admin/license", "GET")(request_with_session(token))
        assert denied.value.status_code == 403
    if role is not Role.ADMIN:
        for method in ("PUT", "DELETE"):
            with pytest.raises(HTTPException) as denied:
                endpoint = route_endpoint(app, "/internal/admin/license", method)
                request = request_with_session(token, csrf, method=method)
                if method == "PUT":
                    from myownca.online.app import LicenseUpload
                    endpoint(LicenseUpload(token="invalid"), request)
                else:
                    endpoint(request)
            assert denied.value.status_code == 403


@pytest.mark.parametrize("state", ["missing", "incomplete", "expired", "revoked"])
def test_identity_rejects_unverified_sessions(app, state):
    install_named_license(app)
    token = None
    if state != "missing":
        add_login_ready_user(app, user_id="user", email="user@example.test", role=Role.USER)
        token, _csrf = create_active_session(app, email="user@example.test")
        session, _user = app.state.auth_service.require_session(token)
        changes = {
            "incomplete": {"stage": SessionStage.TOTP_REQUIRED},
            "expired": {"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)},
            "revoked": {"revoked_at": datetime.now(timezone.utc)},
        }
        app.state.auth_repository.update_session(session.id, **changes[state])
    with pytest.raises(HTTPException) as denied:
        route_endpoint(app, "/internal/license/identity", "GET")(request_with_session(token))
    assert denied.value.status_code == 401


@pytest.mark.parametrize("purpose", ["delivery", "renewal", "enrollment"])
def test_holder_identity_is_exposed_only_after_otp(tmp_path, purpose):
    if purpose == "enrollment":
        app, _session = enrollment_app(str(tmp_path))
        link, token = _enrollment_link(app)
    else:
        factory = _app_with_link if purpose == "delivery" else _app_with_renewal_link
        app, _certificate, link, token, _session = factory(str(tmp_path))
    install_named_license(app)
    assert "license_identity" not in _state(app, token)
    session = _open_session(app, link, token)
    assert _state(app, token, session)["license_identity"] == app.state.licensing.identity()
    app.state.secure_links.revoke(link.id)
    assert "license_identity" not in _state(app, token, session)


def test_holder_identity_requires_correct_certificate_possession(tmp_path):
    app, certificate, _link, token, _session = _app_with_renewal_link(str(tmp_path))
    install_named_license(app)
    state = route_endpoint(app, "/internal/claim/{token}/state", "GET")
    verified = state(token, _mtls_request(certificate.certificate_pem))
    assert verified["auth"] == "mtls"
    assert verified["license_identity"] == app.state.licensing.identity()
    assert "license_identity" not in state(
        token, _mtls_request(certificate.certificate_pem, secret="wrong")
    )
