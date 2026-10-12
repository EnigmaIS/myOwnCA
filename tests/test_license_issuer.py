"""Exercise vendor CLI output against the customer verifier and identity API."""

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from myownca.domain import Role
from myownca.licensing import LicenseError, verify_token
from myownca.online.app import LicenseUpload, create_app
from tests.helpers import add_login_ready_user, create_active_session, request_with_session
from tests.helpers import route_endpoint
from tests.test_production_licensing import Signer


@pytest.fixture
def issuer(monkeypatch, tmp_path):
    # Private vendor tooling is deliberately absent from public checkouts.
    issuer_source = Path(__file__).resolve().parents[1] / "tools/license-issuer/src"
    if not (issuer_source / "license_issuer/cli.py").is_file():
        pytest.skip("private tools/license-issuer is not available in this checkout")
    monkeypatch.syspath_prepend(str(issuer_source))
    from license_issuer.cli import main

    signer = Signer()
    key_path = tmp_path / "disposable-signing-key.pem"
    key_path.write_bytes(signer.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"test-password"),
    ))
    monkeypatch.setenv("MYOWNCA_LICENSE_KEY_PASSWORD", "test-password")
    monkeypatch.setattr("myownca.config.licensing_public_keys",
                        lambda: {signer.key_id: signer.public_b64})
    app = create_app(tmp_path / "issuer.sqlite3", lab_mode=True)
    args = [
        "sign", "--key", str(key_path), "--key-id", signer.key_id,
        "--installation-id", app.state.licensing.installation_id, "--max-lineages", "100",
    ]
    return main, args, signer, app


@pytest.mark.parametrize("company", ["Acme Corp", "Żółć & 株式会社", "A" * 256, "<b>Acme & Co</b>"])
@pytest.mark.parametrize("file_output", [False, True])
def test_issuer_company_reaches_authenticated_identity(issuer, capsys, tmp_path, company, file_output):
    main, args, signer, app = issuer
    output = tmp_path / "customer.lic"
    assert main([*args, "--licensed-to", company, *(["--out", str(output)] if file_output else [])]) == 0
    stdout = capsys.readouterr().out
    token = output.read_text().strip() if file_output else stdout.strip()
    verified = verify_token(token, public_keys={signer.key_id: signer.public_b64})
    assert verified.licensed_to == company
    assert verified.schema == 2
    if not file_output:
        assert len(stdout.splitlines()) == 1

    factor = add_login_ready_user(app, user_id="admin", email="admin@example.test", role=Role.ADMIN)
    session, csrf = create_active_session(app, email="admin@example.test", totp_secret=factor)
    route_endpoint(app, "/internal/admin/license", "PUT")(
        LicenseUpload(token=token), request_with_session(session, csrf, method="PUT"),
    )
    assert route_endpoint(app, "/internal/license/identity", "GET")(request_with_session(session)) == {
        "licensed_to": company, "status": "valid", "verification_warning": False,
    }

    segment, signature = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    assert "status" not in payload and "verification_warning" not in payload
    payload["licensed_to"] = "Forged company"
    forged = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    with pytest.raises(LicenseError, match="signature does not verify"):
        verify_token(f"{forged}.{signature}", public_keys={signer.key_id: signer.public_b64})


@pytest.mark.parametrize("company", ["", "   ", " Acme", "Acme ", "A" * 257])
def test_issuer_rejects_invalid_names_before_writing(issuer, capsys, tmp_path, company):
    main, args, _signer, _app = issuer
    output = tmp_path / "invalid.lic"
    assert main([*args, "--licensed-to", company, "--out", str(output)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "1–256 characters" in captured.err
    assert not output.exists()


def test_issuer_requires_company_name(issuer, capsys):
    main, args, _signer, _app = issuer
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2
    assert "--licensed-to" in capsys.readouterr().err


def test_keygen_instructs_embedding_public_ring_in_release(issuer, capsys, tmp_path, monkeypatch):
    main, _args, signer, _app = issuer
    monkeypatch.setattr("license_issuer.cli.rsa.generate_private_key",
                        lambda **kwargs: signer.private_key)
    assert main(["keygen", "--key-id", "new-producer", "--out", str(tmp_path / "key.pem"),
                 "--public-out", str(tmp_path / "public.b64")]) == 0
    message = capsys.readouterr().err
    assert "seal-wheel --license-public-keys" in message
    assert "MYOWNCA_LICENSE_PUBLIC_KEYS" not in message
    ring = json.loads(message.splitlines()[-1])
    assert ring == {"schema": 1, "keys": {"new-producer": signer.public_b64}}
