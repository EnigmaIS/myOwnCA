from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from myownca.ca_auth.totp import code_for_step, current_step
from myownca.ca_hsm import SoftwareHSM
from myownca.ca_main.crypto import LabCAChain, create_lab_ca_chain
from myownca.ca_main.service import CAMainService
from datetime import datetime, timezone

from myownca.domain import (
    CertificateProfile,
    CertificateTemplate,
    Device,
    PasswordCredential,
    Person,
    Role,
    TOTPFactor,
    User,
)
from myownca.storage.database import Database
from myownca.storage.repositories import PKIRepository
from fastapi.routing import APIRoute
from starlette.requests import Request


def make_csr(
    common_name: str | None,
    *,
    dns_names: tuple[str, ...] = (),
    emails: tuple[str, ...] = (),
) -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject_attributes = (
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)] if common_name is not None else []
    )
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject_attributes))
    general_names: list[x509.GeneralName] = [x509.DNSName(name) for name in dns_names]
    general_names.extend(x509.RFC822Name(email) for email in emails)
    if general_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(general_names), critical=False)
    csr = builder.sign(private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


class TempPKI:
    def __init__(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.database = Database(Path(self.tempdir.name) / "myownca.sqlite3")
        self.database.migrate()
        self.repository = PKIRepository(self.database)
        self.hsm = SoftwareHSM()
        self.service = CAMainService(self.repository, self.hsm)
        self.lab_chain: LabCAChain = create_lab_ca_chain(self.hsm)

    def service_keystore(self):
        from myownca.service_certs.keystore import ServiceKeyStore
        return ServiceKeyStore(Path(self.tempdir.name) / "service-keys", passphrase="test-pass")

    def close(self) -> None:
        self.tempdir.cleanup()

    def add_default_users(self) -> None:
        self.repository.add_user(User(id="su-1", email="su1@example.test", role=Role.SUPERUSER))
        self.repository.add_user(User(id="su-2", email="su2@example.test", role=Role.SUPERUSER))
        self.repository.add_user(User(id="user-1", email="user@example.test", role=Role.USER))

    def add_template(
        self,
        template_id: str,
        profile: CertificateProfile,
        *,
        first_issuance_approvals: int = 2,
        renewal_approvals: int = 1,
    ) -> CertificateTemplate:
        template = CertificateTemplate(
            id=template_id,
            name=template_id,
            profile=profile,
            first_issuance_approvals=first_issuance_approvals,
            renewal_approvals=renewal_approvals,
        )
        self.repository.add_template(template)
        return template

    def default_person_id(self) -> str:
        person_id = "person-default"
        try:
            self.repository.get_person(person_id)
        except Exception:  # noqa: BLE001 - create on first use
            self.repository.add_person(
                Person(
                    id=person_id,
                    name="Default",
                    surname="Holder",
                    email="holder@example.test",
                    created_at=datetime.now(timezone.utc),
                )
            )
        return person_id

    def assign_holder(
        self,
        request_id: str,
        *,
        person_id: str | None = None,
        device_id: str | None = None,
    ) -> None:
        if person_id is None and device_id is None:
            person_id = self.default_person_id()
        self.service.assign_request_holder(
            request_id, person_id=person_id, device_id=device_id
        )


def add_login_ready_user(
    app,
    *,
    user_id: str,
    email: str,
    role: Role,
    password: str = "very-long-test-password",
    totp_secret: str = "JBSWY3DPEHPK3PXP",
) -> str | None:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    app.state.auth_repository.add_user(User(id=user_id, email=email, role=role))
    app.state.auth_repository.add_or_update_password_credential(
        PasswordCredential(
            user_id=user_id,
            password_hash=app.state.auth_service.password_hasher.hash(password),
            must_change_password=False,
            updated_at=now,
        )
    )
    if app.state.auth_service.totp_required(role):
        app.state.auth_repository.add_or_update_totp_factor(
            TOTPFactor(
                user_id=user_id,
                secret_ciphertext=app.state.auth_service._encrypt(totp_secret),
                confirmed_at=now,
                last_verified_step=None,
            )
        )
        return totp_secret
    return None


def seed_person(
    app,
    *,
    person_id: str = "person-default",
    email: str = "holder@example.test",
) -> str:
    try:
        app.state.repository.get_person(person_id)
    except Exception:  # noqa: BLE001 - create on first use
        app.state.repository.add_person(
            Person(
                id=person_id,
                name="Default",
                surname="Holder",
                email=email,
                created_at=datetime.now(timezone.utc),
            )
        )
    return person_id


def seed_device(
    app,
    *,
    device_id: str = "device-default",
    admin_id: str | None = None,
) -> str:
    if admin_id is None:
        admin_id = seed_person(app)
    try:
        app.state.repository.get_device(device_id)
    except Exception:  # noqa: BLE001 - create on first use
        app.state.repository.add_device(
            Device(
                id=device_id,
                device_name="default-device",
                admin_id=admin_id,
                created_at=datetime.now(timezone.utc),
                fqdn="host.example.test",
            )
        )
    return device_id


def assign_request_holder(
    app,
    request_id: str,
    *,
    person_id: str | None = None,
    device_id: str | None = None,
) -> None:
    if person_id is None and device_id is None:
        person_id = seed_person(app)
    app.state.service.assign_request_holder(
        request_id, person_id=person_id, device_id=device_id
    )


def create_active_session(
    app,
    *,
    email: str,
    password: str = "very-long-test-password",
    totp_secret: str | None = None,
) -> tuple[str, str]:
    created = app.state.auth_service.login(email, password)
    if created.session.stage.value == "totp_required":
        assert totp_secret is not None
        created = app.state.auth_service.verify_totp_challenge(
            created.token,
            code_for_step(totp_secret, current_step()),
        )
    assert created.session.stage.value == "active"
    return created.token, created.session.csrf_token


def request_with_session(
    token: str | None = None,
    csrf_token: str | None = None,
    *,
    method: str = "GET",
) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if token is not None:
        headers.append((b"cookie", f"myownca_session={token}".encode()))
    if csrf_token is not None:
        headers.append((b"x-csrf-token", csrf_token.encode()))
    return Request(
        {
            "type": "http",
            "method": method,
            "path": "/",
            "headers": headers,
        }
    )


def route_endpoint(app, path: str, method: str):
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path == path and method.upper() in route.methods:
            return route.endpoint
    raise AssertionError(f"Route not found: {method.upper()} {path}")


def create_app_with_hsm(
    backend,
    backend_name: str,
    database_path: str | Path,
    **kwargs,
):
    """Create an app whose fixed startup backend is supplied by a test double."""
    from myownca.online.app import create_app

    with mock.patch(
        "myownca.online.app.create_hsm",
        return_value=(backend, backend_name),
    ):
        return create_app(database_path, **kwargs)
