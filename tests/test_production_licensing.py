from __future__ import annotations

import base64
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from myownca.domain import (
    CertificateProfile,
    CertificateStatus,
    CertificateTemplate,
    IssuedCertificate,
    RequestKind,
    RevocationReason,
    Role,
    User,
)
from myownca.licensing import (
    DuplicateCertificateIdentityError,
    IssuanceAuthorization,
    LicenseError,
    LicenseInstallationMismatchError,
    LicenseLimitError,
    LicenseRepository,
    LicenseService,
    verify_token,
)
from myownca.online.app import create_app
from tests.helpers import TempPKI, make_csr, seed_person

NOW = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class Signer:
    _private_key = None

    def __init__(self, key_id: str = "prod-test") -> None:
        self.key_id = key_id
        if self.__class__._private_key is None:
            self.__class__._private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096
            )
        self.private_key = self.__class__._private_key
        self.public_b64 = base64.b64encode(
            self.private_key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()

    def payload(
        self,
        installation_id: str,
        *,
        maximum: int = 20,
        valid_from: datetime = NOW,
        days: int = 365,
    ) -> dict[str, object]:
        return {
            "schema": 2,
            "product": "myownca-self-hosted",
            "license_id": "BB-PROD-TEST",
            "licensed_to": "Acme Corp",
            "installation_id": installation_id,
            "issued_at": valid_from.isoformat(),
            "valid_from": valid_from.isoformat(),
            "expires_at": (valid_from + timedelta(days=days)).isoformat(),
            "max_certificate_lineages": maximum,
            "key_id": self.key_id,
        }

    def sign(self, payload: dict[str, object]) -> str:
        segment = _b64url(json.dumps(payload, separators=(",", ":")).encode())
        signature = self.private_key.sign(
            segment.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
        return f"{segment}.{_b64url(signature)}"


def _app(tempdir: str, public_keys: dict[str, str] | None = None):
    with (
        mock.patch("myownca.config.licensing_public_keys", return_value=public_keys or {}),
        mock.patch("myownca.ca_main.crypto._utc_now", return_value=NOW),
    ):
        app = create_app(Path(tempdir) / "production-license.sqlite3", lab_mode=True)
    app.state.repository.add_user(User(id="owner", email="owner@example.test", role=Role.USER))
    app.state.repository.add_template(
        CertificateTemplate(
            id="host",
            name="Host",
            profile=CertificateProfile.HOST_TLS,
            first_issuance_approvals=0,
            renewal_approvals=0,
        )
    )
    return app


def _pending_first(app, name: str):
    request = app.state.service.submit_request(
        "host", make_csr(name, dns_names=(name,)), requested_by_user_id="owner"
    )
    app.state.service.assign_request_holder(request.id, person_id=seed_person(app))
    return app.state.repository.get_request(request.id)


def _seed_active(app, count: int) -> None:
    for index in range(count):
        request = app.state.service.submit_request(
            "host", make_csr(f"seed-{index}.example.test", dns_names=(f"seed-{index}.example.test",))
        )
        app.state.repository.add_issued_certificate(
            IssuedCertificate(
                serial_number=f"SEED-{index}",
                request_id=request.id,
                template_id="host",
                certificate_pem="legacy-test-row",
                subject=f"CN=seed-{index}.example.test",
                issued_at=NOW,
                expires_at=NOW + timedelta(days=365),
                status=CertificateStatus.ACTIVE,
            )
        )


def test_concurrent_last_slot_is_reserved_once() -> None:
    with TemporaryDirectory() as tempdir:
        app = _app(tempdir)
        _seed_active(app, 9)
        requests = [
            _pending_first(app, "one.example.test"),
            _pending_first(app, "two.example.test"),
        ]

        def issue(request):
            return app.state.service.issue_certificate(request.id, app.state.lab_chain.issuer)

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda request: _capture(issue, request), requests))

        issued = [outcome for outcome in outcomes if isinstance(outcome, IssuedCertificate)]
        denied = [outcome for outcome in outcomes if isinstance(outcome, LicenseLimitError)]
        assert len(issued) == 1
        assert len(denied) == 1
        assert app.state.licensing.active_count(NOW) == 10
        assert app.state.licensing.reserved_count(NOW) == 0


def test_renewal_rotates_key_without_consuming_lineage() -> None:
    with TemporaryDirectory() as tempdir:
        app = _app(tempdir)
        person_id = seed_person(app)
        csr = make_csr("same.example.test", dns_names=("same.example.test",))
        first = app.state.service.submit_request("host", csr, requested_by_user_id="owner")
        app.state.service.assign_request_holder(first.id, person_id=person_id)
        certificate = app.state.service.issue_certificate(first.id, app.state.lab_chain.issuer, NOW)

        rotated_csr = make_csr("same.example.test", dns_names=("same.example.test",))
        renewal = app.state.service.submit_request(
            "host",
            rotated_csr,
            kind=RequestKind.RENEWAL,
            requested_by_user_id="owner",
            renewal_of_serial_number=certificate.serial_number,
        )
        app.state.service.assign_request_holder(renewal.id, person_id=person_id)
        renewed = app.state.service.issue_certificate(renewal.id, app.state.lab_chain.issuer, NOW)

        assert renewed.lineage_id == certificate.lineage_id
        assert app.state.licensing.active_count(NOW) == 1
        assert (
            app.state.repository.get_issued_certificate(certificate.serial_number).status
            is CertificateStatus.REVOKED
        )
        replacement_revocation = next(
            item
            for item in app.state.repository.list_revocations()
            if item.serial_number == certificate.serial_number
        )
        assert replacement_revocation.reason is RevocationReason.SUPERSEDED
        assert replacement_revocation.revoked_at == NOW
        with pytest.raises(ValueError, match="subject alternative names"):
            app.state.service.submit_request(
                "host",
                make_csr("changed.example.test", dns_names=("changed.example.test",)),
                kind=RequestKind.RENEWAL,
                requested_by_user_id="owner",
                renewal_of_serial_number=renewed.serial_number,
            )


def test_first_issuance_requires_renewal_for_matching_active_identity() -> None:
    with TemporaryDirectory() as tempdir:
        app = _app(tempdir)
        person_id = seed_person(app)
        csr = make_csr("stable.example.test", dns_names=("stable.example.test",))
        first = app.state.service.submit_request(
            "host", csr, requested_by_user_id="owner"
        )
        app.state.service.assign_request_holder(first.id, person_id=person_id)
        anchor = app.state.service.issue_certificate(
            first.id, app.state.lab_chain.issuer, NOW
        )
        _seed_active(app, 9)
        assert app.state.licensing.active_count(NOW) == 10

        repeated = app.state.service.submit_request(
            "host", csr, requested_by_user_id="owner"
        )
        app.state.service.assign_request_holder(repeated.id, person_id=person_id)
        with pytest.raises(DuplicateCertificateIdentityError, match="Use its Renew action"):
            app.state.service.issue_certificate(repeated.id, app.state.lab_chain.issuer, NOW)

        assert app.state.repository.get_request(repeated.id).status.value == "pending"
        assert app.state.repository.get_issued_certificate(anchor.serial_number).lineage_id == (
            anchor.lineage_id
        )
        assert app.state.licensing.active_count(NOW) == 10
        assert app.state.licensing.reserved_count(NOW) == 0


def test_concurrent_matching_identity_authorizations_block_the_duplicate() -> None:
    with TemporaryDirectory() as tempdir:
        app = _app(tempdir)
        person_id = seed_person(app)
        csr = make_csr("race.example.test", dns_names=("race.example.test",))
        requests = []
        for _index in range(2):
            item = app.state.service.submit_request(
                "host", csr, requested_by_user_id="owner"
            )
            app.state.service.assign_request_holder(item.id, person_id=person_id)
            requests.append(app.state.repository.get_request(item.id))

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(
                pool.map(
                    lambda request: _capture(app.state.licensing.authorize_issuance, request),
                    requests,
                )
            )

        authorizations = [
            item for item in outcomes if isinstance(item, IssuanceAuthorization)
        ]
        duplicates = [
            item for item in outcomes if isinstance(item, DuplicateCertificateIdentityError)
        ]
        assert len(authorizations) == 1
        assert len(duplicates) == 1
        assert app.state.licensing.reserved_count(NOW) == 1
        reserved = authorizations[0]
        assert reserved.reservation_request_id is not None
        app.state.licensing.release_issuance(reserved)
        assert app.state.licensing.reserved_count(NOW) == 0


@pytest.mark.parametrize("retirement", ("revoked", "archived"))
def test_first_issuance_can_replace_retired_matching_certificate(retirement: str) -> None:
    with TemporaryDirectory() as tempdir:
        app = _app(tempdir)
        person_id = seed_person(app)
        csr = make_csr("retired.example.test", dns_names=("retired.example.test",))
        first = app.state.service.submit_request("host", csr, requested_by_user_id="owner")
        app.state.service.assign_request_holder(first.id, person_id=person_id)
        anchor = app.state.service.issue_certificate(first.id, app.state.lab_chain.issuer, NOW)

        if retirement == "revoked":
            app.state.service.revoke_certificate_by_id(anchor.certificate_id, now=NOW)
        else:
            app.state.repository.archive_certificate_by_id(anchor.certificate_id, NOW)

        replacement = app.state.service.submit_request(
            "host", csr, requested_by_user_id="owner"
        )
        app.state.service.assign_request_holder(replacement.id, person_id=person_id)
        issued = app.state.service.issue_certificate(
            replacement.id, app.state.lab_chain.issuer, NOW
        )

        assert issued.lineage_id != anchor.lineage_id


def test_over_free_renewal_survives_expiry_removal_and_invalid_license() -> None:
    with TemporaryDirectory() as tempdir:
        signer = Signer()
        app = _app(tempdir, {signer.key_id: signer.public_b64})
        app.state.licensing.install(
            signer.sign(
                signer.payload(
                    app.state.licensing.installation_id, maximum=20, days=1
                )
            ),
            uploaded_by="admin",
            now=NOW,
        )
        anchor_request = _pending_first(app, "grace.example.test")
        anchor = app.state.service.issue_certificate(
            anchor_request.id, app.state.lab_chain.issuer, NOW
        )
        _seed_active(app, 10)
        renewal = app.state.service.submit_request(
            "host",
            anchor_request.csr_pem,
            kind=RequestKind.RENEWAL,
            requested_by_user_id="owner",
            renewal_of_serial_number=anchor.serial_number,
        )
        app.state.service.assign_request_holder(
            renewal.id, person_id=anchor.holder_person_id
        )
        renewal = app.state.repository.get_request(renewal.id)

        after_expiry = NOW + timedelta(days=31)
        assert app.state.licensing.active_count(after_expiry) == 11
        assert app.state.licensing.effective_limit(after_expiry) == 10
        authorization = app.state.licensing.authorize_issuance(renewal, after_expiry)
        assert authorization.lineage_id == anchor.lineage_id

        app.state.licensing.remove()
        assert app.state.licensing.authorize_issuance(
            renewal, NOW + timedelta(hours=12)
        ).lineage_id == anchor.lineage_id

        app.state.licensing.repository.replace(
            id="invalid",
            token="not.a.valid.token",
            license_id="invalid",
            licensed_to="Invalid",
            valid_from=NOW,
            expires_at=NOW + timedelta(days=365),
            max_active_certs=999,
            uploaded_by="admin",
            uploaded_at=NOW,
        )
        assert app.state.licensing.authorize_issuance(
            renewal, NOW + timedelta(hours=12)
        ).lineage_id == anchor.lineage_id

        growth = _pending_first(app, "blocked.example.test")
        with pytest.raises(LicenseLimitError):
            app.state.licensing.authorize_issuance(
                growth, NOW + timedelta(hours=12)
            )


def test_installation_binding_and_restore_identity() -> None:
    signer = Signer()
    with TemporaryDirectory() as first_dir, TemporaryDirectory() as second_dir:
        public_keys = {signer.key_id: signer.public_b64}
        first = _app(first_dir, public_keys)
        second = _app(second_dir, public_keys)
        token = signer.sign(signer.payload(first.state.licensing.installation_id))
        first.state.licensing.install(token, uploaded_by="admin", now=NOW)
        with pytest.raises(LicenseInstallationMismatchError):
            second.state.licensing.install(token, uploaded_by="admin", now=NOW)
        with mock.patch("myownca.config.licensing_public_keys", return_value=public_keys):
            reopened = create_app(
                Path(first_dir) / "production-license.sqlite3", lab_mode=True
            )
        assert reopened.state.licensing.installation_id == first.state.licensing.installation_id


def test_only_configured_public_keys_are_trusted() -> None:
    pki = TempPKI()
    try:
        signer = Signer(key_id="configured")
        configured = LicenseService(
            LicenseRepository(pki.database),
            pki.repository,
            public_keys={signer.key_id: signer.public_b64},
        )
        unconfigured = LicenseService(LicenseRepository(pki.database), pki.repository)
        token = signer.sign(signer.payload(configured.installation_id))
        installed = configured.install(token, uploaded_by="admin", now=NOW)
        assert installed.key_id == "configured"
        assert configured.summary(NOW)["trusted_key_ids"] == ["configured"]
        assert unconfigured.current() is None
        assert "unknown key" in (unconfigured.verification_error() or "").lower()
    finally:
        pki.close()


def test_strict_signed_payload_failures_are_license_errors() -> None:
    signer = Signer()
    public_keys = {signer.key_id: signer.public_b64}
    payload = signer.payload("11111111-1111-4111-8111-111111111111")
    for change in (
        {"max_certificate_lineages": True},
        {"schema": 99},
        {"unexpected": "field"},
    ):
        candidate = {**payload, **change}
        with pytest.raises(LicenseError):
            verify_token(signer.sign(candidate), public_keys=public_keys)
    missing = dict(payload)
    del missing["expires_at"]
    with pytest.raises(LicenseError):
        verify_token(signer.sign(missing), public_keys=public_keys)


def test_existing_renewal_chain_backfills_to_one_lineage() -> None:
    with mock.patch("myownca.ca_main.crypto._utc_now", return_value=NOW):
        pki = TempPKI()
    try:
        pki.add_default_users()
        pki.add_template(
            "host",
            CertificateProfile.HOST_TLS,
            first_issuance_approvals=0,
            renewal_approvals=0,
        )
        person_id = pki.default_person_id()
        csr = make_csr("legacy.example.test", dns_names=("legacy.example.test",))
        first = pki.service.submit_request("host", csr, requested_by_user_id="user-1")
        pki.service.assign_request_holder(first.id, person_id=person_id)
        anchor = pki.service.issue_certificate(first.id, pki.lab_chain.issuer, NOW)
        renewal = pki.service.submit_request(
            "host",
            csr,
            kind=RequestKind.RENEWAL,
            requested_by_user_id="user-1",
            renewal_of_serial_number=anchor.serial_number,
        )
        pki.service.assign_request_holder(renewal.id, person_id=person_id)
        pki.service.issue_certificate(renewal.id, pki.lab_chain.issuer, NOW)

        licensing = LicenseService(LicenseRepository(pki.database), pki.repository)
        assert licensing.active_count(NOW) == 1
        assert pki.repository.get_request(first.id).lineage_id is not None
        assert pki.repository.get_request(first.id).lineage_id == pki.repository.get_request(
            renewal.id
        ).lineage_id
    finally:
        pki.close()


def test_restart_preserves_lineage_created_during_runtime_issuance() -> None:
    with TemporaryDirectory() as tempdir:
        app = _app(tempdir)
        request = _pending_first(app, "restart.example.test")
        certificate = app.state.service.issue_certificate(
            request.id, app.state.lab_chain.issuer, NOW
        )
        original_lineage_id = certificate.lineage_id

        restarted = LicenseService(
            LicenseRepository(app.state.licensing.repository.database),
            app.state.repository,
        )

        assert restarted.repository.lineage_state() == ("ready", None)
        assert (
            app.state.repository.get_issued_certificate(certificate.serial_number).lineage_id
            == original_lineage_id
        )
        assert restarted.active_count(NOW) == 1


def test_restart_accepts_matching_legacy_first_issuance_in_existing_lineage() -> None:
    with TemporaryDirectory() as tempdir:
        app = _app(tempdir)
        person_id = seed_person(app)
        csr = make_csr("legacy-duplicate.example.test", dns_names=("legacy-duplicate.example.test",))
        first = app.state.service.submit_request("host", csr, requested_by_user_id="owner")
        app.state.service.assign_request_holder(first.id, person_id=person_id)
        anchor = app.state.service.issue_certificate(first.id, app.state.lab_chain.issuer, NOW)

        duplicate = app.state.service.submit_request("host", csr, requested_by_user_id="owner")
        app.state.service.assign_request_holder(duplicate.id, person_id=person_id)
        with mock.patch.object(
            app.state.licensing,
            "authorize_issuance",
            return_value=IssuanceAuthorization(lineage_id=anchor.lineage_id),
        ):
            legacy = app.state.service.issue_certificate(
                duplicate.id, app.state.lab_chain.issuer, NOW
            )

        restarted = LicenseService(
            LicenseRepository(app.state.licensing.repository.database), app.state.repository
        )

        assert legacy.lineage_id == anchor.lineage_id
        assert restarted.repository.lineage_state() == ("ready", None)


def test_restart_rejects_legacy_first_issuance_with_different_identity() -> None:
    with TemporaryDirectory() as tempdir:
        app = _app(tempdir)
        person_id = seed_person(app)
        first = app.state.service.submit_request(
            "host",
            make_csr("legacy-root.example.test", dns_names=("legacy-root.example.test",)),
            requested_by_user_id="owner",
        )
        app.state.service.assign_request_holder(first.id, person_id=person_id)
        anchor = app.state.service.issue_certificate(first.id, app.state.lab_chain.issuer, NOW)

        duplicate = app.state.service.submit_request(
            "host",
            make_csr("legacy-conflict.example.test", dns_names=("legacy-conflict.example.test",)),
            requested_by_user_id="owner",
        )
        app.state.service.assign_request_holder(duplicate.id, person_id=person_id)
        with mock.patch.object(
            app.state.licensing,
            "authorize_issuance",
            return_value=IssuanceAuthorization(lineage_id=anchor.lineage_id),
        ):
            app.state.service.issue_certificate(duplicate.id, app.state.lab_chain.issuer, NOW)

        restarted = LicenseService(
            LicenseRepository(app.state.licensing.repository.database), app.state.repository
        )
        state, detail = restarted.repository.lineage_state()

        assert state == "error"
        assert detail is not None
        assert "does not match lineage" in detail


def _capture(function, argument):
    try:
        return function(argument)
    except Exception as exc:  # noqa: BLE001 - assertions inspect the concrete outcome
        return exc
