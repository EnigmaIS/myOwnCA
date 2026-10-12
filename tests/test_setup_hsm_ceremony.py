from __future__ import annotations

import base64
import io
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request

from myownca.ca_hsm.ceremony import HSMCeremonyError, HSMCeremonyService
from myownca.ca_hsm.pkcs11 import PKCS11Error
from myownca.ca_hsm.scctl import DKEKStatus
from myownca.setup.app import (
    DKEKAnalyzePayload,
    DKEKRestorePayload,
    DKEKSharePayload,
    HSMAdoptPayload,
    HSMCreateSharesPayload,
    HSMCreateShareSpec,
    HSMImportSharesPayload,
    HSMInitializePayload,
    HSMProbePayload,
    create_setup_app,
)
from myownca.setup.token import SetupAuth
from tests.helpers import route_endpoint


def _request(session: str, csrf: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [
                (b"cookie", f"myownca_setup={session}".encode()),
                (b"x-csrf-token", csrf.encode()),
            ],
        }
    )


class FakePKCS11:
    def __init__(
        self,
        *,
        initialized: bool,
        keys: list[dict[str, object]] | None = None,
        serial: str = "TOKEN-SERIAL-1",
    ) -> None:
        self.initialized = initialized
        self.keys = list(keys or [])
        self.serial = serial
        self.verified_pins: list[str] = []

    def status(self) -> dict[str, object]:
        return {
            "token_present": True,
            "pin_tries_left": 3,
            "token": {
                "label": "Recovery Token",
                "serial": self.serial,
                "initialized": self.initialized,
                "user_pin_initialized": self.initialized,
            },
        }

    def verify_pin(self, pin: str) -> None:
        if pin != "123456":
            raise RuntimeError("PIN verification failed")
        self.verified_pins.append(pin)

    def list_keys(self) -> list[dict[str, object]]:
        return list(self.keys)


class FakeScHsmCtl:
    def __init__(self, *, total: int = 0, imported: int = 0, kcv: str = "A1B2C3"):
        self.total = total
        self.imported = imported
        self.kcv = kcv
        self.backend: FakePKCS11 | None = None
        self.initialize_calls: list[dict[str, object]] = []
        self.import_passwords: list[str] = []
        self.create_passwords: list[str] = []

    def create_dkek_share(self, path: Path, *, password: str) -> None:
        self.create_passwords.append(password)
        path.write_bytes(f"encrypted-share-{len(self.create_passwords)}".encode())

    def initialize(self, **values) -> None:
        self.initialize_calls.append(values)
        self.total = int(values["dkek_shares"])
        self.imported = 0
        if self.backend is not None:
            self.backend.initialized = True

    def import_dkek_share(
        self,
        _path: Path,
        *,
        password: str,
        user_pin: str,
    ) -> DKEKStatus:
        assert user_pin == "123456"
        self.import_passwords.append(password)
        self.imported += 1
        return self.dkek_status()

    def dkek_status(self) -> DKEKStatus:
        complete = self.total > 0 and self.imported == self.total
        return DKEKStatus(
            self.total,
            self.imported,
            complete,
            self.kcv if complete else None,
        )


def _app(tempdir: str, backend: FakePKCS11, scctl: FakeScHsmCtl):
    module = Path(tempdir) / "opensc-pkcs11.so"
    module.write_text("fake")
    auth = SetupAuth()
    app = create_setup_app(tempdir, auth)
    app.state.pkcs11_backend_factory = lambda _lib, _label, _pin_provider: backend
    scctl.backend = backend
    app.state.scctl = scctl
    session, csrf = auth.open_session()
    probe = HSMProbePayload(
        backend="pkcs11",
        pkcs11_lib=str(module),
        token_label="Recovery Token",
        reader="Nitrokey HSM 0",
        user_pin="123456" if backend.initialized else None,
    )
    return app, session, csrf, probe


def test_existing_hsm_probe_and_adoption_never_initialize_token() -> None:
    with TemporaryDirectory() as tempdir:
        backend = FakePKCS11(
            initialized=True,
            keys=[{"label": "issuer", "key_reference": 16}],
        )
        scctl = FakeScHsmCtl(total=2, imported=2)
        app, session, csrf, probe = _app(tempdir, backend, scctl)
        request = _request(session, csrf)

        result = route_endpoint(app, "/setup/hsm/test", "POST")(probe, request)
        adopted = route_endpoint(app, "/setup/hsm/adopt", "POST")(
            HSMAdoptPayload(user_pin="123456"),
            request,
        )

        assert result["initialized"] is True
        assert result["keys_present"] is True
        assert result["keys"] == [
            {"label": "issuer", "key_reference": 16, "key_ref": "issuer"}
        ]
        assert result["dkek"]["complete"] is True
        assert adopted["ready"] is True
        assert adopted["keys"] == [
            {
                "label": "issuer",
                "key_reference": 16,
                "key_ref": "issuer",
            }
        ]
        assert app.state.orchestrator.snapshot()["hsm"]["ready"] is True
        assert scctl.initialize_calls == []

        backend.serial = "REPLACEMENT-TOKEN"
        swapped = route_endpoint(app, "/setup/hsm/test", "POST")(probe, request)
        assert swapped["ready"] is False
        assert app.state.orchestrator.snapshot()["hsm"]["ready"] is False

        backend.serial = "TOKEN-SERIAL-1"
        route_endpoint(app, "/setup/hsm/adopt", "POST")(
            HSMAdoptPayload(user_pin="123456"),
            request,
        )
        app.state.orchestrator.set_hsm(
            "pkcs11",
            pkcs11_lib=probe.pkcs11_lib,
            token_label=probe.token_label,
            reader="different reader",
        )
        assert app.state.orchestrator.snapshot()["hsm"]["ready"] is False


@pytest.mark.parametrize("endpoint_path", ("/setup/hsm/test", "/setup/hsm/adopt"))
def test_hsm_setup_surfaces_actionable_opensc_connection_error(endpoint_path: str) -> None:
    with TemporaryDirectory() as tempdir:
        backend = FakePKCS11(initialized=True)
        scctl = FakeScHsmCtl(total=2, imported=2)
        app, session, csrf, probe = _app(tempdir, backend, scctl)
        request = _request(session, csrf)
        endpoint = route_endpoint(app, endpoint_path, "POST")

        with (
            mock.patch.object(backend, "status", side_effect=PKCS11Error("GeneralError")),
            pytest.raises(HTTPException) as caught,
        ):
            if endpoint_path == "/setup/hsm/test":
                endpoint(probe, request)
            else:
                app.state.orchestrator.set_hsm(
                    "pkcs11",
                    pkcs11_lib=probe.pkcs11_lib,
                    token_label=probe.token_label,
                    reader=probe.reader,
                )
                endpoint(HSMAdoptPayload(user_pin="123456"), request)

        assert caught.value.status_code == 400
        assert caught.value.detail == (
            "Cannot communicate with the selected HSM through OpenSC/PCSC (GeneralError). "
            "Check that the reader is connected, pcscd is running, and the myOwnCA "
            "service account can run `sc-hsm-tool -f` without sudo; then retry."
        )


def test_hsm_setup_preserves_other_pkcs11_errors() -> None:
    with TemporaryDirectory() as tempdir:
        backend = FakePKCS11(initialized=True)
        scctl = FakeScHsmCtl(total=2, imported=2)
        app, session, csrf, probe = _app(tempdir, backend, scctl)
        request = _request(session, csrf)
        endpoint = route_endpoint(app, "/setup/hsm/test", "POST")
        pin_error = "PKCS#11 PIN verification failed: PinIncorrect"

        with (
            mock.patch.object(backend, "verify_pin", side_effect=PKCS11Error(pin_error)),
            pytest.raises(HTTPException) as caught,
        ):
            endpoint(probe, request)

        assert caught.value.status_code == 400
        assert caught.value.detail == pin_error


def test_new_hsm_requires_downloaded_n_of_n_shares_then_imports_all() -> None:
    with TemporaryDirectory() as tempdir:
        backend = FakePKCS11(initialized=False)
        scctl = FakeScHsmCtl()
        app, session, csrf, probe = _app(tempdir, backend, scctl)
        request = _request(session, csrf)
        route_endpoint(app, "/setup/hsm/test", "POST")(probe, request)
        initialize = route_endpoint(app, "/setup/hsm/initialize", "POST")
        payload = HSMInitializePayload(
            mode="new",
            so_pin="SO-PIN-SECRET",
            user_pin="123456",
            label="Recovery Token",
            dkek_shares=2,
            reason="Initialize the dedicated recovery token",
            confirmation="INITIALIZE HSM",
        )

        with pytest.raises(HTTPException, match="Generate and download exactly 2"):
            initialize(payload, request)

        create_shares = route_endpoint(app, "/setup/hsm/dkek/shares", "POST")
        response = create_shares(
            HSMCreateSharesPayload(
                shares=[
                    HSMCreateShareSpec(
                        filename=f"share-{index}.pbe",
                        password=f"share-password-{index}",
                    )
                    for index in (1, 2)
                ]
            ),
            request,
        )
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["content-type"] == "application/zip"
        assert response.headers["content-disposition"] == ('attachment; filename="dkek-shares.zip"')
        with zipfile.ZipFile(io.BytesIO(response.body)) as archive:
            assert archive.namelist() == ["share-1.pbe", "share-2.pbe"]
            assert archive.read("share-1.pbe") == b"encrypted-share-1"
            assert archive.read("share-2.pbe") == b"encrypted-share-2"
        assert b"share-password-1" not in response.body
        assert b"share-password-2" not in response.body
        assert scctl.create_passwords == [
            "share-password-1",
            "share-password-2",
        ]

        initialized = initialize(payload, request)
        assert initialized["ready"] is False
        assert len(scctl.initialize_calls) == 1

        shares = [
            DKEKSharePayload(
                filename=f"share-{index}.pbe",
                data_b64=base64.b64encode(f"share-{index}".encode()).decode(),
                password=f"share-password-{index}",
            )
            for index in (1, 2)
        ]
        ready = route_endpoint(app, "/setup/hsm/dkek/import", "POST")(
            HSMImportSharesPayload(shares=shares, user_pin="123456"),
            request,
        )

        assert ready == {
            "ok": True,
            "ready": True,
            "dkek_mode": "shares",
            "kcv": "A1B2C3",
            "token_serial": "TOKEN-SERIAL-1",
        }
        assert scctl.import_passwords == [
            "share-password-1",
            "share-password-2",
        ]
        persisted = (Path(tempdir) / "setup" / "state.json").read_text()
        for secret in (
            "SO-PIN-SECRET",
            "123456",
            "share-password-1",
            "share-password-2",
            shares[0].data_b64,
        ):
            assert secret not in persisted


def test_dkek_share_archive_requires_unique_filenames_and_passwords() -> None:
    with TemporaryDirectory() as tempdir:
        backend = FakePKCS11(initialized=False)
        scctl = FakeScHsmCtl()
        app, session, csrf, probe = _app(tempdir, backend, scctl)
        request = _request(session, csrf)
        route_endpoint(app, "/setup/hsm/test", "POST")(probe, request)
        create_shares = route_endpoint(app, "/setup/hsm/dkek/shares", "POST")

        duplicate_filename = HSMCreateSharesPayload(
            shares=[
                HSMCreateShareSpec(filename="Share.pbe", password="password-one"),
                HSMCreateShareSpec(filename="share.pbe", password="password-two"),
            ]
        )
        with pytest.raises(HTTPException, match="filename must be unique"):
            create_shares(duplicate_filename, request)

        duplicate_password = HSMCreateSharesPayload(
            shares=[
                HSMCreateShareSpec(filename="share-1.pbe", password="same-password"),
                HSMCreateShareSpec(filename="share-2.pbe", password="same-password"),
            ]
        )
        with pytest.raises(HTTPException, match="different password"):
            create_shares(duplicate_password, request)

        assert scctl.create_passwords == []
        assert app.state.generated_dkek_shares == {}


def test_dkek_share_archive_payload_requires_one_to_255_entries() -> None:
    with pytest.raises(ValidationError, match="at least 1 item"):
        HSMCreateSharesPayload(shares=[])

    share = HSMCreateShareSpec(filename="share.pbe", password="password")
    with pytest.raises(ValidationError, match="at most 255 items"):
        HSMCreateSharesPayload(shares=[share] * 256)


def test_latest_complete_dkek_share_batch_controls_initialization() -> None:
    with TemporaryDirectory() as tempdir:
        backend = FakePKCS11(initialized=False)
        scctl = FakeScHsmCtl()
        app, session, csrf, probe = _app(tempdir, backend, scctl)
        request = _request(session, csrf)
        route_endpoint(app, "/setup/hsm/test", "POST")(probe, request)
        create_shares = route_endpoint(app, "/setup/hsm/dkek/shares", "POST")
        create_shares(
            HSMCreateSharesPayload(
                shares=[
                    HSMCreateShareSpec(
                        filename=f"share-{index}.pbe",
                        password=f"password-{index}",
                    )
                    for index in (1, 2)
                ]
            ),
            request,
        )
        create_shares(
            HSMCreateSharesPayload(
                shares=[
                    HSMCreateShareSpec(
                        filename="replacement-share.pbe",
                        password="replacement-password",
                    )
                ]
            ),
            request,
        )

        payload = HSMInitializePayload(
            mode="new",
            so_pin="SO-PIN-SECRET",
            user_pin="123456",
            label="Recovery Token",
            dkek_shares=2,
            reason="Initialize the dedicated recovery token",
            confirmation="INITIALIZE HSM",
        )
        with pytest.raises(HTTPException, match="Generate and download exactly 2"):
            route_endpoint(app, "/setup/hsm/initialize", "POST")(payload, request)
        assert scctl.initialize_calls == []


def test_failed_or_oversized_dkek_share_batch_invalidates_generation_record() -> None:
    with TemporaryDirectory() as tempdir:
        backend = FakePKCS11(initialized=False)
        scctl = FakeScHsmCtl()
        app, session, csrf, probe = _app(tempdir, backend, scctl)
        request = _request(session, csrf)
        route_endpoint(app, "/setup/hsm/test", "POST")(probe, request)
        create_shares = route_endpoint(app, "/setup/hsm/dkek/shares", "POST")
        payload = HSMCreateSharesPayload(
            shares=[
                HSMCreateShareSpec(filename="share-1.pbe", password="password-one"),
                HSMCreateShareSpec(filename="share-2.pbe", password="password-two"),
            ]
        )
        create_shares(payload, request)
        assert app.state.generated_dkek_shares

        with (
            mock.patch.object(
                HSMCeremonyService,
                "create_dkek_share",
                side_effect=[b"first", HSMCeremonyError("share generation failed")],
            ),
            pytest.raises(HTTPException, match="share generation failed"),
        ):
            create_shares(payload, request)
        assert app.state.generated_dkek_shares == {}

        with (
            mock.patch(
                "myownca.setup.app._MAX_DKEK_SHARE_ARCHIVE_BYTES",
                3,
            ),
            mock.patch.object(
                HSMCeremonyService,
                "create_dkek_share",
                return_value=b"four",
            ),
            pytest.raises(HTTPException, match="configured safety limit"),
        ):
            create_shares(payload, request)
        assert app.state.generated_dkek_shares == {}


def test_new_hsm_without_dkek_is_ready_immediately_and_rejects_dkek_change() -> None:
    with TemporaryDirectory() as tempdir:
        backend = FakePKCS11(initialized=False)
        scctl = FakeScHsmCtl()
        app, session, csrf, probe = _app(tempdir, backend, scctl)
        request = _request(session, csrf)
        route_endpoint(app, "/setup/hsm/test", "POST")(probe, request)

        initialized = route_endpoint(app, "/setup/hsm/initialize", "POST")(
            HSMInitializePayload(
                mode="new",
                so_pin="SO-PIN-SECRET",
                user_pin="123456",
                label="Recovery Token",
                dkek_shares=0,
                reason="Initialize without future HSM migration",
                confirmation="INITIALIZE HSM",
            ),
            request,
        )

        assert initialized == {
            "ok": True,
            "mode": "new",
            "dkek_shares": 0,
            "erased_key_count": 0,
            "ready": True,
            "dkek_mode": "disabled",
            "token_serial": "TOKEN-SERIAL-1",
            "kcv": None,
        }
        assert scctl.initialize_calls[0]["dkek_shares"] == 0
        snapshot = app.state.orchestrator.snapshot()
        assert snapshot["hsm"]["ready"] is True
        assert snapshot["hsm"]["readiness"] == {
            "mode": "initialized",
            "token_serial": "TOKEN-SERIAL-1",
            "dkek_mode": "disabled",
            "kcv": None,
        }

        live = route_endpoint(app, "/setup/hsm/test", "POST")(
            probe.model_copy(update={"user_pin": "123456"}),
            request,
        )
        assert live["ready"] is True
        assert live["dkek_mode"] == "disabled"

        scctl.total = 1
        scctl.imported = 1
        changed = route_endpoint(app, "/setup/hsm/test", "POST")(
            probe.model_copy(update={"user_pin": "123456"}),
            request,
        )
        assert changed["ready"] is False
        assert app.state.orchestrator.snapshot()["hsm"]["ready"] is False


def test_recovery_mode_rejects_zero_dkek_shares() -> None:
    with TemporaryDirectory() as tempdir:
        backend = FakePKCS11(initialized=False)
        scctl = FakeScHsmCtl()
        app, session, csrf, probe = _app(tempdir, backend, scctl)
        request = _request(session, csrf)
        route_endpoint(app, "/setup/hsm/test", "POST")(probe, request)

        payload = HSMInitializePayload(
            mode="recovery",
            so_pin="SO-PIN-SECRET",
            user_pin="123456",
            label="Recovery Token",
            dkek_shares=0,
            reason="Attempt recovery without DKEK shares",
            confirmation="INITIALIZE HSM",
        )
        with pytest.raises(HTTPException, match="requires at least one"):
            route_endpoint(app, "/setup/hsm/initialize", "POST")(payload, request)
        assert scctl.initialize_calls == []


def test_initialized_target_with_keys_requires_explicit_setup_erase() -> None:
    with TemporaryDirectory() as tempdir:
        backend = FakePKCS11(
            initialized=True,
            keys=[{"label": "do-not-delete", "key_reference": 7}],
        )
        scctl = FakeScHsmCtl()
        app, session, csrf, probe = _app(tempdir, backend, scctl)
        request = _request(session, csrf)
        route_endpoint(app, "/setup/hsm/test", "POST")(probe, request)
        create_shares = route_endpoint(app, "/setup/hsm/dkek/shares", "POST")
        create_shares(
            HSMCreateSharesPayload(
                shares=[
                    HSMCreateShareSpec(
                        filename=f"erase-share-{index}.pbe",
                        password=f"erase-password-{index}",
                    )
                    for index in (1, 2)
                ]
            ),
            request,
        )

        initialize = route_endpoint(app, "/setup/hsm/initialize", "POST")
        payload = HSMInitializePayload(
            mode="new",
            so_pin="SO-PIN",
            user_pin="123456",
            current_user_pin="123456",
            label="Recovery Token",
            dkek_shares=2,
            reason="Replace the existing token contents with a new DKEK",
            confirmation="INITIALIZE HSM",
        )
        with pytest.raises(HTTPException, match="contains keys"):
            initialize(payload, request)

        result = initialize(
            payload.model_copy(update={"erase_existing_keys": True}),
            request,
        )

        assert result["erased_key_count"] == 1
        assert len(scctl.initialize_calls) == 1

        recovered = initialize(
            payload.model_copy(
                update={
                    "mode": "recovery",
                    "erase_existing_keys": True,
                    "reason": "Replace the recovery target contents with recovered DKEKs",
                }
            ),
            request,
        )

        assert recovered["erased_key_count"] == 1
        assert len(scctl.initialize_calls) == 2


def test_shared_dkek_import_rejects_wrong_count_without_exposing_secrets() -> None:
    backend = FakePKCS11(initialized=True)
    scctl = mock.Mock()
    scctl.dkek_status.return_value = DKEKStatus(3, 0, False, None)
    service = HSMCeremonyService(backend, scctl)

    with pytest.raises(HSMCeremonyError) as caught:
        service.import_dkek_shares(
            [
                (b"share-one-secret", "password-one-secret"),
                (b"share-two-secret", "password-two-secret"),
            ],
            user_pin="123456",
        )

    message = str(caught.value)
    assert "exactly 3" in message
    assert "secret" not in message
    scctl.import_dkek_share.assert_not_called()


def test_shared_dkek_import_rejects_inconsistent_kcvs() -> None:
    backend = FakePKCS11(initialized=True)
    scctl = mock.Mock()
    scctl.dkek_status.side_effect = [
        DKEKStatus(2, 0, False, None),
        DKEKStatus(2, 2, True, "BBBBBB"),
    ]
    scctl.import_dkek_share.side_effect = [
        DKEKStatus(2, 1, False, None),
        DKEKStatus(2, 2, True, "AAAAAA"),
    ]

    with pytest.raises(HSMCeremonyError, match="inconsistent"):
        HSMCeremonyService(backend, scctl).import_dkek_shares(
            [
                (b"share-one", "password-one"),
                (b"share-two", "password-two"),
            ],
            user_pin="123456",
        )


def test_shared_dkek_import_requires_kcv_when_completing_ceremony() -> None:
    backend = FakePKCS11(initialized=True)
    scctl = mock.Mock()
    scctl.dkek_status.side_effect = [
        DKEKStatus(1, 0, False, None),
        DKEKStatus(1, 1, True, None),
    ]
    scctl.import_dkek_share.return_value = DKEKStatus(1, 1, True, None)

    with pytest.raises(HSMCeremonyError, match="no KCV"):
        HSMCeremonyService(backend, scctl).import_dkek_shares(
            [(b"share-one", "password-one")],
            user_pin="123456",
        )


@pytest.mark.parametrize(
    "model",
    [DKEKAnalyzePayload, DKEKRestorePayload],
)
def test_issuer_restore_payload_rejects_obsolete_dkek_shares(model) -> None:
    payload = {
        "shares": [
            {
                "filename": "obsolete.pbe",
                "data_b64": "c2VjcmV0",
                "password": "obsolete-password",
            }
        ],
        "wrapped_key_b64": "d3JhcHBlZA==",
        "key_reference": "16",
        "certificate_pem": "certificate",
        "prior_crl_state": "never_issued_crl",
    }
    if model is DKEKRestorePayload:
        payload.update(
            {
                "reason": "Restore the initial managed issuer",
                "confirmation": "RESTORE SUBCA KEY",
            }
        )

    with pytest.raises(ValidationError, match="shares"):
        model.model_validate(payload)
