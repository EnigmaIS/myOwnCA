from __future__ import annotations

import base64
import io
import zipfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from myownca import __version__
from myownca.ca_hsm.ceremony import HSMCeremonyService
from myownca.ca_hsm.pkcs11 import PKCS11Error, PKCS11HSM
from myownca.ca_hsm.scctl import ScHsmCtl
from myownca.config import Settings
from myownca.domain import CertificateProfile
from myownca.setup.orchestrator import SetupError, SetupOrchestrator
from myownca.setup.preflight import preflight
from myownca.setup.provisioning import (
    SetupProvisioningError,
    SetupProvisioningService,
)
from myownca.setup.state import is_setup_complete
from myownca.setup.token import SetupAuth

_SETUP_HEADERS = {"Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex"}
_MAX_DKEK_SHARE_ARCHIVE_BYTES = 20 * 1024 * 1024
_HSM_CONNECTION_ERROR = (
    "Cannot communicate with the selected HSM through OpenSC/PCSC (GeneralError). "
    "Check that the reader is connected, pcscd is running, and the myOwnCA service "
    "account can run `sc-hsm-tool -f` without sudo; then retry."
)


def _dkek_share_zip_info(filename: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(filename)
    info.date_time = (1980, 1, 1, 0, 0, 0)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o600 << 16
    return info


def _hsm_setup_error_detail(exc: Exception) -> str:
    """Return a safe, actionable detail for setup-only PKCS#11 failures."""

    if isinstance(exc, PKCS11Error) and str(exc) == "GeneralError":
        return _HSM_CONNECTION_ERROR
    return str(exc)


class UnlockPayload(BaseModel):
    token: str = Field(min_length=1)


class InstallTypePayload(BaseModel):
    value: str = Field(min_length=1)


class GovernanceModePayload(BaseModel):
    value: str = Field(min_length=1)


class TOTPPolicyPayload(BaseModel):
    required_roles: list[str]


class DatabasePayload(BaseModel):
    kind: str = Field(min_length=1)
    host: str = ""
    port: int = 3306
    name: str = ""
    user: str = ""
    password: str = ""


class HSMPayload(BaseModel):
    backend: str = Field(min_length=1)
    pkcs11_lib: str = ""
    token_label: str = "myOwnCA"
    reader: str = ""
    aws_region: str = ""
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_session_token: str = ""
    azure_vault_url: str = ""
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""
    azure_key_protection: str = "hsm"
    service_key_backend: str = "software"


class HSMProbePayload(HSMPayload):
    user_pin: str | None = None


class HSMAdoptPayload(BaseModel):
    user_pin: str = Field(min_length=1)


class HSMCreateShareSpec(BaseModel):
    filename: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.pbe$",
    )
    password: str = Field(min_length=1)


class HSMCreateSharesPayload(BaseModel):
    shares: list[HSMCreateShareSpec] = Field(min_length=1, max_length=255)


class ServiceUrlsPayload(BaseModel):
    admin: str = Field(min_length=1)
    superuser: str = Field(min_length=1)
    frontend: str = Field(min_length=1)


class ListenerPayload(BaseModel):
    topology: str = Field(min_length=1)
    bind_host: str = ""
    bind_port: int | None = Field(default=None, ge=1, le=65535)
    tls_enabled: bool = False
    tls_cert: str = ""
    tls_key: str = ""


class IssuanceEndpointsPayload(BaseModel):
    crl: str = ""
    aia: str = ""
    ocsp: str = ""


class RootCertificatePayload(BaseModel):
    pem: str = Field(min_length=1)


class AdminPayload(BaseModel):
    id: str = Field(min_length=1)
    email: str = Field(min_length=1)
    password: str = Field(min_length=1)


class AdminsPayload(BaseModel):
    first: AdminPayload
    second: AdminPayload | None = None


class SensitiveSetupAction(BaseModel):
    confirmation: str = Field(min_length=1)
    reason: str = Field(min_length=10, max_length=500)
    user_pin: str | None = None


class HSMInitializePayload(SensitiveSetupAction):
    mode: str = Field(pattern="^(new|recovery)$")
    so_pin: str = Field(min_length=1)
    user_pin: str = Field(min_length=1)
    current_user_pin: str | None = None
    label: str = Field(min_length=1, max_length=32)
    dkek_shares: int = Field(ge=0, le=255)
    erase_existing_keys: bool = False


class SubCARequestPayload(SensitiveSetupAction):
    common_name: str = Field(min_length=1)
    existing_key_ref: str | None = Field(default=None, min_length=1)
    allowed_profiles: list[CertificateProfile] = Field(
        default_factory=lambda: list(CertificateProfile),
        min_length=1,
    )
    algorithm: str = Field(
        default="ecdsa-p384",
        pattern="^(rsa-(2048|3072|4096)|ecdsa-p(256|384|521))$",
    )


class ResponseImportPayload(SensitiveSetupAction):
    certificate_pem: str = Field(min_length=1, max_length=100_000)


class ExistingKeyAnalyzePayload(BaseModel):
    key_ref: str = Field(min_length=1)
    certificate_pem: str = Field(min_length=1)
    allowed_profiles: list[CertificateProfile] = Field(
        default_factory=lambda: list(CertificateProfile),
        min_length=1,
    )
    algorithm: str = Field(
        default="ecdsa-p384",
        pattern="^(rsa-(2048|3072|4096)|ecdsa-p(256|384|521))$",
    )
    user_pin: str | None = None
    prior_crl_state: str = Field(pattern="^(crl|never_issued_crl)$")
    crl_b64: str | None = None
    # Accepted during rolling upgrades; the current provisioning layer ignores it.
    confirm_never_issued_crl: bool = False


class ExistingKeyCommitPayload(SensitiveSetupAction):
    key_ref: str = Field(min_length=1)
    certificate_pem: str = Field(min_length=1)
    allowed_profiles: list[CertificateProfile] = Field(
        default_factory=lambda: list(CertificateProfile),
        min_length=1,
    )
    algorithm: str = Field(
        default="ecdsa-p384",
        pattern="^(rsa-(2048|3072|4096)|ecdsa-p(256|384|521))$",
    )
    prior_crl_state: str = Field(pattern="^(crl|never_issued_crl)$")
    crl_b64: str | None = None
    # Accepted during rolling upgrades; the current provisioning layer ignores it.
    confirm_never_issued_crl: bool = False


class FileAnalyzePayload(BaseModel):
    bundle_b64: str = Field(min_length=1)
    private_key_b64: str | None = None
    password: str | None = None
    key_label: str = Field(min_length=1)
    allowed_profiles: list[CertificateProfile] = Field(
        default_factory=lambda: list(CertificateProfile),
        min_length=1,
    )
    user_pin: str | None = None
    prior_crl_state: str = Field(pattern="^(crl|never_issued_crl)$")
    crl_b64: str | None = None
    # Accepted during rolling upgrades; the current provisioning layer ignores it.
    confirm_never_issued_crl: bool = False


class FileCommitPayload(SensitiveSetupAction):
    bundle_b64: str = Field(min_length=1)
    private_key_b64: str | None = None
    password: str | None = None
    key_label: str = Field(min_length=1)
    allowed_profiles: list[CertificateProfile] = Field(
        default_factory=lambda: list(CertificateProfile),
        min_length=1,
    )
    prior_crl_state: str = Field(pattern="^(crl|never_issued_crl)$")
    crl_b64: str | None = None
    # Accepted during rolling upgrades; the current provisioning layer ignores it.
    confirm_never_issued_crl: bool = False


class DKEKSharePayload(BaseModel):
    filename: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9_.-]+$")
    data_b64: str = Field(min_length=1, max_length=7_000_000)
    password: str = Field(min_length=1)


class HSMImportSharesPayload(BaseModel):
    shares: list[DKEKSharePayload] = Field(min_length=1, max_length=255)
    user_pin: str = Field(min_length=1)


class DKEKAnalyzePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    wrapped_key_b64: str = Field(min_length=1)
    key_reference: str = Field(min_length=1)
    certificate_pem: str = Field(min_length=1)
    allowed_profiles: list[CertificateProfile] = Field(
        default_factory=lambda: list(CertificateProfile),
        min_length=1,
    )
    user_pin: str | None = None
    prior_crl_state: str = Field(pattern="^(crl|never_issued_crl)$")
    crl_b64: str | None = None
    # Accepted during rolling upgrades; the current provisioning layer ignores it.
    confirm_never_issued_crl: bool = False


class DKEKRestorePayload(SensitiveSetupAction):
    model_config = ConfigDict(extra="forbid")

    wrapped_key_b64: str = Field(min_length=1)
    key_reference: str = Field(min_length=1)
    certificate_pem: str = Field(min_length=1)
    allowed_profiles: list[CertificateProfile] = Field(
        default_factory=lambda: list(CertificateProfile),
        min_length=1,
    )
    prior_crl_state: str = Field(pattern="^(crl|never_issued_crl)$")
    crl_b64: str | None = None
    # Accepted during rolling upgrades; the current provisioning layer ignores it.
    confirm_never_issued_crl: bool = False


class LabIssuerPayload(SensitiveSetupAction):
    pass


class IssuerResetPayload(SensitiveSetupAction):
    pass


class FinalizePayload(BaseModel):
    user_pin: str | None = None


def create_setup_app(state_dir: str | Path, auth: SetupAuth) -> FastAPI:
    orchestrator = SetupOrchestrator(state_dir)
    static_dir = Path(__file__).with_name("static")

    # No OpenAPI docs on the CA's setup front door (defense-in-depth; localhost-only).
    app = FastAPI(
        title="myOwnCA Setup",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.auth = auth
    app.state.orchestrator = orchestrator
    # Overridden by the launcher's server runner; a no-op under tests.
    app.state.request_shutdown = lambda: None
    # Optional test/deployment override for the authenticated provider probe.
    # By default the selected adapter performs its real test_connection().
    app.state.cloud_provider_test_hook = None
    app.state.scctl = None
    app.state.generated_dkek_shares = {}
    app.state.pkcs11_backend_factory = lambda lib_path, token_label, pin_provider: PKCS11HSM(
        lib_path,
        token_label,
        pin_provider,
    )
    app.state.scctl_factory = lambda reader: ScHsmCtl(
        Settings.from_env().sc_hsm_tool_path,
        reader,
    )

    def pkcs11_components(
        *,
        user_pin: str | None,
    ) -> tuple[dict[str, object], PKCS11HSM, ScHsmCtl]:
        snapshot = orchestrator.snapshot()
        hsm = snapshot.get("hsm")
        if not isinstance(hsm, dict) or hsm.get("backend") != "pkcs11":
            raise SetupError("Select and save a PKCS#11 HSM first")
        backend = app.state.pkcs11_backend_factory(
            str(hsm["pkcs11_lib"]),
            str(hsm["token_label"]),
            lambda: user_pin,
        )
        scctl = app.state.scctl or app.state.scctl_factory(str(hsm.get("reader") or "") or None)
        return hsm, backend, scctl

    def hsm_probe(
        *,
        user_pin: str | None,
    ) -> dict[str, object]:
        hsm, backend, scctl = pkcs11_components(user_pin=user_pin)
        return HSMCeremonyService(backend, scctl).probe(
            user_pin=user_pin,
            reader=str(hsm.get("reader") or "") or None,
        )

    @app.exception_handler(RequestValidationError)
    async def sanitized_validation_error(
        _request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        # Setup payloads contain provider credentials, PINs, passwords and key
        # material.  Pydantic's rejected input must never be reflected.
        details = [
            {
                "loc": list(error.get("loc", ())),
                "type": str(error.get("type", "value_error")),
                "msg": str(error.get("msg", "Invalid request value")),
            }
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": details})

    def require_session(request: Request) -> None:
        if not auth.valid_session(request.cookies.get("myownca_setup")):
            raise HTTPException(status_code=401, detail="Setup session required")

    def require_csrf(request: Request) -> None:
        if not auth.valid_csrf(request.headers.get("x-csrf-token")):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")

    def require_confirmation(payload: SensitiveSetupAction, expected: str) -> None:
        if payload.confirmation != expected:
            raise HTTPException(
                status_code=400,
                detail=f"Type {expected!r} to confirm this setup operation",
            )

    def pkcs11_readiness_matches(
        hsm_snapshot: dict[str, object],
        live: dict[str, object],
    ) -> bool:
        readiness = hsm_snapshot.get("readiness")
        expected = readiness if isinstance(readiness, dict) else {}
        return HSMCeremonyService.readiness_matches(
            live,
            expected_serial=str(expected.get("token_serial") or ""),
            expected_dkek_mode=str(expected.get("dkek_mode") or ""),
            expected_kcv=(
                str(expected["kcv"])
                if expected.get("kcv") is not None
                else None
            ),
        )

    def assert_live_pkcs11_readiness(user_pin: str | None = None) -> None:
        setup_snapshot = orchestrator.snapshot()
        hsm_snapshot = setup_snapshot.get("hsm")
        if not isinstance(hsm_snapshot, dict) or hsm_snapshot.get("backend") != "pkcs11":
            return
        if not hsm_snapshot.get("ready"):
            raise SetupError("Initialize or adopt the current HSM and complete key setup")
        live = hsm_probe(user_pin=user_pin)
        if not pkcs11_readiness_matches(hsm_snapshot, live):
            orchestrator.invalidate_pkcs11_ready()
            raise SetupError(
                "The live HSM token or DKEK state no longer matches the setup readiness marker"
            )

    def provisioning(user_pin: str | None = None) -> SetupProvisioningService:
        try:
            if not is_setup_complete(state_dir):
                assert_live_pkcs11_readiness(user_pin)
                orchestrator.prepare_runtime(require_governance=False)
            return SetupProvisioningService(
                state_dir,
                user_pin=user_pin,
                scctl=getattr(app.state, "scctl", None),
            )
        except (SetupError, SetupProvisioningError, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    def provisioning_call(callback):
        try:
            result = callback()
            if (
                is_setup_complete(state_dir)
                and isinstance(result, dict)
                and result.get("configured") is True
            ):
                app.state.request_shutdown()
            return result
        except SetupProvisioningError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/", include_in_schema=False)
    def setup_root() -> RedirectResponse:
        # The whole server exists to run the wizard; send the bare URL there.
        return RedirectResponse("/setup")

    @app.get("/setup", include_in_schema=False)
    def setup_page() -> FileResponse:
        return FileResponse(static_dir / "setup.html", headers=_SETUP_HEADERS)

    @app.get("/theme.css", include_in_schema=False)
    def theme_css() -> FileResponse:
        return FileResponse(Path(__file__).parents[1] / "ui_theme.css", media_type="text/css")

    @app.get("/branding/logo", include_in_schema=False)
    def branding_logo() -> FileResponse:
        # The setup app is pre-database, so it only ever serves the bundled default.
        return FileResponse(
            static_dir / "branding" / "logo.svg",
            media_type="image/svg+xml",
            headers={
                "Content-Security-Policy": "script-src 'none'",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.post("/setup/unlock")
    def unlock(payload: UnlockPayload, response: Response) -> dict[str, object]:
        if not auth.consume_token(payload.token):
            raise HTTPException(status_code=401, detail="Invalid setup token")
        session_token, csrf_token = auth.open_session()
        response.set_cookie(
            "myownca_setup",
            session_token,
            httponly=True,
            samesite="strict",
            secure=False,  # setup runs on plain HTTP over localhost
            path="/",
        )
        return {"csrf_token": csrf_token}

    @app.get("/setup/state")
    def state(request: Request) -> dict[str, object]:
        require_session(request)
        return {
            **orchestrator.snapshot(),
            "app_version": __version__,
            "issuer_completion_only": is_setup_complete(state_dir),
        }

    @app.get("/setup/preflight")
    def preflight_report(request: Request) -> dict[str, object]:
        require_session(request)
        return preflight(state_dir)

    @app.post("/setup/install-type")
    def install_type(payload: InstallTypePayload, request: Request) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            orchestrator.set_install_type(payload.value)
        except SetupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return orchestrator.snapshot()

    @app.post("/setup/governance-mode")
    def governance_mode(
        payload: GovernanceModePayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            orchestrator.set_governance_mode(payload.value)
        except SetupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return orchestrator.snapshot()

    @app.post("/setup/totp-policy")
    def totp_policy(
        payload: TOTPPolicyPayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            orchestrator.set_totp_policy(payload.required_roles)
        except SetupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return orchestrator.snapshot()

    @app.post("/setup/database")
    def set_database(payload: DatabasePayload, request: Request) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            orchestrator.set_database(
                payload.kind,
                host=payload.host,
                port=payload.port,
                name=payload.name,
                user=payload.user,
                password=payload.password,
            )
        except SetupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return orchestrator.snapshot()

    @app.post("/setup/database/test")
    def test_database(request: Request) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            orchestrator.test_database()
        except SetupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"ok": True}

    @app.post("/setup/hsm")
    def set_hsm(payload: HSMPayload, request: Request) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            values = payload.model_dump()
            orchestrator.set_hsm(values.pop("backend"), **values)
        except SetupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return orchestrator.snapshot()

    @app.post("/setup/hsm/test")
    def test_hsm(payload: HSMProbePayload, request: Request) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            values = payload.model_dump()
            user_pin = values.pop("user_pin", None)
            backend = values.pop("backend")
            if backend == "pkcs11":
                orchestrator.set_hsm(backend, **values)
                live = hsm_probe(user_pin=user_pin)
                snapshot = orchestrator.snapshot()
                hsm_snapshot = snapshot.get("hsm")
                ready = bool(isinstance(hsm_snapshot, dict) and hsm_snapshot.get("ready"))
                readiness = (
                    hsm_snapshot.get("readiness")
                    if isinstance(hsm_snapshot, dict)
                    else None
                )
                if (
                    ready
                    and isinstance(hsm_snapshot, dict)
                    and not pkcs11_readiness_matches(hsm_snapshot, live)
                ):
                    orchestrator.invalidate_pkcs11_ready()
                    ready = False
                    readiness = None
                return {
                    "ok": True,
                    "backend": backend,
                    "ready": ready,
                    "readiness_mode": (
                        readiness.get("mode")
                        if ready and isinstance(readiness, dict)
                        else None
                    ),
                    "dkek_mode": (
                        readiness.get("dkek_mode")
                        if ready and isinstance(readiness, dict)
                        else None
                    ),
                    **live,
                }
            orchestrator.test_hsm(
                backend,
                provider_test_hook=app.state.cloud_provider_test_hook,
                **values,
            )
        except (SetupError, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=_hsm_setup_error_detail(exc)) from exc
        return {"ok": True, "backend": backend}

    @app.post("/setup/hsm/dkek/shares")
    def create_hsm_dkek_shares(
        payload: HSMCreateSharesPayload,
        request: Request,
    ) -> Response:
        require_session(request)
        require_csrf(request)
        try:
            _hsm, _backend, scctl = pkcs11_components(user_pin=None)
            identity = (
                str(_hsm["pkcs11_lib"]),
                str(_hsm["token_label"]),
                str(_hsm.get("reader") or ""),
            )
            app.state.generated_dkek_shares.pop(identity, None)
            filenames = [share.filename for share in payload.shares]
            passwords = [share.password for share in payload.shares]
            if len({filename.casefold() for filename in filenames}) != len(filenames):
                raise SetupError("Each DKEK share filename must be unique")
            if len(set(passwords)) != len(passwords):
                raise SetupError("Each DKEK share must use a different password")
            generated_shares = HSMCeremonyService(
                _backend,
                scctl,
            ).create_dkek_shares(
                passwords=passwords,
                max_total_bytes=_MAX_DKEK_SHARE_ARCHIVE_BYTES,
            )
            archive_buffer = io.BytesIO()
            with zipfile.ZipFile(
                archive_buffer,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as archive:
                for share_spec, share in zip(
                    payload.shares,
                    generated_shares,
                    strict=True,
                ):
                    archive.writestr(
                        _dkek_share_zip_info(share_spec.filename),
                        share,
                    )
            archive_bytes = archive_buffer.getvalue()
            if len(archive_bytes) > _MAX_DKEK_SHARE_ARCHIVE_BYTES:
                raise SetupError("DKEK share archive exceeds the 20 MiB safety limit")
            app.state.generated_dkek_shares[identity] = tuple(filenames)
        except (OSError, SetupError, RuntimeError, ValueError, zipfile.LargeZipFile) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return Response(
            content=archive_bytes,
            media_type="application/zip",
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Content-Disposition": 'attachment; filename="dkek-shares.zip"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.post("/setup/hsm/initialize")
    def initialize_hsm(
        payload: HSMInitializePayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        require_confirmation(payload, "INITIALIZE HSM")
        try:
            hsm, _backend, scctl = pkcs11_components(user_pin=None)
            if payload.label != hsm["token_label"]:
                raise SetupError("Initialization label must match the saved token label")
            if payload.mode == "recovery" and payload.dkek_shares == 0:
                raise SetupError("Recovery mode requires at least one DKEK share")
            if payload.mode == "new" and payload.dkek_shares > 0:
                identity = (
                    str(hsm["pkcs11_lib"]),
                    str(hsm["token_label"]),
                    str(hsm.get("reader") or ""),
                )
                downloaded = app.state.generated_dkek_shares.get(identity, ())
                if len(downloaded) != payload.dkek_shares:
                    raise SetupError(
                        f"Generate and download exactly {payload.dkek_shares} "
                        "distinct DKEK shares before initialization"
                    )
            inspection_backend = app.state.pkcs11_backend_factory(
                str(hsm["pkcs11_lib"]),
                str(hsm["token_label"]),
                lambda: payload.current_user_pin,
            )
            raw_token = inspection_backend.status().get("token")
            token_before = raw_token if isinstance(raw_token, dict) else {}
            token_serial = str(token_before.get("serial") or "")
            erased_keys = HSMCeremonyService(inspection_backend, scctl).initialize(
                so_pin=payload.so_pin,
                user_pin=payload.user_pin,
                current_user_pin=payload.current_user_pin,
                label=payload.label,
                dkek_shares=payload.dkek_shares,
                erase_existing_keys=payload.erase_existing_keys,
            )
            marker: dict[str, object] | None = None
            if payload.dkek_shares == 0:
                verification_backend = app.state.pkcs11_backend_factory(
                    str(hsm["pkcs11_lib"]),
                    str(hsm["token_label"]),
                    lambda: payload.user_pin,
                )
                live = HSMCeremonyService(verification_backend, scctl).probe(
                    user_pin=payload.user_pin,
                    reader=str(hsm.get("reader") or "") or None,
                )
                raw_pin = live.get("pin")
                pin = raw_pin if isinstance(raw_pin, dict) else {}
                if not pin.get("verified"):
                    raise SetupError("The newly initialized HSM User PIN could not be verified")
                if not HSMCeremonyService.readiness_matches(
                    live,
                    expected_serial=token_serial,
                    expected_dkek_mode="disabled",
                    expected_kcv=None,
                ):
                    raise SetupError(
                        "The newly initialized HSM does not match disabled DKEK mode"
                    )
                marker = orchestrator.record_pkcs11_ready(
                    mode="initialized",
                    token_serial=token_serial,
                    dkek_mode="disabled",
                    kcv=None,
                )
        except (SetupError, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "ok": True,
            "mode": payload.mode,
            "dkek_shares": payload.dkek_shares,
            "erased_key_count": len(erased_keys),
            "ready": marker is not None,
            "dkek_mode": "disabled" if marker is not None else "shares",
            "token_serial": marker["token_serial"] if marker is not None else None,
            "kcv": marker["kcv"] if marker is not None else None,
        }

    @app.post("/setup/hsm/dkek/import")
    def import_hsm_dkek_shares(
        payload: HSMImportSharesPayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            _hsm, backend, scctl = pkcs11_components(user_pin=payload.user_pin)
            filenames = [share.filename for share in payload.shares]
            if len(set(filenames)) != len(filenames):
                raise SetupError("Each DKEK share filename must be unique")
            decoded_shares: list[tuple[bytes, str]] = []
            for index, share in enumerate(payload.shares, start=1):
                try:
                    share_bytes = base64.b64decode(
                        share.data_b64,
                        validate=True,
                    )
                except ValueError as exc:
                    raise SetupError(f"DKEK share {index} is not valid base64") from exc
                decoded_shares.append((share_bytes, share.password))
            final_status = HSMCeremonyService(
                backend,
                scctl,
            ).import_dkek_shares(
                decoded_shares,
                user_pin=payload.user_pin,
            )
            token_status = backend.status().get("token")
            token = token_status if isinstance(token_status, dict) else {}
            marker = orchestrator.record_pkcs11_ready(
                mode="initialized",
                token_serial=str(token.get("serial") or ""),
                dkek_mode="shares",
                kcv=final_status.kcv,
            )
        except (OSError, SetupError, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "ok": True,
            "ready": True,
            "dkek_mode": marker["dkek_mode"],
            "kcv": marker["kcv"],
            "token_serial": marker["token_serial"],
        }

    @app.post("/setup/hsm/adopt")
    def adopt_hsm(
        payload: HSMAdoptPayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            _hsm, backend, scctl = pkcs11_components(user_pin=payload.user_pin)
            token, keys, dkek = HSMCeremonyService(backend, scctl).adopt(
                user_pin=payload.user_pin,
            )
            marker = orchestrator.record_pkcs11_ready(
                mode="existing",
                token_serial=str(token.get("serial") or ""),
                dkek_mode="shares",
                kcv=dkek.kcv,
            )
        except (SetupError, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=_hsm_setup_error_detail(exc)) from exc
        return {
            "ok": True,
            "ready": True,
            "dkek_mode": marker["dkek_mode"],
            "key_count": len(keys),
            "keys": keys,
            "kcv": marker["kcv"],
            "token_serial": marker["token_serial"],
        }

    @app.post("/setup/service-urls")
    def set_service_urls(payload: ServiceUrlsPayload, request: Request) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            orchestrator.set_service_urls(
                admin=payload.admin,
                superuser=payload.superuser,
                frontend=payload.frontend,
            )
        except SetupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return orchestrator.snapshot()

    @app.post("/setup/listener")
    def set_listener(payload: ListenerPayload, request: Request) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            orchestrator.set_listener(
                topology=payload.topology,
                bind_host=payload.bind_host,
                bind_port=payload.bind_port,
                tls_enabled=payload.tls_enabled,
                tls_cert=payload.tls_cert,
                tls_key=payload.tls_key,
            )
        except SetupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return orchestrator.snapshot()

    @app.post("/setup/issuance-endpoints")
    def set_issuance_endpoints(
        payload: IssuanceEndpointsPayload, request: Request
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            orchestrator.set_issuance_endpoints(crl=payload.crl, aia=payload.aia, ocsp=payload.ocsp)
        except SetupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return orchestrator.snapshot()

    @app.post("/setup/root-certificate")
    def set_root_certificate(
        payload: RootCertificatePayload, request: Request
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            orchestrator.set_root_certificate(payload.pem)
        except SetupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return orchestrator.snapshot()

    @app.post("/setup/root-certificate/verify")
    def verify_root_certificate(
        payload: RootCertificatePayload, request: Request
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            return orchestrator.verify_root_certificate(payload.pem)
        except SetupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/setup/issuer")
    def issuer_status(request: Request) -> dict[str, object]:
        require_session(request)
        try:
            status = provisioning().status()
            return {
                "ready": True,
                **status,
                "locked": bool(status["locked"] or is_setup_complete(state_dir)),
            }
        except HTTPException as exc:
            return {
                "ready": False,
                "configured": False,
                "locked": bool(orchestrator.snapshot().get("issuer_locked")),
                "pending": [],
                "detail": exc.detail,
            }

    @app.post("/setup/issuer/request", status_code=201)
    def create_issuer_request(
        payload: SubCARequestPayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        require_confirmation(payload, "CREATE SUBCA")
        service = provisioning(payload.user_pin)
        return provisioning_call(
            lambda: service.create_request(
                common_name=payload.common_name,
                allowed_profiles=payload.allowed_profiles,
                algorithm=payload.algorithm,
                existing_key_ref=payload.existing_key_ref,
                reason=payload.reason,
            )
        )

    @app.post("/setup/issuer/response/import", status_code=201)
    def import_issuer_response(
        payload: ResponseImportPayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        require_confirmation(payload, "ACTIVATE SUBCA")
        return provisioning_call(
            lambda: provisioning(payload.user_pin).import_response(
                certificate_pem=payload.certificate_pem, reason=payload.reason
            )
        )

    @app.post("/setup/issuer/existing-key/analyze")
    def analyze_existing_issuer_key(
        payload: ExistingKeyAnalyzePayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        service = provisioning(payload.user_pin)
        return provisioning_call(
            lambda: service.analyze_existing_key(
                key_ref=payload.key_ref,
                certificate_pem=payload.certificate_pem,
                allowed_profiles=payload.allowed_profiles,
                algorithm=payload.algorithm,
                prior_crl_state=payload.prior_crl_state,
                crl_b64=payload.crl_b64,
            )
        )

    @app.post("/setup/issuer/existing-key/commit", status_code=201)
    def commit_existing_issuer_key(
        payload: ExistingKeyCommitPayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        require_confirmation(payload, "IMPORT EXISTING SUBCA")
        service = provisioning(payload.user_pin)
        return provisioning_call(
            lambda: service.commit_existing_key(
                key_ref=payload.key_ref,
                certificate_pem=payload.certificate_pem,
                allowed_profiles=payload.allowed_profiles,
                algorithm=payload.algorithm,
                prior_crl_state=payload.prior_crl_state,
                crl_b64=payload.crl_b64,
                reason=payload.reason,
            )
        )

    @app.post("/setup/issuer/file/analyze")
    def analyze_issuer_file(
        payload: FileAnalyzePayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        service = provisioning(payload.user_pin)
        return provisioning_call(
            lambda: service.analyze_file(
                bundle_b64=payload.bundle_b64,
                private_key_b64=payload.private_key_b64,
                password=payload.password,
                key_label=payload.key_label,
                allowed_profiles=payload.allowed_profiles,
                prior_crl_state=payload.prior_crl_state,
                crl_b64=payload.crl_b64,
            )
        )

    @app.post("/setup/issuer/file/commit", status_code=201)
    def commit_issuer_file(
        payload: FileCommitPayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        require_confirmation(payload, "IMPORT SUBCA KEY")
        service = provisioning(payload.user_pin)
        return provisioning_call(
            lambda: service.commit_file(
                bundle_b64=payload.bundle_b64,
                private_key_b64=payload.private_key_b64,
                password=payload.password,
                key_label=payload.key_label,
                allowed_profiles=payload.allowed_profiles,
                prior_crl_state=payload.prior_crl_state,
                crl_b64=payload.crl_b64,
                reason=payload.reason,
            )
        )

    @app.post("/setup/issuer/dkek/analyze")
    def analyze_issuer_dkek(
        payload: DKEKAnalyzePayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        service = provisioning(payload.user_pin)
        return provisioning_call(
            lambda: service.analyze_dkek(
                wrapped_key_b64=payload.wrapped_key_b64,
                key_reference=payload.key_reference,
                certificate_pem=payload.certificate_pem,
                allowed_profiles=payload.allowed_profiles,
                prior_crl_state=payload.prior_crl_state,
                crl_b64=payload.crl_b64,
            )
        )

    @app.post("/setup/issuer/dkek/restore", status_code=201)
    def restore_issuer_dkek(
        payload: DKEKRestorePayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        require_confirmation(payload, "RESTORE SUBCA KEY")
        service = provisioning(payload.user_pin)
        return provisioning_call(
            lambda: service.restore_dkek(
                wrapped_key_b64=payload.wrapped_key_b64,
                key_reference=payload.key_reference,
                certificate_pem=payload.certificate_pem,
                allowed_profiles=payload.allowed_profiles,
                prior_crl_state=payload.prior_crl_state,
                crl_b64=payload.crl_b64,
                reason=payload.reason,
            )
        )

    @app.post("/setup/issuer/lab", status_code=201)
    def create_lab_issuer(
        payload: LabIssuerPayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        require_confirmation(payload, "CREATE LAB CA")
        return provisioning_call(lambda: provisioning().provision_lab(reason=payload.reason))

    @app.post("/setup/issuer/reset")
    def reset_issuer(
        payload: IssuerResetPayload,
        request: Request,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        require_confirmation(payload, "RESET ISSUER")
        return provisioning_call(
            lambda: provisioning(payload.user_pin).reset(reason=payload.reason)
        )

    @app.post("/setup/admins")
    def set_admins(payload: AdminsPayload, request: Request) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            orchestrator.set_admins(
                payload.first.model_dump(),
                payload.second.model_dump() if payload.second is not None else None,
            )
        except SetupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return orchestrator.snapshot()

    @app.post("/setup/finalize")
    def finalize(
        request: Request,
        payload: FinalizePayload | None = None,
    ) -> dict[str, object]:
        require_session(request)
        require_csrf(request)
        try:
            assert_live_pkcs11_readiness(payload.user_pin if payload is not None else None)
            orchestrator.finalize(user_pin=payload.user_pin if payload is not None else None)
        except SetupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        app.state.request_shutdown()
        return {"complete": True}

    return app
