from __future__ import annotations

import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.exceptions import RequestValidationError

from myownca.online.app import create_app


def _validation_response(app, errors: list[dict]):
    handler = app.exception_handlers[RequestValidationError]
    return asyncio.run(handler(None, RequestValidationError(errors)))


def _assert_redacted(response, secrets: tuple[str, ...]) -> None:
    assert response.status_code == 422
    serialized = response.body.decode()
    for secret in secrets:
        assert secret not in serialized
    for error in json.loads(serialized)["detail"]:
        assert set(error) == {"loc", "type", "msg"}


def test_leaf_import_validation_never_reflects_secret_inputs() -> None:
    with TemporaryDirectory() as tempdir:
        app = create_app(Path(tempdir) / "validation.sqlite3", lab_mode=True)
        secrets = (
            "PRIVATE-KEY-MATERIAL",
            "P12-SUPER-SECRET",
        )
        response = _validation_response(
            app,
            [
                {
                    "type": "string_type",
                    "loc": ("body", "bundle_b64"),
                    "msg": "Input should be a valid string",
                    "input": ["PRIVATE-KEY-MATERIAL"],
                },
                {
                    "type": "string_type",
                    "loc": ("body", "password"),
                    "msg": "Input should be a valid string",
                    "input": {"value": "P12-SUPER-SECRET"},
                    "ctx": {"rejected": "P12-SUPER-SECRET"},
                },
            ],
        )
        _assert_redacted(response, secrets)


def test_hsm_restore_validation_never_reflects_recovery_secrets() -> None:
    with TemporaryDirectory() as tempdir:
        app = create_app(Path(tempdir) / "validation.sqlite3", lab_mode=True)
        secrets = (
            "DKEK-SHARE-BYTES",
            "DKEK-SHARE-PASSWORD",
            "WRAPPED-PRIVATE-KEY",
            "HSM-USER-PIN",
        )
        response = _validation_response(
            app,
            [
                {
                    "type": "model_type",
                    "loc": ("body", "shares", 0),
                    "msg": "Input should be a valid object",
                    "input": {
                        "data": "DKEK-SHARE-BYTES",
                        "password": "DKEK-SHARE-PASSWORD",
                    },
                },
                {
                    "type": "string_type",
                    "loc": ("body", "wrapped_key_b64"),
                    "msg": "Input should be a valid string",
                    "input": ["WRAPPED-PRIVATE-KEY"],
                    "ctx": {"pin": "HSM-USER-PIN"},
                },
            ],
        )
        _assert_redacted(response, secrets)
