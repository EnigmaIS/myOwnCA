from __future__ import annotations

import base64
import sys
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from myownca.ca_hsm.base import KeyImportError
from myownca.ca_hsm.pkcs11 import (
    PKCS11Error,
    PKCS11PartialImportError,
    PKCS11Unavailable,
    _InProcessPKCS11HSM,
)
from myownca.ca_hsm.pkcs11_protocol import (
    MAX_MESSAGE_BYTES,
    PKCS11ProtocolError,
    WorkerRequest,
    error_response,
    success_response,
)


def _argument(arguments: dict[str, Any], name: str, expected_type):
    value = arguments.get(name)
    if not isinstance(value, expected_type):
        raise PKCS11ProtocolError(f"Worker argument '{name}' is invalid")
    return value


def _decode(arguments: dict[str, Any], name: str) -> bytes:
    value = _argument(arguments, name, str)
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise PKCS11ProtocolError(f"Worker argument '{name}' is not valid base64") from exc


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _require_pin(request: WorkerRequest) -> str:
    if not request.pin:
        raise PKCS11Error("HSM PIN is locked; unlock the PIN before this operation")
    return request.pin


def dispatch(request: WorkerRequest) -> Any:
    pin = request.pin
    backend = _InProcessPKCS11HSM(
        request.lib_path,
        request.token_label,
        pin_provider=lambda: pin,
    )
    arguments = request.arguments

    if request.operation == "status":
        return backend.status()
    if request.operation == "verify_pin":
        backend.verify_pin(_require_pin(request))
        return True
    if request.operation == "generate_key":
        return backend.generate_key(
            _argument(arguments, "label", str),
            _argument(arguments, "algorithm", str),
        )
    if request.operation == "import_key":
        _require_pin(request)
        private_key = serialization.load_der_private_key(
            _decode(arguments, "private_key_der"),
            password=None,
        )
        certificate_der = arguments.get("certificate_der")
        certificate = (
            x509.load_der_x509_certificate(_decode(arguments, "certificate_der"))
            if certificate_der is not None
            else None
        )
        return backend.import_key(
            _argument(arguments, "label", str),
            private_key,
            certificate,
        )
    if request.operation == "public_key":
        public_key = backend.public_key(_argument(arguments, "key_ref", str))
        return _encode(
            public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    if request.operation == "sign_x509":
        return _encode(
            backend.sign_x509_payload(
                _decode(arguments, "payload"),
                _argument(arguments, "key_ref", str),
                _decode(arguments, "expected_public_key_der"),
            )
        )
    if request.operation == "sign_data":
        return _encode(
            backend.sign_data(
                _decode(arguments, "payload"),
                _argument(arguments, "key_ref", str),
            )
        )
    if request.operation == "list_keys":
        return backend.list_keys()
    if request.operation == "delete_key":
        return backend.delete_key(_argument(arguments, "label", str))
    if request.operation == "delete_key_reference":
        key_reference = arguments.get("key_reference")
        if not isinstance(key_reference, (int, str)) or isinstance(key_reference, bool):
            raise PKCS11ProtocolError("Worker argument 'key_reference' is invalid")
        return backend.delete_key_reference(key_reference)
    if request.operation == "self_test":
        return backend.self_test()
    raise PKCS11ProtocolError(f"Unknown PKCS#11 worker operation: {request.operation}")


def handle(payload: str) -> str:
    try:
        request = WorkerRequest.from_json(payload)
        return success_response(dispatch(request))
    except PKCS11PartialImportError as exc:
        return error_response(
            "partial_import",
            exc.__class__.__name__,
            message="PKCS#11 key import rollback was incomplete",
            details={
                "key_ref": exc.key_ref,
                "remaining_objects": list(exc.remaining_objects),
            },
        )
    except PKCS11Unavailable as exc:
        return error_response("unavailable", exc.__class__.__name__, message=str(exc))
    except KeyError as exc:
        return error_response("key_error", exc.__class__.__name__, message=str(exc))
    except KeyImportError as exc:
        return error_response("key_import_error", exc.__class__.__name__, message=str(exc))
    except PKCS11ProtocolError as exc:
        return error_response("protocol_error", exc.__class__.__name__, message=str(exc))
    except ValueError as exc:
        return error_response("value_error", exc.__class__.__name__, message=str(exc))
    except PKCS11Error as exc:
        return error_response("pkcs11_error", exc.__class__.__name__, message=str(exc))
    except Exception as exc:  # noqa: BLE001 - never emit provider or secret-bearing text
        return error_response("internal_error", exc.__class__.__name__)


def main() -> int:
    payload = sys.stdin.buffer.read(MAX_MESSAGE_BYTES + 1)
    if len(payload) > MAX_MESSAGE_BYTES:
        response = error_response(
            "protocol_error",
            "MessageTooLarge",
            message="PKCS#11 worker request exceeds the size limit",
        )
    else:
        try:
            decoded = payload.decode("utf-8")
        except UnicodeDecodeError:
            response = error_response(
                "protocol_error",
                "UnicodeDecodeError",
                message="PKCS#11 worker request is not UTF-8",
            )
        else:
            response = handle(decoded)
    sys.stdout.write(response)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
