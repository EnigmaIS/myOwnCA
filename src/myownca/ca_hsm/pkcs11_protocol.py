from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 2 * 1024 * 1024
WORKER_TIMEOUT_SECONDS = 60


class PKCS11ProtocolError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class WorkerRequest:
    operation: str
    lib_path: str
    token_label: str
    pin: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    version: int = PROTOCOL_VERSION

    def to_json(self) -> str:
        return json.dumps(
            {
                "version": self.version,
                "operation": self.operation,
                "lib_path": self.lib_path,
                "token_label": self.token_label,
                "pin": self.pin,
                "arguments": self.arguments,
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, payload: str) -> WorkerRequest:
        try:
            raw = json.loads(payload)
        except (json.JSONDecodeError, TypeError) as exc:
            raise PKCS11ProtocolError("Worker request is not valid JSON") from exc
        if not isinstance(raw, dict):
            raise PKCS11ProtocolError("Worker request must be a JSON object")
        if raw.get("version") != PROTOCOL_VERSION:
            raise PKCS11ProtocolError("Unsupported worker protocol version")
        operation = raw.get("operation")
        lib_path = raw.get("lib_path")
        token_label = raw.get("token_label")
        pin = raw.get("pin")
        arguments = raw.get("arguments", {})
        if not isinstance(operation, str) or not operation:
            raise PKCS11ProtocolError("Worker operation is required")
        if not isinstance(lib_path, str) or not lib_path:
            raise PKCS11ProtocolError("PKCS#11 module path is required")
        if not isinstance(token_label, str) or not token_label:
            raise PKCS11ProtocolError("PKCS#11 token label is required")
        if pin is not None and not isinstance(pin, str):
            raise PKCS11ProtocolError("PKCS#11 PIN must be a string")
        if not isinstance(arguments, dict):
            raise PKCS11ProtocolError("Worker arguments must be a JSON object")
        return cls(
            operation=operation,
            lib_path=lib_path,
            token_label=token_label,
            pin=pin,
            arguments=arguments,
        )


def success_response(result: Any) -> str:
    return json.dumps(
        {"version": PROTOCOL_VERSION, "ok": True, "result": result},
        ensure_ascii=True,
        separators=(",", ":"),
    )


def error_response(
    error_type: str,
    code: str,
    *,
    message: str | None = None,
    details: dict[str, Any] | None = None,
) -> str:
    error: dict[str, Any] = {"type": error_type, "code": code}
    if message:
        error["message"] = message
    if details:
        error["details"] = details
    return json.dumps(
        {"version": PROTOCOL_VERSION, "ok": False, "error": error},
        ensure_ascii=True,
        separators=(",", ":"),
    )
