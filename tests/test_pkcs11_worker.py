from __future__ import annotations

import base64
import datetime
import json
import subprocess
from typing import ClassVar
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from myownca.ca_hsm.pkcs11 import PKCS11HSM, PKCS11Error, PKCS11Unavailable
from myownca.ca_hsm.pkcs11_protocol import (
    PROTOCOL_VERSION,
    WorkerRequest,
    success_response,
)
from myownca.ca_hsm.pkcs11_worker import dispatch, handle


def _completed(result, *, returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess(
        ["python", "-m", "myownca.ca_hsm.pkcs11_worker"],
        returncode,
        stdout=success_response(result) if returncode == 0 else "",
        stderr=stderr,
    )


def _request(operation: str, *, pin: str | None = "123456", arguments=None):
    return WorkerRequest(
        operation=operation,
        lib_path="opensc-pkcs11",
        token_label="myOwnCA",
        pin=pin,
        arguments=arguments or {},
    )


class _FakeWorkerBackend:
    calls: ClassVar[list[tuple[str, object]]] = []

    def __init__(self, lib_path, token_label, pin_provider):
        self.lib_path = lib_path
        self.token_label = token_label
        self.pin_provider = pin_provider

    def status(self):
        self.calls.append(("status", None))
        return {"token_present": True}

    def verify_pin(self, pin):
        self.calls.append(("verify_pin", pin))

    def generate_key(self, label, algorithm):
        self.calls.append(("generate_key", (label, algorithm)))
        return label

    def import_key(self, label, private_key, certificate):
        self.calls.append(("import_key", (label, private_key, certificate)))
        return label

    def public_key(self, key_ref):
        self.calls.append(("public_key", key_ref))
        return ec.generate_private_key(ec.SECP256R1()).public_key()

    def sign_x509_payload(self, payload, key_ref, expected_public_key_der):
        self.calls.append(("sign_x509", (payload, key_ref, expected_public_key_der)))
        return b"x509-signature"

    def sign_data(self, payload, key_ref):
        self.calls.append(("sign_data", (payload, key_ref)))
        return b"data-signature"

    def list_keys(self):
        self.calls.append(("list_keys", None))
        return [{"label": "issuer"}]

    def delete_key(self, label):
        self.calls.append(("delete_key", label))
        return 2

    def delete_key_reference(self, key_reference):
        self.calls.append(("delete_key_reference", key_reference))
        return 2

    def self_test(self):
        self.calls.append(("self_test", None))
        return {"passed": True}


def test_protocol_round_trip() -> None:
    request = _request("list_keys", arguments={"value": 1})
    assert WorkerRequest.from_json(request.to_json()) == request


def test_worker_rejects_malformed_request_without_traceback() -> None:
    response = json.loads(handle("{not-json"))
    assert response["ok"] is False
    assert response["error"]["type"] == "protocol_error"
    assert "traceback" not in json.dumps(response).lower()


def test_worker_returns_sanitized_unavailable_and_pin_errors() -> None:
    secret = "PIN-MUST-NOT-BE-RETURNED"
    with mock.patch(
        "myownca.ca_hsm.pkcs11_worker._InProcessPKCS11HSM.status",
        side_effect=PKCS11Unavailable("PKCS#11 module could not be loaded: OSError"),
    ):
        unavailable = json.loads(handle(_request("status", pin=None).to_json()))
    assert unavailable["error"]["type"] == "unavailable"
    assert unavailable["error"]["code"] == "PKCS11Unavailable"

    with mock.patch(
        "myownca.ca_hsm.pkcs11_worker._InProcessPKCS11HSM.verify_pin",
        side_effect=PKCS11Error("PKCS#11 PIN verification failed: PinIncorrect"),
    ):
        rejected = json.loads(
            handle(_request("verify_pin", pin=secret).to_json())
        )
    assert rejected["error"]["type"] == "pkcs11_error"
    assert secret not in json.dumps(rejected)


@pytest.mark.parametrize(
    ("operation", "arguments", "expected"),
    [
        ("status", {}, {"token_present": True}),
        ("verify_pin", {}, True),
        ("generate_key", {"label": "issuer", "algorithm": "ecdsa-p256"}, "issuer"),
        ("list_keys", {}, [{"label": "issuer"}]),
        ("delete_key", {"label": "issuer"}, 2),
        ("delete_key_reference", {"key_reference": 16}, 2),
        ("self_test", {}, {"passed": True}),
        (
            "sign_x509",
            {
                "payload": base64.b64encode(b"tbs").decode(),
                "key_ref": "issuer",
                "expected_public_key_der": base64.b64encode(b"spki").decode(),
            },
            base64.b64encode(b"x509-signature").decode(),
        ),
        (
            "sign_data",
            {
                "payload": base64.b64encode(b"payload").decode(),
                "key_ref": "issuer",
            },
            base64.b64encode(b"data-signature").decode(),
        ),
    ],
)
def test_worker_dispatches_supported_operations(operation, arguments, expected) -> None:
    _FakeWorkerBackend.calls.clear()
    with mock.patch(
        "myownca.ca_hsm.pkcs11_worker._InProcessPKCS11HSM",
        _FakeWorkerBackend,
    ):
        assert dispatch(_request(operation, arguments=arguments)) == expected
    assert _FakeWorkerBackend.calls


def test_worker_deserializes_imported_key_material() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    private_der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    _FakeWorkerBackend.calls.clear()
    with mock.patch(
        "myownca.ca_hsm.pkcs11_worker._InProcessPKCS11HSM",
        _FakeWorkerBackend,
    ):
        result = dispatch(
            _request(
                "import_key",
                arguments={
                    "label": "imported",
                    "private_key_der": base64.b64encode(private_der).decode(),
                    "certificate_der": None,
                },
            )
        )
    assert result == "imported"
    _, (_, loaded_key, certificate) = _FakeWorkerBackend.calls[-1]
    assert certificate is None
    assert loaded_key.private_numbers() == key.private_numbers()


def test_worker_serializes_public_key_material() -> None:
    _FakeWorkerBackend.calls.clear()
    with mock.patch(
        "myownca.ca_hsm.pkcs11_worker._InProcessPKCS11HSM",
        _FakeWorkerBackend,
    ):
        encoded = dispatch(
            _request("public_key", arguments={"key_ref": "issuer"})
        )
    loaded = serialization.load_der_public_key(base64.b64decode(encoded))
    assert isinstance(loaded, ec.EllipticCurvePublicKey)
    assert _FakeWorkerBackend.calls == [("public_key", "issuer")]


def test_facade_passes_pin_only_through_stdin_and_refreshes_each_call() -> None:
    secret = "PIN-MUST-STAY-OFF-ARGV"
    backend = PKCS11HSM("module", "myOwnCA", pin_provider=lambda: secret)
    results = [
        _completed([{"label": "old"}]),
        _completed([]),
    ]
    with mock.patch("subprocess.run", side_effect=results) as run:
        assert backend.list_keys() == [{"label": "old"}]
        assert backend.list_keys() == []

    assert run.call_count == 2
    for call in run.call_args_list:
        command = call.args[0]
        assert secret not in command
        assert secret not in call.kwargs["env"].values()
        assert json.loads(call.kwargs["input"])["pin"] == secret


def test_facade_sanitizes_worker_timeout_and_crash() -> None:
    backend = PKCS11HSM("module", "myOwnCA", pin_provider=lambda: "secret-pin")
    with (
        mock.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(["worker"], 60, stderr="secret-pin"),
        ),
        pytest.raises(PKCS11Error, match="WorkerTimeout") as caught,
    ):
        backend.list_keys()
    assert "secret-pin" not in str(caught.value)

    with (
        mock.patch(
            "subprocess.run",
            return_value=_completed(None, returncode=9, stderr="secret-pin"),
        ),
        pytest.raises(PKCS11Error, match="ProcessExit9") as caught,
    ):
        backend.list_keys()
    assert "secret-pin" not in str(caught.value)


def test_facade_rejects_malformed_worker_output() -> None:
    backend = PKCS11HSM("module", "myOwnCA", pin_provider=lambda: "123456")
    completed = subprocess.CompletedProcess(["worker"], 0, stdout="not-json", stderr="")
    with (
        mock.patch("subprocess.run", return_value=completed),
        pytest.raises(PKCS11Error, match="malformed JSON"),
    ):
        backend.list_keys()


def test_facade_certificate_crl_csr_and_data_signing() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    def worker(command, **kwargs):
        assert command[1:] == ["-m", "myownca.ca_hsm.pkcs11_worker"]
        request = json.loads(kwargs["input"])
        operation = request["operation"]
        arguments = request["arguments"]
        if operation == "public_key":
            result = base64.b64encode(public_der).decode()
        elif operation in {"sign_x509", "sign_data"}:
            payload = base64.b64decode(arguments["payload"])
            result = base64.b64encode(
                key.sign(payload, ec.ECDSA(hashes.SHA256()))
            ).decode()
        else:
            raise AssertionError(operation)
        return _completed(result)

    backend = PKCS11HSM("module", "myOwnCA", pin_provider=lambda: "123456")
    now = datetime.datetime.now(datetime.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Worker CA")])
    certificate_builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    crl_builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
    )
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(name)

    with mock.patch("subprocess.run", side_effect=worker):
        certificate = backend.sign_certificate(certificate_builder, "issuer")
        crl = backend.sign_crl(crl_builder, "issuer")
        csr = backend.sign_csr(csr_builder, "issuer")
        signature = backend.sign_data(b"payload", "issuer")

    key.public_key().verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        ec.ECDSA(certificate.signature_hash_algorithm),
    )
    key.public_key().verify(
        crl.signature,
        crl.tbs_certlist_bytes,
        ec.ECDSA(crl.signature_hash_algorithm),
    )
    assert csr.is_signature_valid
    key.public_key().verify(signature, b"payload", ec.ECDSA(hashes.SHA256()))


def test_worker_response_version_is_current() -> None:
    response = json.loads(success_response(True))
    assert response["version"] == PROTOCOL_VERSION
