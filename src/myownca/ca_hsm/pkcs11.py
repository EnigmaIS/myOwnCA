from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from myownca.ca_hsm.base import (
    KeyImportError,
    KeyVerification,
    public_keys_match,
    validate_imported_key,
    verify_backend_key,
)
from myownca.ca_hsm.pkcs11_protocol import (
    MAX_MESSAGE_BYTES,
    PROTOCOL_VERSION,
    WORKER_TIMEOUT_SECONDS,
    WorkerRequest,
)
from myownca.ca_hsm.scctl import normalize_key_reference

PinProvider = Callable[[], "str | None"]

_DER = serialization.Encoding.DER
_SELFTEST_LABEL = "__myownca_selftest__"
_PKCS15_TIMEOUT_SECONDS = 10
_IMPORT_LABEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")

# DER-encoded named-curve OIDs as they appear in PKCS#11 CKA_EC_PARAMS.
_CURVE_BY_EC_PARAMS = {
    bytes.fromhex("06082a8648ce3d030107"): ec.SECP256R1,  # 1.2.840.10045.3.1.7
    bytes.fromhex("06052b81040022"): ec.SECP384R1,        # 1.3.132.0.34
    bytes.fromhex("06052b81040023"): ec.SECP521R1,        # 1.3.132.0.35
}
_EC_CURVE_NAME = {
    "ecdsa-p256": "secp256r1",
    "ecdsa-p384": "secp384r1",
    "ecdsa-p521": "secp521r1",
}
_EC_PARAMS_BY_CURVE_NAME = {
    curve().name: params for params, curve in _CURVE_BY_EC_PARAMS.items()
}


@dataclass(frozen=True, slots=True)
class _ImportTemplates:
    public_key: dict[object, object]
    private_key: dict[object, object]
    certificate: dict[object, object] | None


@dataclass(frozen=True, slots=True)
class _PKCS15PrivateKey:
    key_reference: int
    object_id: bytes | None
    label: str


class PKCS11Unavailable(RuntimeError):
    """Raised when the python-pkcs11 library or PKCS#11 module can't be loaded."""


class PKCS11Error(RuntimeError):
    pass


class HSMLockedError(PKCS11Error):
    """Raised when no unlocked User PIN is available for the token.

    Separate from :class:`PKCS11Error` because this is an operator-recoverable
    state rather than a fault: callers can offer an unlock and let the operation
    be retried, instead of surfacing it as a server error.
    """

    DEFAULT_MESSAGE = "HSM PIN is locked; unlock the PIN before this operation"

    def __init__(self, message: str = DEFAULT_MESSAGE) -> None:
        super().__init__(message)


class PKCS11PartialImportError(PKCS11Error):
    """An import failed and one or more token objects could not be rolled back."""

    def __init__(self, key_ref: str, remaining_objects: tuple[str, ...]) -> None:
        self.key_ref = key_ref
        self.remaining_objects = remaining_objects
        super().__init__(
            f"PKCS#11 key import for '{key_ref}' failed and left token objects: "
            + ", ".join(remaining_objects)
        )


def _pkcs11_error_detail(exc: BaseException) -> str:
    """Return a stable provider error code without reflecting driver text.

    PKCS#11 drivers and wrappers are not consistent about exception messages.
    Some include the arguments passed to ``C_CreateObject`` or ``C_Login``;
    reflecting that text into an API error can expose private-key attributes or
    a PIN.  python-pkcs11 already represents CKR values with distinct exception
    classes, so the class name is the useful, non-secret diagnostic boundary.
    """

    return exc.__class__.__name__


def _display_token_label(value: object) -> str:
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    return str(value).replace("\x00", "").strip()


def _normalize_token_label(value: object) -> str:
    return " ".join(_display_token_label(value).split()).casefold()


def _parse_user_pin_tries_left(output: str) -> int | None:
    in_user_pin = False
    for line in output.splitlines():
        pin_match = re.match(r"\s*PIN\s+\[(?P<label>[^\]]+)\]", line)
        if pin_match:
            label = re.sub(r"[\s_-]+", "", pin_match.group("label")).casefold()
            in_user_pin = label == "userpin"
            continue
        if not in_user_pin:
            continue
        tries_match = re.search(r"Tries\s+left\s*:\s*(\d+)", line, re.IGNORECASE)
        if tries_match:
            return int(tries_match.group(1))
    return None


def _pkcs15_tool_candidates(lib_path: str) -> list[str]:
    candidates: list[str] = []
    lib = Path(lib_path)
    if lib.parent.name.lower() == "pkcs11":
        root = lib.parent.parent
        suffix = ".exe" if os.name == "nt" else ""
        candidates.extend(
            [
                str(root / "tools" / f"pkcs15-tool{suffix}"),
                str(root / "bin" / f"pkcs15-tool{suffix}"),
            ]
        )
    candidates.append("pkcs15-tool")
    return candidates


def _read_user_pin_tries_left(lib_path: str) -> int | None:
    for candidate in _pkcs15_tool_candidates(lib_path):
        if candidate != "pkcs15-tool" and not Path(candidate).exists():
            continue
        try:
            completed = subprocess.run(
                [candidate, "-D"],
                capture_output=True,
                text=True,
                timeout=_PKCS15_TIMEOUT_SECONDS,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
        if completed.returncode != 0:
            continue
        tries_left = _parse_user_pin_tries_left(completed.stdout or "")
        if tries_left is not None:
            return tries_left
    return None


def _parse_pkcs15_private_keys(output: str) -> list[_PKCS15PrivateKey]:
    """Parse native SmartCard-HSM key refs and PKCS#11 IDs from pkcs15-tool."""

    records: list[_PKCS15PrivateKey] = []
    current_reference: int | None = None
    current_id: bytes | None = None
    current_label = ""

    def finish() -> None:
        if current_reference is not None:
            records.append(_PKCS15PrivateKey(current_reference, current_id, current_label))

    for line in output.splitlines():
        key_match = re.match(r"^\s*Private\s+.+?\s+Key\s+\[(?P<label>.*)\]\s*$", line)
        if key_match:
            finish()
            current_reference = None
            current_id = None
            current_label = key_match.group("label")
            continue
        reference_match = re.match(r"^\s*Key ref\s*:\s*(\d+)\b", line)
        if reference_match:
            reference = int(reference_match.group(1))
            if 1 <= reference <= 255:
                current_reference = reference
            continue
        id_match = re.match(r"^\s*ID\s*:\s*(.+?)\s*$", line)
        if id_match:
            raw_value = id_match.group(1).strip()
            if raw_value.startswith("<"):
                current_id = None
                continue
            value = re.sub(r"[^0-9A-Fa-f]", "", raw_value)
            if value and len(value) % 2 == 0:
                try:
                    current_id = bytes.fromhex(value)
                except ValueError:
                    current_id = None
            continue
    finish()
    return records


def _read_pkcs15_private_keys(lib_path: str) -> list[_PKCS15PrivateKey]:
    for candidate in _pkcs15_tool_candidates(lib_path):
        if candidate != "pkcs15-tool" and not Path(candidate).exists():
            continue
        try:
            completed = subprocess.run(
                [candidate, "-D"],
                capture_output=True,
                text=True,
                timeout=_PKCS15_TIMEOUT_SECONDS,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
        if completed.returncode == 0:
            return _parse_pkcs15_private_keys(completed.stdout or "")
    return []


def load_pkcs11_module():
    try:
        import pkcs11
    except ImportError as exc:  # pragma: no cover - exercised only without the dep
        raise PKCS11Unavailable(
            "python-pkcs11 is not installed; run 'pip install python-pkcs11'"
        ) from exc
    return pkcs11


def _load_pkcs11_library(lib_path: str):
    pkcs11 = load_pkcs11_module()
    try:
        return pkcs11, pkcs11.lib(lib_path)
    except Exception as exc:
        raise PKCS11Unavailable(
            f"PKCS#11 module could not be loaded: {_pkcs11_error_detail(exc)}"
        ) from exc


class PKCS11HSM:
    """PKCS#11 backend facade with one fresh provider process per operation."""

    def __init__(self, lib_path: str, token_label: str, pin_provider: PinProvider) -> None:
        self._lib_path = lib_path
        self._token_label = token_label
        self._pin_provider = pin_provider

    def generate_key(self, label: str, algorithm: str = "rsa-2048") -> str:
        result = self._call_with_pin(
            "generate_key",
            {"label": label, "algorithm": algorithm},
        )
        if not isinstance(result, str):
            raise PKCS11Error("PKCS#11 worker returned an invalid key reference")
        return result

    def import_key(
        self,
        label: str,
        private_key: CertificateIssuerPrivateKeyTypes,
        certificate: x509.Certificate | None = None,
    ) -> str:
        if not _IMPORT_LABEL_PATTERN.fullmatch(label):
            raise ValueError("Unsafe PKCS#11 key label")
        validate_imported_key(private_key, certificate)
        private_der = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        arguments = {
            "label": label,
            "private_key_der": _b64encode(private_der),
            "certificate_der": (
                _b64encode(certificate.public_bytes(serialization.Encoding.DER))
                if certificate is not None
                else None
            ),
        }
        result = self._call_with_pin("import_key", arguments)
        if not isinstance(result, str):
            raise PKCS11Error("PKCS#11 worker returned an invalid key reference")
        return result

    def verify_key(self, key_ref: str, certificate: x509.Certificate) -> KeyVerification:
        return verify_backend_key(self, key_ref, certificate)

    def public_key(self, key_ref: str) -> CertificatePublicKeyTypes:
        encoded = self._call_with_pin("public_key", {"key_ref": key_ref})
        public_key = serialization.load_der_public_key(_b64decode_result(encoded))
        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            raise PKCS11Error("PKCS#11 worker returned an unsupported public key")
        return public_key

    def private_key(self, key_ref: str) -> CertificateIssuerPrivateKeyTypes:
        raise PKCS11Error(
            "PKCS#11 private keys are non-extractable; use sign_certificate/sign_crl/sign_data"
        )

    def sign_certificate(
        self, builder: x509.CertificateBuilder, key_ref: str
    ) -> x509.Certificate:
        pub = self.public_key(key_ref)
        template = builder.sign(_dummy_key(pub), _hash_for(pub))
        signature = self._sign_x509(
            template.tbs_certificate_bytes,
            key_ref,
            pub,
        )
        return x509.load_der_x509_certificate(
            _splice_signature(template.public_bytes(_DER), signature)
        )

    def sign_crl(
        self, builder: x509.CertificateRevocationListBuilder, key_ref: str
    ) -> x509.CertificateRevocationList:
        pub = self.public_key(key_ref)
        template = builder.sign(_dummy_key(pub), _hash_for(pub))
        signature = self._sign_x509(template.tbs_certlist_bytes, key_ref, pub)
        return x509.load_der_x509_crl(
            _splice_signature(template.public_bytes(_DER), signature)
        )

    def sign_csr(
        self, builder: x509.CertificateSigningRequestBuilder, key_ref: str
    ) -> x509.CertificateSigningRequest:
        pub = self.public_key(key_ref)
        public_der = pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        template = builder.sign(_dummy_key(pub), _hash_for(pub))
        tbs = _csr_tbs_with_public_key(template.tbs_certrequest_bytes, public_der)
        signature = _b64decode_result(
            self._call_with_pin(
                "sign_x509",
                {
                    "payload": _b64encode(tbs),
                    "key_ref": key_ref,
                    "expected_public_key_der": _b64encode(public_der),
                },
            )
        )
        return x509.load_der_x509_csr(
            _splice_tbs_and_signature(template.public_bytes(_DER), tbs, signature)
        )

    def sign_data(self, payload: bytes, key_ref: str) -> bytes:
        return _b64decode_result(
            self._call_with_pin(
                "sign_data",
                {"payload": _b64encode(payload), "key_ref": key_ref},
            )
        )

    def status(self) -> dict[str, object]:
        result = self._call("status")
        if not isinstance(result, dict):
            raise PKCS11Error("PKCS#11 worker returned invalid token status")
        return result

    def list_keys(self) -> list[dict[str, object]]:
        result = self._call_with_pin("list_keys")
        if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
            raise PKCS11Error("PKCS#11 worker returned invalid key inventory")
        return result

    def delete_key(self, label: str) -> int:
        result = self._call_with_pin("delete_key", {"label": label})
        if not isinstance(result, int) or isinstance(result, bool):
            raise PKCS11Error("PKCS#11 worker returned an invalid deletion count")
        return result

    def delete_key_reference(self, key_reference: int | str) -> int:
        result = self._call_with_pin(
            "delete_key_reference",
            {"key_reference": key_reference},
        )
        if not isinstance(result, int) or isinstance(result, bool):
            raise PKCS11Error("PKCS#11 worker returned an invalid deletion count")
        return result

    def self_test(self) -> dict[str, object]:
        result = self._call_with_pin("self_test")
        if not isinstance(result, dict):
            raise PKCS11Error("PKCS#11 worker returned an invalid self-test result")
        return result

    def verify_pin(self, pin: str) -> None:
        if not pin:
            raise HSMLockedError()
        self._call("verify_pin", pin=pin)

    def _sign_x509(
        self,
        payload: bytes,
        key_ref: str,
        public_key: CertificatePublicKeyTypes,
    ) -> bytes:
        public_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return _b64decode_result(
            self._call_with_pin(
                "sign_x509",
                {
                    "payload": _b64encode(payload),
                    "key_ref": key_ref,
                    "expected_public_key_der": _b64encode(public_der),
                },
            )
        )

    def _call_with_pin(
        self,
        operation: str,
        arguments: dict[str, object] | None = None,
    ):
        pin = self._pin_provider()
        if not pin:
            raise HSMLockedError()
        return self._call(operation, arguments, pin=pin)

    def _call(
        self,
        operation: str,
        arguments: dict[str, object] | None = None,
        *,
        pin: str | None = None,
    ):
        request = WorkerRequest(
            operation=operation,
            lib_path=self._lib_path,
            token_label=self._token_label,
            pin=pin,
            arguments=dict(arguments or {}),
        )
        payload = request.to_json()
        if len(payload.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise PKCS11Error("PKCS#11 worker request exceeds the size limit")
        command = [sys.executable, "-m", "myownca.ca_hsm.pkcs11_worker"]
        environment = os.environ.copy()
        if pin:
            environment = {
                name: value for name, value in environment.items() if value != pin
            }
        try:
            completed = subprocess.run(
                command,
                input=payload,
                capture_output=True,
                text=True,
                timeout=WORKER_TIMEOUT_SECONDS,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
            code = (
                "WorkerTimeout"
                if isinstance(exc, subprocess.TimeoutExpired)
                else exc.__class__.__name__
            )
            raise PKCS11Error(f"PKCS#11 worker failed: {code}") from exc
        if completed.returncode != 0:
            raise PKCS11Error(
                f"PKCS#11 worker failed: ProcessExit{completed.returncode}"
            )
        if not isinstance(completed.stdout, str):
            raise PKCS11Error("PKCS#11 worker returned an invalid response")
        if len(completed.stdout.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise PKCS11Error("PKCS#11 worker returned an oversized response")
        try:
            response = json.loads(completed.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise PKCS11Error("PKCS#11 worker returned malformed JSON") from exc
        if (
            not isinstance(response, dict)
            or response.get("version") != PROTOCOL_VERSION
            or not isinstance(response.get("ok"), bool)
        ):
            raise PKCS11Error("PKCS#11 worker returned an invalid response")
        if response["ok"]:
            return response.get("result")
        self._raise_worker_error(response.get("error"))

    @staticmethod
    def _raise_worker_error(raw_error) -> None:
        if not isinstance(raw_error, dict):
            raise PKCS11Error("PKCS#11 worker returned an invalid error")
        error_type = raw_error.get("type")
        code = str(raw_error.get("code") or "WorkerError")
        message = raw_error.get("message")
        safe_message = message if isinstance(message, str) and message else code
        if error_type == "partial_import":
            details = raw_error.get("details")
            details = details if isinstance(details, dict) else {}
            key_ref = str(details.get("key_ref") or "")
            remaining = details.get("remaining_objects")
            remaining_objects = (
                tuple(str(item) for item in remaining)
                if isinstance(remaining, list)
                else ()
            )
            raise PKCS11PartialImportError(key_ref, remaining_objects)
        if error_type == "unavailable":
            raise PKCS11Unavailable(safe_message)
        if error_type == "key_error":
            raise KeyError(safe_message)
        if error_type == "key_import_error":
            raise KeyImportError(safe_message)
        if error_type == "value_error":
            raise ValueError(safe_message)
        if code == HSMLockedError.__name__:
            # The worker reports the exception class as its code; preserve the
            # locked subtype so callers can still offer an unlock.
            raise HSMLockedError(safe_message)
        raise PKCS11Error(safe_message)


class _InProcessPKCS11HSM:
    """HSMBackend implementation backed by a PKCS#11 token (SmartCard-HSM / NitroKey HSM).

    The User PIN is never held by this object; it is fetched per call from
    ``pin_provider`` (an admin unlocks it for their session). Private keys never
    leave the token: certificate, CRL, and CSR signing use a throwaway in-memory
    key of the matching type to render the to-be-signed bytes via ``cryptography``,
    then the real signature from the token is spliced into the DER structure.
    """

    def __init__(self, lib_path: str, token_label: str, pin_provider: PinProvider) -> None:
        self._lib_path = lib_path
        self._token_label = token_label
        self._pin_provider = pin_provider

    # -- backend protocol -----------------------------------------------------

    def generate_key(self, label: str, algorithm: str = "rsa-2048") -> str:
        with self._session() as (session, pkcs11):
            if self._find(session, pkcs11, label) is not None:
                raise ValueError(f"Key label already exists: {label}")
            self._generate_keypair(session, pkcs11, label, algorithm, store=True)
            return label

    def import_key(
        self,
        label: str,
        private_key: CertificateIssuerPrivateKeyTypes,
        certificate: x509.Certificate | None = None,
    ) -> str:
        """Create a non-extractable RSA/EC key pair and optional X.509 object.

        Import support is token-specific. Unsupported or read-only attributes
        fail closed; no weaker template is retried. Every successfully-created
        pair must pass a public-key comparison and live signing proof before it
        is returned to the caller.
        """

        if not _IMPORT_LABEL_PATTERN.fullmatch(label):
            raise ValueError("Unsafe PKCS#11 key label")
        validate_imported_key(private_key, certificate)
        with self._session() as (session, pkcs11):
            if self._find(session, pkcs11, label) is not None:
                raise ValueError(f"Key label already exists: {label}")
            key_id = _allocate_key_id(session, pkcs11)
            templates = _import_templates(
                pkcs11,
                label=label,
                key_id=key_id,
                private_key=private_key,
                certificate=certificate,
            )
            created: list[tuple[str, object]] = []
            try:
                public_object = session.create_object(templates.public_key)
                created.append(("public-key", public_object))
                private_object = session.create_object(templates.private_key)
                created.append(("private-key", private_object))
                self._verify_imported_objects(
                    public_object,
                    private_object,
                    private_key.public_key(),
                    pkcs11,
                )
                if templates.certificate is not None:
                    certificate_object = session.create_object(templates.certificate)
                    created.append(("certificate", certificate_object))
            except Exception as exc:
                remaining: list[str] = []
                for object_name, token_object in reversed(created):
                    try:
                        token_object.destroy()
                    except Exception:  # noqa: BLE001 - report incomplete rollback below
                        remaining.append(object_name)
                if remaining:
                    raise PKCS11PartialImportError(label, tuple(reversed(remaining))) from exc
                if isinstance(exc, KeyImportError):
                    raise
                raise PKCS11Error(
                    f"PKCS#11 key import failed: {_pkcs11_error_detail(exc)}"
                ) from exc
        return label

    def public_key(self, key_ref: str) -> CertificatePublicKeyTypes:
        with self._session() as (session, pkcs11):
            pub = self._require(session, pkcs11, key_ref, pkcs11.ObjectClass.PUBLIC_KEY)
            return self._to_public_key(pub, pkcs11)

    def sign_data(self, payload: bytes, key_ref: str) -> bytes:
        with self._session() as (session, pkcs11):
            priv = self._require(session, pkcs11, key_ref, pkcs11.ObjectClass.PRIVATE_KEY)
            pub = self._to_public_key(
                self._require(session, pkcs11, key_ref, pkcs11.ObjectClass.PUBLIC_KEY), pkcs11
            )
            if isinstance(pub, rsa.RSAPublicKey):
                salt_len = pub.key_size // 8 - hashes.SHA256().digest_size - 2
                return priv.sign(
                    payload,
                    mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS_PSS,
                    mechanism_param=(pkcs11.Mechanism.SHA256, pkcs11.MGF.SHA256, salt_len),
                )
            raw = priv.sign(payload, mechanism=pkcs11.Mechanism.ECDSA_SHA256)
            return _raw_ecdsa_to_der(raw)

    def sign_x509_payload(
        self,
        payload: bytes,
        key_ref: str,
        expected_public_key_der: bytes,
    ) -> bytes:
        with self._session() as (session, pkcs11):
            pub = self._to_public_key(
                self._require(session, pkcs11, key_ref, pkcs11.ObjectClass.PUBLIC_KEY),
                pkcs11,
            )
            actual_der = pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if actual_der != expected_public_key_der:
                raise PKCS11Error("PKCS#11 key changed before signing")
            return self._sign_tbs(session, pkcs11, key_ref, payload, pub)

    # -- management helpers ---------------------------------------------------

    def status(self) -> dict[str, object]:
        pkcs11, lib = _load_pkcs11_library(self._lib_path)
        slots = lib.get_slots()
        tokens = self._present_tokens(lib, pkcs11)
        token_info: dict[str, object] | None = None
        try:
            token, auto_selected = self._resolve_token(lib, pkcs11)
        except PKCS11Error:
            pass
        else:
            token_info = self._token_info(token, pkcs11)
            token_info["auto_selected"] = auto_selected
        return {
            "lib_path": self._lib_path,
            "token_label": self._token_label,
            "slots": len(slots),
            "token_present": token_info is not None,
            "token": token_info,
            "tokens": [self._token_info(token, pkcs11) for token in tokens],
            "pin_tries_left": self.pin_tries_left(),
        }

    def list_keys(self) -> list[dict[str, object]]:
        with self._session() as (session, pkcs11):
            key_metadata: list[tuple[object, object, bytes | None, str, int | None]] = []
            for obj in session.get_objects({pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY}):
                object_id = _object_id(obj, pkcs11)
                key_metadata.append(
                    (
                        obj.label,
                        object_id,
                        _key_type_name(obj.key_type, pkcs11),
                        _key_size(obj, pkcs11),
                    )
                )
        native_refs: dict[bytes, list[int]] = {}
        native_refs_by_label: dict[str, list[int]] = {}
        for record in _read_pkcs15_private_keys(self._lib_path):
            if record.object_id is not None:
                native_refs.setdefault(record.object_id, []).append(record.key_reference)
            if record.label:
                native_refs_by_label.setdefault(record.label, []).append(record.key_reference)
        return [
            {
                "label": label,
                "key_type": key_type,
                "key_size": key_size,
                "id": object_id.hex() if object_id is not None else None,
                "key_reference": (
                    refs[0]
                    if len(refs) == 1
                    else label_refs[0]
                    if len(label_refs) == 1
                    else None
                )
                if object_id is not None or label_refs
                else None,
            }
            for label, object_id, key_type, key_size in key_metadata
            for refs in (native_refs.get(object_id, []),)
            for label_refs in (native_refs_by_label.get(str(label), []),)
        ]

    def delete_key(self, label: str) -> int:
        with self._session() as (session, pkcs11):
            destroyed = 0
            for obj in session.get_objects({pkcs11.Attribute.LABEL: label}):
                obj.destroy()
                destroyed += 1
            if destroyed == 0:
                raise ValueError(f"No key object found with label: {label}")
            return destroyed

    def delete_key_reference(self, key_reference: int | str) -> int:
        """Destroy objects belonging to one native SmartCard-HSM key reference."""

        reference = normalize_key_reference(key_reference)
        records = [
            record
            for record in _read_pkcs15_private_keys(self._lib_path)
            if record.key_reference == reference and record.object_id is not None
        ]
        if len(records) != 1:
            raise ValueError(f"No unique PKCS#11 object ID found for key reference: {reference}")
        object_id = records[0].object_id
        assert object_id is not None
        with self._session() as (session, pkcs11):
            objects = list(session.get_objects({pkcs11.Attribute.ID: object_id}))
            if not objects:
                raise ValueError(f"No key object found with reference: {reference}")
            destroyed = 0
            for obj in objects:
                obj.destroy()
                destroyed += 1
            return destroyed

    def self_test(self) -> dict[str, object]:
        with self._session() as (session, pkcs11):
            for stale in session.get_objects({pkcs11.Attribute.LABEL: _SELFTEST_LABEL}):
                stale.destroy()
            # ``store=False`` is honoured by some tokens but not all (the
            # SmartCard-HSM persists EC keys regardless), so always destroy the
            # generated objects in a finally block rather than relying on it.
            pub_obj, priv_obj = self._generate_keypair(
                session, pkcs11, _SELFTEST_LABEL, "ecdsa-p256", store=False
            )
            try:
                pub = self._to_public_key(pub_obj, pkcs11)
                nonce = os.urandom(32)
                start = perf_counter()
                raw = priv_obj.sign(nonce, mechanism=pkcs11.Mechanism.ECDSA_SHA256)
                duration_ms = (perf_counter() - start) * 1000
                pub.verify(_raw_ecdsa_to_der(raw), nonce, ec.ECDSA(hashes.SHA256()))
            finally:
                for obj in (priv_obj, pub_obj):
                    try:
                        obj.destroy()
                    except Exception:  # noqa: BLE001, S110 - best-effort cleanup
                        pass
            return {
                "passed": True,
                "algorithm": "ecdsa-p256",
                "duration_ms": round(duration_ms, 2),
            }

    def verify_pin(self, pin: str) -> None:
        if not pin:
            raise HSMLockedError()
        pkcs11, lib = _load_pkcs11_library(self._lib_path)
        try:
            token, _ = self._resolve_token(lib, pkcs11)
            with token.open(user_pin=pin, rw=True):
                return
        except pkcs11.exceptions.PKCS11Error as exc:
            detail = _pkcs11_error_detail(exc)
            tries_left = self.pin_tries_left()
            if tries_left is not None:
                detail = f"{detail} (User PIN tries left: {tries_left})"
            raise PKCS11Error(f"PKCS#11 PIN verification failed: {detail}") from exc

    def pin_tries_left(self) -> int | None:
        return _read_user_pin_tries_left(self._lib_path)

    # -- internals ------------------------------------------------------------

    @contextmanager
    def _session(self) -> Iterator[tuple[object, object]]:
        pin = self._pin_provider()
        if not pin:
            raise HSMLockedError()
        pkcs11, lib = _load_pkcs11_library(self._lib_path)
        token, _ = self._resolve_token(lib, pkcs11)
        try:
            with token.open(user_pin=pin, rw=True) as session:
                yield session, pkcs11
        except pkcs11.exceptions.PKCS11Error as exc:
            raise PKCS11Error(f"PKCS#11 session failed: {_pkcs11_error_detail(exc)}") from exc

    def _resolve_token(self, lib, pkcs11):
        tokens = self._present_tokens(lib, pkcs11)
        if not tokens:
            raise PKCS11Error("No PKCS#11 token is present")
        expected = _normalize_token_label(self._token_label)
        matches = [
            token
            for token in tokens
            if _normalize_token_label(getattr(token, "label", "")) == expected
        ]
        if len(matches) == 1:
            return matches[0], False
        if len(matches) > 1:
            raise PKCS11Error(f"Multiple tokens labelled '{self._token_label}'")
        if len(tokens) == 1:
            return tokens[0], True
        available = ", ".join(
            repr(_display_token_label(getattr(token, "label", ""))) for token in tokens
        )
        raise PKCS11Error(
            f"No PKCS#11 token labelled '{self._token_label}'. Available token labels: {available}"
        )

    @staticmethod
    def _present_tokens(lib, pkcs11):
        tokens = []
        for slot in lib.get_slots():
            try:
                tokens.append(slot.get_token())
            except pkcs11.exceptions.TokenNotPresent:
                continue
        return tokens

    @staticmethod
    def _token_info(token, pkcs11) -> dict[str, object]:
        flags = token.flags
        serial = (
            token.serial.decode(errors="replace")
            if isinstance(token.serial, bytes)
            else token.serial
        )
        return {
            "label": _display_token_label(token.label),
            "manufacturer": token.manufacturer_id,
            "model": token.model,
            "serial": serial,
            "initialized": bool(flags & pkcs11.TokenFlag.TOKEN_INITIALIZED),
            "login_required": bool(flags & pkcs11.TokenFlag.LOGIN_REQUIRED),
            "user_pin_initialized": bool(flags & pkcs11.TokenFlag.USER_PIN_INITIALIZED),
        }

    def _generate_keypair(self, session, pkcs11, label, algorithm, *, store):
        key_id = _allocate_key_id(session, pkcs11) if store else None
        key_options = {"label": label, "store": store}
        if key_id is not None:
            key_options["id"] = key_id
        if algorithm.startswith("rsa-"):
            bits = int(algorithm.split("-", 1)[1])
            return session.generate_keypair(
                pkcs11.KeyType.RSA, bits, **key_options
            )
        if algorithm in _EC_CURVE_NAME:
            from pkcs11.util.ec import encode_named_curve_parameters

            params = session.create_domain_parameters(
                pkcs11.KeyType.EC,
                {pkcs11.Attribute.EC_PARAMS: encode_named_curve_parameters(_EC_CURVE_NAME[algorithm])},
                local=True,
            )
            return params.generate_keypair(**key_options)
        raise ValueError(f"Unsupported key algorithm: {algorithm}")

    def _sign_tbs(self, session, pkcs11, key_ref, tbs: bytes, pub) -> bytes:
        priv = self._require(session, pkcs11, key_ref, pkcs11.ObjectClass.PRIVATE_KEY)
        if isinstance(pub, rsa.RSAPublicKey):
            return priv.sign(tbs, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS)
        raw = priv.sign(tbs, mechanism=pkcs11.Mechanism.ECDSA_SHA256)
        return _raw_ecdsa_to_der(raw)

    def _verify_imported_objects(
        self,
        public_object,
        private_object,
        expected_public_key: CertificatePublicKeyTypes,
        pkcs11,
    ) -> None:
        actual_public_key = self._to_public_key(public_object, pkcs11)
        if not public_keys_match(actual_public_key, expected_public_key):
            raise KeyImportError("PKCS#11 token returned a different imported public key")
        challenge = b"myOwnCA PKCS11 import proof v1\x00" + os.urandom(32)
        try:
            if isinstance(actual_public_key, rsa.RSAPublicKey):
                signature = private_object.sign(
                    challenge,
                    mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS,
                )
                actual_public_key.verify(
                    signature,
                    challenge,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            else:
                raw_signature = private_object.sign(
                    challenge,
                    mechanism=pkcs11.Mechanism.ECDSA_SHA256,
                )
                actual_public_key.verify(
                    _raw_ecdsa_to_der(raw_signature),
                    challenge,
                    ec.ECDSA(hashes.SHA256()),
                )
        except Exception as exc:
            raise KeyImportError("Imported PKCS#11 key failed its signing proof") from exc

    @staticmethod
    def _find(session, pkcs11, label):
        objects = list(session.get_objects({pkcs11.Attribute.LABEL: label}))
        return objects[0] if objects else None

    @staticmethod
    def _require(session, pkcs11, label, klass):
        try:
            return session.get_key(object_class=klass, label=label)
        except pkcs11.exceptions.NoSuchKey as exc:
            raise KeyError(f"Unknown key reference: {label}") from exc

    @staticmethod
    def _to_public_key(pub, pkcs11) -> CertificatePublicKeyTypes:
        if pub.key_type == pkcs11.KeyType.RSA:
            modulus = int.from_bytes(pub[pkcs11.Attribute.MODULUS], "big")
            exponent = int.from_bytes(pub[pkcs11.Attribute.PUBLIC_EXPONENT], "big")
            return rsa.RSAPublicNumbers(exponent, modulus).public_key()
        if pub.key_type == pkcs11.KeyType.EC:
            curve = _curve_from_ec_params(bytes(pub[pkcs11.Attribute.EC_PARAMS]))
            point = _read_octet_string(bytes(pub[pkcs11.Attribute.EC_POINT]))
            return ec.EllipticCurvePublicKey.from_encoded_point(curve(), point)
        raise PKCS11Error(f"Unsupported PKCS#11 key type: {pub.key_type}")


# -- import templates ---------------------------------------------------------


def _allocate_key_id(session, pkcs11) -> bytes:
    """Allocate a compact PKCS#11 ID for reliable native inventory matching."""

    used: set[int] = set()
    for obj in session.get_objects({}):
        try:
            object_id = bytes(obj[pkcs11.Attribute.ID])
        except Exception:  # noqa: BLE001 - CKA_ID is optional on PKCS#11 objects
            continue
        if len(object_id) == 1 and 1 <= object_id[0] <= 255:
            used.add(object_id[0])
    for reference in range(1, 256):
        if reference not in used:
            return bytes((reference,))
    raise PKCS11Error("No free SmartCard-HSM key reference is available")


def _import_templates(
    pkcs11,
    *,
    label: str,
    key_id: bytes,
    private_key: CertificateIssuerPrivateKeyTypes,
    certificate: x509.Certificate | None,
) -> _ImportTemplates:
    """Build conservative PKCS#11 v2.40 C_CreateObject templates."""

    common = {
        pkcs11.Attribute.TOKEN: True,
        pkcs11.Attribute.LABEL: label,
        pkcs11.Attribute.ID: key_id,
    }
    public_common = {
        **common,
        pkcs11.Attribute.PRIVATE: False,
        pkcs11.Attribute.VERIFY: True,
    }
    private_common = {
        **common,
        pkcs11.Attribute.PRIVATE: True,
        pkcs11.Attribute.SENSITIVE: True,
        pkcs11.Attribute.EXTRACTABLE: False,
        pkcs11.Attribute.SIGN: True,
    }

    if isinstance(private_key, rsa.RSAPrivateKey):
        numbers = private_key.private_numbers()
        public_numbers = numbers.public_numbers
        public_template = {
            **public_common,
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY,
            pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
            pkcs11.Attribute.MODULUS: _pkcs11_integer(public_numbers.n),
            pkcs11.Attribute.PUBLIC_EXPONENT: _pkcs11_integer(public_numbers.e),
        }
        private_template = {
            **private_common,
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
            pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
            pkcs11.Attribute.MODULUS: _pkcs11_integer(public_numbers.n),
            pkcs11.Attribute.PUBLIC_EXPONENT: _pkcs11_integer(public_numbers.e),
            pkcs11.Attribute.PRIVATE_EXPONENT: _pkcs11_integer(numbers.d),
            pkcs11.Attribute.PRIME_1: _pkcs11_integer(numbers.p),
            pkcs11.Attribute.PRIME_2: _pkcs11_integer(numbers.q),
            pkcs11.Attribute.EXPONENT_1: _pkcs11_integer(numbers.dmp1),
            pkcs11.Attribute.EXPONENT_2: _pkcs11_integer(numbers.dmq1),
            pkcs11.Attribute.COEFFICIENT: _pkcs11_integer(numbers.iqmp),
        }
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        try:
            ec_params = _EC_PARAMS_BY_CURVE_NAME[private_key.curve.name]
        except KeyError as exc:  # validate_imported_key normally rejects first
            raise KeyImportError("Unsupported EC curve for PKCS#11 import") from exc
        point = private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        scalar_width = (private_key.curve.key_size + 7) // 8
        scalar = private_key.private_numbers().private_value.to_bytes(scalar_width, "big")
        public_template = {
            **public_common,
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY,
            pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC,
            pkcs11.Attribute.EC_PARAMS: ec_params,
            pkcs11.Attribute.EC_POINT: _encode_tlv(0x04, point),
        }
        private_template = {
            **private_common,
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
            pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC,
            pkcs11.Attribute.EC_PARAMS: ec_params,
            pkcs11.Attribute.VALUE: scalar,
        }
    else:  # pragma: no cover - validate_imported_key rejects this first
        raise KeyImportError("Only RSA and EC private keys can be imported")

    certificate_template = None
    if certificate is not None:
        certificate_template = {
            **common,
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE,
            pkcs11.Attribute.CERTIFICATE_TYPE: pkcs11.CertificateType.X_509,
            pkcs11.Attribute.PRIVATE: False,
            pkcs11.Attribute.SUBJECT: certificate.subject.public_bytes(),
            pkcs11.Attribute.ISSUER: certificate.issuer.public_bytes(),
            pkcs11.Attribute.SERIAL_NUMBER: _der_positive_integer(
                certificate.serial_number
            ),
            pkcs11.Attribute.VALUE: certificate.public_bytes(serialization.Encoding.DER),
        }
    return _ImportTemplates(public_template, private_template, certificate_template)


def _pkcs11_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("PKCS#11 integers must be positive")
    width = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(width, "big")


def _der_positive_integer(value: int) -> bytes:
    encoded = _pkcs11_integer(value)
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _encode_tlv(0x02, encoded)


def _object_id(obj, pkcs11) -> bytes | None:
    try:
        return bytes(obj[pkcs11.Attribute.ID])
    except Exception:  # noqa: BLE001 - CKA_ID is optional/advisory for listing
        return None


# -- module-level crypto/DER helpers ------------------------------------------


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode_result(value: object) -> bytes:
    if not isinstance(value, str):
        raise PKCS11Error("PKCS#11 worker returned invalid binary data")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise PKCS11Error("PKCS#11 worker returned malformed binary data") from exc


def _hash_for(public_key) -> hashes.HashAlgorithm:
    return hashes.SHA256()


def _dummy_key(public_key) -> CertificateIssuerPrivateKeyTypes:
    if isinstance(public_key, rsa.RSAPublicKey):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return ec.generate_private_key(public_key.curve)
    raise PKCS11Error("Unsupported issuer key type for signing")


def _raw_ecdsa_to_der(raw: bytes) -> bytes:
    half = len(raw) // 2
    r = int.from_bytes(raw[:half], "big")
    s = int.from_bytes(raw[half:], "big")
    return encode_dss_signature(r, s)


def _curve_from_ec_params(ec_params: bytes):
    try:
        return _CURVE_BY_EC_PARAMS[ec_params]
    except KeyError as exc:
        raise PKCS11Error("Unsupported EC curve on token") from exc


def _read_octet_string(der: bytes) -> bytes:
    if not der or der[0] != 0x04:
        raise PKCS11Error("Malformed EC point: expected DER OCTET STRING")
    length, idx = _read_length(der, 1)
    return der[idx : idx + length]


def _splice_signature(der: bytes, signature: bytes) -> bytes:
    # Certificate / CRL / CSR all share SEQUENCE{ info, sigAlg, BIT STRING signature }.
    tag, content, _ = _read_tlv(der, 0)
    if tag != 0x30:
        raise PKCS11Error("Malformed DER: expected outer SEQUENCE")
    info, off = _read_element(content, 0)
    sig_alg, off = _read_element(content, off)
    new_signature = _encode_tlv(0x03, b"\x00" + signature)  # BIT STRING, 0 unused bits
    return _encode_tlv(0x30, info + sig_alg + new_signature)


def _splice_tbs_and_signature(der: bytes, tbs: bytes, signature: bytes) -> bytes:
    tag, content, _ = _read_tlv(der, 0)
    if tag != 0x30:
        raise PKCS11Error("Malformed DER: expected outer SEQUENCE")
    _, off = _read_element(content, 0)
    sig_alg, off = _read_element(content, off)
    new_signature = _encode_tlv(0x03, b"\x00" + signature)  # BIT STRING, 0 unused bits
    return _encode_tlv(0x30, tbs + sig_alg + new_signature)


def _csr_tbs_with_public_key(tbs: bytes, public_key_der: bytes) -> bytes:
    tag, content, _ = _read_tlv(tbs, 0)
    if tag != 0x30:
        raise PKCS11Error("Malformed CSR info: expected SEQUENCE")
    version, off = _read_element(content, 0)
    subject, off = _read_element(content, off)
    _, off = _read_element(content, off)
    return _encode_tlv(0x30, version + subject + public_key_der + content[off:])


def _read_length(data: bytes, idx: int) -> tuple[int, int]:
    first = data[idx]
    idx += 1
    if first < 0x80:
        return first, idx
    count = first & 0x7F
    return int.from_bytes(data[idx : idx + count], "big"), idx + count


def _read_tlv(data: bytes, idx: int) -> tuple[int, bytes, int]:
    tag = data[idx]
    length, body = _read_length(data, idx + 1)
    return tag, data[body : body + length], body + length


def _read_element(data: bytes, idx: int) -> tuple[bytes, int]:
    length, body = _read_length(data, idx + 1)
    end = body + length
    return data[idx:end], end


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _encode_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(content)) + content


def _key_type_name(key_type, pkcs11) -> str:
    if key_type == pkcs11.KeyType.RSA:
        return "RSA"
    if key_type == pkcs11.KeyType.EC:
        return "EC"
    return str(key_type)


def _key_size(obj, pkcs11) -> int | None:
    try:
        if obj.key_type == pkcs11.KeyType.RSA:
            return len(bytes(obj[pkcs11.Attribute.MODULUS])) * 8
        if obj.key_type == pkcs11.KeyType.EC:
            curve = _curve_from_ec_params(bytes(obj[pkcs11.Attribute.EC_PARAMS]))
            return curve().key_size
    except Exception:  # noqa: BLE001 - size is advisory metadata only
        return None
    return None
