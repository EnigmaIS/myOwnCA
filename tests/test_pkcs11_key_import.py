from __future__ import annotations

import contextlib
import datetime
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from myownca.ca_hsm.pkcs11 import (
    PKCS11Error,
    PKCS11PartialImportError,
    _allocate_key_id,
    _import_templates,
    _InProcessPKCS11HSM,
    _parse_pkcs15_private_keys,
    _PKCS15PrivateKey,
    _read_octet_string,
)


class _Attribute:
    TOKEN = "token"
    LABEL = "label"
    ID = "id"
    PRIVATE = "private"
    VERIFY = "verify"
    SENSITIVE = "sensitive"
    EXTRACTABLE = "extractable"
    SIGN = "sign"
    CLASS = "class"
    KEY_TYPE = "key-type"
    MODULUS = "modulus"
    PUBLIC_EXPONENT = "public-exponent"
    PRIVATE_EXPONENT = "private-exponent"
    PRIME_1 = "prime-1"
    PRIME_2 = "prime-2"
    EXPONENT_1 = "exponent-1"
    EXPONENT_2 = "exponent-2"
    COEFFICIENT = "coefficient"
    EC_PARAMS = "ec-params"
    EC_POINT = "ec-point"
    VALUE = "value"
    CERTIFICATE_TYPE = "certificate-type"
    SUBJECT = "subject"
    ISSUER = "issuer"
    SERIAL_NUMBER = "serial-number"


class _ObjectClass:
    PUBLIC_KEY = "public-key"
    PRIVATE_KEY = "private-key"
    CERTIFICATE = "certificate"


class _KeyType:
    RSA = "rsa"
    EC = "ec"


class _Mechanism:
    SHA256_RSA_PKCS = "sha256-rsa-pkcs"
    ECDSA_SHA256 = "ecdsa-sha256"


class _CertificateType:
    X_509 = "x509"


class _FakePkcs11:
    Attribute = _Attribute
    ObjectClass = _ObjectClass
    KeyType = _KeyType
    Mechanism = _Mechanism
    CertificateType = _CertificateType


def _certificate(private_key) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PKCS11 import")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(129)
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )


class _TokenObject:
    def __init__(self, template, private_key, *, fail_destroy: bool = False) -> None:
        self.template = template
        self.private_key = private_key
        self.key_type = template.get(_Attribute.KEY_TYPE)
        self.label = template.get(_Attribute.LABEL)
        self.destroyed = False
        self.fail_destroy = fail_destroy

    def __getitem__(self, attribute):
        return self.template[attribute]

    def sign(self, payload: bytes, *, mechanism, mechanism_param=None) -> bytes:
        if mechanism == _Mechanism.SHA256_RSA_PKCS:
            return self.private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        if mechanism == _Mechanism.ECDSA_SHA256:
            der = self.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
            from cryptography.hazmat.primitives.asymmetric.utils import (  # noqa: PLC0415
                decode_dss_signature,
            )

            r, s = decode_dss_signature(der)
            width = (self.private_key.curve.key_size + 7) // 8
            return r.to_bytes(width, "big") + s.to_bytes(width, "big")
        raise AssertionError(mechanism)

    def destroy(self) -> None:
        if self.fail_destroy:
            raise RuntimeError("token refused destroy")
        self.destroyed = True


class _SessionBoundTokenObject:
    """Expose a provider-like invalid-handle failure after session close."""

    def __init__(self, template) -> None:
        self.template = template
        self.key_type = template.get(_Attribute.KEY_TYPE)
        self._label = template.get(_Attribute.LABEL)
        self.closed = False
        self.destroyed = False

    @property
    def label(self):
        if self.closed:
            raise RuntimeError("SessionHandleInvalid")
        return self._label

    def __getitem__(self, attribute):
        return self.template[attribute]


class _Session:
    def __init__(
        self,
        private_key,
        *,
        fail_on_class: str | None = None,
        fail_destroy_class: str | None = None,
    ) -> None:
        self.private_key = private_key
        self.fail_on_class = fail_on_class
        self.fail_destroy_class = fail_destroy_class
        self.objects: list[_TokenObject] = []
        self.templates: list[dict[object, object]] = []

    def get_objects(self, query=None):
        query = query or {}
        return [
            item
            for item in self.objects
            if not item.destroyed
            and all(item.template.get(attribute) == value for attribute, value in query.items())
        ]

    def create_object(self, template):
        object_class = template[_Attribute.CLASS]
        if object_class == self.fail_on_class:
            raise RuntimeError("unsupported create object")
        item = _TokenObject(
            template,
            self.private_key,
            fail_destroy=object_class == self.fail_destroy_class,
        )
        self.templates.append(template)
        self.objects.append(item)
        return item


class _GenerateSession(_Session):
    def generate_keypair(self, *args, **kwargs):
        self.generate_args = args
        self.generate_kwargs = kwargs
        return object(), object()


@contextlib.contextmanager
def _session_context(session):
    yield session, _FakePkcs11


@contextlib.contextmanager
def _expiring_session_context(session):
    try:
        yield session, _FakePkcs11
    finally:
        session.object.closed = True


def test_rsa_templates_are_sensitive_nonextractable_and_share_id() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    templates = _import_templates(
        _FakePkcs11,
        label="subca",
        key_id=b"\x10\x20",
        private_key=key,
        certificate=_certificate(key),
    )

    assert templates.private_key[_Attribute.SENSITIVE] is True
    assert templates.private_key[_Attribute.EXTRACTABLE] is False
    assert templates.private_key[_Attribute.PRIVATE] is True
    assert templates.private_key[_Attribute.SIGN] is True
    assert templates.public_key[_Attribute.VERIFY] is True
    assert templates.public_key[_Attribute.ID] == b"\x10\x20"
    assert templates.private_key[_Attribute.ID] == b"\x10\x20"
    assert templates.certificate is not None
    assert templates.certificate[_Attribute.ID] == b"\x10\x20"
    # Serial 129 must be a positive DER INTEGER with a leading zero.
    assert templates.certificate[_Attribute.SERIAL_NUMBER] == b"\x02\x02\x00\x81"


def test_pkcs11_id_allocator_uses_free_single_byte_id() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    session = _Session(key)
    session.create_object(
        {
            _Attribute.CLASS: _ObjectClass.PRIVATE_KEY,
            _Attribute.ID: b"\x01",
        }
    )
    session.create_object(
        {
            _Attribute.CLASS: _ObjectClass.PUBLIC_KEY,
            _Attribute.ID: b"\x02\x03",
        }
    )
    assert _allocate_key_id(session, _FakePkcs11) == b"\x02"


def test_list_keys_reports_pkcs15_key_reference_not_pkcs11_object_id() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    session = _Session(key)
    session.create_object(
        {
            _Attribute.CLASS: _ObjectClass.PRIVATE_KEY,
            _Attribute.KEY_TYPE: _KeyType.EC,
            _Attribute.LABEL: "subca",
            _Attribute.ID: b"\x2A",
        }
    )
    hsm = _InProcessPKCS11HSM("module", "token", pin_provider=lambda: "123456")

    with (
        mock.patch.object(hsm, "_session", return_value=_session_context(session)),
        mock.patch(
            "myownca.ca_hsm.pkcs11._read_pkcs15_private_keys",
            return_value=[
                _PKCS15PrivateKey(key_reference=1, object_id=b"\x2A", label="subca")
            ],
        ),
    ):
        keys = hsm.list_keys()

    assert keys[0]["id"] == "2a"
    assert keys[0]["key_reference"] == 1


def test_list_keys_can_match_native_reference_by_label_when_id_is_absent() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    session = _Session(key)
    session.create_object(
        {
            _Attribute.CLASS: _ObjectClass.PRIVATE_KEY,
            _Attribute.KEY_TYPE: _KeyType.EC,
            _Attribute.LABEL: "external-key",
        }
    )
    hsm = _InProcessPKCS11HSM("module", "token", pin_provider=lambda: "123456")

    with (
        mock.patch.object(hsm, "_session", return_value=_session_context(session)),
        mock.patch(
            "myownca.ca_hsm.pkcs11._read_pkcs15_private_keys",
            return_value=[
                _PKCS15PrivateKey(key_reference=7, object_id=None, label="external-key")
            ],
        ),
    ):
        keys = hsm.list_keys()

    assert keys[0]["key_reference"] == 7


def test_list_keys_copies_provider_metadata_before_closing_session() -> None:
    object_id = b"\x2A"
    token_object = _SessionBoundTokenObject(
        {
            _Attribute.CLASS: _ObjectClass.PRIVATE_KEY,
            _Attribute.KEY_TYPE: _KeyType.EC,
            _Attribute.LABEL: "subca",
            _Attribute.ID: object_id,
            _Attribute.EC_PARAMS: bytes.fromhex("06082a8648ce3d030107"),
        }
    )

    class _SingleObjectSession:
        object = token_object

        def get_objects(self, query=None):
            return [self.object]

    hsm = _InProcessPKCS11HSM("module", "token", pin_provider=lambda: "123456")
    with (
        mock.patch.object(hsm, "_session", return_value=_expiring_session_context(_SingleObjectSession())),
        mock.patch(
            "myownca.ca_hsm.pkcs11._read_pkcs15_private_keys",
            return_value=[
                _PKCS15PrivateKey(key_reference=1, object_id=object_id, label="subca")
            ],
        ),
    ):
        assert hsm.list_keys() == [
            {
                "label": "subca",
                "key_type": "EC",
                "key_size": 256,
                "id": "2a",
                "key_reference": 1,
            }
        ]


def test_pkcs15_parser_distinguishes_native_key_reference_from_object_id() -> None:
    records = _parse_pkcs15_private_keys(
        """
        Private EC Key [subca]
                Key ref        : 1 (0x1)
                ID             : 2A
        Private RSA Key [other]
                Key ref        : 42 (0x2A)
                ID             : 10
        """
    )

    assert records == [
        _PKCS15PrivateKey(key_reference=1, object_id=b"\x2A", label="subca"),
        _PKCS15PrivateKey(key_reference=42, object_id=b"\x10", label="other"),
    ]


def test_generated_keypair_receives_native_reference_id() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    session = _GenerateSession(key)
    hsm = _InProcessPKCS11HSM("module", "token", pin_provider=lambda: "123456")

    hsm._generate_keypair(session, _FakePkcs11, "generated", "rsa-2048", store=True)

    assert session.generate_kwargs["id"] == b"\x01"


def test_ec_templates_use_der_octet_point_and_fixed_width_scalar() -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    templates = _import_templates(
        _FakePkcs11,
        label="ec-subca",
        key_id=b"id",
        private_key=key,
        certificate=None,
    )

    expected_point = key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    assert _read_octet_string(templates.public_key[_Attribute.EC_POINT]) == expected_point
    assert len(templates.private_key[_Attribute.VALUE]) == 48
    assert templates.certificate is None


@pytest.mark.parametrize(
    "key",
    [
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        ec.generate_private_key(ec.SECP256R1()),
    ],
)
def test_pkcs11_import_creates_pair_certificate_and_runs_signing_proof(key) -> None:
    session = _Session(key)
    hsm = _InProcessPKCS11HSM("module", "token", pin_provider=lambda: "123456")

    with mock.patch.object(hsm, "_session", return_value=_session_context(session)):
        assert hsm.import_key("imported", key, _certificate(key)) == "imported"

    assert [item[_Attribute.CLASS] for item in session.templates] == [
        _ObjectClass.PUBLIC_KEY,
        _ObjectClass.PRIVATE_KEY,
        _ObjectClass.CERTIFICATE,
    ]
    ids = {item[_Attribute.ID] for item in session.templates}
    assert len(ids) == 1
    assert next(iter(ids)) == b"\x01"
    assert all(not item.destroyed for item in session.objects)


def test_pkcs11_import_rolls_back_pair_if_certificate_object_is_unsupported() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    session = _Session(key, fail_on_class=_ObjectClass.CERTIFICATE)
    hsm = _InProcessPKCS11HSM("module", "token", pin_provider=lambda: "123456")

    with mock.patch.object(hsm, "_session", return_value=_session_context(session)):
        with pytest.raises(PKCS11Error, match="RuntimeError") as caught:
            hsm.import_key("rollback", key, _certificate(key))

    assert all(item.destroyed for item in session.objects)
    assert "unsupported create object" not in str(caught.value)


def test_pkcs11_import_never_reflects_driver_secret_or_key_template() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    session = _Session(key)
    hsm = _InProcessPKCS11HSM("module", "token", pin_provider=lambda: "123456")

    secret = "PIN=123456 VALUE=private-scalar"
    with (
        mock.patch.object(hsm, "_session", return_value=_session_context(session)),
        mock.patch.object(session, "create_object", side_effect=RuntimeError(secret)),
    ):
        with pytest.raises(PKCS11Error) as caught:
            hsm.import_key("redacted", key, _certificate(key))

    assert secret not in str(caught.value)
    assert "123456" not in str(caught.value)
    assert "private-scalar" not in str(caught.value)
    assert "RuntimeError" in str(caught.value)


def test_pkcs11_partial_rollback_reports_remaining_object_type_and_reference() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    session = _Session(
        key,
        fail_on_class=_ObjectClass.CERTIFICATE,
        fail_destroy_class=_ObjectClass.PRIVATE_KEY,
    )
    hsm = _InProcessPKCS11HSM("module", "token", pin_provider=lambda: "123456")

    with mock.patch.object(hsm, "_session", return_value=_session_context(session)):
        with pytest.raises(PKCS11PartialImportError) as caught:
            hsm.import_key("partial", key, _certificate(key))

    assert caught.value.key_ref == "partial"
    assert caught.value.remaining_objects == ("private-key",)


def test_pkcs11_delete_key_reference_preserves_duplicate_label_at_other_id() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    session = _Session(key)
    for object_id in (b"\x07", b"\x21"):
        session.create_object(
            {
                _Attribute.CLASS: _ObjectClass.PRIVATE_KEY,
                _Attribute.KEY_TYPE: _KeyType.EC,
                _Attribute.LABEL: "issuer-key",
                _Attribute.ID: object_id,
            }
        )
        session.create_object(
            {
                _Attribute.CLASS: _ObjectClass.PUBLIC_KEY,
                _Attribute.KEY_TYPE: _KeyType.EC,
                _Attribute.LABEL: "issuer-key",
                _Attribute.ID: object_id,
            }
        )
    hsm = _InProcessPKCS11HSM("module", "token", pin_provider=lambda: "123456")

    with (
        mock.patch.object(hsm, "_session", return_value=_session_context(session)),
        mock.patch(
            "myownca.ca_hsm.pkcs11._read_pkcs15_private_keys",
            return_value=[
                _PKCS15PrivateKey(key_reference=33, object_id=b"\x21", label="issuer-key")
            ],
        ),
    ):
        assert hsm.delete_key_reference("0x21") == 2

    remaining = [item for item in session.objects if not item.destroyed]
    assert len(remaining) == 2
    assert {item[_Attribute.ID] for item in remaining} == {b"\x07"}
