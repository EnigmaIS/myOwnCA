import datetime
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from myownca_core.leaf import (
    CSRValidationError, IssuerValidityError, LeafProfile, build_leaf, validate_leaf_csr,
    validate_issuer_validity,
)


class _SoftwareSigner:
    """Test Signer: signs the prepared builder with an in-memory issuer key (no HSM)."""

    def __init__(self, key):
        self._key = key

    def sign_certificate(self, builder, key_ref):
        return builder.sign(self._key, hashes.SHA256())


def _tls_key_usage():
    return x509.KeyUsage(
        digital_signature=True, content_commitment=False, key_encipherment=True,
        data_encipherment=False, key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=None, decipher_only=None)


def _issuer(*, starts_at=None, expires_at=None):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuer")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(starts_at or now - datetime.timedelta(days=1))
            .not_valid_after(expires_at or now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, _SoftwareSigner(key)


_NOW = datetime.datetime(2026, 9, 16, 12, tzinfo=datetime.timezone.utc)
_DAY = datetime.timedelta(days=1)
_SECOND = datetime.timedelta(seconds=1)


@pytest.mark.parametrize(
    "starts_at,expires_at,code",
    [
        (_NOW - _DAY, _NOW + _DAY, "issuer_validity_exceeded"),
        (_NOW - _DAY, _NOW + 365 * _DAY - _SECOND, "issuer_validity_exceeded"),
        (_NOW - _DAY, _NOW, "issuer_expired"),
        (_NOW - _DAY, _NOW - _SECOND, "issuer_expired"),
        (_NOW + _SECOND, _NOW + 366 * _DAY, "issuer_not_yet_valid"),
    ],
)
def test_leaf_rejects_unusable_issuer_before_signing(starts_at, expires_at, code):
    issuer, signer = _issuer(starts_at=starts_at, expires_at=expires_at)
    with mock.patch.object(signer, "sign_certificate", wraps=signer.sign_certificate) as sign:
        with pytest.raises(IssuerValidityError) as error:
            build_leaf(_csr(), _profile(validity_days=365), issuer_certificate=issuer,
                       issuer_key_ref="k", signer=signer, now=_NOW)
        assert error.value.code == code
        assert "CA" in str(error.value)
        sign.assert_not_called()


@pytest.mark.parametrize("elapsed", [datetime.timedelta(0), datetime.timedelta(minutes=2), _DAY])
@pytest.mark.parametrize("now", [
    _NOW,
    _NOW.replace(tzinfo=None),
    _NOW.astimezone(datetime.timezone(datetime.timedelta(hours=2))),
    _NOW.replace(microsecond=999999),
])
def test_exact_expiry_and_backdating_preserve_requested_lifetime(elapsed, now):
    issuer, signer = _issuer(starts_at=_NOW - elapsed, expires_at=_NOW + 365 * _DAY)
    cert = build_leaf(_csr(), _profile(validity_days=365), issuer_certificate=issuer,
                      issuer_key_ref="k", signer=signer, now=now)
    assert cert.not_valid_after_utc == issuer.not_valid_after_utc
    assert cert.not_valid_after_utc - _NOW == 365 * _DAY
    assert cert.not_valid_before_utc == max(
        issuer.not_valid_before_utc, _NOW - datetime.timedelta(minutes=5)
    )


def test_direct_leaf_builder_rechecks_clock_after_signing():
    issuer, signer = _issuer(starts_at=_NOW - _DAY, expires_at=_NOW + _DAY)
    with mock.patch("myownca_core.leaf._utc_now", side_effect=[_NOW, _NOW + _DAY]):
        with pytest.raises(IssuerValidityError) as error:
            build_leaf(_csr(), _profile(validity_days=1), issuer_certificate=issuer,
                       issuer_key_ref="k", signer=signer)
    assert error.value.code == "issuer_expired"


@pytest.mark.parametrize("offset,code", [
    (datetime.timedelta(microseconds=-1), "issuer_not_yet_valid"),
    (datetime.timedelta(0), None),
    (_DAY - datetime.timedelta(microseconds=1), None),
    (_DAY, "issuer_expired"),
    (_DAY + datetime.timedelta(microseconds=1), "issuer_expired"),
])
def test_issuer_clock_boundaries_at_subsecond_precision(offset, code):
    issuer, _ = _issuer(starts_at=_NOW, expires_at=_NOW + _DAY)
    if code is None:
        validate_issuer_validity(issuer, now=_NOW + offset)
    else:
        with pytest.raises(IssuerValidityError) as error:
            validate_issuer_validity(issuer, now=_NOW + offset)
        assert error.value.code == code


def test_rejects_signer_result_outside_issuer_interval():
    issuer, _ = _issuer(starts_at=_NOW - _DAY, expires_at=_NOW + _DAY)
    wrong_result, _ = _issuer(starts_at=_NOW, expires_at=_NOW + 2 * _DAY)
    signer = mock.Mock(sign_certificate=mock.Mock(return_value=wrong_result))
    with pytest.raises(IssuerValidityError) as error:
        build_leaf(_csr(), _profile(validity_days=1), issuer_certificate=issuer,
                   issuer_key_ref="k", signer=signer, now=_NOW)
    assert error.value.code == "issuer_validity_exceeded"


def _csr(cn="device-01.devices.test", sans=None, request_ca=False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]) if cn else x509.Name([])
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    if sans is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    if request_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(key, hashes.SHA256())


def _profile(**kw):
    base = dict(validity_days=90, key_usage=_tls_key_usage(),
                extended_key_usages=(ExtendedKeyUsageOID.SERVER_AUTH,))
    base.update(kw)
    return LeafProfile(**base)


def test_build_leaf_basic_extensions():
    issuer_cert, signer = _issuer()
    cert = build_leaf(_csr(sans=[x509.DNSName("device-01.devices.test")]), _profile(),
                      issuer_certificate=issuer_cert, issuer_key_ref="k", signer=signer)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature and ku.key_encipherment and not ku.key_cert_sign
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    expected = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key())
    assert aki.key_identifier == expected.key_identifier
    cert.verify_directly_issued_by(issuer_cert)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["device-01.devices.test"]


def test_eku_omitted_when_empty():
    issuer_cert, signer = _issuer()
    cert = build_leaf(_csr(), _profile(extended_key_usages=()),
                      issuer_certificate=issuer_cert, issuer_key_ref="k", signer=signer)
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)


def test_cdp_and_aia_present_only_with_urls():
    issuer_cert, signer = _issuer()
    cert = build_leaf(_csr(), _profile(),
                      issuer_certificate=issuer_cert, issuer_key_ref="k", signer=signer,
                      crl_url="http://crl.example/c.crl", ocsp_url="http://ocsp.example",
                      ca_issuers_url="http://aia.example/i.cer")
    cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert cdp[0].full_name[0].value == "http://crl.example/c.crl"
    aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    methods = {ad.access_method for ad in aia}
    assert AuthorityInformationAccessOID.OCSP in methods
    assert AuthorityInformationAccessOID.CA_ISSUERS in methods
    bare = build_leaf(_csr(), _profile(), issuer_certificate=issuer_cert, issuer_key_ref="k", signer=signer)
    with pytest.raises(x509.ExtensionNotFound):
        bare.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    with pytest.raises(x509.ExtensionNotFound):
        bare.extensions.get_extension_for_class(x509.AuthorityInformationAccess)


def test_required_san_type_enforced():
    issuer_cert, signer = _issuer()
    p = _profile(required_san_types=(x509.DNSName,))
    with pytest.raises(CSRValidationError):
        build_leaf(_csr(sans=None), p, issuer_certificate=issuer_cert, issuer_key_ref="k", signer=signer)
    with pytest.raises(CSRValidationError):
        build_leaf(_csr(sans=[x509.RFC822Name("a@b.test")]), p,
                   issuer_certificate=issuer_cert, issuer_key_ref="k", signer=signer)
    ok = build_leaf(_csr(sans=[x509.DNSName("x.devices.test")]), p,
                    issuer_certificate=issuer_cert, issuer_key_ref="k", signer=signer)
    assert ok.subject.get_attributes_for_oid(NameOID.COMMON_NAME)


def test_leaf_csr_can_be_validated_without_signing():
    profile = _profile(
        required_san_types=(x509.RFC822Name,),
        allowed_san_types=(x509.RFC822Name,),
    )
    with pytest.raises(CSRValidationError, match="email SAN"):
        validate_leaf_csr(_csr(sans=[x509.DNSName("wrong.example.test")]), profile)
    assert validate_leaf_csr(_csr(sans=[x509.RFC822Name("alice@example.test")]), profile) is None


def test_allowed_san_type_rejected():
    issuer_cert, signer = _issuer()
    p = _profile(allowed_san_types=(x509.DNSName,))
    with pytest.raises(CSRValidationError):
        build_leaf(_csr(sans=[x509.DNSName("ok.test"), x509.RFC822Name("no@test")]), p,
                   issuer_certificate=issuer_cert, issuer_key_ref="k", signer=signer)


def test_csr_requesting_ca_rejected():
    issuer_cert, signer = _issuer()
    with pytest.raises(CSRValidationError):
        build_leaf(_csr(request_ca=True), _profile(),
                   issuer_certificate=issuer_cert, issuer_key_ref="k", signer=signer)


def test_missing_cn_rejected():
    issuer_cert, signer = _issuer()
    with pytest.raises(CSRValidationError):
        build_leaf(_csr(cn=None), _profile(),
                   issuer_certificate=issuer_cert, issuer_key_ref="k", signer=signer)
