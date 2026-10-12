from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from myownca.service_certs.base import (
    AcmeChallenge,
    ChallengeType,
    ServiceCertError,
    ServiceCertUnavailable,
)

# Publishes an HTTP-01 keyauthorization for a token and removes it afterwards.
Http01Publisher = Callable[[str, str], None]
Http01Cleanup = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class _Acme:
    client: object
    messages: object
    challenges: object
    josepy: object


def _load() -> _Acme:
    try:
        import josepy  # noqa: PLC0415
        from acme import challenges, client, messages  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - exercised only without the dep
        raise ServiceCertUnavailable(
            "ACME support is bundled with myownca; reinstall the complete distribution"
        ) from exc
    return _Acme(client=client, messages=messages, challenges=challenges, josepy=josepy)


class AcmeClient:
    """Thin wrapper over certbot's ``acme`` library (RFC 8555).

    Account keys are RSA-2048. HTTP-01 is fully automated; DNS-01 is two-phase
    (begin returns the TXT records to publish; complete answers and finalizes).
    """

    def __init__(self, user_agent: str = "myownca-acme") -> None:
        self._user_agent = user_agent

    @staticmethod
    def generate_account_key_pem() -> str:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    def register_account(self, directory_url: str, account_key_pem: str, contact: str) -> str:
        acme = _load()
        client, _ = self._client(acme, directory_url, account_key_pem)
        registration = acme.messages.NewRegistration.from_data(
            email=contact or None, terms_of_service_agreed=True
        )
        result = client.new_account(registration)
        return result.uri

    def order_http01(
        self,
        directory_url: str,
        account_key_pem: str,
        account_url: str,
        csr_pem: str,
        publisher: Http01Publisher,
        cleanup: Http01Cleanup,
    ) -> str:
        _order_url, order_json = self.begin_http01(
            directory_url, account_key_pem, account_url, csr_pem
        )
        return self.complete_http01(
            directory_url,
            account_key_pem,
            account_url,
            order_json,
            publisher,
            cleanup,
        )

    def begin_http01(
        self,
        directory_url: str,
        account_key_pem: str,
        account_url: str,
        csr_pem: str,
    ) -> tuple[str, str]:
        """Create an HTTP-01 order and return state that can be resumed."""
        acme = _load()
        client, _ = self._client(acme, directory_url, account_key_pem, account_url)
        order = client.new_order(csr_pem.encode())
        return order.uri, order.json_dumps()

    def complete_http01(
        self,
        directory_url: str,
        account_key_pem: str,
        account_url: str,
        order_json: str,
        publisher: Http01Publisher,
        cleanup: Http01Cleanup,
    ) -> str:
        """Answer and finalize an existing HTTP-01 order.

        The order is refreshed first.  If a prior worker finalized it but lost
        its lease before persisting the response, the existing certificate is
        downloaded instead of creating (or finalizing) a second order.
        """
        acme = _load()
        client, jwk = self._client(acme, directory_url, account_key_pem, account_url)
        published: list[str] = []
        try:
            order = acme.messages.OrderResource.json_loads(order_json)
            order, fullchain = _refresh_order(acme, client, order)
            if fullchain is not None:
                return fullchain
            if order.body.status == acme.messages.STATUS_PENDING:
                for authz in order.authorizations:
                    if authz.body.status == acme.messages.STATUS_VALID:
                        continue
                    challb = _select(acme, authz, ChallengeType.HTTP_01)
                    response, validation = challb.response_and_validation(jwk)
                    token = challb.chall.encode("token")
                    publisher(token, validation)
                    published.append(token)
                    client.answer_challenge(challb, response)
            finalized = _finalize_existing(acme, client, order)
        except Exception as exc:  # noqa: BLE001 - surface a clean module error
            raise ServiceCertError(f"ACME HTTP-01 order failed: {exc}") from exc
        finally:
            for token in published:
                cleanup(token)
        return finalized.fullchain_pem

    def begin_dns01(
        self, directory_url: str, account_key_pem: str, account_url: str, csr_pem: str
    ) -> tuple[str, str, list[AcmeChallenge]]:
        acme = _load()
        client, jwk = self._client(acme, directory_url, account_key_pem, account_url)
        order = client.new_order(csr_pem.encode())
        challenges_out: list[AcmeChallenge] = []
        for authz in order.authorizations:
            domain = authz.body.identifier.value
            challb = _select(acme, authz, ChallengeType.DNS_01)
            _, validation = challb.response_and_validation(jwk)
            challenges_out.append(
                AcmeChallenge(
                    domain=domain,
                    challenge_type=ChallengeType.DNS_01,
                    token=challb.chall.encode("token"),
                    key_authorization=validation,
                    dns_txt_value=validation,
                )
            )
        return order.uri, order.json_dumps(), challenges_out

    def complete_dns01(
        self, directory_url: str, account_key_pem: str, account_url: str, order_json: str
    ) -> str:
        acme = _load()
        client, jwk = self._client(acme, directory_url, account_key_pem, account_url)
        try:
            order = acme.messages.OrderResource.json_loads(order_json)
            order, fullchain = _refresh_order(acme, client, order)
            if fullchain is not None:
                return fullchain
            if order.body.status == acme.messages.STATUS_PENDING:
                for authz in order.authorizations:
                    if authz.body.status == acme.messages.STATUS_VALID:
                        continue
                    challb = _select(acme, authz, ChallengeType.DNS_01)
                    response, _ = challb.response_and_validation(jwk)
                    client.answer_challenge(challb, response)
            finalized = _finalize_existing(acme, client, order)
        except Exception as exc:  # noqa: BLE001
            raise ServiceCertError(f"ACME DNS-01 finalize failed: {exc}") from exc
        return finalized.fullchain_pem

    @staticmethod
    def dns_record_name(domain: str) -> str:
        return f"_acme-challenge.{domain}"

    # -- internals ------------------------------------------------------------

    def _client(self, acme: _Acme, directory_url: str, account_key_pem: str, account_url: str | None = None):
        key = serialization.load_pem_private_key(account_key_pem.encode(), password=None)
        jwk = acme.josepy.JWKRSA(key=key)
        net = acme.client.ClientNetwork(jwk, user_agent=self._user_agent)
        if account_url:
            net.account = acme.messages.RegistrationResource(
                uri=account_url, body=acme.messages.Registration()
            )
        directory = acme.client.ClientV2.get_directory(directory_url, net)
        return acme.client.ClientV2(directory, net=net), jwk


def _select(acme: _Acme, authz, challenge_type: ChallengeType):
    for challb in authz.body.challenges:
        if challb.chall.typ == challenge_type.value:
            return challb
    raise ServiceCertError(f"Authorization offers no {challenge_type.value} challenge")


def _refresh_order(acme: _Acme, client, order):
    """Return current server state and an already-issued chain, when present."""
    response = client._post_as_get(order.uri)  # noqa: SLF001 - no public ACME equivalent
    body = acme.messages.Order.from_json(response.json())
    if body.status == acme.messages.STATUS_VALID and body.certificate is not None:
        certificate = client._post_as_get(  # noqa: SLF001 - RFC POST-as-GET
            body.certificate
        )
        return order.update(body=body, fullchain_pem=certificate.text), certificate.text

    authorizations = []
    for url in body.authorizations:
        authorization_response = client._post_as_get(  # noqa: SLF001
            url
        )
        authorizations.append(
            client._authzr_from_response(  # noqa: SLF001
                authorization_response, uri=url
            )
        )
    return order.update(body=body, authorizations=authorizations), None


def _finalize_existing(acme: _Acme, client, order):
    deadline = datetime.now() + timedelta(seconds=90)
    if order.body.status == acme.messages.STATUS_PROCESSING:
        return client.poll_finalization(order, deadline)
    if order.body.status == acme.messages.STATUS_READY:
        return client.finalize_order(order, deadline)
    return client.poll_and_finalize(order, deadline)
