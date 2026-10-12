"""CA certificates must reach a holder as installable files.

A root that arrives inside a PKCS#12 is installed with the identity but is not
trusted: iOS only offers the trust toggle for a root installed as a certificate
in its own right. Devices therefore need the chain as separate .cer files, and
sometimes need only the chain -- before any certificate exists for them.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography import x509
from fastapi import HTTPException

from myownca.comms import NotificationChannel
from myownca.domain import Person, Role
from myownca.online.app import CACertificateSendRequest, create_app
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)

NOW = datetime.now(timezone.utc)
SEND = "/internal/ca-certificates/send"


class _Fixture:
    def __init__(self, tempdir: str, *, role: Role = Role.SUPERUSER) -> None:
        self.app = create_app(Path(tempdir) / "ca.sqlite3")
        secret = add_login_ready_user(
            self.app, user_id="u-1", email="u1@example.test", role=role
        )
        self.token, self.csrf = create_active_session(
            self.app, email="u1@example.test", totp_secret=secret
        )
        self.app.state.repository.add_person(
            Person(
                id="p1",
                name="Alice",
                surname="Ng",
                email="alice@example.test",
                created_at=NOW,
            )
        )

    def send(self, person_id: str = "p1"):
        return route_endpoint(self.app, SEND, "POST")(
            CACertificateSendRequest(person_id=person_id),
            request_with_session(self.token, self.csrf, method="POST"),
        )


class CaCertificateSendTests(unittest.TestCase):
    def test_the_chain_is_sent_as_individual_der_files(self) -> None:
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            sent: dict[str, object] = {}

            def capture(channel, recipient, message):
                sent["channel"] = channel
                sent["recipient"] = recipient
                sent["message"] = message
                return mock.MagicMock(success=True, detail="ok")

            with mock.patch.object(fixture.app.state.comms, "send", side_effect=capture):
                body = fixture.send()

            self.assertTrue(body["success"])
            self.assertEqual(sent["channel"], NotificationChannel.EMAIL)
            self.assertEqual(sent["recipient"], "alice@example.test")
            attachments = sent["message"].attachments
            names = [item.filename for item in attachments]
            self.assertIn("sub-ca.cer", names)
            self.assertIn("root-ca.cer", names)
            for item in attachments:
                self.assertEqual(item.media_type, "application/pkix-cert")
                # DER, not PEM: a device installs a .cer on open.
                self.assertFalse(item.content.startswith(b"-----BEGIN"))
                x509.load_der_x509_certificate(item.content)

    def test_no_end_entity_material_is_included(self) -> None:
        """The whole point of this route is that it carries only the chain."""
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            with mock.patch.object(
                fixture.app.state.comms, "send",
                side_effect=lambda c, r, m: mock.MagicMock(success=True, detail="ok"),
            ) as sent:
                fixture.send()
            message = sent.call_args.args[2]
            for item in message.attachments:
                certificate = x509.load_der_x509_certificate(item.content)
                basic = certificate.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value
                self.assertTrue(basic.ca, f"{item.filename} is not a CA certificate")

    def test_each_attachment_is_a_distinct_certificate(self) -> None:
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            with mock.patch.object(
                fixture.app.state.comms, "send",
                side_effect=lambda c, r, m: mock.MagicMock(success=True, detail="ok"),
            ) as sent:
                fixture.send()
            contents = [item.content for item in sent.call_args.args[2].attachments]
            self.assertEqual(len(contents), len(set(contents)))

    def test_a_single_tier_ca_sends_one_certificate_not_two(self) -> None:
        """Where the issuer is itself the root, sending both entries would have
        the holder install the same certificate twice under different names."""
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            from myownca.ca_main.crypto import certificate_to_pem

            issuer = fixture.app.state.lab_chain.issuer.certificate
            fixture.app.state.repository.set_root_certificate_pem(
                certificate_to_pem(issuer)
            )

            with mock.patch.object(
                fixture.app.state.comms, "send",
                side_effect=lambda c, r, m: mock.MagicMock(success=True, detail="ok"),
            ) as sent:
                fixture.send()

            attachments = sent.call_args.args[2].attachments
            self.assertEqual(len(attachments), 1)
            self.assertEqual(attachments[0].filename, "sub-ca.cer")

    def test_an_unknown_person_is_refused(self) -> None:
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            with self.assertRaises(HTTPException) as caught:
                fixture.send("nobody")
            self.assertEqual(caught.exception.status_code, 404)

    def test_a_person_without_an_email_is_refused(self) -> None:
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            fixture.app.state.repository.add_person(
                Person(id="p2", name="Bob", surname="No-Mail", email="", created_at=NOW)
            )
            with self.assertRaises(HTTPException) as caught:
                fixture.send("p2")
            self.assertEqual(caught.exception.status_code, 409)

    def test_both_privileged_roles_may_send(self) -> None:
        for role in (Role.ADMIN, Role.SUPERUSER):
            with TemporaryDirectory() as tempdir:
                fixture = _Fixture(tempdir, role=role)
                with mock.patch.object(
                    fixture.app.state.comms, "send",
                    side_effect=lambda c, r, m: mock.MagicMock(success=True, detail="ok"),
                ):
                    self.assertTrue(fixture.send()["success"], role)

    def test_an_unprivileged_role_may_not(self) -> None:
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir, role=Role.USER)
            with self.assertRaises(HTTPException) as caught:
                fixture.send()
            self.assertEqual(caught.exception.status_code, 403)

    def test_the_send_is_audited_against_the_person(self) -> None:
        with TemporaryDirectory() as tempdir:
            fixture = _Fixture(tempdir)
            with mock.patch.object(
                fixture.app.state.comms, "send",
                side_effect=lambda c, r, m: mock.MagicMock(success=True, detail="ok"),
            ):
                fixture.send()
            actions = [e.action for e in fixture.app.state.audit.list_events(limit=50)]
            self.assertIn("send_ca_certificates", actions)


class PortalWiringTests(unittest.TestCase):
    """Both portals expose the send, and the P12 form exposes the option."""

    def _asset(self, name: str) -> str:
        import myownca.online.app as app_module

        return (Path(app_module.__file__).parent / "static" / name).read_text()

    def test_both_portals_offer_the_ca_send(self) -> None:
        for script in ("superuser.js", "admin.js"):
            source = self._asset(script)
            self.assertIn("/internal/ca-certificates/send", source, script)
            self.assertIn("Send CA certs", source, script)

    def test_the_send_is_offered_only_when_a_person_has_an_email(self) -> None:
        """The route refuses without one; offering the action anyway would give
        the operator an error instead of a disabled control."""
        superuser = self._asset("superuser.js")
        self.assertIn(
            'label: "Send CA certs",\n        enabled: (s) => Boolean(s) && Boolean(s.email),',
            superuser,
        )
        self.assertIn("if (row.email) {", self._asset("admin.js"))

    def test_the_pkcs12_form_offers_the_option_checked(self) -> None:
        page = self._asset("superuser.html")
        self.assertIn('name="include_ca_certificates" checked', page)
        self.assertIn("Certificate Trust Settings", page)

    def test_the_form_sends_the_option(self) -> None:
        """A checkbox that never reaches the request would silently do nothing."""
        self.assertIn(
            "include_ca_certificates: form.elements.include_ca_certificates.checked",
            self._asset("superuser.js"),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
