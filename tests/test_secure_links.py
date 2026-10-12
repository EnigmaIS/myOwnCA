import unittest
from datetime import datetime, timedelta, timezone

from myownca.domain import (
    CertificateProfile,
    CertificateStatus,
    Device,
    IssuedCertificate,
    Person,
)
from myownca.holder import (
    LinkPurpose,
    SecureLinkError,
    SecureLinkRepository,
    SecureLinkService,
    mask_email,
)
from myownca.storage.repositories import RepositoryError
from tests.helpers import TempPKI, make_csr

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


class SecureLinkFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.pki.add_template("host", CertificateProfile.HOST_TLS)
        repo = self.pki.repository
        repo.add_person(
            Person(id="p1", name="Al", surname="Holder", email="al@example.test", created_at=_NOW)
        )
        repo.add_person(
            Person(id="p-noemail", name="No", surname="Mail", email="", created_at=_NOW)
        )
        repo.add_device(Device(id="d1", device_name="box", admin_id="p1", created_at=_NOW))
        request = self.pki.service.submit_request(
            "host", make_csr("h.example.test", dns_names=("h.example.test",))
        )
        self.serial = "S1"
        repo.add_issued_certificate(
            IssuedCertificate(
                serial_number=self.serial,
                request_id=request.id,
                template_id="host",
                certificate_pem="-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
                subject="CN=h.example.test",
                issued_at=_NOW,
                expires_at=_NOW + timedelta(days=365),
                status=CertificateStatus.ACTIVE,
                holder_person_id="p1",
            )
        )
        device_request = self.pki.service.submit_request(
            "host", make_csr("d.example.test", dns_names=("d.example.test",))
        )
        self.device_serial = "S2"
        repo.add_issued_certificate(
            IssuedCertificate(
                serial_number=self.device_serial,
                request_id=device_request.id,
                template_id="host",
                certificate_pem="-----BEGIN CERTIFICATE-----\ny\n-----END CERTIFICATE-----\n",
                subject="CN=d.example.test",
                issued_at=_NOW,
                expires_at=_NOW + timedelta(days=365),
                status=CertificateStatus.ACTIVE,
                holder_device_id="d1",
            )
        )
        self.links = SecureLinkService(SecureLinkRepository(self.pki.database), repo)

    def tearDown(self) -> None:
        self.pki.close()

    def _mint(self, purpose=LinkPurpose.DELIVERY, **kwargs):
        kwargs.setdefault("created_by", "su-1")
        if purpose is not LinkPurpose.ENROLLMENT:
            kwargs.setdefault("serial_number", self.serial)
        kwargs.setdefault("now", _NOW)
        return self.links.mint(purpose, **kwargs)


class MintTests(SecureLinkFixture):
    def test_token_returned_once_and_hashed_at_rest(self) -> None:
        link, token = self._mint()
        self.assertGreaterEqual(len(token), 40)
        self.assertNotEqual(link.token_hash, token)
        self.assertNotIn(token, link.token_hash)
        self.assertEqual(self.links.find_by_token(token).id, link.id)
        self.assertIsNone(self.links.find_by_token("wrong-" + token))
        self.assertIsNone(self.links.find_by_token(None))

    def test_holder_resolution_person_and_device_admin(self) -> None:
        person_link, _ = self._mint()
        self.assertEqual(person_link.person_id, "p1")
        device_link, _ = self._mint(serial_number=self.device_serial)
        self.assertEqual(device_link.person_id, "p1")  # device admin

    def test_person_override(self) -> None:
        self.pki.repository.add_person(
            Person(id="p2", name="Bo", surname="Alt", email="bo@example.test", created_at=_NOW)
        )
        link, _ = self._mint(person_id="p2")
        self.assertEqual(link.person_id, "p2")

    def test_unknown_serial_rejected(self) -> None:
        with self.assertRaises(SecureLinkError):
            self._mint(serial_number="GHOST")

    def test_recipient_without_email_rejected(self) -> None:
        with self.assertRaises(SecureLinkError) as ctx:
            self._mint(person_id="p-noemail")
        self.assertIn("no email", str(ctx.exception))

    def test_enrollment_requires_person(self) -> None:
        with self.assertRaises(SecureLinkError):
            self.links.mint(LinkPurpose.ENROLLMENT, created_by="su-1", now=_NOW)
        link, _ = self.links.mint(
            LinkPurpose.ENROLLMENT, created_by="su-1", person_id="p1", now=_NOW
        )
        self.assertIsNone(link.serial_number)

    def test_default_policy_per_purpose(self) -> None:
        delivery, _ = self._mint()
        renewal, _ = self._mint(LinkPurpose.RENEWAL)
        self.assertEqual(delivery.expires_at, _NOW + timedelta(days=7))
        self.assertEqual(delivery.max_uses, 3)
        self.assertEqual(renewal.expires_at, _NOW + timedelta(days=14))
        self.assertEqual(renewal.max_uses, 1)

    def test_settings_override_policy(self) -> None:
        self.pki.repository.set_setting("holder_link_expiry_days_delivery", "3")
        self.pki.repository.set_setting("holder_link_max_uses_delivery", "1")
        link, _ = self._mint()
        self.assertEqual(link.expires_at, _NOW + timedelta(days=3))
        self.assertEqual(link.max_uses, 1)

    def test_garbage_setting_falls_back_to_default(self) -> None:
        self.pki.repository.set_setting("holder_link_expiry_days_delivery", "soon")
        self.pki.repository.set_setting("holder_link_max_uses_delivery", "-2")
        link, _ = self._mint()
        self.assertEqual(link.expires_at, _NOW + timedelta(days=7))
        self.assertEqual(link.max_uses, 3)


class UsabilityTests(SecureLinkFixture):
    def test_lifecycle_reasons(self) -> None:
        link, _ = self._mint()
        self.assertIsNone(self.links.usability(link, now=_NOW))
        self.assertEqual(
            self.links.usability(link, now=_NOW + timedelta(days=8)), "expired"
        )
        revoked = self.links.revoke(link.id, now=_NOW)
        self.assertEqual(self.links.usability(revoked, now=_NOW), "revoked")

    def test_revoke_unknown_link_raises(self) -> None:
        with self.assertRaises(RepositoryError):
            self.links.revoke("ghost")


class OtpAndSessionTests(SecureLinkFixture):
    def test_happy_path(self) -> None:
        link, token = self._mint()
        code = self.links.start_otp(link, now=_NOW)
        self.assertRegex(code, r"^\d{6}$")
        stored = self.links.repository.get_link(link.id)
        self.assertNotEqual(stored.otp_hash, code)

        session = self.links.verify_otp(link, code, now=_NOW)
        self.assertIsNotNone(session)
        after = self.links.repository.get_link(link.id)
        self.assertEqual(after.use_count, 1)
        self.assertIsNone(after.otp_hash)  # code is single-use

        resolved = self.links.session_link(token, session, now=_NOW + timedelta(minutes=5))
        self.assertEqual(resolved.id, link.id)
        self.assertIsNone(self.links.session_link(token, "forged", now=_NOW))
        self.assertIsNone(self.links.session_link(token, session, now=_NOW + timedelta(minutes=31)))

    def test_wrong_code_locks_after_five_attempts_across_resends(self) -> None:
        link, _ = self._mint()
        self.links.start_otp(link, now=_NOW)
        for _ in range(2):
            self.assertIsNone(self.links.verify_otp(link, "000000", now=_NOW))
        # Re-sending a code must not reset the lockout budget.
        self.links.start_otp(link, now=_NOW)
        for _ in range(3):
            self.assertIsNone(self.links.verify_otp(link, "000000", now=_NOW))
        locked = self.links.repository.get_link(link.id)
        self.assertIsNotNone(locked.locked_at)
        self.assertEqual(self.links.usability(locked, now=_NOW), "locked")
        with self.assertRaises(SecureLinkError):
            self.links.start_otp(locked, now=_NOW)

    def test_expired_code_rejected(self) -> None:
        link, _ = self._mint()
        code = self.links.start_otp(link, now=_NOW)
        self.assertIsNone(self.links.verify_otp(link, code, now=_NOW + timedelta(minutes=11)))

    def test_correct_code_after_session_does_not_replay(self) -> None:
        link, _ = self._mint()
        code = self.links.start_otp(link, now=_NOW)
        self.assertIsNotNone(self.links.verify_otp(link, code, now=_NOW))
        self.assertIsNone(self.links.verify_otp(link, code, now=_NOW))  # consumed

    def test_exhausted_link_keeps_open_session_until_it_expires(self) -> None:
        link, token = self._mint(max_uses=1)
        code = self.links.start_otp(link, now=_NOW)
        session = self.links.verify_otp(link, code, now=_NOW)
        exhausted = self.links.repository.get_link(link.id)
        self.assertEqual(self.links.usability(exhausted, now=_NOW), "exhausted")
        with self.assertRaises(SecureLinkError):
            self.links.start_otp(exhausted, now=_NOW)
        # ...but the session that consumed the last use still works.
        self.assertIsNotNone(
            self.links.session_link(token, session, now=_NOW + timedelta(minutes=10))
        )

    def test_revocation_kills_open_session(self) -> None:
        link, token = self._mint()
        code = self.links.start_otp(link, now=_NOW)
        session = self.links.verify_otp(link, code, now=_NOW)
        self.links.revoke(link.id, now=_NOW)
        self.assertIsNone(self.links.session_link(token, session, now=_NOW))

    def test_recipient_email_and_mask(self) -> None:
        link, _ = self._mint()
        self.assertEqual(self.links.recipient_email(link), "al@example.test")
        self.assertEqual(mask_email("al@example.test"), "a***@example.test")
        self.assertEqual(mask_email("nodomain"), "n***")


class ListingTests(SecureLinkFixture):
    def test_list_links_and_per_serial(self) -> None:
        self._mint()
        self._mint(LinkPurpose.RENEWAL)
        self._mint(serial_number=self.device_serial)
        self.assertEqual(len(self.links.list_links()), 3)
        per_serial = self.links.repository.list_links_for_serial(self.serial)
        self.assertEqual(len(per_serial), 2)
        renewals = self.links.repository.list_links_for_serial(
            self.serial, LinkPurpose.RENEWAL
        )
        self.assertEqual(len(renewals), 1)
        self.assertIs(renewals[0].purpose, LinkPurpose.RENEWAL)


if __name__ == "__main__":
    unittest.main()
