from __future__ import annotations

import unittest

from myownca.ca_main.policy import ApprovalPolicyError
from myownca.domain import CertificateProfile, RequestKind
from myownca.storage.repositories import DuplicateApprovalError, RepositoryError
from tests.helpers import TempPKI, make_csr


class ApprovalPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TempPKI()
        self.pki.add_default_users()
        self.pki.add_template("user", CertificateProfile.USER_AUTH)

    def tearDown(self) -> None:
        self.pki.close()

    def test_first_issuance_requires_two_distinct_superusers_by_default(self) -> None:
        request = self.pki.service.submit_request(
            "user", make_csr("Alice Example", emails=("alice@example.test",))
        )
        self.pki.service.approve_request(request.id, "su-1")

        with self.assertRaises(ApprovalPolicyError):
            self.pki.service.issue_certificate(request.id, self.pki.lab_chain.issuer)

        self.pki.service.approve_request(request.id, "su-2")
        self.pki.assign_holder(request.id)
        issued = self.pki.service.issue_certificate(request.id, self.pki.lab_chain.issuer)
        self.assertEqual(issued.request_id, request.id)

    def test_same_superuser_cannot_count_twice(self) -> None:
        request = self.pki.service.submit_request(
            "user", make_csr("Alice Example", emails=("alice@example.test",))
        )
        self.pki.service.approve_request(request.id, "su-1")

        with self.assertRaises(DuplicateApprovalError):
            self.pki.service.approve_request(request.id, "su-1")

    def test_non_superusers_cannot_approve(self) -> None:
        request = self.pki.service.submit_request(
            "user", make_csr("Alice Example", emails=("alice@example.test",))
        )

        with self.assertRaises(RepositoryError):
            self.pki.service.approve_request(request.id, "user-1")

    def test_renewals_default_to_lighter_one_approval_policy(self) -> None:
        original = self.pki.service.submit_request(
            "user",
            make_csr("Alice Example", emails=("alice@example.test",)),
            requested_by_user_id="user-1",
        )
        self.pki.service.approve_request(original.id, "su-1")
        self.pki.service.approve_request(original.id, "su-2")
        self.pki.assign_holder(original.id)
        original_certificate = self.pki.service.issue_certificate(
            original.id, self.pki.lab_chain.issuer
        )

        renewal = self.pki.service.submit_request(
            "user",
            make_csr("Alice Example", emails=("alice@example.test",)),
            kind=RequestKind.RENEWAL,
            requested_by_user_id="user-1",
            renewal_of_serial_number=original_certificate.serial_number,
        )
        self.pki.service.approve_request(renewal.id, "su-1")
        self.pki.assign_holder(renewal.id)
        renewed = self.pki.service.issue_certificate(renewal.id, self.pki.lab_chain.issuer)
        self.assertEqual(renewed.request_id, renewal.id)
        self.assertEqual(renewal.renewal_of_serial_number, original_certificate.serial_number)

    def test_renewals_must_reference_owned_active_issued_certificate(self) -> None:
        with self.assertRaises(ValueError):
            self.pki.service.submit_request(
                "user",
                make_csr("Alice Example", emails=("alice@example.test",)),
                kind=RequestKind.RENEWAL,
                requested_by_user_id="user-1",
            )

        original = self.pki.service.submit_request(
            "user",
            make_csr("Alice Example", emails=("alice@example.test",)),
            requested_by_user_id="user-1",
        )
        self.pki.service.approve_request(original.id, "su-1")
        self.pki.service.approve_request(original.id, "su-2")
        self.pki.assign_holder(original.id)
        original_certificate = self.pki.service.issue_certificate(
            original.id, self.pki.lab_chain.issuer
        )

        with self.assertRaises(RepositoryError):
            self.pki.service.submit_request(
                "user",
                make_csr("Alice Example", emails=("alice@example.test",)),
                kind=RequestKind.RENEWAL,
                requested_by_user_id="someone-else",
                renewal_of_serial_number=original_certificate.serial_number,
            )

        self.pki.service.revoke_certificate(original_certificate.serial_number)
        with self.assertRaises(RepositoryError):
            self.pki.service.submit_request(
                "user",
                make_csr("Alice Example", emails=("alice@example.test",)),
                kind=RequestKind.RENEWAL,
                requested_by_user_id="user-1",
                renewal_of_serial_number=original_certificate.serial_number,
            )
