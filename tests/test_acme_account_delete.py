from __future__ import annotations

import unittest
from tempfile import TemporaryDirectory

from myownca.service_certs.base import AcmeAccountInUseError
from tests.test_acme_renewal import _fullchain, _http01_cert
from tests.test_service_certs import _FakeAcme, _service


class RepoAccountDeleteTests(unittest.TestCase):
    def test_dependents_and_cascade_delete(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            cert = _http01_cert(svc)  # creates 1 account + 1 cert + 1 cert_config
            account_id = svc.list_accounts()[0].id

            deps = svc.repository.list_account_dependents(account_id)
            self.assertEqual([c.name for c in deps], [cert.name])

            svc.repository.delete_account(account_id)
            self.assertEqual(svc.list_accounts(), [])
            self.assertIsNone(svc.repository.get_cert_config(cert.id))  # link removed
            self.assertEqual(svc.get_cert(cert.id).name, cert.name)     # cert kept

    def test_no_dependents_for_fresh_account(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            account = svc.create_account("https://acme.test/dir")
            self.assertEqual(svc.repository.list_account_dependents(account.id), [])


class AcmeAccountInUseErrorTests(unittest.TestCase):
    def test_carries_dependents_and_message(self) -> None:
        class _Cert:
            name = "web"
        err = AcmeAccountInUseError([_Cert()])
        self.assertEqual(len(err.dependents), 1)
        self.assertIn("web", str(err))
        self.assertIn("force", str(err))


class ServiceAccountDeleteTests(unittest.TestCase):
    def test_blocks_without_force_then_deletes_with_force(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            _http01_cert(svc)
            account_id = svc.list_accounts()[0].id

            with self.assertRaises(AcmeAccountInUseError):
                svc.delete_account(account_id)            # dependents, no force

            svc.delete_account(account_id, force=True)     # force overrides
            self.assertEqual(svc.list_accounts(), [])

    def test_deletes_unused_account_without_force(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            account = svc.create_account("https://acme.test/dir")
            svc.delete_account(account.id)
            self.assertEqual(svc.list_accounts(), [])

    def test_account_dependents_passthrough(self) -> None:
        with TemporaryDirectory() as tempdir:
            svc = _service(tempdir, acme=_FakeAcme(_fullchain()))
            cert = _http01_cert(svc)
            account_id = svc.list_accounts()[0].id
            self.assertEqual([c.name for c in svc.account_dependents(account_id)], [cert.name])


if __name__ == "__main__":
    unittest.main()
