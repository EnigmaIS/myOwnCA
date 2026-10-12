from __future__ import annotations

import unittest
from unittest import mock

from myownca.service_certs.base import ServiceCertError, ServiceCertUnavailable
from myownca.service_certs.dns_provider import (
    LexiconDnsProvider,
    _lexicon_config_dict,
    provider_from_account,
    resolve_cname,
    wait_for_txt,
)


class WaitForTxtTests(unittest.TestCase):
    def test_returns_true_once_value_appears(self) -> None:
        seen = [set(), set(), {"the-value"}]
        calls = iter(seen)
        ok = wait_for_txt(
            "_acme-challenge.example.test", "the-value",
            timeout_seconds=10, interval_seconds=0,
            _resolve=lambda name: next(calls), _sleep=lambda s: None,
        )
        self.assertTrue(ok)

    def test_returns_false_on_timeout(self) -> None:
        ok = wait_for_txt(
            "_acme-challenge.example.test", "the-value",
            timeout_seconds=0, interval_seconds=0,
            _resolve=lambda name: set(), _sleep=lambda s: None,
        )
        self.assertFalse(ok)


class LexiconProviderTests(unittest.TestCase):
    def test_publish_and_remove_call_lexicon(self) -> None:
        fake_ops = mock.MagicMock()
        fake_ctx = mock.MagicMock()
        fake_ctx.__enter__.return_value = fake_ops
        fake_ctx.__exit__.return_value = False
        with mock.patch(
            "myownca.service_certs.dns_provider._lexicon_client", return_value=fake_ctx
        ) as factory:
            provider = LexiconDnsProvider("luadns", {"auth_username": "u", "auth_token": "t"})
            provider.publish_txt("_acme-challenge.example.test", "v1")
            provider.remove_txt("_acme-challenge.example.test", "v1")
        self.assertEqual(factory.call_count, 2)
        fake_ops.create_record.assert_called_once()
        fake_ops.delete_record.assert_called_once()

    def test_missing_dependency_raises_unavailable(self) -> None:
        with mock.patch(
            "myownca.service_certs.dns_provider._lexicon_client",
            side_effect=ServiceCertUnavailable("dns extra missing"),
        ), self.assertRaises(ServiceCertUnavailable):
            LexiconDnsProvider("luadns", {"auth_username": "u", "auth_token": "t"}).publish_txt(
                "_acme-challenge.example.test", "v"
            )

    def test_publish_wraps_provider_error_as_service_cert_error(self) -> None:
        # A lexicon failure (e.g. LuaDNS "No domain found") must surface as a clean
        # ServiceCertError (-> 400), not escape as a 500.
        ctx = mock.MagicMock()
        ctx.__enter__.side_effect = RuntimeError("No domain found")
        with mock.patch("myownca.service_certs.dns_provider._lexicon_client", return_value=ctx):
            provider = LexiconDnsProvider("luadns", {"auth_username": "u", "auth_token": "t"})
            with self.assertRaises(ServiceCertError) as ctx_mgr:
                provider.publish_txt("_acme-challenge.trinity.athae.net", "v")
        self.assertIn("No domain found", str(ctx_mgr.exception))


class LexiconConfigTests(unittest.TestCase):
    def test_requests_dns_zone_resolution(self) -> None:
        # resolve_zone_name makes lexicon find the real hosted zone via a DNS SOA walk
        # instead of tldextract-reducing a delegated sub-zone (trinity.athae.net) to its
        # registrable domain (athae.net), which the account doesn't host -> "No domain found".
        cfg = _lexicon_config_dict("luadns", {"auth_username": "u", "auth_token": "t"}, "trinity.athae.net")
        self.assertIs(cfg["resolve_zone_name"], True)
        self.assertEqual(cfg["domain"], "trinity.athae.net")
        self.assertEqual(cfg["provider_name"], "luadns")
        self.assertEqual(cfg["luadns"], {"auth_username": "u", "auth_token": "t"})


class ResolveCnameTests(unittest.TestCase):
    def test_no_cname_returns_input(self) -> None:
        self.assertEqual(
            resolve_cname("_acme-challenge.example.test", _lookup=lambda n: None),
            "_acme-challenge.example.test",
        )

    def test_follows_single_cname_delegation(self) -> None:
        chain = {"_acme-challenge.athae.net": "_acme-challenge.trinity.athae.net"}
        self.assertEqual(
            resolve_cname("_acme-challenge.athae.net", _lookup=chain.get),
            "_acme-challenge.trinity.athae.net",
        )

    def test_follows_a_chain_to_the_end(self) -> None:
        chain = {"a": "b", "b": "c"}
        self.assertEqual(resolve_cname("a", _lookup=chain.get), "c")

    def test_loop_is_bounded(self) -> None:
        chain = {"a": "b", "b": "a"}
        self.assertIn(resolve_cname("a", _lookup=chain.get), {"a", "b"})  # terminates, no hang

    def test_strips_trailing_dot(self) -> None:
        self.assertEqual(resolve_cname("a.test.", _lookup=lambda n: None), "a.test")


class ProviderFromAccountTests(unittest.TestCase):
    def test_none_when_no_provider(self) -> None:
        account = mock.Mock(dns_provider=None, dns_credentials_ciphertext=None)
        self.assertIsNone(provider_from_account(account, decrypt=lambda c: "{}"))

    def test_builds_provider_when_configured(self) -> None:
        account = mock.Mock(dns_provider="luadns", dns_credentials_ciphertext="ct")
        provider = provider_from_account(account, decrypt=lambda c: '{"auth_username":"u","auth_token":"t"}')
        self.assertIsInstance(provider, LexiconDnsProvider)


if __name__ == "__main__":
    unittest.main()
