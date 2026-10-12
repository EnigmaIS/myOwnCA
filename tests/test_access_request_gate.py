from __future__ import annotations

import unittest

from myownca.online.access_request_gate import (
    domain_of,
    email_allowed,
    is_request_allowed,
    normalize_domains,
)


class NormalizeDomainsTests(unittest.TestCase):
    def test_splits_lowercases_and_dedupes(self) -> None:
        self.assertEqual(
            normalize_domains("Example.com, foo.org\n bar.net\tbaz.io, example.com"),
            ["example.com", "foo.org", "bar.net", "baz.io"],
        )

    def test_strips_leading_at(self) -> None:
        self.assertEqual(normalize_domains("@example.com"), ["example.com"])

    def test_accepts_leading_wildcard(self) -> None:
        self.assertEqual(normalize_domains("*.example.com"), ["*.example.com"])

    def test_empty_is_empty_list(self) -> None:
        self.assertEqual(normalize_domains(""), [])
        self.assertEqual(normalize_domains("  ,\n \t"), [])

    def test_rejects_malformed(self) -> None:
        for bad in ["nodot", "a b.com", "*", "*.com.", "a.*.com", "@", "foo@bar.com", "-x.com"]:
            with self.assertRaises(ValueError, msg=bad):
                normalize_domains(bad)


class EmailAllowedTests(unittest.TestCase):
    def test_exact(self) -> None:
        self.assertTrue(email_allowed("u@example.com", ["example.com"]))
        self.assertFalse(email_allowed("u@other.com", ["example.com"]))

    def test_wildcard_subdomains_not_apex(self) -> None:
        dom = ["*.example.com"]
        self.assertTrue(email_allowed("u@dept.example.com", dom))
        self.assertTrue(email_allowed("u@a.b.example.com", dom))
        self.assertFalse(email_allowed("u@example.com", dom))

    def test_wildcard_label_boundary_safe(self) -> None:
        self.assertFalse(email_allowed("u@evil-example.com", ["*.example.com"]))

    def test_case_insensitive(self) -> None:
        self.assertTrue(email_allowed("U@Example.COM", ["example.com"]))

    def test_apex_plus_wildcard(self) -> None:
        dom = ["example.com", "*.example.com"]
        self.assertTrue(email_allowed("u@example.com", dom))
        self.assertTrue(email_allowed("u@x.example.com", dom))

    def test_no_at_is_false(self) -> None:
        self.assertFalse(email_allowed("noatsign", ["example.com"]))
        self.assertIsNone(domain_of("noatsign"))


class IsRequestAllowedTests(unittest.TestCase):
    def test_disabled_blocks(self) -> None:
        self.assertFalse(is_request_allowed(False, ["example.com"], "u@example.com"))

    def test_enabled_empty_blocks(self) -> None:
        self.assertFalse(is_request_allowed(True, [], "u@example.com"))

    def test_enabled_match_allows(self) -> None:
        self.assertTrue(is_request_allowed(True, ["example.com"], "u@example.com"))


if __name__ == "__main__":
    unittest.main()
