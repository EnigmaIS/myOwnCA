"""Shared static assets must carry one cache-busting version across all portals.

Two real defects motivated this. A change to ``app_shared.js`` shipped without
bumping any ``?v=``, so upgraded installs kept serving the cached previous file
and the feature never appeared. Separately, a change bumped ``app_shared.js`` in
``superuser.html`` alone, leaving admin, user and auditor pinned to the older
version of the very same file -- so one portal got the new code and three did
not.

Neither is visible in a normal test run: the Python is correct, the tests pass,
and only a browser holding a cached copy shows the bug. These assertions make
the drift a build failure instead.
"""
from __future__ import annotations

import re
import unittest
from collections import defaultdict
from pathlib import Path

import myownca.online.app as app_module

STATIC = Path(app_module.__file__).parent / "static"

# Files shared by multiple portals. A per-portal script (admin.js, superuser.js) is
# deliberately excluded: only one page references it, so it cannot disagree.
SHARED_ASSETS = (
    "app_shared.js", "app.css", "notification-schedule.js", "notification-schedule.css",
)

REFERENCE = re.compile(r"([A-Za-z0-9_.-]+\.(?:js|css))\?v=(\d+)")


def _versions() -> dict[str, dict[str, int]]:
    """asset -> {portal filename: version}"""
    found: dict[str, dict[str, int]] = defaultdict(dict)
    for page in sorted(STATIC.glob("*.html")):
        for asset, version in REFERENCE.findall(page.read_text()):
            found[asset][page.name] = int(version)
    return found


class SharedAssetVersionTests(unittest.TestCase):
    def test_every_portal_requests_the_same_version_of_a_shared_asset(self) -> None:
        versions = _versions()
        for asset in SHARED_ASSETS:
            references = versions.get(asset, {})
            self.assertTrue(references, f"No portal references {asset}")
            distinct = set(references.values())
            self.assertEqual(
                len(distinct),
                1,
                f"{asset} is one file but portals request different versions "
                f"{references}. Portals on the lower version will serve a "
                f"cached copy without the change.",
            )

    def test_shared_assets_are_referenced_by_every_portal_that_needs_them(self) -> None:
        """A portal missing the stylesheet entirely would render unstyled."""
        versions = _versions()
        pages_with_scripts = {
            page.name
            for page in STATIC.glob("*.html")
            if "app_shared.js" in page.read_text()
        }
        self.assertEqual(
            set(versions["app_shared.js"]),
            pages_with_scripts,
            "app_shared.js is referenced without a ?v= cache-busting version",
        )

    def test_every_versioned_reference_parses(self) -> None:
        """A malformed ?v= would silently never bust the cache."""
        for page in sorted(STATIC.glob("*.html")):
            text = page.read_text()
            for match in re.finditer(r"/app/assets/([A-Za-z0-9_.-]+)\?v=([^\"']*)", text):
                self.assertRegex(
                    match.group(2),
                    r"^\d+$",
                    f"{page.name} references {match.group(1)} with a "
                    f"non-numeric version {match.group(2)!r}",
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
