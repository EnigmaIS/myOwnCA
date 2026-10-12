from __future__ import annotations

import base64
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from myownca.online.app import _qr_svg_data_uri, create_app
from tests.helpers import route_endpoint


class RootRedirectTests(unittest.TestCase):
    def test_root_redirects_to_login(self) -> None:
        with TemporaryDirectory() as tempdir:
            with mock.patch.dict("os.environ", {"MYOWNCA_STATE_DIR": tempdir}):
                app = create_app(Path(tempdir) / "api.sqlite3")
            resp = route_endpoint(app, "/", "GET")()
        self.assertIn(resp.status_code, (302, 303, 307))
        self.assertEqual(resp.headers["location"], "/login")


class QrDataUriTests(unittest.TestCase):
    def test_returns_svg_data_uri(self) -> None:
        uri = _qr_svg_data_uri("otpauth://totp/myOwnCA:a@b.test?secret=ABC234&issuer=myOwnCA")
        self.assertTrue(uri.startswith("data:image/svg+xml;base64,"))
        svg = base64.b64decode(uri.split(",", 1)[1])
        self.assertIn(b"<svg", svg)
        self.assertIn(b"path", svg)

    def test_distinct_input_yields_distinct_qr(self) -> None:
        self.assertNotEqual(_qr_svg_data_uri("otpauth://a"), _qr_svg_data_uri("otpauth://b"))


if __name__ == "__main__":
    unittest.main()
