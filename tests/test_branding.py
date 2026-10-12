from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from myownca.domain import Role
from myownca.online.app import create_app
from myownca.online.branding import (
    BrandingError,
    DEFAULT_ACCENT_COLOR,
    load_logo,
    normalize_theme_color,
    reset_logo,
    save_logo,
    sniff_content_type,
    theme_css_for_color,
)
from tests.helpers import (
    add_login_ready_user,
    create_active_session,
    request_with_session,
    route_endpoint,
)

_REPO = Path(__file__).resolve().parents[1]

_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
_JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
_SVG = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>'


class DefaultAssetsTests(unittest.TestCase):
    def test_default_logo_assets_present_and_svg(self) -> None:
        for rel in (
            "src/myownca/online/static/branding/logo.svg",
            "src/myownca/setup/static/branding/logo.svg",
        ):
            path = _REPO / rel
            self.assertTrue(path.is_file(), f"missing {rel}")
            head = path.read_bytes()[:512].lstrip().lower()
            self.assertTrue(head.startswith(b"<?xml") or head.startswith(b"<svg"), rel)


class SniffTests(unittest.TestCase):
    def test_accepts_each_real_type(self) -> None:
        self.assertEqual(sniff_content_type("image/png", _PNG), "image/png")
        self.assertEqual(sniff_content_type("image/jpeg", _JPEG), "image/jpeg")
        self.assertEqual(sniff_content_type("image/svg+xml", _SVG), "image/svg+xml")

    def test_rejects_disguised_type(self) -> None:
        with self.assertRaises(BrandingError):
            sniff_content_type("image/png", _JPEG)

    def test_rejects_unsupported_type(self) -> None:
        with self.assertRaises(BrandingError):
            sniff_content_type("image/gif", _PNG)

    def test_rejects_oversize(self) -> None:
        with self.assertRaises(BrandingError):
            sniff_content_type("image/png", _PNG[:8] + b"\x00" * 2_000_001)


class ThemeColorTests(unittest.TestCase):
    def test_normalizes_hex_color(self) -> None:
        self.assertEqual(normalize_theme_color("246B5B"), DEFAULT_ACCENT_COLOR)
        self.assertEqual(normalize_theme_color("  #3366CC  "), "#3366cc")

    def test_rejects_invalid_hex_color(self) -> None:
        for value in ("", "#123", "#12345g", "not-a-color"):
            with self.subTest(value=value):
                with self.assertRaises(BrandingError):
                    normalize_theme_color(value)

    def test_theme_css_contains_derived_tokens(self) -> None:
        css = theme_css_for_color("#ffcc00")
        self.assertIn("--accent: #ffcc00;", css)
        self.assertIn("--accent-contrast: #172026;", css)
        self.assertIn("--hero-wash-clear: rgba(255, 204, 0, 0);", css)


class StoreTests(unittest.TestCase):
    def test_save_load_round_trip_and_extension(self) -> None:
        with TemporaryDirectory() as tmp:
            save_logo(tmp, "image/png", _PNG)
            self.assertTrue((Path(tmp) / "branding" / "logo.png").is_file())
            loaded = load_logo(tmp)
            self.assertIsNotNone(loaded)
            data, content_type = loaded
            self.assertEqual(data, _PNG)
            self.assertEqual(content_type, "image/png")

    def test_save_replaces_prior_logo(self) -> None:
        with TemporaryDirectory() as tmp:
            save_logo(tmp, "image/png", _PNG)
            save_logo(tmp, "image/svg+xml", _SVG)
            self.assertFalse((Path(tmp) / "branding" / "logo.png").exists())
            self.assertEqual(load_logo(tmp)[1], "image/svg+xml")

    def test_load_none_when_absent(self) -> None:
        with TemporaryDirectory() as tmp:
            self.assertIsNone(load_logo(tmp))

    def test_reset_removes(self) -> None:
        with TemporaryDirectory() as tmp:
            save_logo(tmp, "image/png", _PNG)
            reset_logo(tmp)
            self.assertIsNone(load_logo(tmp))


def _app(tempdir: str):
    with mock.patch.dict("os.environ", {"MYOWNCA_STATE_DIR": tempdir}):
        return create_app(Path(tempdir) / "api.sqlite3")


def _admin_request(app, *, method: str = "GET", user_id: str = "admin-1"):
    secret = add_login_ready_user(
        app, user_id=user_id, email=f"{user_id}@example.test", role=Role.ADMIN
    )
    token, csrf = create_active_session(
        app, email=f"{user_id}@example.test", totp_secret=secret
    )
    return request_with_session(token, csrf, method=method)


_PNG_DATA = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


class BrandingEndpointTests(unittest.TestCase):
    def test_get_returns_default_when_none_uploaded(self) -> None:
        from fastapi.responses import FileResponse as _FR
        with TemporaryDirectory() as tempdir:
            app = _app(tempdir)
            with mock.patch.dict("os.environ", {"MYOWNCA_STATE_DIR": tempdir}):
                resp = route_endpoint(app, "/branding/logo", "GET")()
            self.assertIsInstance(resp, _FR)
            self.assertEqual(resp.headers["X-Content-Type-Options"], "nosniff")

    def test_upload_then_get_returns_uploaded(self) -> None:
        import base64
        from myownca.online.app import BrandingLogoUpload
        with TemporaryDirectory() as tempdir:
            app = _app(tempdir)
            with mock.patch.dict("os.environ", {"MYOWNCA_STATE_DIR": tempdir}):
                req = _admin_request(app, method="POST")
                result = route_endpoint(app, "/internal/branding/logo", "POST")(
                    BrandingLogoUpload(
                        content_type="image/png",
                        data_b64=base64.b64encode(_PNG_DATA).decode(),
                    ),
                    req,
                )
                self.assertTrue(result["stored"])
                resp = route_endpoint(app, "/branding/logo", "GET")()
            self.assertEqual(resp.media_type, "image/png")
            self.assertEqual(resp.body, _PNG_DATA)
            self.assertEqual(resp.headers["Content-Security-Policy"], "script-src 'none'")

    def test_delete_reverts_to_default(self) -> None:
        import base64
        from fastapi.responses import FileResponse as _FR
        from myownca.online.app import BrandingLogoUpload
        with TemporaryDirectory() as tempdir:
            app = _app(tempdir)
            with mock.patch.dict("os.environ", {"MYOWNCA_STATE_DIR": tempdir}):
                req_post = _admin_request(app, method="POST", user_id="admin-1")
                route_endpoint(app, "/internal/branding/logo", "POST")(
                    BrandingLogoUpload(
                        content_type="image/png",
                        data_b64=base64.b64encode(_PNG_DATA).decode(),
                    ),
                    req_post,
                )
                req_delete = _admin_request(app, method="DELETE", user_id="admin-2")
                route_endpoint(app, "/internal/branding/logo", "DELETE")(req_delete)
                resp = route_endpoint(app, "/branding/logo", "GET")()
            self.assertIsInstance(resp, _FR)

    def test_upload_bad_type_is_400(self) -> None:
        import base64
        from fastapi import HTTPException
        from myownca.online.app import BrandingLogoUpload
        with TemporaryDirectory() as tempdir:
            app = _app(tempdir)
            with mock.patch.dict("os.environ", {"MYOWNCA_STATE_DIR": tempdir}):
                req = _admin_request(app, method="POST")
                with self.assertRaises(HTTPException) as ctx:
                    route_endpoint(app, "/internal/branding/logo", "POST")(
                        BrandingLogoUpload(
                            content_type="image/png",
                            data_b64=base64.b64encode(b"not a png").decode(),
                        ),
                        req,
                    )
            self.assertEqual(ctx.exception.status_code, 400)

    def test_upload_bad_base64_is_400(self) -> None:
        from fastapi import HTTPException
        from myownca.online.app import BrandingLogoUpload
        with TemporaryDirectory() as tempdir:
            app = _app(tempdir)
            with mock.patch.dict("os.environ", {"MYOWNCA_STATE_DIR": tempdir}):
                req = _admin_request(app, method="POST")
                with self.assertRaises(HTTPException) as ctx:
                    route_endpoint(app, "/internal/branding/logo", "POST")(
                        BrandingLogoUpload(
                            content_type="image/png", data_b64="!!! not base64 !!!"
                        ),
                        req,
                    )
            self.assertEqual(ctx.exception.status_code, 400)

    def test_theme_color_round_trip_and_theme_css_override(self) -> None:
        from myownca.online.app import BrandingThemeUpdate

        with TemporaryDirectory() as tempdir:
            app = _app(tempdir)
            with mock.patch.dict("os.environ", {"MYOWNCA_STATE_DIR": tempdir}):
                req_get = _admin_request(app, user_id="theme-admin-1")
                default = route_endpoint(app, "/internal/branding/theme", "GET")(req_get)
                self.assertEqual(default, {"accent_color": DEFAULT_ACCENT_COLOR, "custom": False})

                req_put = _admin_request(app, method="PUT", user_id="theme-admin-2")
                saved = route_endpoint(app, "/internal/branding/theme", "PUT")(
                    BrandingThemeUpdate(accent_color="#3366cc"),
                    req_put,
                )
                self.assertEqual(saved, {"accent_color": "#3366cc", "custom": True})

                css = route_endpoint(app, "/theme.css", "GET")()
                self.assertEqual(css.media_type, "text/css")
                self.assertIn("--accent: #3366cc;", css.body.decode())
                self.assertIn("Admin branding override", css.body.decode())

                req_delete = _admin_request(app, method="DELETE", user_id="theme-admin-3")
                reset = route_endpoint(app, "/internal/branding/theme", "DELETE")(req_delete)
                self.assertEqual(reset, {"accent_color": DEFAULT_ACCENT_COLOR, "custom": False})
                reset_css = route_endpoint(app, "/theme.css", "GET")().body.decode()
                self.assertNotIn("Admin branding override", reset_css)

    def test_theme_color_rejects_invalid_value(self) -> None:
        from fastapi import HTTPException
        from myownca.online.app import BrandingThemeUpdate

        with TemporaryDirectory() as tempdir:
            app = _app(tempdir)
            with mock.patch.dict("os.environ", {"MYOWNCA_STATE_DIR": tempdir}):
                req = _admin_request(app, method="PUT")
                with self.assertRaises(HTTPException) as ctx:
                    route_endpoint(app, "/internal/branding/theme", "PUT")(
                        BrandingThemeUpdate(accent_color="#nope"),
                        req,
                    )
            self.assertEqual(ctx.exception.status_code, 400)
