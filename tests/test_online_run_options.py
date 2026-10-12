from __future__ import annotations

import unittest
from unittest import mock

from myownca.config import Settings
from myownca.online.app import _uvicorn_options, run


class UvicornOptionsTests(unittest.TestCase):
    def test_defaults_no_tls(self) -> None:
        options = _uvicorn_options(Settings.from_mapping({}))
        self.assertEqual(options["host"], "127.0.0.1")
        self.assertEqual(options["port"], 8000)
        self.assertNotIn("ssl_certfile", options)
        self.assertNotIn("ssl_keyfile", options)

    def test_bind_from_settings(self) -> None:
        options = _uvicorn_options(
            Settings.from_mapping({"MYOWNCA_BIND_HOST": "0.0.0.0", "MYOWNCA_BIND_PORT": "8443"})
        )
        self.assertEqual(options["host"], "0.0.0.0")
        self.assertEqual(options["port"], 8443)

    def test_tls_when_cert_and_key_set(self) -> None:
        options = _uvicorn_options(
            Settings.from_mapping({"MYOWNCA_TLS_CERT": "/c.crt", "MYOWNCA_TLS_KEY": "/k.key"})
        )
        self.assertEqual(options["ssl_certfile"], "/c.crt")
        self.assertEqual(options["ssl_keyfile"], "/k.key")

    def test_partial_tls_config_raises(self) -> None:
        # Setting only one of cert/key must fail loudly, not silently serve HTTP.
        with self.assertRaises(ValueError):
            _uvicorn_options(Settings.from_mapping({"MYOWNCA_TLS_CERT": "/c.crt"}))
        with self.assertRaises(ValueError):
            _uvicorn_options(Settings.from_mapping({"MYOWNCA_TLS_KEY": "/k.key"}))

    def test_run_invokes_uvicorn_with_options(self) -> None:
        with mock.patch("myownca.online.app.uvicorn.run") as uvicorn_run:
            with mock.patch.dict(
                "os.environ",
                {
                    "MYOWNCA_BIND_PORT": "9443",
                    "MYOWNCA_TLS_CERT": "/c.crt",
                    "MYOWNCA_TLS_KEY": "/k.key",
                },
            ):
                run()
        args, kwargs = uvicorn_run.call_args
        self.assertEqual(args[0], "myownca.online.app:app")
        self.assertEqual(kwargs["port"], 9443)
        self.assertEqual(kwargs["ssl_certfile"], "/c.crt")
        self.assertEqual(kwargs["ssl_keyfile"], "/k.key")
