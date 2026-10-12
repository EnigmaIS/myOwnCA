from __future__ import annotations

import base64
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from myownca.config import Settings
from myownca.setup.config_writer import write_config, write_secrets


class SettingsLayeringTests(unittest.TestCase):
    def test_reads_values_from_files(self) -> None:
        with TemporaryDirectory() as tempdir:
            write_config(tempdir, {"MYOWNCA_DATABASE_PATH": "/data/ca.sqlite3"})
            write_secrets(tempdir, {"MYOWNCA_AUTH_ENCRYPTION_SECRET": "file-secret"})
            settings = Settings.load(tempdir, environ={})
            self.assertEqual(settings.database_path, Path("/data/ca.sqlite3"))
            self.assertEqual(settings.auth_encryption_secret, "file-secret")

    def test_environment_overrides_files(self) -> None:
        with TemporaryDirectory() as tempdir:
            write_config(tempdir, {"MYOWNCA_DATABASE_PATH": "/data/from-file.sqlite3"})
            settings = Settings.load(
                tempdir,
                environ={"MYOWNCA_DATABASE_PATH": "/data/from-env.sqlite3"},
            )
            self.assertEqual(settings.database_path, Path("/data/from-env.sqlite3"))

    def test_secrets_override_config_for_same_key(self) -> None:
        with TemporaryDirectory() as tempdir:
            write_config(tempdir, {"MYOWNCA_AUTH_ENCRYPTION_SECRET": "from-config"})
            write_secrets(tempdir, {"MYOWNCA_AUTH_ENCRYPTION_SECRET": "from-secrets"})
            settings = Settings.load(tempdir, environ={})
            self.assertEqual(settings.auth_encryption_secret, "from-secrets")

    def test_falls_back_to_defaults_when_unset(self) -> None:
        with TemporaryDirectory() as tempdir:
            settings = Settings.load(tempdir, environ={})
            self.assertTrue(settings.lab_mode)  # default true

    def test_non_myownca_env_keys_are_ignored(self) -> None:
        with TemporaryDirectory() as tempdir:
            settings = Settings.load(
                tempdir,
                environ={
                    "HOME": "/root",
                    "PATH": "/usr/bin",
                    "MYOWNCA_HSM_BACKEND": "software",
                },
            )
            # The MYOWNCA_ key is honoured and unrelated keys are dropped silently.
            self.assertEqual(settings.hsm_backend, "software")

    def test_from_env_still_works(self) -> None:
        # Back-compat: existing callers use from_env() with os.environ.
        settings = Settings.from_env()
        self.assertIsInstance(settings, Settings)


class LicensePublicKeySettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        cls.KEY_A = base64.b64encode(
            key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()
        cls.KEY_B = cls.KEY_A

    def test_keys_come_from_release_loader(self) -> None:
        self.assertEqual(Settings.from_mapping({}).license_public_keys, {})
        ring = {"release-1": self.KEY_A, "release-2": self.KEY_B}
        with mock.patch("myownca.config.licensing_public_keys", return_value=ring):
            settings = Settings.from_mapping({})
        self.assertEqual(settings.license_public_keys, ring)
        self.assertIsNone(settings.license_public_keys_error)

    def test_every_legacy_value_is_rejected(self) -> None:
        for value in ("", "{}", "not-json", json.dumps({"release": self.KEY_A})):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "no longer supported"):
                    Settings.from_mapping({"MYOWNCA_LICENSE_PUBLIC_KEYS": value})

    def test_configuration_layers_cannot_hide_legacy_setting(self) -> None:
        for source in ("config", "secrets", "environment", "all"):
            with self.subTest(source=source), TemporaryDirectory() as tempdir:
                if source in ("config", "all"):
                    write_config(tempdir, {"MYOWNCA_LICENSE_PUBLIC_KEYS": ""})
                if source in ("secrets", "all"):
                    write_secrets(tempdir, {"MYOWNCA_LICENSE_PUBLIC_KEYS": "{}"})
                environ = ({"MYOWNCA_LICENSE_PUBLIC_KEYS": json.dumps({"release": self.KEY_A})}
                           if source in ("environment", "all") else {})
                with self.assertRaisesRegex(ValueError, "no longer supported"):
                    Settings.load(tempdir, environ=environ)


class SettingsBindTlsTests(unittest.TestCase):
    def test_bind_defaults(self) -> None:
        settings = Settings.from_mapping({})
        self.assertEqual(settings.bind_host, "127.0.0.1")
        self.assertEqual(settings.bind_port, 8000)
        self.assertIsNone(settings.tls_cert)
        self.assertIsNone(settings.tls_key)

    def test_bind_from_env(self) -> None:
        settings = Settings.from_mapping(
            {
                "MYOWNCA_BIND_HOST": "0.0.0.0",
                "MYOWNCA_BIND_PORT": "8443",
                "MYOWNCA_TLS_CERT": "/etc/myownca/tls.crt",
                "MYOWNCA_TLS_KEY": "/etc/myownca/tls.key",
            }
        )
        self.assertEqual(settings.bind_host, "0.0.0.0")
        self.assertEqual(settings.bind_port, 8443)
        self.assertEqual(settings.tls_cert, "/etc/myownca/tls.crt")
        self.assertEqual(settings.tls_key, "/etc/myownca/tls.key")

    def test_bind_values_load_from_config_and_environment_overrides_them(self) -> None:
        with TemporaryDirectory() as tempdir:
            write_config(
                tempdir,
                {
                    "MYOWNCA_BIND_HOST": "172.21.220.42",
                    "MYOWNCA_BIND_PORT": "8443",
                },
            )
            from_config = Settings.load(tempdir, environ={})
            from_environment = Settings.load(
                tempdir,
                environ={"MYOWNCA_BIND_HOST": "127.0.0.1", "MYOWNCA_BIND_PORT": "9443"},
            )
        self.assertEqual((from_config.bind_host, from_config.bind_port), ("172.21.220.42", 8443))
        self.assertEqual((from_environment.bind_host, from_environment.bind_port), ("127.0.0.1", 9443))

    def test_bad_bind_port_falls_back_to_default(self) -> None:
        self.assertEqual(Settings.from_mapping({"MYOWNCA_BIND_PORT": "nope"}).bind_port, 8000)


class SettingsPkcs11Tests(unittest.TestCase):
    def test_resolve_pkcs11_lib_finds_homebrew_opensc(self) -> None:
        expected = "/opt/homebrew/lib/opensc-pkcs11.so"

        def exists(path: Path) -> bool:
            return str(path) == expected

        with mock.patch.object(Path, "exists", exists):
            self.assertEqual(Settings.from_mapping({}).resolve_pkcs11_lib(), expected)

    def test_resolve_pkcs11_lib_finds_windows_opensc(self) -> None:
        expected = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"

        def exists(path: Path) -> bool:
            return str(path) == expected

        with mock.patch.object(Path, "exists", exists):
            self.assertEqual(Settings.from_mapping({}).resolve_pkcs11_lib(), expected)

    def test_explicit_pkcs11_lib_wins_over_candidates(self) -> None:
        settings = Settings.from_mapping({"MYOWNCA_PKCS11_LIB": "/custom/opensc.so"})
        with mock.patch.object(Path, "exists", return_value=True):
            self.assertEqual(settings.resolve_pkcs11_lib(), "/custom/opensc.so")
