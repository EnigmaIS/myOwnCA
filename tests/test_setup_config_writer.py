from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from myownca.setup.config_writer import (
    read_config_env,
    read_secrets,
    write_config,
    write_secrets,
)


class SecretsFileTests(unittest.TestCase):
    def test_round_trips_values(self) -> None:
        with TemporaryDirectory() as tempdir:
            write_secrets(
                tempdir,
                {
                    "MYOWNCA_AUTH_ENCRYPTION_SECRET": "abc123",
                    "MYOWNCA_ONLINE_KEY_PASSPHRASE": "p@ss=with=equals",
                },
            )
            loaded = read_secrets(tempdir)
            self.assertEqual(loaded["MYOWNCA_AUTH_ENCRYPTION_SECRET"], "abc123")
            # Value containing '=' must survive (split on first '=' only).
            self.assertEqual(loaded["MYOWNCA_ONLINE_KEY_PASSPHRASE"], "p@ss=with=equals")

    def test_missing_file_reads_empty(self) -> None:
        with TemporaryDirectory() as tempdir:
            self.assertEqual(read_secrets(tempdir), {})

    def test_secret_file_is_owner_only(self) -> None:
        with TemporaryDirectory() as tempdir:
            write_secrets(tempdir, {"MYOWNCA_AUTH_ENCRYPTION_SECRET": "x"})
            path = Path(tempdir) / "secrets" / "secrets.env"
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_secret_dir_is_owner_only(self) -> None:
        with TemporaryDirectory() as tempdir:
            write_secrets(tempdir, {"MYOWNCA_AUTH_ENCRYPTION_SECRET": "x"})
            secret_dir = Path(tempdir) / "secrets"
            self.assertEqual(secret_dir.stat().st_mode & 0o777, 0o700)

    def test_newline_in_value_is_rejected(self) -> None:
        # A newline would split into extra KEY=value lines on read, injecting
        # a second secret. Reject it rather than silently corrupt the file.
        with TemporaryDirectory() as tempdir:
            with self.assertRaises(ValueError):
                write_secrets(tempdir, {"MYOWNCA_DB_PASSWORD": "p1\nMYOWNCA_EVIL=x"})


class ConfigFileTests(unittest.TestCase):
    def test_round_trips_env_table(self) -> None:
        with TemporaryDirectory() as tempdir:
            write_config(
                tempdir,
                {
                    "MYOWNCA_LAB_MODE": "false",
                    "MYOWNCA_DATABASE_PATH": "./var/myownca.sqlite3",
                },
            )
            loaded = read_config_env(tempdir)
            self.assertEqual(loaded["MYOWNCA_LAB_MODE"], "false")
            self.assertEqual(loaded["MYOWNCA_DATABASE_PATH"], "./var/myownca.sqlite3")

    def test_missing_file_reads_empty(self) -> None:
        with TemporaryDirectory() as tempdir:
            self.assertEqual(read_config_env(tempdir), {})

    def test_values_are_stringified(self) -> None:
        with TemporaryDirectory() as tempdir:
            write_config(tempdir, {"MYOWNCA_ADMIN_PORT": "8443"})
            self.assertEqual(read_config_env(tempdir)["MYOWNCA_ADMIN_PORT"], "8443")

    def test_config_file_is_world_readable(self) -> None:
        # config.toml holds only non-secret settings, so 0o644 is intended
        # (this is the whole reason secrets live in a separate 0o600 file).
        with TemporaryDirectory() as tempdir:
            write_config(tempdir, {"MYOWNCA_LAB_MODE": "false"})
            path = Path(tempdir) / "config.toml"
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_non_string_value_is_rejected(self) -> None:
        # A hand-edited native TOML bool/int would otherwise coerce to
        # "True"/"8443" and mislead env-var consumers, so reject it loudly.
        with TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "config.toml"
            path.write_text("[env]\nMYOWNCA_LAB_MODE = false\n")
            with self.assertRaises(TypeError):
                read_config_env(tempdir)

    def test_corrupt_config_file_raises_with_path(self) -> None:
        with TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "config.toml"
            path.write_text("not valid toml = = [[[")
            with self.assertRaises(ValueError) as caught:
                read_config_env(tempdir)
            self.assertIn("config.toml", str(caught.exception))


class SecretArtifactTests(unittest.TestCase):
    def test_writes_0600_artifact_under_secrets(self) -> None:
        from myownca.setup.config_writer import write_secret_artifact

        with TemporaryDirectory() as tempdir:
            path = write_secret_artifact(tempdir, "pending-admins.json", b'{"x":1}')
            self.assertEqual(path, Path(tempdir) / "secrets" / "pending-admins.json")
            self.assertEqual(path.read_bytes(), b'{"x":1}')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual((Path(tempdir) / "secrets").stat().st_mode & 0o777, 0o700)
