"""Revocation rows must not be left keyed by a synthetic issuer id.

`issuer_id` was added nullable in migration 0032, so certificates predating it were
backfilled by 0035 with a synthetic value (the row's own serial), and 0037 copied
their revocations into `issuer_revocations` under that same synthetic key.

**Scope, measured rather than assumed.** On the normal upgrade path the CRL is
already correct without this reconciliation: the boot repair calls
`update_certificate_inventory_metadata_by_id`, which upserts the revocation under
the corrected fingerprint from `certificate_revocations` -- a table 0037 copies from
but never deletes. `test_common_upgrade_path_is_already_correct_without_reconcile`
pins that behaviour so nobody "fixes" it twice.

What reconciliation adds is narrower:

  * it removes the **orphaned** synthetic-keyed rows, which otherwise accumulate
    permanently and make `issuer_revocations` unreadable by SQL alone; and
  * it recovers a revocation that has **no** `certificate_revocations` source row,
    where the upsert above cannot fire and the entry would never reach any CRL.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from myownca.storage.database import Database
from myownca.storage.repositories import PKIRepository

UTC = timezone.utc
NOW = datetime.now(UTC)


def _ca(common_name: str = "Repro Sub CA"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(ca_key, ca_cert, serial: int):
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy.test")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOW - timedelta(days=400))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )


def _database(tempdir: str) -> Database:
    database = Database(Path(tempdir) / "legacy.sqlite3")
    database.migrate()
    return database


def _seed_certificate(
    database: Database,
    *,
    suffix: str,
    leaf: x509.Certificate,
    inventory_issuer_id: str,
) -> str:
    """One inventory row, with whatever issuer_id the caller wants to simulate."""
    serial = format(leaf.serial_number, "x")
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO certificate_templates(id, name, profile, validity_days,"
            " first_issuance_approvals, renewal_approvals) VALUES(?,?,?,?,?,?)",
            (f"tpl-{suffix}", f"tpl-{suffix}", "host_tls", 365, 1, 1),
        )
        connection.execute(
            "INSERT INTO certificate_requests(id, template_id, csr_pem, status, kind,"
            " created_at) VALUES(?,?,?,?,?,?)",
            (f"req-{suffix}", f"tpl-{suffix}", "x", "issued", "first_issuance", NOW.isoformat()),
        )
        connection.execute(
            "INSERT INTO certificate_inventory(certificate_id, serial_number, request_id,"
            " template_id, certificate_pem, subject, issued_at, expires_at, status,"
            " source, issuer_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                f"cert-{suffix}",
                serial,
                f"req-{suffix}",
                f"tpl-{suffix}",
                leaf.public_bytes(serialization.Encoding.PEM).decode(),
                "CN=legacy.test",
                NOW.isoformat(),
                (NOW + timedelta(days=365)).isoformat(),
                "revoked",
                "issued",
                inventory_issuer_id,
            ),
        )
    return serial


def _seed_revocation(database: Database, issuer_id: str, serial: str, reason: str = "key_compromise") -> None:
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO issuer_revocations(issuer_id, serial_number, reason, revoked_at,"
            " source, created_at) VALUES(?,?,?,?,?,?)",
            (issuer_id, serial, reason, NOW.isoformat(), "local", NOW.isoformat()),
        )


def _revocation_keys(database: Database) -> list[tuple[str, str]]:
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT issuer_id, serial_number FROM issuer_revocations ORDER BY issuer_id"
        ).fetchall()
    return [(row["issuer_id"], row["serial_number"]) for row in rows]


class IssuerRevocationReconcileTests(unittest.TestCase):
    def test_stranded_revocation_is_moved_onto_the_real_issuer(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _database(tempdir)
            repository = PKIRepository(database)
            ca_key, ca_cert = _ca()
            real = ca_cert.fingerprint(hashes.SHA256()).hex()
            leaf = _leaf(ca_key, ca_cert, 0x0A0B0C0D)
            # inventory already repaired to the real fingerprint...
            serial = _seed_certificate(database, suffix="a", leaf=leaf, inventory_issuer_id=real)
            # ...but the revocation still carries the synthetic id 0037 gave it.
            _seed_revocation(database, serial, serial)

            self.assertEqual(repository.list_issuer_revocations(real), [])

            moved = repository.reconcile_issuer_revocations()

            self.assertEqual(moved, 1)
            self.assertEqual(_revocation_keys(database), [(real, serial)])
            recovered = repository.list_issuer_revocations(real)
            self.assertEqual([item.serial_number for item in recovered], [serial])

    def test_is_idempotent(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _database(tempdir)
            repository = PKIRepository(database)
            ca_key, ca_cert = _ca()
            real = ca_cert.fingerprint(hashes.SHA256()).hex()
            leaf = _leaf(ca_key, ca_cert, 0x0A0B0C0D)
            serial = _seed_certificate(database, suffix="a", leaf=leaf, inventory_issuer_id=real)
            _seed_revocation(database, serial, serial)

            repository.reconcile_issuer_revocations()
            before = _revocation_keys(database)
            second = repository.reconcile_issuer_revocations()

            self.assertEqual(second, 0)
            self.assertEqual(_revocation_keys(database), before)

    def test_correctly_keyed_rows_are_untouched(self) -> None:
        with TemporaryDirectory() as tempdir:
            database = _database(tempdir)
            repository = PKIRepository(database)
            ca_key, ca_cert = _ca()
            real = ca_cert.fingerprint(hashes.SHA256()).hex()
            leaf = _leaf(ca_key, ca_cert, 0x0A0B0C0D)
            serial = _seed_certificate(database, suffix="a", leaf=leaf, inventory_issuer_id=real)
            _seed_revocation(database, real, serial)

            self.assertEqual(repository.reconcile_issuer_revocations(), 0)
            self.assertEqual(_revocation_keys(database), [(real, serial)])

    def test_stale_duplicate_is_dropped_without_clobbering_the_correct_row(self) -> None:
        """A correct row already exists; the stale one must go, not overwrite it."""
        with TemporaryDirectory() as tempdir:
            database = _database(tempdir)
            repository = PKIRepository(database)
            ca_key, ca_cert = _ca()
            real = ca_cert.fingerprint(hashes.SHA256()).hex()
            leaf = _leaf(ca_key, ca_cert, 0x0A0B0C0D)
            serial = _seed_certificate(database, suffix="a", leaf=leaf, inventory_issuer_id=real)
            _seed_revocation(database, real, serial, reason="superseded")
            _seed_revocation(database, serial, serial, reason="key_compromise")

            repository.reconcile_issuer_revocations()

            self.assertEqual(_revocation_keys(database), [(real, serial)])
            kept = repository.list_issuer_revocations(real)
            self.assertEqual(kept[0].reason.value, "superseded")  # the correct row won

    def test_unattributable_revocation_is_left_alone(self) -> None:
        """No inventory row for that serial: keep the data rather than guess."""
        with TemporaryDirectory() as tempdir:
            database = _database(tempdir)
            repository = PKIRepository(database)
            _seed_revocation(database, "some-synthetic-id", "deadbeef")

            self.assertEqual(repository.reconcile_issuer_revocations(), 0)
            self.assertEqual(_revocation_keys(database), [("some-synthetic-id", "deadbeef")])

    def test_ambiguous_serial_across_two_issuers_is_skipped(self) -> None:
        """A serial is unique only within an issuer, so never guess between two."""
        with TemporaryDirectory() as tempdir:
            database = _database(tempdir)
            repository = PKIRepository(database)
            key_a, cert_a = _ca("CA A")
            key_b, cert_b = _ca("CA B")
            real_a = cert_a.fingerprint(hashes.SHA256()).hex()
            real_b = cert_b.fingerprint(hashes.SHA256()).hex()
            shared = 0x0A0B0C0D
            serial = _seed_certificate(
                database, suffix="a", leaf=_leaf(key_a, cert_a, shared), inventory_issuer_id=real_a
            )
            _seed_certificate(
                database, suffix="b", leaf=_leaf(key_b, cert_b, shared), inventory_issuer_id=real_b
            )
            _seed_revocation(database, "synthetic", serial)

            self.assertEqual(repository.reconcile_issuer_revocations(), 0)
            self.assertEqual(_revocation_keys(database), [("synthetic", serial)])

    def test_inventory_still_synthetic_is_not_treated_as_a_target(self) -> None:
        """Before the inventory is repaired there is nothing trustworthy to move to."""
        with TemporaryDirectory() as tempdir:
            database = _database(tempdir)
            repository = PKIRepository(database)
            ca_key, ca_cert = _ca()
            leaf = _leaf(ca_key, ca_cert, 0x0A0B0C0D)
            serial = _seed_certificate(
                database, suffix="a", leaf=leaf, inventory_issuer_id="0a0b0c0d"
            )
            _seed_revocation(database, serial, serial)

            self.assertEqual(repository.reconcile_issuer_revocations(), 0)
            self.assertEqual(_revocation_keys(database), [(serial, serial)])


class BootRepairEndToEndTests(unittest.TestCase):
    """The reconciliation must actually be wired into create_app, not merely exist."""

    def test_booting_recovers_a_revocation_that_has_no_legacy_source_row(self) -> None:
        import json

        from myownca.online.app import create_app

        with TemporaryDirectory() as tempdir:
            database = _database(tempdir)
            ca_key, ca_cert = _ca()
            real = ca_cert.fingerprint(hashes.SHA256()).hex()
            leaf = _leaf(ca_key, ca_cert, 0x0A0B0C0D)
            with database.connect() as connection:
                connection.execute(
                    "INSERT INTO sub_cas(id, certificate_pem, key_ref, subject, created_at,"
                    " allowed_profiles_json) VALUES(?,?,?,?,?,?)",
                    (
                        "sub-1",
                        ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
                        "sub-ca-key",
                        ca_cert.subject.rfc4514_string(),
                        NOW.isoformat(),
                        json.dumps(["user_auth", "host_tls", "smime"]),
                    ),
                )
            # Exactly what the 0035/0037 migrations leave behind for a pre-0032 cert:
            # the inventory's issuer_id is the row's own serial, and the revocation
            # is keyed by that same synthetic value.
            synthetic = format(leaf.serial_number, "x")
            serial = _seed_certificate(
                database, suffix="a", leaf=leaf, inventory_issuer_id=synthetic
            )
            _seed_revocation(database, synthetic, serial)

            repository = PKIRepository(database)
            self.assertEqual(repository.list_issuer_revocations(real), [])

            create_app(Path(tempdir) / "legacy.sqlite3", lab_mode=True)

            recovered = repository.list_issuer_revocations(real)
            self.assertEqual([item.serial_number for item in recovered], [serial])

    def test_common_upgrade_path_is_already_correct_without_reconcile(self) -> None:
        """Characterisation, not a test of the reconciliation.

        With the `certificate_revocations` source row present -- the state a real
        0035/0037 upgrade actually leaves -- the boot repair's upsert already puts
        the revocation under the corrected fingerprint, so CRL and OCSP agree even
        with reconciliation disabled. Pinned so the scope of this change is not
        later overstated. What reconciliation adds here is removing the orphan,
        asserted below.
        """
        import json

        from myownca.online.app import create_app

        with TemporaryDirectory() as tempdir:
            database = _database(tempdir)
            ca_key, ca_cert = _ca()
            real = ca_cert.fingerprint(hashes.SHA256()).hex()
            leaf = _leaf(ca_key, ca_cert, 0x0A0B0C0D)
            serial = format(leaf.serial_number, "x")
            with database.connect() as connection:
                connection.execute(
                    "INSERT INTO sub_cas(id, certificate_pem, key_ref, subject, created_at,"
                    " allowed_profiles_json) VALUES(?,?,?,?,?,?)",
                    (
                        "sub-1",
                        ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
                        "sub-ca-key",
                        ca_cert.subject.rfc4514_string(),
                        NOW.isoformat(),
                        json.dumps(["user_auth", "host_tls", "smime"]),
                    ),
                )
            _seed_certificate(database, suffix="a", leaf=leaf, inventory_issuer_id=serial)
            _seed_revocation(database, serial, serial)
            with database.connect() as connection:
                connection.execute(
                    "INSERT INTO certificate_revocations(certificate_id, serial_number, reason,"
                    " revoked_at) VALUES(?,?,?,?)",
                    ("cert-a", serial, "key_compromise", NOW.isoformat()),
                )

            create_app(Path(tempdir) / "legacy.sqlite3", lab_mode=True)

            repository = PKIRepository(database)
            in_crl = {item.serial_number for item in repository.list_issuer_revocations(real)}
            in_ocsp = {item.serial_number for item in repository.list_revocations()}
            self.assertIn(serial, in_crl)
            self.assertIn(serial, in_ocsp)
            self.assertEqual(in_crl, in_ocsp)

            # The actual contribution of the reconciliation on this path: the
            # synthetic-keyed duplicate is gone, so every remaining row is keyed by
            # a real issuer fingerprint.
            self.assertEqual(
                sorted({key for key, _ in _revocation_keys(database)}), [real]
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
