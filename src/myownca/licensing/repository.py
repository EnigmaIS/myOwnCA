from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import NAMESPACE_URL, uuid4, uuid5

from cryptography import x509

from myownca.ca_main.identity import certificate_identity_digest
from myownca.licensing.base import (
    DuplicateCertificateIdentityError,
    LicenseLimitError,
    LicenseStateError,
)
from myownca.storage.database import Database

_COLUMNS = (
    "id, token, license_id, licensed_to, valid_from, expires_at, "
    "max_active_certs, uploaded_by, uploaded_at"
)
_INSTALLATION_ID_SETTING = "licensing_installation_id"
_OBSERVED_STATUS_SETTING = "licensing_last_observed_status"
_EXPIRY_MILESTONE_SETTING = "licensing_last_expiry_milestone"
_RESERVATION_TTL = timedelta(minutes=5)


class LicenseRepository:
    """Database-backed license, lineage, and capacity state."""

    def __init__(self, database: Database) -> None:
        self.database = database

    # -- license token and installation identity -----------------------------

    def installation_id(self) -> str:
        """Return the stable per-database UUID, creating it under a DB lock."""

        with self.database.connect() as connection:
            self._lock_capacity(connection)
            row = connection.execute(
                "SELECT value FROM online_settings WHERE key = ?",
                (_INSTALLATION_ID_SETTING,),
            ).fetchone()
            if row is not None:
                return row["value"]
            value = str(uuid4())
            connection.execute(
                "INSERT INTO online_settings(key, value) VALUES (?, ?)",
                (_INSTALLATION_ID_SETTING, value),
            )
            return value

    def get(self):
        with self.database.connect() as connection:
            return connection.execute(
                f"SELECT {_COLUMNS} FROM licenses ORDER BY uploaded_at DESC, id LIMIT 1"
            ).fetchone()

    def replace(
        self,
        *,
        id: str,
        token: str,
        license_id: str,
        licensed_to: str,
        valid_from: datetime,
        expires_at: datetime,
        max_active_certs: int,
        uploaded_by: str,
        uploaded_at: datetime,
    ) -> None:
        with self.database.connect() as connection:
            connection.execute("DELETE FROM licenses")
            connection.execute(
                f"INSERT INTO licenses({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    id,
                    token,
                    license_id,
                    licensed_to,
                    _dump(valid_from),
                    _dump(expires_at),
                    max_active_certs,
                    uploaded_by,
                    _dump(uploaded_at),
                ),
            )

    def clear(self) -> bool:
        with self.database.connect() as connection:
            result = connection.execute("DELETE FROM licenses")
        return result.rowcount > 0

    def observe_status(self, status: str) -> str | None:
        """Persist a status transition and return the previous value."""

        with self.database.connect() as connection:
            self._lock_capacity(connection)
            row = connection.execute(
                "SELECT value FROM online_settings WHERE key = ?",
                (_OBSERVED_STATUS_SETTING,),
            ).fetchone()
            previous = None if row is None else row["value"]
            if previous == status:
                return previous
            if row is None:
                connection.execute(
                    "INSERT INTO online_settings(key, value) VALUES (?, ?)",
                    (_OBSERVED_STATUS_SETTING, status),
                )
            else:
                connection.execute(
                    "UPDATE online_settings SET value = ? WHERE key = ?",
                    (status, _OBSERVED_STATUS_SETTING),
                )
            return previous

    def observe_expiry_milestone(self, milestone: str) -> str | None:
        with self.database.connect() as connection:
            self._lock_capacity(connection)
            row = connection.execute(
                "SELECT value FROM online_settings WHERE key = ?",
                (_EXPIRY_MILESTONE_SETTING,),
            ).fetchone()
            previous = None if row is None else row["value"]
            if previous == milestone:
                return previous
            if row is None:
                connection.execute(
                    "INSERT INTO online_settings(key, value) VALUES (?, ?)",
                    (_EXPIRY_MILESTONE_SETTING, milestone),
                )
            else:
                connection.execute(
                    "UPDATE online_settings SET value = ? WHERE key = ?",
                    (milestone, _EXPIRY_MILESTONE_SETTING),
                )
            return previous

    # -- legacy lineage backfill ---------------------------------------------

    def ensure_lineages(self, now: datetime) -> None:
        """Idempotently attach existing certificates to their renewal roots."""

        moment = _as_utc(now)
        try:
            with self.database.connect() as connection:
                self._lock_capacity(connection)
                certificates = connection.execute(
                    "SELECT * FROM certificate_inventory "
                    "ORDER BY issued_at, issuer_id, serial_number"
                ).fetchall()
                requests = {
                    row["id"]: row
                    for row in connection.execute(
                        """
                        SELECT r.*, refs.certificate_id AS renewal_of_certificate_id
                        FROM certificate_requests r
                        LEFT JOIN certificate_request_renewal_refs refs
                          ON refs.request_id = r.id
                        """
                    ).fetchall()
                }
                existing_lineages = connection.execute(
                    "SELECT * FROM certificate_lineages"
                ).fetchall()
                lineage_by_root_request = {
                    row["root_request_id"]: row["id"] for row in existing_lineages
                }
                root_request_by_lineage = {
                    row["id"]: row["root_request_id"] for row in existing_lineages
                }
                lineage_by_id = {row["id"]: row for row in existing_lineages}
                cert_by_id = {row["certificate_id"]: row for row in certificates}
                cert_by_request_id = {row["request_id"]: row for row in certificates}
                cert_ids_by_serial: dict[str, list[str]] = {}
                for certificate in certificates:
                    cert_ids_by_serial.setdefault(certificate["serial_number"], []).append(
                        certificate["certificate_id"]
                    )
                lineage_by_certificate_id: dict[str, str] = {}
                root_by_lineage: dict[str, dict] = {}

                def legacy_anchor_id(serial: str) -> str:
                    candidates = cert_ids_by_serial.get(serial, [])
                    if not candidates:
                        raise LicenseStateError(f"Renewal anchor {serial} does not exist")
                    if len(candidates) > 1:
                        raise LicenseStateError(
                            f"Renewal anchor serial {serial} is ambiguous; "
                            "a canonical certificate reference is required"
                        )
                    return candidates[0]

                def assert_matches_stored_lineage(certificate, lineage) -> None:
                    try:
                        parsed = x509.load_pem_x509_certificate(
                            certificate["certificate_pem"].encode()
                        )
                        digest = certificate_identity_digest(parsed)
                    except (TypeError, ValueError) as exc:
                        raise LicenseStateError(
                            f"Certificate {certificate['certificate_id']} cannot be parsed "
                            "for lineage validation"
                        ) from exc
                    if (
                        certificate["template_id"] != lineage["template_id"]
                        or certificate["holder_person_id"] != lineage["holder_person_id"]
                        or certificate["holder_device_id"] != lineage["holder_device_id"]
                        or digest != lineage["identity_digest"]
                    ):
                        raise LicenseStateError(
                            f"Certificate {certificate['certificate_id']} does not match "
                            f"lineage {lineage['id']}"
                        )

                def resolve(
                    certificate_id: str, trail: set[str] | None = None
                ) -> tuple[str, dict]:
                    if certificate_id in lineage_by_certificate_id:
                        lineage_id = lineage_by_certificate_id[certificate_id]
                        return lineage_id, root_by_lineage[lineage_id]
                    trail = set() if trail is None else set(trail)
                    if certificate_id in trail:
                        raise LicenseStateError(
                            f"Renewal cycle includes certificate {certificate_id}"
                        )
                    trail.add(certificate_id)
                    certificate = cert_by_id.get(certificate_id)
                    if certificate is None:
                        raise LicenseStateError(
                            f"Renewal anchor {certificate_id} does not exist"
                        )
                    request = requests.get(certificate["request_id"])
                    if request is None:
                        raise LicenseStateError(
                            f"Certificate {certificate_id} references a missing request"
                        )
                    if request["kind"] == "first_issuance":
                        existing_ids = {
                            value
                            for value in (
                                certificate.get("lineage_id"),
                                request.get("lineage_id"),
                                lineage_by_root_request.get(request["id"]),
                            )
                            if value
                        }
                        if len(existing_ids) > 1:
                            raise LicenseStateError(
                                f"Certificate {certificate_id} has conflicting lineage assignments"
                            )
                        lineage_id = (
                            next(iter(existing_ids))
                            if existing_ids
                            else str(uuid5(NAMESPACE_URL, f"myownca:lineage:{request['id']}"))
                        )
                        known_root = root_request_by_lineage.get(lineage_id)
                        if known_root is not None and known_root != request["id"]:
                            lineage = lineage_by_id[lineage_id]
                            root_request = requests.get(known_root)
                            root = cert_by_request_id.get(known_root)
                            if (
                                root_request is None
                                or root_request["kind"] != "first_issuance"
                                or root is None
                            ):
                                raise LicenseStateError(
                                    f"Certificate {certificate_id} lineage has no valid root request"
                                )
                            assert_matches_stored_lineage(root, lineage)
                            assert_matches_stored_lineage(certificate, lineage)
                        else:
                            root = certificate
                    elif request["kind"] == "renewal" and request["renewal_of_serial_number"]:
                        anchor_id = request.get("renewal_of_certificate_id") or legacy_anchor_id(
                            request["renewal_of_serial_number"]
                        )
                        lineage_id, root = resolve(anchor_id, trail)
                        existing_ids = {
                            value
                            for value in (
                                certificate.get("lineage_id"),
                                request.get("lineage_id"),
                            )
                            if value
                        }
                        if any(existing_id != lineage_id for existing_id in existing_ids):
                            raise LicenseStateError(
                                f"Renewal certificate {certificate_id} has a conflicting "
                                "lineage assignment"
                            )
                    else:
                        raise LicenseStateError(
                            f"Issued request {request['id']} has no valid renewal root"
                        )
                    lineage_by_certificate_id[certificate_id] = lineage_id
                    root_by_lineage[lineage_id] = root
                    return lineage_id, root

                for certificate in certificates:
                    resolve(certificate["certificate_id"])

                for lineage_id, root in root_by_lineage.items():
                    root_request = requests[root["request_id"]]
                    try:
                        parsed = x509.load_pem_x509_certificate(root["certificate_pem"].encode())
                        digest = certificate_identity_digest(parsed)
                    except (TypeError, ValueError) as exc:
                        raise LicenseStateError(
                            f"Certificate {root['serial_number']} cannot be parsed for lineage backfill"
                        ) from exc
                    stored_lineage = lineage_by_id.get(lineage_id)
                    if stored_lineage is not None:
                        assert_matches_stored_lineage(root, stored_lineage)
                    connection.execute(
                        """
                        INSERT INTO certificate_lineages(
                            id, root_request_id, template_id, holder_person_id,
                            holder_device_id, identity_digest, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET identity_digest = excluded.identity_digest
                        """,
                        (
                            lineage_id,
                            root_request["id"],
                            root["template_id"],
                            root["holder_person_id"],
                            root["holder_device_id"],
                            digest,
                            root["issued_at"],
                        ),
                    )

                for certificate_id, lineage_id in lineage_by_certificate_id.items():
                    certificate = cert_by_id[certificate_id]
                    connection.execute(
                        "UPDATE certificate_inventory SET lineage_id = ? "
                        "WHERE certificate_id = ?",
                        (lineage_id, certificate_id),
                    )
                    connection.execute(
                        "UPDATE issued_certificates SET lineage_id = ? "
                        "WHERE certificate_id = ?",
                        (lineage_id, certificate_id),
                    )
                    connection.execute(
                        "UPDATE certificate_requests SET lineage_id = ? WHERE id = ?",
                        (lineage_id, certificate["request_id"]),
                    )

                # Pending renewals inherit the already-resolved anchor lineage.
                for request in requests.values():
                    anchor = request["renewal_of_serial_number"]
                    if request["kind"] == "renewal" and anchor:
                        anchor_id = request.get("renewal_of_certificate_id") or legacy_anchor_id(
                            anchor
                        )
                        lineage_id, _root = resolve(anchor_id)
                        if request.get("lineage_id") not in (None, lineage_id):
                            raise LicenseStateError(
                                f"Renewal request {request['id']} has a conflicting lineage assignment"
                            )
                        connection.execute(
                            "UPDATE certificate_requests SET lineage_id = ? WHERE id = ?",
                            (lineage_id, request["id"]),
                        )

                self._set_lineage_state(connection, "ready", None, moment)
        except Exception as exc:
            # Record the safe-mode reason in a fresh transaction; never hide the
            # original failure by failing to write diagnostics.
            try:
                with self.database.connect() as connection:
                    self._set_lineage_state(connection, "error", str(exc)[:1000], moment)
            except Exception:  # noqa: BLE001 - preserve the useful root cause
                pass
            if isinstance(exc, LicenseStateError):
                raise
            raise LicenseStateError(f"Certificate lineage backfill failed: {exc}") from exc

    def lineage_state(self) -> tuple[str, str | None]:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT status, detail FROM license_lineage_state WHERE singleton_id = 1"
            ).fetchone()
        if row is None:
            return "error", "Certificate lineage state is missing"
        return row["status"], row["detail"]

    # -- capacity and reservations -------------------------------------------

    def active_lineage_count(self, now: datetime) -> int:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(DISTINCT COALESCE(lineage_id, request_id)) AS count
                FROM certificate_inventory
                WHERE status = ? AND expires_at > ?
                """,
                ("active", _dump(now)),
            ).fetchone()
        return int(row["count"] if row else 0)

    def reserved_lineage_count(self, now: datetime) -> int:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM license_quota_reservations WHERE expires_at > ?",
                (_dump(now),),
            ).fetchone()
        return int(row["count"] if row else 0)

    def reserve_lineage(
        self,
        *,
        request_id: str,
        template_id: str,
        holder_person_id: str | None,
        holder_device_id: str | None,
        identity_digest: str,
        allow_lineage_reuse: bool,
        limit: int,
        now: datetime,
    ) -> tuple[str, datetime | None]:
        """Return a matching lineage or reserve capacity for a new one.

        The holder, template and normalized certificate identity define the
        licensed unit.  Looking up that tuple while holding the same capacity
        lock as the quota check prevents concurrent imports/first issuances of
        one identity from consuming multiple slots. Imports may deliberately
        reuse a matching lineage; first-issuance requests must renew instead.

        ``expires_at`` is ``None`` when an existing lineage was reused; callers
        must only consume/release a reservation when a timestamp is returned.
        """
        moment = _as_utc(now)
        expires_at = moment + _RESERVATION_TTL
        with self.database.connect() as connection:
            self._lock_capacity(connection)
            state = connection.execute(
                "SELECT status, detail FROM license_lineage_state WHERE singleton_id = 1"
            ).fetchone()
            if state is None or state["status"] != "ready":
                detail = state["detail"] if state else "lineage state is missing"
                raise LicenseStateError(detail or "Certificate lineage backfill is incomplete")
            self._cleanup_expired_reservations(connection, moment)
            existing = connection.execute(
                """
                SELECT lineage_id, expires_at FROM license_quota_reservations
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
            if existing is not None:
                return existing["lineage_id"], datetime.fromisoformat(existing["expires_at"])
            if holder_person_id is not None:
                matching_lineage = connection.execute(
                    """
                    SELECT id FROM certificate_lineages
                    WHERE template_id = ?
                      AND holder_person_id = ?
                      AND holder_device_id IS NULL
                      AND identity_digest = ?
                    ORDER BY created_at, id
                    LIMIT 1
                    """,
                    (template_id, holder_person_id, identity_digest),
                ).fetchone()
            else:
                matching_lineage = connection.execute(
                    """
                    SELECT id FROM certificate_lineages
                    WHERE template_id = ?
                      AND holder_person_id IS NULL
                      AND holder_device_id = ?
                      AND identity_digest = ?
                    ORDER BY created_at, id
                    LIMIT 1
                    """,
                    (template_id, holder_device_id, identity_digest),
                ).fetchone()
            if matching_lineage is not None:
                if not allow_lineage_reuse:
                    active_certificate = connection.execute(
                        """
                        SELECT certificate_id FROM certificate_inventory
                        WHERE lineage_id = ? AND status = ? AND archived_at IS NULL
                        ORDER BY issued_at DESC, certificate_id
                        LIMIT 1
                        """,
                        (matching_lineage["id"], "active"),
                    ).fetchone()
                    if active_certificate is not None:
                        raise DuplicateCertificateIdentityError(
                            "An active certificate with the same holder, template, and "
                            "identity already exists. Use its Renew action instead of "
                            "creating a new certificate."
                        )
                    pending_reservation = connection.execute(
                        """
                        SELECT request_id FROM license_quota_reservations
                        WHERE lineage_id = ?
                        """,
                        (matching_lineage["id"],),
                    ).fetchone()
                    if pending_reservation is not None:
                        raise DuplicateCertificateIdentityError(
                            "An equivalent first-issuance request is already pending."
                        )
                    matching_lineage = None
            if matching_lineage is not None:
                # Keep a concurrent reuse durable even if the request that
                # originally reserved this lineage fails and releases its
                # reservation before this request is finalized.
                connection.execute(
                    """
                    UPDATE certificate_requests SET lineage_id = ?
                    WHERE id = ? AND lineage_id IS NULL
                    """,
                    (matching_lineage["id"], request_id),
                )
                return matching_lineage["id"], None
            active = connection.execute(
                """
                SELECT COUNT(DISTINCT COALESCE(lineage_id, request_id)) AS count
                FROM certificate_inventory
                WHERE status = ? AND expires_at > ?
                """,
                ("active", _dump(moment)),
            ).fetchone()["count"]
            reserved = connection.execute(
                "SELECT COUNT(*) AS count FROM license_quota_reservations"
            ).fetchone()["count"]
            if int(active) + int(reserved) >= limit:
                raise LicenseLimitError(
                    f"Certificate lineage limit reached ({active}+{reserved}/{limit}). "
                    "Free a lineage or install a higher-tier license."
                )
            lineage_id = str(uuid4())
            connection.execute(
                """
                INSERT INTO certificate_lineages(
                    id, root_request_id, template_id, holder_person_id,
                    holder_device_id, identity_digest, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lineage_id,
                    request_id,
                    template_id,
                    holder_person_id,
                    holder_device_id,
                    identity_digest,
                    _dump(moment),
                ),
            )
            connection.execute(
                """
                INSERT INTO license_quota_reservations(
                    request_id, lineage_id, reserved_at, expires_at
                ) VALUES (?, ?, ?, ?)
                """,
                (request_id, lineage_id, _dump(moment), _dump(expires_at)),
            )
        return lineage_id, expires_at

    def release_reservation(self, request_id: str) -> None:
        with self.database.connect() as connection:
            self._lock_capacity(connection)
            row = connection.execute(
                "SELECT lineage_id FROM license_quota_reservations WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                return
            connection.execute(
                "DELETE FROM license_quota_reservations WHERE request_id = ?", (request_id,)
            )
            connection.execute(
                """
                DELETE FROM certificate_lineages
                WHERE id = ?
                  AND NOT EXISTS (
                      SELECT 1 FROM certificate_inventory WHERE lineage_id = ?
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM certificate_requests WHERE lineage_id = ?
                  )
                """,
                (row["lineage_id"], row["lineage_id"], row["lineage_id"]),
            )

    def lineage_for_request(self, request_id: str) -> str | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT lineage_id FROM certificate_requests WHERE id = ?", (request_id,)
            ).fetchone()
        return None if row is None else row["lineage_id"]

    # -- connection-local helpers --------------------------------------------

    @staticmethod
    def _lock_capacity(connection) -> None:
        updated = connection.execute(
            """
            UPDATE license_quota_lock
            SET generation = generation + 1
            WHERE singleton_id = 1
            """
        )
        if updated.rowcount != 1:
            raise LicenseStateError("License quota lock is missing")

    @staticmethod
    def _set_lineage_state(connection, status: str, detail: str | None, now: datetime) -> None:
        connection.execute(
            """
            UPDATE license_lineage_state
            SET status = ?, detail = ?, updated_at = ?
            WHERE singleton_id = 1
            """,
            (status, detail, _dump(now)),
        )

    @staticmethod
    def _cleanup_expired_reservations(connection, now: datetime) -> None:
        rows = connection.execute(
            "SELECT lineage_id FROM license_quota_reservations WHERE expires_at <= ?",
            (_dump(now),),
        ).fetchall()
        connection.execute(
            "DELETE FROM license_quota_reservations WHERE expires_at <= ?", (_dump(now),)
        )
        for row in rows:
            connection.execute(
                """
                DELETE FROM certificate_lineages
                WHERE id = ?
                  AND NOT EXISTS (
                      SELECT 1 FROM certificate_inventory WHERE lineage_id = ?
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM certificate_requests WHERE lineage_id = ?
                  )
                """,
                (row["lineage_id"], row["lineage_id"], row["lineage_id"]),
            )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _dump(value: datetime) -> str:
    return _as_utc(value).isoformat()
