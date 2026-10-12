from __future__ import annotations

from datetime import datetime, timezone

from myownca.comms import NotificationChannel
from myownca.notifications.base import (
    NotificationAudience,
    NotificationEvent,
    NotificationFormat,
    NotificationLogEntry,
    NotificationRule,
    NotificationTemplate,
)
from myownca.storage.database import Database, IntegrityError
from myownca.storage.repositories import RepositoryError


def _dump(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat() if value else None


def _load(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class NotificationRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    # -- templates ------------------------------------------------------------

    def add_template(self, template: NotificationTemplate) -> None:
        try:
            with self.database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO notification_templates(name, event_type, format, subject, body, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        template.name,
                        template.event_type.value,
                        template.format.value,
                        template.subject,
                        template.body,
                        _dump(template.updated_at or datetime.now(timezone.utc)),
                    ),
                )
        except IntegrityError as exc:
            raise RepositoryError(f"A template named {template.name!r} already exists") from exc

    def get_template(self, name: str) -> NotificationTemplate:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM notification_templates WHERE name = ?", (name,)
            ).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown notification template: {name}")
        return _template_from_row(row)

    def list_templates(self) -> list[NotificationTemplate]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM notification_templates ORDER BY event_type, name"
            ).fetchall()
        return [_template_from_row(row) for row in rows]

    def update_template(self, template: NotificationTemplate) -> None:
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE notification_templates
                SET event_type = ?, format = ?, subject = ?, body = ?, updated_at = ?
                WHERE name = ?
                """,
                (
                    template.event_type.value,
                    template.format.value,
                    template.subject,
                    template.body,
                    _dump(datetime.now(timezone.utc)),
                    template.name,
                ),
            )
            if cursor.rowcount == 0:
                raise RepositoryError(f"Unknown notification template: {template.name}")

    def delete_template(self, name: str) -> None:
        try:
            with self.database.connect() as connection:
                cursor = connection.execute(
                    "DELETE FROM notification_templates WHERE name = ?", (name,)
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(f"Unknown notification template: {name}")
        except IntegrityError as exc:
            raise RepositoryError(
                "Cannot delete a template still referenced by a rule"
            ) from exc

    # -- rules ----------------------------------------------------------------

    def add_rule(self, rule: NotificationRule) -> None:
        try:
            with self.database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO notification_rules(
                        id, event_type, template_name, channel, audience, enabled,
                        period_days, threshold_days, notification_text, last_run_at,
                        include_renewal_link
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rule.id,
                        rule.event_type.value,
                        rule.template_name,
                        rule.channel.value,
                        rule.audience.value,
                        int(rule.enabled),
                        rule.period_days,
                        rule.threshold_days,
                        rule.notification_text,
                        _dump(rule.last_run_at),
                        int(rule.include_renewal_link),
                    ),
                )
        except IntegrityError as exc:
            raise RepositoryError(f"Unknown template for rule: {rule.template_name}") from exc

    def get_rule(self, rule_id: str) -> NotificationRule:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM notification_rules WHERE id = ?", (rule_id,)
            ).fetchone()
        if row is None:
            raise RepositoryError(f"Unknown notification rule: {rule_id}")
        return _rule_from_row(row)

    def list_rules(self, *, event_type: NotificationEvent | None = None) -> list[NotificationRule]:
        query = "SELECT * FROM notification_rules"
        params: tuple[object, ...] = ()
        if event_type is not None:
            query += " WHERE event_type = ?"
            params = (event_type.value,)
        query += " ORDER BY event_type, id"
        with self.database.connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [_rule_from_row(row) for row in rows]

    def update_rule(self, rule: NotificationRule) -> None:
        try:
            with self.database.connect() as connection:
                cursor = connection.execute(
                    """
                    UPDATE notification_rules
                    SET event_type = ?, template_name = ?, channel = ?, audience = ?,
                        enabled = ?, period_days = ?, threshold_days = ?,
                        notification_text = ?, include_renewal_link = ?
                    WHERE id = ?
                    """,
                    (
                        rule.event_type.value,
                        rule.template_name,
                        rule.channel.value,
                        rule.audience.value,
                        int(rule.enabled),
                        rule.period_days,
                        rule.threshold_days,
                        rule.notification_text,
                        int(rule.include_renewal_link),
                        rule.id,
                    ),
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(f"Unknown notification rule: {rule.id}")
        except IntegrityError as exc:
            raise RepositoryError(f"Unknown template for rule: {rule.template_name}") from exc

    def delete_rule(self, rule_id: str) -> None:
        with self.database.connect() as connection:
            cursor = connection.execute("DELETE FROM notification_rules WHERE id = ?", (rule_id,))
            if cursor.rowcount == 0:
                raise RepositoryError(f"Unknown notification rule: {rule_id}")

    def set_rule_last_run(self, rule_id: str, when: datetime) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE notification_rules SET last_run_at = ? WHERE id = ?",
                (_dump(when), rule_id),
            )

    # -- delivery log ---------------------------------------------------------

    def add_log(self, entry: NotificationLogEntry) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO notification_log(
                    id, rule_id, event_type, template_name, channel, recipient,
                    subject, object_ref, success, detail, sent_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id,
                    entry.rule_id,
                    entry.event_type,
                    entry.template_name,
                    entry.channel,
                    entry.recipient,
                    entry.subject,
                    entry.object_ref,
                    int(entry.success),
                    entry.detail,
                    _dump(entry.sent_at),
                ),
            )

    def list_log(self, *, limit: int = 100) -> list[NotificationLogEntry]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM notification_log ORDER BY sent_at DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_log_from_row(row) for row in rows]

    def count_failed_since(self, since: datetime) -> int:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM notification_log
                WHERE success = 0 AND sent_at >= ?
                """,
                (_dump(since),),
            ).fetchone()
        return int(row["count"])

    def was_notified_since(self, *, rule_id: str, object_ref: str, since: datetime) -> bool:
        """True if a successful send for this (rule, object) exists at/after `since`.

        Used to de-duplicate scheduled reminders so a cert is not re-notified every run.
        """
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM notification_log
                WHERE rule_id = ? AND object_ref = ? AND success = 1 AND sent_at >= ?
                LIMIT 1
                """,
                (rule_id, object_ref, _dump(since)),
            ).fetchone()
        return row is not None

    def was_attempted_since(self, *, rule_id: str, object_ref: str, since: datetime) -> bool:
        """True for any delivery attempt, including a failed channel send."""

        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM notification_log "
                "WHERE rule_id = ? AND object_ref = ? AND sent_at >= ? LIMIT 1",
                (rule_id, object_ref, _dump(since)),
            ).fetchone()
        return row is not None


def _template_from_row(row) -> NotificationTemplate:
    return NotificationTemplate(
        name=row["name"],
        event_type=NotificationEvent(row["event_type"]),
        format=NotificationFormat(row["format"]),
        subject=row["subject"],
        body=row["body"],
        updated_at=_load(row["updated_at"]),
    )


def _rule_from_row(row) -> NotificationRule:
    return NotificationRule(
        id=row["id"],
        event_type=NotificationEvent(row["event_type"]),
        template_name=row["template_name"],
        channel=NotificationChannel(row["channel"]),
        audience=NotificationAudience(row["audience"]),
        enabled=bool(row["enabled"]),
        period_days=row["period_days"],
        threshold_days=row["threshold_days"],
        notification_text=row["notification_text"],
        last_run_at=_load(row["last_run_at"]),
        include_renewal_link=bool(row["include_renewal_link"]),
    )


def _log_from_row(row) -> NotificationLogEntry:
    return NotificationLogEntry(
        id=row["id"],
        rule_id=row["rule_id"],
        event_type=row["event_type"],
        template_name=row["template_name"],
        channel=row["channel"],
        recipient=row["recipient"],
        subject=row["subject"],
        object_ref=row["object_ref"],
        success=bool(row["success"]),
        detail=row["detail"],
        sent_at=_load(row["sent_at"]),
    )
