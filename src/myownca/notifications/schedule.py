"""Application-owned notification scheduling with persisted, live settings."""

from __future__ import annotations

import logging
from threading import RLock

from pydantic import BaseModel, ConfigDict, Field

from myownca.online.scheduler import IntervalScheduler

logger = logging.getLogger(__name__)


class NotificationScheduleSettings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(strict=True)
    # Bound durations to a portable signed 32-bit number of seconds.
    interval_seconds: int = Field(strict=True, gt=0, le=2147483647)


class NotificationSchedule:
    """One application instance owns this scheduler and its notification service.

    A single JSON setting makes enablement/cadence persistence atomic on both
    supported database backends. This is not cross-process coordination.
    """

    SETTING_KEY = "notification_schedule"

    def __init__(self, repository, notifications) -> None:
        self.repository = repository
        self.notifications = notifications
        self._lock = RLock()
        stored = repository.get_setting(self.SETTING_KEY)
        self._settings = (
            NotificationScheduleSettings.model_validate_json(stored)
            if stored else NotificationScheduleSettings(enabled=False, interval_seconds=86400)
        )
        self.scheduler = IntervalScheduler(
            self._tick,
            interval_seconds=self._settings.interval_seconds,
            enabled=self._settings.enabled,
            run_immediately=True,
            name="expiry-notifications",
        )

    def settings(self) -> NotificationScheduleSettings:
        with self._lock:
            return self._settings

    def update(self, settings: NotificationScheduleSettings) -> NotificationScheduleSettings:
        with self._lock:
            previous = self._settings
            if settings != previous:
                self.repository.set_setting(self.SETTING_KEY, settings.model_dump_json())
                self._settings = settings
                self.scheduler.configure(
                    interval_seconds=settings.interval_seconds, enabled=settings.enabled,
                )
                logger.info(
                    "Expiry notification schedule updated (enabled=%s, every %ss)",
                    settings.enabled, settings.interval_seconds,
                )
            return previous

    def _tick(self) -> None:
        with self._lock:
            if not self._settings.enabled:
                return
        summary = self.notifications.run_scheduled()
        if summary.get("skipped_reason"):
            logger.info("Expiry notification pass skipped: %s", summary["skipped_reason"])
            return
        rules = summary["rules"]
        failed = sum(entry["failed"] for entry in rules)
        log = logger.warning if failed else logger.info
        log(
            "Expiry notification pass completed: rules=%s sent=%s failed=%s skipped=%s",
            len(rules), sum(entry["sent"] for entry in rules), failed,
            sum(entry["skipped"] for entry in rules),
        )
