"""A tiny generic interval scheduler — a daemon thread that runs a tick callable
every ``interval_seconds``. Mirrors the ACME RenewalScheduler loop; used for the
OCSP daily refresh. A condition makes shutdown and optional live configuration
prompt; tick errors are logged and swallowed so the thread survives.
"""

from __future__ import annotations

import logging
import threading
from time import monotonic
from typing import Callable

logger = logging.getLogger(__name__)


class IntervalScheduler:
    def __init__(
        self, tick: Callable[[], None], *, interval_seconds: int, name: str,
        run_immediately: bool = False, enabled: bool = True,
    ) -> None:
        self._tick = tick
        self._interval = max(int(interval_seconds), 1)
        self._name = name
        self._condition = threading.Condition()
        self._stopped = True
        self._enabled = enabled
        self._run_immediately = run_immediately
        self._pending = False
        self._completed_at = 0.0
        self._thread: threading.Thread | None = None

    def run_once(self) -> None:
        try:
            self._tick()
        except Exception:  # noqa: BLE001 - a tick error must not propagate or kill the loop
            logger.warning("%s scheduler pass failed", self._name, exc_info=True)

    def is_running(self) -> bool:
        with self._condition:
            return self._thread is not None and self._thread.is_alive()

    def configure(self, *, interval_seconds: int, enabled: bool) -> None:
        """Apply a live cadence; enabling requests one immediate background pass."""
        with self._condition:
            self._interval = max(int(interval_seconds), 1)
            self._pending = enabled and (self._pending or not self._enabled)
            self._enabled = enabled
            self._condition.notify_all()

    def start(self) -> None:
        with self._condition:
            if self.is_running():
                return
            self._stopped = False
            self._pending = self._enabled and self._run_immediately
            self._completed_at = monotonic()
            self._thread = threading.Thread(target=self._loop, name=self._name, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._condition:
            self._stopped = True
            self._condition.notify_all()
            thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
            with self._condition:
                if self._thread is thread and not thread.is_alive():
                    self._thread = None

    def _loop(self) -> None:
        while True:
            with self._condition:
                while True:
                    if self._stopped:
                        return
                    remaining = self._completed_at + self._interval - monotonic()
                    if self._enabled and (self._pending or remaining <= 0):
                        self._pending = False
                        break
                    self._condition.wait(
                        min(remaining, threading.TIMEOUT_MAX) if self._enabled else None
                    )
            self.run_once()
            with self._condition:
                self._completed_at = monotonic()
