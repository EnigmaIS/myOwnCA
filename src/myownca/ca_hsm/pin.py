from __future__ import annotations

import threading
from datetime import datetime, timezone


class HSMPinVault:
    """Process-memory store of HSM User PINs, keyed by auth session.

    PINs are never persisted. Each admin session must unlock the PIN on its own;
    locking, session expiry, or a service restart drops it. ``active_pin`` returns
    a currently-unlocked PIN so approval-triggered issuance can sign with the
    hardware key even though that signing happens outside the unlocking session.
    """

    def __init__(self) -> None:
        self._pins: dict[str, tuple[str, datetime | None]] = {}
        self._lock = threading.RLock()

    def unlock(
        self,
        session_key: str,
        pin: str,
        *,
        expires_at: datetime | None = None,
    ) -> None:
        if not pin:
            raise ValueError("PIN must not be empty")
        with self._lock:
            self._pins[session_key] = (pin, _utc(expires_at) if expires_at else None)

    def lock(self, session_key: str) -> None:
        with self._lock:
            self._pins.pop(session_key, None)

    def is_unlocked(self, session_key: str) -> bool:
        with self._lock:
            self._prune_expired()
            return session_key in self._pins

    def pin_for(self, session_key: str) -> str | None:
        with self._lock:
            self._prune_expired()
            stored = self._pins.get(session_key)
            return stored[0] if stored else None

    def active_pin(self) -> str | None:
        with self._lock:
            self._prune_expired()
            for pin, _expires_at in self._pins.values():
                return pin
            return None

    def clear(self) -> None:
        with self._lock:
            self._pins.clear()

    def _prune_expired(self) -> None:
        now = datetime.now(timezone.utc)
        expired = [
            session_key
            for session_key, (_pin, expires_at) in self._pins.items()
            if expires_at is not None and expires_at <= now
        ]
        for session_key in expired:
            self._pins.pop(session_key, None)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
