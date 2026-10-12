from __future__ import annotations

import hashlib
import hmac
import secrets


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SetupAuth:
    """Single-use bootstrap token + in-memory setup session for the wizard.

    The wizard is a single-process, ephemeral server, so session state lives in
    memory only. The bootstrap token is generated once per process launch (or
    injected for headless use), printed to the console, and exchanged for a
    session cookie + CSRF token exactly once. A fresh token is minted when the
    setup process restarts. All comparisons are constant-time.
    """

    def __init__(self, token: str | None = None) -> None:
        self.token = token or secrets.token_urlsafe(32)
        self._token_hash = _hash(self.token)
        self._token_consumed = False
        self._session_hash: str | None = None
        self._csrf_token: str | None = None

    def __repr__(self) -> str:
        # Never expose the plaintext token in tracebacks, logs, or a debugger.
        return "SetupAuth(token=<redacted>)"

    def verify_token(self, presented: str | None) -> bool:
        if not presented or self._token_consumed:
            return False
        return hmac.compare_digest(_hash(presented), self._token_hash)

    def consume_token(self, presented: str | None) -> bool:
        """Atomically validate and retire the per-launch bootstrap token."""

        if not self.verify_token(presented):
            return False
        self._token_consumed = True
        return True

    def open_session(self) -> tuple[str, str]:
        """Issue a fresh session token + CSRF token, replacing any prior pair."""
        session_token = secrets.token_urlsafe(32)
        # These two writes are not atomic, but run synchronously within a single
        # asyncio event-loop tick (no await between them), so no request can
        # observe the new session hash paired with the old CSRF token.
        self._session_hash = _hash(session_token)
        self._csrf_token = secrets.token_urlsafe(32)
        return session_token, self._csrf_token

    def valid_session(self, session_token: str | None) -> bool:
        if not session_token or self._session_hash is None:
            return False
        return hmac.compare_digest(_hash(session_token), self._session_hash)

    def valid_csrf(self, presented: str | None) -> bool:
        if not presented or self._csrf_token is None:
            return False
        return hmac.compare_digest(presented, self._csrf_token)
