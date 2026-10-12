"""Remove redundant wizard credentials only after completed account bootstrap."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from sqlalchemy.engine import make_url

from myownca.domain import Role
from myownca.setup.config_writer import read_secrets
from myownca.setup.state import is_setup_complete, load_setup_state
from myownca_core.private_files import atomic_write

logger = logging.getLogger(__name__)

_CLOUD_CREDENTIALS = {
    "aws_access_key_id": "MYOWNCA_AWS_ACCESS_KEY_ID",
    "aws_secret_access_key": "MYOWNCA_AWS_SECRET_ACCESS_KEY",
    "aws_session_token": "MYOWNCA_AWS_SESSION_TOKEN",
    "azure_tenant_id": "MYOWNCA_AZURE_TENANT_ID",
    "azure_client_id": "MYOWNCA_AZURE_CLIENT_ID",
    "azure_client_secret": "MYOWNCA_AZURE_CLIENT_SECRET",
}


def cleanup_completed_setup(state_dir: str | Path, auth_repository) -> None:
    """Best-effort and idempotent; never log credential values or exception text."""
    try:
        if not is_setup_complete(state_dir):
            return
        if auth_repository.count_active_users_with_role(Role.ADMIN) == 0:
            return
        state = load_setup_state(state_dir)
        state_path = Path(state_dir) / "setup" / "state.json"
        changed = False
        retained = False
        for admin in state.data.get("admins") or []:
            if "password" in admin:
                del admin["password"]
                changed = True

        runtime_secrets = read_secrets(state_dir)
        database = state.data.get("database") or {}
        if "password" in database:
            url = runtime_secrets.get("MYOWNCA_DATABASE_URL")
            if url and make_url(url).password == database["password"]:
                del database["password"]
                changed = True
            else:
                retained = True

        hsm = state.data.get("hsm") or {}
        for field, setting in _CLOUD_CREDENTIALS.items():
            if field not in hsm:
                continue
            if not hsm[field] or runtime_secrets.get(setting) == hsm[field]:
                del hsm[field]
                changed = True
            else:
                retained = True
        if changed:
            payload = json.dumps({"steps": state.steps, "data": state.data}, indent=2) + "\n"
            # Existing access arrangements are repaired explicitly, not changed
            # as a side effect of ordinary startup cleanup.
            atomic_write(state_path, payload.encode(), preserve_access=True)
        if retained:
            logger.warning(
                "Completed setup retains credentials without a matching runtime secret; "
                "check secrets/secrets.env. Cleanup will retry at the next startup."
            )
    except Exception as exc:  # noqa: BLE001 - cleanup must not prevent login/recovery
        logger.warning(
            "Completed setup secret cleanup could not finish (%s); "
            "check setup/state.json and its access permissions. "
            "Cleanup will retry at the next startup.",
            type(exc).__name__,
        )
