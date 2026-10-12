from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


_SESSION_STATE_DIR = Path(tempfile.mkdtemp(prefix="myownca-test-state-"))

# Several test modules import myownca.online.app at module scope, and that module
# creates a FastAPI app during import. Set hermetic paths before collection so
# the import-time app cannot read a developer's real ./var keys or database.
os.environ["MYOWNCA_STATE_DIR"] = str(_SESSION_STATE_DIR)
os.environ["MYOWNCA_DATABASE_PATH"] = str(_SESSION_STATE_DIR / "myownca.sqlite3")
os.environ["MYOWNCA_ONLINE_KEY_DIR"] = str(_SESSION_STATE_DIR / "online-keys")
os.environ["MYOWNCA_SERVICE_KEY_DIR"] = str(_SESSION_STATE_DIR / "service-keys")


@pytest.fixture(autouse=True, scope="session")
def _isolated_state_dir():
    """Point MYOWNCA_STATE_DIR at a throwaway dir for the whole test session.

    create_app() imports any wizard-captured root from
    <state_dir>/setup/root-ca.pem on boot. Without this, tests that call
    create_app() without setting MYOWNCA_STATE_DIR would read the real ./var
    on a machine that has run the setup wizard, making the suite non-hermetic.
    Tests that need a specific state dir still override MYOWNCA_STATE_DIR locally.
    """
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setenv("MYOWNCA_STATE_DIR", str(_SESSION_STATE_DIR))
        monkeypatch.setenv("MYOWNCA_DATABASE_PATH", str(_SESSION_STATE_DIR / "myownca.sqlite3"))
        monkeypatch.setenv("MYOWNCA_ONLINE_KEY_DIR", str(_SESSION_STATE_DIR / "online-keys"))
        monkeypatch.setenv("MYOWNCA_SERVICE_KEY_DIR", str(_SESSION_STATE_DIR / "service-keys"))
        yield _SESSION_STATE_DIR
