from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from myownca.setup.state import (
    SetupState,
    is_setup_complete,
    load_setup_state,
    mark_setup_complete,
    resolve_state_dir,
    save_setup_state,
)


class StateDirResolutionTests(unittest.TestCase):
    def test_explicit_argument_wins(self) -> None:
        self.assertEqual(
            resolve_state_dir("/tmp/explicit", environ={"MYOWNCA_STATE_DIR": "/tmp/env"}),
            Path("/tmp/explicit"),
        )

    def test_env_var_used_when_no_explicit(self) -> None:
        self.assertEqual(
            resolve_state_dir(None, environ={"MYOWNCA_STATE_DIR": "/tmp/env"}),
            Path("/tmp/env"),
        )

    def test_defaults_to_var(self) -> None:
        self.assertEqual(resolve_state_dir(None, environ={}), Path("./var"))

    def test_empty_env_var_falls_through_to_default(self) -> None:
        self.assertEqual(
            resolve_state_dir(None, environ={"MYOWNCA_STATE_DIR": ""}),
            Path("./var"),
        )


class CompletionLatchTests(unittest.TestCase):
    def test_not_complete_on_fresh_dir(self) -> None:
        with TemporaryDirectory() as tempdir:
            self.assertFalse(is_setup_complete(tempdir))

    def test_mark_complete_creates_marker_with_payload(self) -> None:
        with TemporaryDirectory() as tempdir:
            marker = mark_setup_complete(tempdir, {"version": "0.2.0"})
            self.assertTrue(is_setup_complete(tempdir))
            self.assertEqual(marker, Path(tempdir) / "setup" / "complete")
            self.assertEqual(json.loads(marker.read_text())["version"], "0.2.0")

    def test_marker_is_owner_only(self) -> None:
        with TemporaryDirectory() as tempdir:
            marker = mark_setup_complete(tempdir, None)
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)


class SetupProgressTests(unittest.TestCase):
    def test_fresh_state_is_empty(self) -> None:
        with TemporaryDirectory() as tempdir:
            state = load_setup_state(tempdir)
            self.assertEqual(state.steps, {})
            self.assertEqual(state.data, {})

    def test_round_trips_steps_and_data(self) -> None:
        with TemporaryDirectory() as tempdir:
            state = SetupState(
                steps={"install_type": "done"},
                data={"install_type": "lab"},
            )
            save_setup_state(tempdir, state)
            reloaded = load_setup_state(tempdir)
            self.assertEqual(reloaded.steps, {"install_type": "done"})
            self.assertEqual(reloaded.data, {"install_type": "lab"})

    def test_state_file_is_owner_only(self) -> None:
        with TemporaryDirectory() as tempdir:
            save_setup_state(tempdir, SetupState())
            path = Path(tempdir) / "setup" / "state.json"
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_corrupt_state_file_raises_with_path(self) -> None:
        with TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "setup" / "state.json"
            path.parent.mkdir(parents=True)
            path.write_text("{ not valid json")
            with self.assertRaises(ValueError) as caught:
                load_setup_state(tempdir)
            self.assertIn("state.json", str(caught.exception))
