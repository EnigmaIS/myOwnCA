"""Run export dialog regressions against the real shared JavaScript."""

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_export_dialog_error_feedback():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for export dialog checks")
    result = subprocess.run(
        [
            node,
            str(ROOT / "tests/js/export_dialog.cjs"),
            str(ROOT / "src/myownca/online/static/app_shared.js"),
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
