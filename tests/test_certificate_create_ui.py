"""Exercise certificate creation against the real operator JavaScript."""

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_certificate_create_handles_issuance_and_approval_results():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for certificate creation dialog checks")
    result = subprocess.run(
        [
            node,
            str(ROOT / "tests/js/certificate_create.cjs"),
            str(ROOT / "src/myownca/online/static/superuser.js"),
        ],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
