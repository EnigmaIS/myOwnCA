"""Behavioural JavaScript checks and recipient placement in all portal shells."""

import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src/myownca/online/static"


class PortalParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


@pytest.mark.parametrize("portal", ["admin", "superuser", "user", "auditor", "holder"])
def test_recipient_follows_logo_and_is_hidden_until_loaded(portal):
    parser = PortalParser()
    parser.feed((STATIC / f"{portal}.html").read_text())
    identity_index = next(
        index for index, (_tag, attrs) in enumerate(parser.elements)
        if "data-license-identity" in attrs
    )
    tag, logo = parser.elements[identity_index - 1]
    assert tag == "img" and logo["src"] == "/branding/logo"
    assert "hidden" in parser.elements[identity_index][1]
    if portal == "holder":
        scripts = [attrs["src"] for tag, attrs in parser.elements if tag == "script"]
        assert scripts[0].startswith("/app/assets/app_shared.js?v=")
        assert scripts[1].startswith("/app/assets/holder.js?v=")


def test_shared_identity_renderer_behaviour():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the shared licence renderer checks")
    result = subprocess.run(
        [node, str(ROOT / "tests/js/license_identity.cjs"), str(STATIC / "app_shared.js")],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
