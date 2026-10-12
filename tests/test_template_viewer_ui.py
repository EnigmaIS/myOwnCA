import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest


STATIC = Path(__file__).parents[1] / "src" / "myownca" / "online" / "static"


def _asset(name: str) -> str:
    return (STATIC / name).read_text()


def test_template_view_action_opens_the_read_only_modal() -> None:
    source = _asset("admin.js")
    view_action_start = source.index('{ label: "View"')
    view_action = source[view_action_start : source.index("\n", view_action_start)]

    assert 'openTemplateModal(s, "view")' in view_action
    assert "showDetails" not in view_action


def test_template_viewer_disables_the_editor_without_a_save_action() -> None:
    source = _asset("admin.js")
    modal_start = source.index("function openTemplateModal")
    modal_source = source[modal_start : source.index("\nasync function deleteTemplate", modal_start)]

    assert 'const isView = mode === "view";' in modal_source
    assert 'form.elements.id.value = source.id;' in modal_source
    assert 'form.querySelectorAll("input, select, textarea, button")' in modal_source
    assert "control.disabled = true;" in modal_source
    assert "saveButton.remove();" in modal_source
    assert 'view: "View template"' in modal_source
    assert "This template is read-only." in modal_source
    assert "if (isView) return;" in modal_source
    assert 'if (mode === "edit") {' in modal_source


def test_template_editor_exposes_and_submits_key_algorithm_policy() -> None:
    source = _asset("admin.js")
    markup = _asset("admin.html")

    assert "Allowed certificate key algorithms" in markup
    assert '"allowed_key_algorithms", supportedCertificateAlgorithms' in source
    assert 'body.allowed_key_algorithms = BB.checkedValues(form, "allowed_key_algorithms")' in source
    assert "Select at least one certificate key algorithm." in source


def test_approval_inputs_have_accessible_help_and_keep_existing_defaults() -> None:
    class Parser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.inputs = {}
            self.help_ids = set()

        def handle_starttag(self, tag, attrs):
            attributes = dict(attrs)
            if tag == "input":
                self.inputs[attributes.get("name")] = attributes
            if tag == "p" and attributes.get("class") == "field-help":
                self.help_ids.add(attributes.get("id"))

    parser = Parser()
    parser.feed(_asset("admin.html"))
    for name, help_id, default in (
        ("first_issuance_approvals", "template-first-approval-help", "2"),
        ("renewal_approvals", "template-renewal-approval-help", "1"),
    ):
        field = parser.inputs[name]
        assert field["aria-describedby"] == help_id
        assert help_id in parser.help_ids
        assert field["value"] == default
        assert field["min"] == "0"


def test_approval_guidance_initial_values_and_field_updates():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for template approval guidance checks")
    result = subprocess.run(
        [node, str(STATIC.parents[3] / "tests/js/template_approval_guidance.cjs"),
         str(STATIC / "admin.js")],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
