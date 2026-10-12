from pathlib import Path


STATIC = Path(__file__).parents[1] / "src" / "myownca" / "online" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text()


def test_shared_leaf_import_asset_uses_two_phase_api_and_file_limit() -> None:
    source = _read("leaf-import.js")
    assert 'myOwnCA.api("/internal/certificates/import/analyze"' in source
    assert 'myOwnCA.api("/internal/certificates/import"' in source
    assert "5 * 1024 * 1024" in source
    assert "bundle_b64" in source
    assert "private_key_b64" in source
    assert "template_id" in source


def test_shared_import_asset_supports_existing_and_atomic_new_holders() -> None:
    source = _read("leaf-import.js")
    for contract_field in (
        "person_id",
        "device_id",
        "new_person",
        "new_device",
        "holder_mode",
        "template_candidates",
        "recommended_template_id",
    ):
        assert contract_field in source


def test_import_asset_is_loaded_before_each_role_script() -> None:
    role_scripts = {
        "admin.html": "admin.js",
        "superuser.html": "superuser.js",
        "user.html": "user.js",
    }
    for html_name, role_script in role_scripts.items():
        html = _read(html_name)
        assert html.index("app_shared.js") < html.index("leaf-import.js")
        assert html.index("leaf-import.js") < html.index(role_script)


def test_role_portals_expose_people_and_device_import_entry_points() -> None:
    admin_html = _read("admin.html")
    user_html = _read("user.html")
    superuser_js = _read("superuser.js")

    assert 'data-view="people"' in admin_html
    assert 'data-view="devices"' in admin_html
    assert 'id="admin-people-add-import"' in admin_html
    assert 'id="admin-devices-add-import"' in admin_html
    assert 'id="my-person-table"' in user_html
    assert 'id="my-devices-table"' in user_html
    assert 'id="my-device-add-import"' in user_html
    assert 'openLeafImport("person"' in superuser_js
    assert 'openLeafImport("device"' in superuser_js


def test_admin_can_create_matching_template_inline() -> None:
    source = _read("leaf-import.js")
    assert 'role === "admin"' in source
    assert 'myOwnCA.api("/internal/templates"' in source
    assert "Create template and re-analyze" in source


def test_certificate_inventory_exposes_archived_records_and_guarded_retirement() -> None:
    shared = _read("app_shared.js")
    user_html = _read("user.html")
    user_js = _read("user.js")
    operator_html = _read("superuser.html")
    operator_js = _read("superuser.js")

    assert "openArchiveCertificateModal" in shared
    assert "ARCHIVE CERTIFICATE" in shared
    assert "/internal/auth/totp/reauthenticate" in shared
    assert "/internal/auth/password/reauthenticate" in shared
    assert "Key-bearing export requires fresh authentication." in shared
    assert "/internal/certificate-inventory/" in shared
    assert "fixed 30-day grace period" in shared
    assert 'id="certificates-include-archived"' in user_html
    assert 'id="certs-include-archived"' in operator_html
    assert "include_archived=" in user_js
    assert "include_archived=" in operator_js
    assert "Revoke & archive" in user_js
    assert "Revoke & archive" in operator_js
