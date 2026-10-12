from pathlib import Path


STATIC = Path(__file__).parents[1] / "src" / "myownca" / "online" / "static"


def _asset(name: str) -> str:
    return (STATIC / name).read_text()


def test_certificate_view_action_opens_the_read_only_modal() -> None:
    source = _asset("superuser.js")
    view_start = source.index("async function viewCertificate")
    view_source = source[view_start : source.index("\nasync function renewCertificate", view_start)]

    assert "openCertificateViewModal(await BB.api(certificateApiPath(certificate)));" in view_source
    assert "showDetails" not in view_source


def test_certificate_viewer_renders_metadata_and_collapsed_pem_sections() -> None:
    source = _asset("superuser.js")
    modal_start = source.index("function openCertificateViewModal")
    modal_source = source[modal_start : source.index("\nasync function viewCertificate", modal_start)]

    assert 'content.className = "certificate-view";' in modal_source
    assert 'intro.textContent = "This certificate record is read-only.";' in modal_source
    for label in [
        "Subject",
        "Status",
        "Holder",
        "Template",
        "Certificate ID",
        "Serial number",
        "Requester",
        "Request ID",
        "Issued",
        "Expires",
        "Source",
        "Issuer ID",
        "Archived",
        "Server key",
    ]:
        assert f'certificateDetailRow(details, "{label}"' in modal_source
    assert '"Certificate PEM"' in modal_source
    assert '"Issuer chain PEM"' in modal_source
    assert modal_source.count("appendCertificatePemSection(") == 2
    assert 'document.createElement("details")' in source
    assert "details.open" not in modal_source
    assert "form.addEventListener" not in modal_source
    assert "BB.modal({ title: `View certificate — ${certificate.subject || certificate.serial_number}`, content });" in modal_source


def test_certificate_viewer_has_dedicated_layout_styles() -> None:
    source = _asset("app.css")

    assert ".certificate-view {" in source
    assert ".certificate-view-summary {" in source
    assert ".certificate-view details {" in source
