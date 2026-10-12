from pathlib import Path


STATIC = Path(__file__).parents[1] / "src" / "myownca" / "online" / "static"
SETUP_PAGE = (
    Path(__file__).parents[1] / "src" / "myownca" / "setup" / "static" / "setup.html"
)


def test_setup_exposes_all_initial_sub_ca_import_modes() -> None:
    page = SETUP_PAGE.read_text()

    assert "Root CA certificate import" in page
    assert "Paste your offline-generated root cert for Production." in page
    assert 'id="root-cert-file" type="file"' in page
    assert "Or paste the Root CA certificate PEM" in page
    assert page.index('id="root-cert-file"') < page.index('id="root-cert-input"')
    assert 'class="form-row root-cert-action-row"' in page
    assert ".root-cert-action-row button { width: 100%; }" in page
    assert "Create new key + offline ceremony" in page
    assert 'id="issuer-production-root-hint"' not in page
    assert 'id="issuer-request-status"' in page
    assert 'id="issuer-response-status"' in page
    assert 'id="issuer-production-root-status"' in page
    assert 'Import the Root CA certificate before provisioning a Production issuer' in page
    assert 'function updateIssuerProductionRootStatus()' in page
    assert 'updateIssuerProductionRootStatus();' in page
    assert 'clearIssuerProductionRootStatus();' in page
    assert 'function showIssuerError(error, localStatusId = null)' in page
    assert 'status.className = "status-message status-neutral hidden";' in page
    algorithm_order = [
        'value="ecdsa-p521"',
        'value="ecdsa-p384"',
        'value="ecdsa-p256"',
        'value="rsa-4096"',
        'value="rsa-3072"',
        'value="rsa-2048"',
    ]
    new_algorithm = page[page.index('id="issuer-new-algorithm"'):page.index('</select></label>', page.index('id="issuer-new-algorithm"'))]
    existing_algorithm = page[page.index('id="issuer-existing-algorithm"'):page.index('</select></label>', page.index('id="issuer-existing-algorithm"'))]
    assert [new_algorithm.index(option) for option in algorithm_order] == sorted(
        new_algorithm.index(option) for option in algorithm_order
    )
    assert [existing_algorithm.index(option) for option in algorithm_order] == sorted(
        existing_algorithm.index(option) for option in algorithm_order
    )
    assert "Import existing Sub CA certificate" in page
    assert "Import P12 or PEM" in page
    assert "Validate import (dry run)" in page
    assert "Validate bundle (dry run)" in page
    assert "Validate recovery (dry run)" in page
    assert ">Analyze</button>" not in page
    assert "Restore Sub CA key from wrapped backup" in page
    assert 'id="issuer-existing-hsm-fields"' in page
    assert 'id="issuer-existing-hsm-list"' in page
    assert 'id="issuer-existing-hsm-key"' in page
    assert 'id="issuer-existing-hsm-details"' in page
    assert 'id="issuer-existing-cloud-fields"' in page
    assert "AWS KMS key ARN" in page
    assert "Azure Key Vault key URL" in page
    assert 'placeholder="HSM label, ARN, or versioned key URL"' not in page
    assert 'id="issuer-existing-pin"' not in page
    assert "function hsmKeyAlgorithm(key)" in page
    assert "function updateIssuerExistingKeyView()" in page
    assert 'body: JSON.stringify({\n            ...hsmPayload(),\n            user_pin: pin,' in page
    assert "Test/Lab — create local CA" in page
    assert "function updateIssuerModeActions" in page
    assert '$("issuer-lab-mode").classList.toggle("hidden", !lab)' in page
    assert 'const canAdoptExistingKey = backend === "aws_kms"' in page
    assert '(backend === "pkcs11" && pkcs11Mode === "existing")' in page
    assert '!lab && !canAdoptExistingKey' in page
    assert '$("issuer-new-mode").classList.toggle("hidden", !lab && pkcs11Mode === "recovery")' in page
    assert "function clearPkcs11SetupChoices" in page
    assert 'input[name="pkcs11-setup-mode"], input[name="pkcs11-dkek-migration"]' in page
    assert 'radio.name === "key-storage-location" || selectedHsmBackend() !== "pkcs11"' in page
    assert '!lab && backend !== "software"' in page
    assert '!lab && !canRestoreWrappedKey' in page
    assert 'backend === "pkcs11"' in page
    assert '["existing", "recovery"].includes(pkcs11Mode)' in page
    assert "/setup/issuer/existing-key/analyze" in page
    assert "/setup/issuer/existing-key/commit" in page
    assert "/setup/issuer/file/analyze" in page
    assert "/setup/issuer/file/commit" in page
    assert "/setup/issuer/dkek/analyze" in page
    assert "/setup/issuer/dkek/restore" in page
    assert "/setup/issuer/request" in page
    assert "/setup/issuer/response/import" in page
    assert 'id="issuer-request-csr"' in page
    assert 'id="issuer-request-copy"' in page
    assert 'id="issuer-response-cert"' in page
    assert 'id="issuer-response-cert-file" type="file"' in page
    assert 'id="issuer-existing-cert"' in page
    assert 'id="issuer-existing-cert-file" type="file"' in page
    assert 'id="issuer-existing-status" class="status-message status-neutral hidden"' in page
    assert 'id="issuer-dkek-cert"' in page
    assert 'id="issuer-dkek-cert-file" type="file"' in page
    assert 'id="issuer-file-status" class="status-message status-neutral hidden"' in page
    assert 'id="issuer-dkek-status" class="status-message status-neutral hidden"' in page
    assert 'id="issuer-file-bundle-pem"' in page
    assert 'id="issuer-file-bundle" type="file"' in page
    assert 'class="issuer-file-source-grid"' in page
    assert page.count('class="issuer-file-source"') == 3
    assert '.issuer-file-source {' in page
    assert '.issuer-file-source textarea {' in page
    assert 'class="url-grid issuer-file-options"' in page
    assert "function updateIssuerPkcs11PinFields()" in page
    for field_id, input_id in (
        ("issuer-new-pin-field", "issuer-new-pin"),
        ("issuer-response-pin-field", "issuer-response-pin"),
        ("issuer-file-pin-field", "issuer-file-pin"),
    ):
        assert f'id="{field_id}" class="issuer-pkcs11-pin-field"' in page
        assert f'id="{input_id}" type="password"' in page
    assert 'field.classList.toggle("hidden", !isPkcs11)' in page
    assert 'input.disabled = !isPkcs11' in page
    assert 'if (!isPkcs11) input.value = ""' in page
    assert 'updateIssuerExistingKeyView();\n      updateIssuerPkcs11PinFields();' in page
    assert page.count('...(selectedHsmBackend() === "pkcs11" ? {') == 3
    for prefix in ("issuer-existing", "issuer-file", "issuer-dkek"):
        assert f'id="{prefix}-crl-file" type="file"' in page
        assert f'id="{prefix}-crl-pem"' in page
        assert f'id="{prefix}-crl-file-field"' in page
        assert f'id="{prefix}-crl-pem-field"' in page
        assert page.index(f'id="{prefix}-crl-file"') < page.index(f'id="{prefix}-crl-pem"')
    assert "Or paste the latest complete CRL PEM" in page
    assert "I explicitly confirm that this Sub CA never issued a CRL" not in page
    assert page.index('id="issuer-response-cert-file"') < page.index('id="issuer-response-cert"')
    assert page.index('id="issuer-existing-cert-file"') < page.index('id="issuer-existing-cert"')
    assert page.index('id="issuer-file-bundle"') < page.index('id="issuer-file-bundle-pem"')
    assert page.index('id="issuer-dkek-cert-file"') < page.index('id="issuer-dkek-cert"')
    assert "async function certificateInputPem" in page
    assert "function bindCertificateSources" in page
    assert 'bindCertificateSources("root-cert-input", "root-cert-file", clearRootCertificateVerification)' in page
    assert 'bindCertificateSources("issuer-existing-cert", "issuer-existing-cert-file")' in page
    assert 'bindCertificateSources("issuer-dkek-cert", "issuer-dkek-cert-file")' in page
    assert "async function bundleInputBase64()" in page
    assert "async function textOrFileBase64" in page
    assert "function updateCrlMigrationFields(prefix)" in page
    assert "Paste the latest complete CRL PEM or choose a CRL file." in page
    assert 'bindCertificateSources("issuer-existing-crl-pem", "issuer-existing-crl-file")' in page
    assert 'bindCertificateSources("issuer-file-crl-pem", "issuer-file-crl-file")' in page
    assert 'bindCertificateSources("issuer-dkek-crl-pem", "issuer-dkek-crl-file")' in page
    assert 'updateCrlMigrationFields(prefix)' in page
    assert '"issuer-existing-status"' in page
    assert '"issuer-file-status"' in page
    assert '"issuer-dkek-status"' in page
    assert 'id="issuer-existing-csr-key"' not in page
    assert "existing_key_ref: existingKeyRef" not in page
    assert "Use adopted HSM key + offline ceremony" not in page
    assert 'id="pkcs11-probe-pin"' in page
    assert "User PIN (optional; required to list private keys)" in page
    assert "User PIN for probe/adoption" not in page
    assert "PKCS#11 User PIN for final key verification (required for HSM)" in page
    assert '$("finalize-pin").required = backend === "pkcs11"' in page
    assert '$("finalize-pin").disabled = backend !== "pkcs11"' in page
    assert 'const finalPinReady = selectedHsmBackend() !== "pkcs11" || Boolean($("finalize-pin").value.trim())' in page
    assert 'Enter the PKCS#11 User PIN for final key verification before finishing setup.' in page
    assert '$("finalize-pin").addEventListener("input", updateFinalizeAvailability)' in page
    assert 'id="pkcs11-adopt-pin"' in page
    assert 'body: JSON.stringify({ user_pin: $("pkcs11-adopt-pin").value })' in page
    assert "Erase and initialize HSM" in page
    assert "erase_existing_keys: eraseExistingKeys" in page
    assert 'selectedPkcs11SetupMode() !== "existing"' in page
    assert "pkcs11InitializationBlockedByKeys" in page
    assert "retry to proceed with erasure" in page
    assert "function apiErrorMessage" in page
    assert 'id="issuer-setup-status" class="status-message status-neutral"' in page
    assert page.index('id="issuer-existing-commit"') < page.index('id="issuer-setup-status"')
    assert page.index('id="issuer-setup-status"') < page.index('id="issuer-analysis-output"') < page.index('id="issuer-reset"')
    assert "Optional: Reset issuer setup" in page
    assert "The Issuing Sub CA is already configured and working." in page
    assert 'id="issuer-reset" type="button" class="warning-button">Reset issuer setup…</button>' in page
    assert "background: #d6a617" in page
    assert 'status.className = "status-message status-error"' in page
    assert 'item.loc.filter((part) => part !== "body").join(".")' in page
    assert "function validatePkcs11Initialization" in page
    assert 'pattern="[0-9A-Fa-f]{16}"' in page
    assert 'pattern="[0-9]{6,15}"' in page
    assert "openssl genpkey" in page
    assert "-algorithm RSA" in page
    assert "openssl req -new -x509" in page
    assert "openssl x509 -req" in page
    assert "-copy_extensions copy" in page
    assert 'class="command-helper"' in page
    assert 'data-copy-command="issuer-sign-command"' in page
    assert 'class="status-message status-neutral" role="status" aria-live="polite"' in page
    assert "catch (_) {}" not in page
    assert "navigator.clipboard.writeText" in page
    assert "/setup/issuer/request-bundle" not in page
    assert "/setup/issuer/response-bundle" not in page
    assert "Signed response archive" not in page
    assert "Type <code>CREATE LAB CA</code>" not in page
    assert 'id="issuer-lab-confirm"' not in page
    assert "Type <code>IMPORT EXISTING SUBCA</code>" not in page
    assert "5 MiB" in page
    assert "Wrapped-key bundle" in page
    assert "Enter the password for each selected share:" in page
    assert "Native HSM backups can be created later." in page
    assert "Security → HSM &amp; Keys → Export native HSM backups" in page
    assert 'id="pkcs11-import-share-rows"' in page
    assert "function updatePkcs11ImportShareRows" in page
    assert 'filename.readOnly = true' in page
    assert 'password.dataset.dkekPassword = "true"' in page
    assert 'addEventListener("change", updatePkcs11ImportShareRows)' in page
    assert 'id="issuer-dkek-shares"' not in page
    assert 'id="issuer-dkek-share-passwords"' not in page
    assert 'sessionStorage.setItem("myownca_setup_csrf"' in page
    assert "The setup session expired or the setup process restarted" in page
    assert not (STATIC / "admin-issuer-wizard.js").exists()


def test_hsm_key_inventory_exposes_native_backup_and_delayed_retirement() -> None:
    script = (STATIC / "admin.js").read_text()
    page = (STATIC / "admin.html").read_text()

    assert "Request native SmartCard-HSM backup export" in script
    assert "/internal/hsm/token-backup/export-proposals" in script
    assert "/internal/admin/hsm/token-backup/proposals/" in script
    assert "REQUEST EXPORT ENTIRE HSM" in script
    assert "APPROVE EXPORT ENTIRE HSM" in script
    assert "hsm_raw_backup_export" in script
    assert 'BB.$("#hsm-raw-backup-controls").classList.remove("hidden");' in script
    assert 'BB.$("#hsm-raw-backup-export").disabled = !rawBackupAvailable;' in script
    assert "wrapped-key-${reference}.bin" not in script
    assert "Create key recovery backup" not in script
    assert "/internal/hsm/keys/recovery-backup" not in script
    assert "/internal/hsm/keys/recovery-restore" not in script
    assert "Retire key" in script
    assert "mandatory 30-day grace period" in script
    assert "fixed 30-day grace period" in page
    assert "This grace period cannot be bypassed" in page
    assert "Request native HSM backup export" in page
    assert "A different administrator must approve the request" in page
