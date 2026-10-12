(() => {
  "use strict";

  const MAX_FILE_BYTES = 5 * 1024 * 1024;
  const SUPPORTED_KEY_USAGES = new Set([
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "encipher_only",
    "decipher_only",
  ]);
  const SUPPORTED_EXTENDED_KEY_USAGES = new Set([
    "client_auth",
    "server_auth",
    "email_protection",
  ]);

  function formTemplate() {
    const template = document.createElement("template");
    template.innerHTML = `
      <form class="leaf-import-form">
        <ol class="leaf-import-steps" aria-label="Import progress">
          <li class="is-active" data-step-indicator="holder">1. Holder</li>
          <li data-step-indicator="files">2. Files</li>
          <li data-step-indicator="review">3. Review</li>
        </ol>

        <section class="leaf-import-section" data-import-section="holder">
          <h3>Certificate holder</h3>
          <fieldset class="leaf-import-mode">
            <legend>Holder source</legend>
            <label class="checkbox">
              <input type="radio" name="holder_mode" value="existing" checked>
              Existing holder
            </label>
            <label class="checkbox" data-new-holder-choice>
              <input type="radio" name="holder_mode" value="new">
              Add holder together with the certificate
            </label>
          </fieldset>
          <label>Holder type
            <select name="holder_type">
              <option value="person">Person</option>
              <option value="device">Device</option>
            </select>
          </label>
          <div data-existing-holder>
            <label data-existing-person>Person
              <select name="person_id"></select>
            </label>
            <label data-existing-device class="hidden">Device
              <select name="device_id"></select>
            </label>
          </div>
          <fieldset data-new-person class="hidden">
            <legend>New person</legend>
            <div class="grid grid-2">
              <label>First name <input name="new_person_name"></label>
              <label>Surname <input name="new_person_surname"></label>
            </div>
            <label>Email <input name="new_person_email" type="email"></label>
            <div class="grid grid-2">
              <label>Phone <input name="new_person_phone"></label>
              <label>Slack handle <input name="new_person_slack_handle" placeholder="@user"></label>
            </div>
            <label>Company <input name="new_person_company"></label>
            <label>Comments <textarea name="new_person_comments" rows="2"></textarea></label>
          </fieldset>
          <fieldset data-new-device class="hidden">
            <legend>New device</legend>
            <label>Device name <input name="new_device_name"></label>
            <label>FQDN <input name="new_device_fqdn" placeholder="host.example.test"></label>
            <label>Responsible person
              <select name="new_device_admin_id"></select>
            </label>
            <label>Comments <textarea name="new_device_comments" rows="2"></textarea></label>
          </fieldset>
        </section>

        <section class="leaf-import-section" data-import-section="files">
          <h3>Certificate files</h3>
          <label>Certificate bundle
            <input name="bundle_file" type="file"
              accept=".pem,.crt,.cer,.p12,.pfx,application/x-pem-file,application/x-pkcs12"
              required>
          </label>
          <p class="hint">PEM may contain the leaf, chain, and private key. PKCS#12/PFX and certificate-only imports are also supported. Maximum 5 MiB per file.</p>
          <label>Separate private key PEM (optional)
            <input name="private_key_file" type="file" accept=".pem,.key,application/x-pem-file">
          </label>
          <label>File password (optional)
            <input name="password" type="password" autocomplete="off">
          </label>
        </section>

        <section class="leaf-import-section hidden" data-import-section="review" aria-live="polite">
          <h3>Validated certificate</h3>
          <dl class="leaf-import-summary" data-analysis-summary></dl>
          <details>
            <summary>Certificate policy signals</summary>
            <div data-analysis-signals></div>
          </details>
          <label>Matching template
            <select name="template_id"></select>
          </label>
          <p class="form-state" data-template-state></p>
          <fieldset class="hidden" data-template-create>
            <legend>Create a matching template</legend>
            <p class="hint">Only Administrators can create templates. The certificate's exact KU/EKU policy will be used.</p>
            <div class="grid grid-2">
              <label>Template ID <input name="new_template_id"></label>
              <label>Name <input name="new_template_name"></label>
            </div>
            <label>Profile
              <select name="new_template_profile">
                <option value="user_auth">User / client authentication</option>
                <option value="host_tls">Host / server TLS</option>
                <option value="smime">S/MIME</option>
              </select>
            </label>
            <label>Validity for future renewals (days)
              <input name="new_template_validity_days" type="number" min="1" value="365">
            </label>
            <button type="button" class="secondary" data-create-template>Create template and re-analyze</button>
          </fieldset>
        </section>

        <p class="form-state" role="status" aria-live="polite" data-import-state>
          Select the holder and certificate files, then analyze them.
        </p>
        <div class="actions leaf-import-actions">
          <button type="submit" data-primary-action>Analyze certificate</button>
        </div>
      </form>
    `;
    return template.content.firstElementChild;
  }

  function bytesToBase64(bytes) {
    let binary = "";
    const chunkSize = 32 * 1024;
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    }
    return window.btoa(binary);
  }

  async function fileToBase64(file, label) {
    if (!file) return null;
    if (file.size > MAX_FILE_BYTES) {
      throw new Error(`${label} exceeds the 5 MiB upload limit.`);
    }
    return bytesToBase64(new Uint8Array(await file.arrayBuffer()));
  }

  function holderLabel(type, row) {
    if (type === "device") {
      const owner = row.admin_name || row.admin_email || row.admin_id || "no owner";
      return `${row.device_name}${row.fqdn ? ` (${row.fqdn})` : ""} — ${owner}`;
    }
    return `${row.full_name || `${row.name || ""} ${row.surname || ""}`.trim()} (${row.email})`;
  }

  function detailRow(term, value) {
    const termNode = document.createElement("dt");
    termNode.textContent = term;
    const valueNode = document.createElement("dd");
    valueNode.textContent = value || "—";
    return [termNode, valueNode];
  }

  function dateText(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
  }

  function safeTemplateId(analysis) {
    const tail = String(analysis.serial_number || analysis.fingerprint_sha256 || "certificate")
      .replace(/[^A-Za-z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(-24);
    return `import-${tail || "certificate"}`;
  }

  function suggestedProfile(signals) {
    const usages = new Set(signals?.extended_key_usages || []);
    if (usages.has("server_auth")) return "host_tls";
    if (usages.has("email_protection")) return "smime";
    return "user_auth";
  }

  function templateCanBeCreated(signals) {
    const keyUsages = signals?.key_usages || [];
    const extendedKeyUsages = signals?.extended_key_usages || [];
    return keyUsages.length > 0
      && extendedKeyUsages.length > 0
      && keyUsages.every((usage) => SUPPORTED_KEY_USAGES.has(usage))
      && extendedKeyUsages.every(
        (usage) => SUPPORTED_EXTENDED_KEY_USAGES.has(usage),
      );
  }

  function formValue(form, name) {
    return String(form.elements[name]?.value || "").trim();
  }

  function setRequired(root, required) {
    root.querySelectorAll("input, select, textarea").forEach((control) => {
      if (control.dataset.alwaysOptional === "true") return;
      control.required = required && [
        "new_person_name",
        "new_person_surname",
        "new_person_email",
        "new_device_name",
        "new_device_admin_id",
      ].includes(control.name);
    });
  }

  function analysisSignalsText(analysis) {
    const signals = analysis.signals || {};
    const sans = (signals.subject_alt_names || [])
      .map((item) => `${item.kind}: ${item.value}`)
      .join("; ") || "none";
    return [
      `Key usage: ${(signals.key_usages || []).join(", ") || "none"}`,
      `Extended key usage: ${(signals.extended_key_usages || []).join(", ") || "none"}`,
      `SAN: ${sans}`,
    ];
  }

  async function openLeafImportModal({
    holderType = "person",
    holder = null,
    initialMode = "existing",
    people = null,
    devices = null,
    onImported = null,
  } = {}) {
    const [peopleRows, deviceRows] = await Promise.all([
      people ? Promise.resolve(people) : myOwnCA.api("/internal/people"),
      devices ? Promise.resolve(devices) : myOwnCA.api("/internal/devices"),
    ]);
    const role = myOwnCA.currentUser?.role;
    const allowNewPerson = role === "admin" || role === "superuser";
    const form = formTemplate();
    const stateNode = form.querySelector("[data-import-state]");
    const primaryButton = form.querySelector("[data-primary-action]");
    const reviewSection = form.querySelector('[data-import-section="review"]');
    const summary = form.querySelector("[data-analysis-summary]");
    const signalsNode = form.querySelector("[data-analysis-signals]");
    const templateState = form.querySelector("[data-template-state]");
    const templateCreate = form.querySelector("[data-template-create]");
    const createTemplateButton = form.querySelector("[data-create-template]");
    const personSelect = form.elements.person_id;
    const deviceSelect = form.elements.device_id;
    const deviceAdminSelect = form.elements.new_device_admin_id;
    let analysis = null;
    let artifacts = null;
    let busy = false;

    myOwnCA.fillSelect(personSelect, peopleRows, {
      value: "id",
      label: (row) => holderLabel("person", row),
      placeholder: "Choose person",
    });
    myOwnCA.fillSelect(deviceAdminSelect, peopleRows, {
      value: "id",
      label: (row) => holderLabel("person", row),
      placeholder: "Choose responsible person",
    });
    myOwnCA.fillSelect(deviceSelect, deviceRows, {
      value: "id",
      label: (row) => holderLabel("device", row),
      placeholder: "Choose device",
    });

    form.elements.holder_type.value = holderType === "device" ? "device" : "person";
    if (holder?.id) {
      form.elements[holderType === "device" ? "device_id" : "person_id"].value = holder.id;
    }
    if (role === "user" && peopleRows.length === 1) {
      deviceAdminSelect.value = peopleRows[0].id;
    }
    const requestedNewMode = initialMode === "new";
    form.elements.holder_mode.value = requestedNewMode ? "new" : "existing";
    if (requestedNewMode && role === "user" && form.elements.holder_type.value === "person") {
      form.elements.holder_type.value = "device";
    }

    function setState(message, tone = "") {
      stateNode.textContent = message;
      stateNode.classList.toggle("danger-text", tone === "error");
      stateNode.classList.toggle("status-pass", tone === "success");
    }

    function syncHolderFields() {
      const mode = form.elements.holder_mode.value;
      const type = form.elements.holder_type.value;
      const newMode = mode === "new";
      const personOption = form.elements.holder_type.querySelector('option[value="person"]');
      personOption.disabled = newMode && !allowNewPerson;
      if (newMode && type === "person" && !allowNewPerson) {
        form.elements.holder_type.value = "device";
        syncHolderFields();
        return;
      }
      form.querySelector("[data-existing-holder]").classList.toggle("hidden", newMode);
      form.querySelector("[data-existing-person]").classList.toggle(
        "hidden", newMode || type !== "person",
      );
      form.querySelector("[data-existing-device]").classList.toggle(
        "hidden", newMode || type !== "device",
      );
      const newPerson = form.querySelector("[data-new-person]");
      const newDevice = form.querySelector("[data-new-device]");
      newPerson.classList.toggle("hidden", !newMode || type !== "person");
      newDevice.classList.toggle("hidden", !newMode || type !== "device");
      setRequired(newPerson, newMode && type === "person");
      setRequired(newDevice, newMode && type === "device");
      personSelect.required = !newMode && type === "person";
      deviceSelect.required = !newMode && type === "device";
    }

    function resetAnalysis() {
      analysis = null;
      artifacts = null;
      reviewSection.classList.add("hidden");
      primaryButton.textContent = "Analyze certificate";
      primaryButton.disabled = false;
      form.querySelectorAll("[data-step-indicator]").forEach((item) => {
        item.classList.toggle("is-active", item.dataset.stepIndicator === "holder");
        item.classList.remove("is-complete");
      });
      setState("Select the holder and certificate files, then analyze them.");
    }

    function holderPayload() {
      const type = form.elements.holder_type.value;
      const mode = form.elements.holder_mode.value;
      if (mode === "existing") {
        const id = formValue(form, type === "person" ? "person_id" : "device_id");
        if (!id) throw new Error(`Choose an existing ${type}.`);
        return type === "person" ? { person_id: id } : { device_id: id };
      }
      if (type === "person") {
        if (!allowNewPerson) throw new Error("Users cannot create additional Person records.");
        return {
          new_person: {
            name: formValue(form, "new_person_name"),
            surname: formValue(form, "new_person_surname"),
            email: formValue(form, "new_person_email"),
            phone: formValue(form, "new_person_phone"),
            slack_handle: formValue(form, "new_person_slack_handle"),
            company: formValue(form, "new_person_company"),
            comments: formValue(form, "new_person_comments"),
          },
        };
      }
      const adminId = formValue(form, "new_device_admin_id") || peopleRows[0]?.id || "";
      if (!adminId) throw new Error("Choose the responsible person for the new device.");
      return {
        new_device: {
          device_name: formValue(form, "new_device_name"),
          fqdn: formValue(form, "new_device_fqdn"),
          admin_id: adminId,
          comments: formValue(form, "new_device_comments"),
        },
      };
    }

    async function artifactPayload() {
      const bundleFile = form.elements.bundle_file.files[0];
      const keyFile = form.elements.private_key_file.files[0];
      if (!bundleFile) throw new Error("Choose a PEM, P12, or PFX certificate bundle.");
      return {
        bundle_b64: await fileToBase64(bundleFile, "Certificate bundle"),
        private_key_b64: await fileToBase64(keyFile, "Private key"),
        password: form.elements.password.value || null,
      };
    }

    function renderAnalysis(result) {
      summary.replaceChildren(
        ...detailRow("Subject", result.subject),
        ...detailRow("Issuer", result.issuer),
        ...detailRow("Serial", result.serial_number),
        ...detailRow("Valid from", dateText(result.not_before)),
        ...detailRow("Valid until", dateText(result.not_after)),
        ...detailRow("Private key", result.has_private_key ? "Included and matched" : "Certificate only"),
        ...detailRow("Container", String(result.source_format || "").toUpperCase()),
      );
      signalsNode.replaceChildren();
      for (const line of analysisSignalsText(result)) {
        const paragraph = document.createElement("p");
        paragraph.textContent = line;
        signalsNode.append(paragraph);
      }
      myOwnCA.fillSelect(form.elements.template_id, result.template_candidates || [], {
        value: "id",
        label: (row) => `${row.name} (${row.profile})`,
        placeholder: "Choose matching template",
      });
      if (result.recommended_template_id) {
        form.elements.template_id.value = result.recommended_template_id;
      }
      const hasCandidates = Boolean((result.template_candidates || []).length);
      form.elements.template_id.disabled = !hasCandidates;
      form.elements.template_id.required = hasCandidates;
      templateCreate.classList.add("hidden");
      if (hasCandidates) {
        templateState.textContent = result.recommended_template_id
          ? "One exact KU/EKU match was found. Confirm it before import."
          : "Choose one of the exact KU/EKU matches.";
        primaryButton.disabled = false;
      } else if (role === "admin" && templateCanBeCreated(result.signals)) {
        templateState.textContent = "No exact template exists. Create one below, then continue.";
        templateCreate.classList.remove("hidden");
        form.elements.new_template_id.value = safeTemplateId(result);
        form.elements.new_template_name.value = `Imported certificate ${result.serial_number}`;
        form.elements.new_template_profile.value = suggestedProfile(result.signals);
        primaryButton.disabled = true;
      } else {
        templateState.textContent = role === "admin"
          ? "No exact template exists and this certificate uses KU/EKU values unsupported by template policy."
          : "No exact template exists. Ask an Administrator to create a matching template.";
        primaryButton.disabled = true;
      }
      reviewSection.classList.remove("hidden");
      form.querySelectorAll("[data-step-indicator]").forEach((item) => {
        item.classList.remove("is-active", "is-complete");
        if (item.dataset.stepIndicator === "review") item.classList.add("is-active");
        else item.classList.add("is-complete");
      });
      primaryButton.textContent = "Import certificate";
      setState("Certificate and chain validated. Confirm the holder and template.", "success");
    }

    async function analyze() {
      holderPayload();
      artifacts = await artifactPayload();
      analysis = await myOwnCA.api("/internal/certificates/import/analyze", {
        method: "POST",
        body: JSON.stringify(artifacts),
      });
      renderAnalysis(analysis);
    }

    async function createMatchingTemplate() {
      if (!analysis) return;
      const id = formValue(form, "new_template_id");
      const name = formValue(form, "new_template_name");
      if (!id || !name) throw new Error("Template ID and name are required.");
      createTemplateButton.disabled = true;
      try {
        await myOwnCA.api("/internal/templates", {
          method: "POST",
          body: JSON.stringify({
            id,
            name,
            profile: form.elements.new_template_profile.value,
            validity_days: Number(form.elements.new_template_validity_days.value || 365),
            first_issuance_approvals: 2,
            renewal_approvals: 1,
            key_usages: analysis.signals.key_usages,
            extended_key_usages: analysis.signals.extended_key_usages,
            key_usage_critical: analysis.signals.key_usage_critical ?? true,
            extended_key_usage_critical: analysis.signals.extended_key_usage_critical ?? false,
          }),
        });
        analysis = await myOwnCA.api("/internal/certificates/import/analyze", {
          method: "POST",
          body: JSON.stringify(artifacts),
        });
        renderAnalysis(analysis);
        form.elements.template_id.value = id;
      } finally {
        createTemplateButton.disabled = false;
      }
    }

    const dialog = myOwnCA.modal({
      title: initialMode === "new" ? "Add holder and import certificate" : "Import certificate",
      content: form,
      onClose: () => {
        form.elements.password.value = "";
        artifacts = null;
        analysis = null;
      },
    });

    form.querySelector("[data-new-holder-choice]").classList.toggle(
      "hidden", role === "user" && deviceRows.length === 0 && peopleRows.length === 0,
    );
    form.elements.holder_mode.forEach((input) => {
      input.addEventListener("change", syncHolderFields);
    });
    form.elements.holder_type.addEventListener("change", syncHolderFields);
    for (const field of [form.elements.bundle_file, form.elements.private_key_file]) {
      field.addEventListener("change", resetAnalysis);
    }
    form.elements.password.addEventListener("input", resetAnalysis);
    createTemplateButton.addEventListener("click", async () => {
      try {
        setState("Creating a matching template…");
        await createMatchingTemplate();
      } catch (error) {
        setState(error?.message || String(error), "error");
        myOwnCA.showError(error);
      }
    });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (busy) return;
      busy = true;
      primaryButton.disabled = true;
      try {
        if (!analysis) {
          setState("Reading and validating the certificate bundle…");
          await analyze();
          return;
        }
        const templateId = formValue(form, "template_id");
        if (!templateId) throw new Error("Choose a matching template before import.");
        setState("Importing the certificate and holder atomically…");
        const imported = await myOwnCA.api("/internal/certificates/import", {
          method: "POST",
          body: JSON.stringify({
            ...artifacts,
            ...holderPayload(),
            template_id: templateId,
          }),
        });
        myOwnCA.showResult({
          status: "Certificate imported successfully.",
          certificate: imported,
        });
        dialog.close();
        if (onImported) {
          try {
            await onImported(imported);
          } catch (refreshError) {
            myOwnCA.showError(refreshError);
          }
        }
      } catch (error) {
        setState(error?.message || String(error), "error");
        myOwnCA.showError(error);
      } finally {
        busy = false;
        if (form.isConnected) {
          primaryButton.disabled = Boolean(
            analysis && !(analysis.template_candidates || []).length,
          );
        }
      }
    });
    syncHolderFields();
    return dialog;
  }

  myOwnCA.openLeafImportModal = openLeafImportModal;
  myOwnCA.LEAF_IMPORT_MAX_FILE_BYTES = MAX_FILE_BYTES;
})();
