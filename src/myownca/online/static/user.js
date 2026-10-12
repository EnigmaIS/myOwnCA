const BB = myOwnCA;
let templates = [];
let certificates = [];
let ownPeople = [];
let ownDevices = [];
let emailSanDirty = false;

BB.init().then(() => {
  BB.mountRecoveryCodes("#account-security");
  return loadAll();
}).catch(BB.showError);
BB.$("#refresh").addEventListener("click", () => loadAll().catch(BB.showError));
BB.$("#clear-output").addEventListener("click", () => BB.setOutput("Select a request or certificate to inspect it."));
BB.$("#my-person-refresh").addEventListener("click", () => refreshOwnPeople().catch(BB.showError));
BB.$("#my-devices-refresh").addEventListener("click", () => refreshOwnDevices().catch(BB.showError));
BB.$("#my-device-add-import").addEventListener("click", () => {
  openUserLeafImport("device", null, "new").catch(BB.showError);
});
BB.$("#certificates-include-archived").addEventListener("change", () => loadAll().catch(BB.showError));
BB.$("#request-kind").addEventListener("change", syncRenewalMode);
BB.$("#renewal-certificate-select").addEventListener("change", syncRenewalTemplate);
BB.$("#key-source").addEventListener("change", syncKeySource);
BB.$("#template-select").addEventListener("change", syncKeySource);
BB.$("#request-form").elements.email_addresses.addEventListener("input", () => {
  emailSanDirty = true;
});

BB.$("#request-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const body = BB.formPayload(event.currentTarget);
    let created;
    if (BB.$("#key-source").value === "server" && body.kind !== "renewal") {
      const profile = selectedProfile();
      created = await BB.api("/internal/certificate-requests/generate", {
        method: "POST",
        body: JSON.stringify({
          template_id: body.template_id,
          common_name: body.common_name,
          ...BB.profileSanPayload(event.currentTarget, profile),
          algorithm: body.algorithm,
        }),
      });
    } else {
      delete body.common_name;
      delete body.dns_names;
      delete body.email_addresses;
      delete body.algorithm;
      if (body.kind === "renewal") {
        const certificate = certificates.find(
          (candidate) =>
            candidate.certificate_id === body.renewal_of_serial_number ||
            (!candidate.certificate_id && candidate.serial_number === body.renewal_of_serial_number),
        );
        if (!certificate) {
          throw new Error("Choose one of your active issued certificates to renew.");
        }
        body.template_id = certificate.template_id;
        if (certificate.certificate_id) {
          body.renewal_of_certificate_id = certificate.certificate_id;
          delete body.renewal_of_serial_number;
        }
      } else {
        delete body.renewal_of_serial_number;
        delete body.renewal_of_certificate_id;
      }
      created = await BB.api("/internal/certificate-requests", {
        method: "POST",
        body: JSON.stringify(body),
      });
    }
    BB.setOutput(created);
    event.currentTarget.reset();
    emailSanDirty = false;
    syncKeySource();
    await loadAll();
  } catch (error) {
    BB.showError(error);
  }
});

async function loadAll() {
  const includeArchived = BB.$("#certificates-include-archived").checked;
  [templates, certificates, ownPeople, ownDevices] = await Promise.all([
    BB.api("/internal/templates"),
    BB.api(`/internal/certificate-inventory?include_archived=${includeArchived}`),
    BB.api("/internal/people"),
    BB.api("/internal/devices"),
  ]);
  BB.fillSelect(BB.$("#template-select"), templates, {
    value: "id",
    label: (row) => `${row.name} (${row.profile})`,
    placeholder: "Choose template",
  });
  BB.fillSelect(
    BB.$("#renewal-certificate-select"),
    certificates
      .filter((certificate) => certificate.status === "active")
      .map((certificate) => ({
        ...certificate,
        canonical_reference: certificate.certificate_id || certificate.serial_number,
      })),
    {
      value: "canonical_reference",
      label: (row) => `${row.subject} — ${row.template_name} (${row.serial_number})`,
      placeholder: "Choose certificate to renew",
    },
  );
  syncRenewalMode();
  renderTemplates();
  renderRequests(await BB.api("/internal/certificate-requests"));
  renderCertificates(certificates);
  renderOwnPeople();
  renderOwnDevices();
}

async function refreshOwnPeople() {
  ownPeople = await BB.api("/internal/people");
  renderOwnPeople();
}

async function refreshOwnDevices() {
  ownDevices = await BB.api("/internal/devices");
  renderOwnDevices();
}

function renderOwnPeople() {
  BB.renderTable(
    BB.$("#my-person-table"),
    ownPeople,
    [
      { header: "Name", render: (row) => row.full_name },
      { header: "Email", key: "email" },
      { header: "Company", render: (row) => row.company || "—" },
      {
        header: "Actions",
        render: (row) => BB.actionButton(
          "Import certificate",
          () => openUserLeafImport("person", row).catch(BB.showError),
        ),
      },
    ],
    { emptyText: "Your Person record is not available." },
  );
}

function renderOwnDevices() {
  BB.renderTable(
    BB.$("#my-devices-table"),
    ownDevices,
    [
      { header: "Device", key: "device_name" },
      { header: "FQDN", render: (row) => row.fqdn || "—" },
      {
        header: "Actions",
        render: (row) => BB.actionButton(
          "Import certificate",
          () => openUserLeafImport("device", row).catch(BB.showError),
        ),
      },
    ],
    { emptyText: "You do not administer any devices yet." },
  );
}

async function openUserLeafImport(holderType, holder = null, initialMode = "existing") {
  await BB.openLeafImportModal({
    holderType,
    holder,
    initialMode,
    people: ownPeople,
    devices: ownDevices,
    onImported: loadAll,
  });
}

function renderTemplates() {
  BB.renderTable(BB.$("#template-table"), templates, [
    { header: "Name", key: "name" },
    { header: "Profile", key: "profile" },
    { header: "KU", render: (row) => row.key_usages.join(", ") },
    { header: "EKU", render: (row) => row.extended_key_usages.join(", ") },
  ]);
}

function renderRequests(rows) {
  BB.renderTable(BB.$("#request-table"), rows, [
    { header: "Created", render: (row) => new Date(row.created_at).toLocaleString() },
    { header: "Template", render: (row) => `${row.template_name} (${row.profile})` },
    { header: "Kind", key: "kind" },
    { header: "Renews", render: (row) => row.renewal_of_serial_number || "—" },
    { header: "Status", render: (row) => BB.badge(row.status) },
    { header: "Approvals", render: (row) => `${row.approval_count}/${row.required_approvals}` },
    { header: "Certificate", render: (row) => row.issued_serial_number || "pending" },
    {
      header: "Actions",
      render: (row) => {
        const actions = document.createElement("div");
        actions.className = "actions";
        if (row.status === "pending") {
          actions.append(BB.actionButton("Withdraw", async () => {
            try {
              await rejectRequest(row.id);
            } catch (error) {
              BB.showError(error);
            }
          }, "danger"));
        }
        actions.append(BB.actionButton("Details", async () => {
          BB.setOutput(await BB.api(`/internal/certificate-requests/${row.id}`));
        }));
        return actions;
      },
    },
  ]);
}

async function rejectRequest(requestId) {
  const response = await BB.api(`/internal/certificate-requests/${requestId}/reject`, {
    method: "POST",
  });
  BB.setOutput({
    status: "Request withdrawn. Submit a new CSR request when ready.",
    ...response,
  });
  await loadAll();
}

function renderCertificates(rows) {
  BB.renderTable(BB.$("#certificate-table"), rows, [
    { header: "Issued", render: (row) => new Date(row.issued_at).toLocaleString() },
    { header: "Subject", key: "subject" },
    { header: "Template", key: "template_name" },
    { header: "Source", render: (row) => row.source === "imported" ? "Imported" : "Issued" },
    { header: "Status", render: (row) => BB.badge(row.status) },
    { header: "Archived", render: (row) => row.archived_at ? new Date(row.archived_at).toLocaleDateString() : "—" },
    { header: "Key", render: (row) => (row.server_key_held ? "🔑 server" : "—") },
    {
      header: "Actions",
      render: (row) => {
        const actions = document.createElement("div");
        actions.className = "actions";
        actions.append(BB.actionButton("View PEM", async () => {
          const path = row.certificate_id
            ? `/internal/certificate-inventory/${encodeURIComponent(row.certificate_id)}`
            : `/internal/certificates/${encodeURIComponent(row.serial_number)}`;
          const certificate = await BB.api(path);
          const wrapper = document.createElement("div");
          wrapper.append(BB.pemDownload(`${row.serial_number}.pem`, certificate.certificate_pem));
          const pre = document.createElement("pre");
          pre.textContent = certificate.certificate_pem;
          wrapper.append(pre);
          BB.$("#output").replaceChildren(wrapper);
        }));
        actions.append(BB.actionButton("Export…", () =>
          BB.openExportModal(row, { onChange: () => loadAll().catch(BB.showError) }),
        ));
        if (!row.archived_at) {
          actions.append(BB.actionButton(
            "Revoke & archive",
            () => BB.openArchiveCertificateModal(row, { onChange: loadAll }).catch(BB.showError),
            "danger",
          ));
        }
        return actions;
      },
    },
    {
      header: "Renew",
      render: (row) => row.status === "active"
        ? BB.actionButton("Renew", () => selectRenewal(row))
        : "—",
    },
  ]);
}

function syncRenewalMode() {
  const isRenewal = BB.$("#request-kind").value === "renewal";
  BB.$("#renewal-certificate-field").classList.toggle("hidden", !isRenewal);
  BB.$("#renewal-hint").classList.toggle("hidden", !isRenewal);
  BB.$("#renewal-certificate-select").required = isRenewal;
  BB.$("#template-select").disabled = isRenewal;
  if (isRenewal) {
    // Renewals reuse the anchor CSR, so server-side key generation is moot.
    BB.$("#key-source").value = "csr";
  }
  BB.$("#key-source").disabled = isRenewal;
  syncKeySource();
  if (isRenewal) {
    syncRenewalTemplate();
  }
}

function syncKeySource() {
  const serverMode = BB.$("#key-source").value === "server";
  BB.$("#csr-fields").classList.toggle("hidden", serverMode);
  BB.$("#server-key-fields").classList.toggle("hidden", !serverMode);
  const form = BB.$("#request-form");
  form.elements.csr_pem.required = !serverMode;
  form.elements.common_name.required = serverMode;
  syncAlgorithmOptions();
  const profile = selectedProfile();
  BB.syncProfileSanFields(form, profile, { enabled: serverMode });
  if (serverMode && profile !== "host_tls" && !emailSanDirty) {
    form.elements.email_addresses.value = BB.currentUser?.email || "";
  }
}

function syncAlgorithmOptions() {
  const template = templates.find((candidate) => candidate.id === BB.$("#template-select").value);
  const allowed = template?.allowed_key_algorithms || [];
  const select = BB.$("#request-form").elements.algorithm;
  const previous = select.value;
  select.replaceChildren(...allowed.map((algorithm) => {
    const option = document.createElement("option");
    option.value = algorithm;
    option.textContent = algorithm;
    return option;
  }));
  if (allowed.includes(previous)) select.value = previous;
}

function selectedProfile() {
  const templateId = BB.$("#template-select").value;
  return templates.find((template) => template.id === templateId)?.profile || null;
}

function syncRenewalTemplate() {
  const reference = BB.$("#renewal-certificate-select").value;
  const certificate = certificates.find(
    (candidate) =>
      candidate.certificate_id === reference ||
      (!candidate.certificate_id && candidate.serial_number === reference),
  );
  if (certificate) {
    BB.$("#template-select").value = certificate.template_id;
  }
}

function selectRenewal(certificate) {
  BB.$("#request-kind").value = "renewal";
  BB.$("#renewal-certificate-select").value = certificate.certificate_id || certificate.serial_number;
  syncRenewalMode();
  document.querySelector("#request-form").scrollIntoView({ behavior: "smooth", block: "start" });
}
