const BB = myOwnCA;

// Shared, lazily-loaded datasets.
let people = [];
let devices = [];
let certs = [];
let peopleRows = [];
let serviceCerts = [];
let latestCrl = null;
let notifTemplates = [];
let notifVariables = null;
let notifTemplatesBar = null;
let notifRulesBar = null;

// Action bars (created on first mount of each view).
let requestsBar = null;
let certsBar = null;
let peopleBar = null;
let devicesBar = null;
let svcBar = null;
let acmeErrors = [];
let acmeAccounts = [];
let acmeAccountBar;
let superuserCsrPage = null;

const DASHBOARD_ALERTS = {
  requests: { id: "certificate-requests", view: "requests" },
  certificates: { id: "expiring-certificates", view: "certificates" },
  externalCertificates: { id: "external-certificates", view: "external-certs" },
  accessRequests: { id: "access-requests", view: "people" },
};

// -- View registry & router ---------------------------------------------------
const views = {
  dashboard: { title: "Dashboard", section: "#view-dashboard", load: loadDashboard, refresh: loadDashboard },
  requests: { title: "Requests", section: "#view-requests", load: loadRequests, refresh: refreshRequests },
  certificates: { title: "Certificates", section: "#view-certificates", load: loadCertificates, refresh: refreshCertificates },
  people: { title: "People", section: "#view-people", load: loadPeople, refresh: refreshPeople },
  devices: { title: "Devices", section: "#view-devices", load: loadDevices, refresh: refreshDevices },
  "external-certs": { title: "External Certs", section: "#view-external-certs", load: loadExternalCerts, refresh: refreshExternalCerts },
  settings: { title: "Settings", section: "#view-settings", load: loadSettings, refresh: refreshSettings },
  others: { title: "Others", section: "#view-others", load: loadOthers, refresh: refreshCrl },
  user: { title: "Submit CSR", section: "#view-user", load: loadSuperuserCsrPage, refresh: refreshSuperuserCsrPage },
  "account/rec": { title: "Recovery codes", section: "#view-account-rec", load: loadRecoveryCodes },
  logs: { title: "Logs", section: "#view-logs" },
};

function currentViewId() {
  const id = window.location.hash.replace(/^#\/?/, "");
  return views[id] ? id : "dashboard";
}

function navigate(viewId) {
  const view = views[viewId];
  document.querySelectorAll(".view").forEach((section) => {
    section.hidden = true;
  });
  document.querySelectorAll(".side-nav a").forEach((link) => link.removeAttribute("aria-current"));
  const link = document.querySelector(`.side-nav a[data-view="${viewId}"]`);
  if (link) link.setAttribute("aria-current", "page");

  if (!view.section) return;
  BB.$(view.section).hidden = false;
  if (!view.mounted) {
    view.mounted = true;
    Promise.resolve(view.load && view.load()).catch(BB.showError);
  } else if (view.refresh) {
    view.refresh().catch(BB.showError);
  }
}

window.addEventListener("hashchange", () => navigate(currentViewId()));

BB.init("superuser")
  .then(async () => {
    BB.$("#recovery-totp-status").textContent = BB.currentUser.totp_configured
      ? `TOTP is configured${BB.currentUser.totp_required ? " and required for Certificate Operators" : ""}.`
      : "No TOTP factor is configured for this account.";
    BB.$("#recovery-codes").disabled = !BB.currentUser.totp_configured;
    await BB.loadDashboardAlertMutes().catch(() => {});
    const initialViewId = currentViewId();
    navigate(initialViewId);
    refreshLicenseTierIndicators().catch(() => BB.renderLicenseTier(null));
    if (initialViewId !== "dashboard") refreshPendingNavigation().catch(() => {});
  })
  .catch((error) => BB.showError(error));

// -- Logs / details -----------------------------------------------------------
BB.$("#drawer-close").addEventListener("click", () => {
  BB.setOutput("Select a record and choose “View” or “Details”.");
});

function showDetails(value) {
  BB.showResult(value);
}

// Errors must surface even when the drawer is closed.
BB.showError = (error) => BB.showResult({ error: error?.message || String(error) }, { kind: "error" });

async function loadSuperuserCsrPage() {
  superuserCsrPage = BB.mountCsrPage(BB.$("#view-user"), { onDetails: showDetails });
  await superuserCsrPage.refresh();
}

async function refreshSuperuserCsrPage() {
  if (!superuserCsrPage) {
    await loadSuperuserCsrPage();
    return;
  }
  await superuserCsrPage.refresh();
}

async function loadRecoveryCodes() {
  BB.$("#recovery-codes").addEventListener("click", regenerateRecoveryCodes);
}

// -- Small modal helpers ------------------------------------------------------
function cloneForm(templateId) {
  const fragment = BB.$(templateId).content.cloneNode(true);
  return { fragment, form: fragment.querySelector("form") };
}

// -- Requests view ------------------------------------------------------------
BB.$("#requests-refresh").addEventListener("click", () => refreshRequests().catch(BB.showError));

async function loadRequests() {
  requestsBar = BB.actionBar(BB.$("#requests-actionbar"), {
    emptyLabel: "Select a request to enable actions",
    actions: [
      {
        label: "Approve",
        variant: "accent",
        enabled: (sel) => Boolean(sel) && sel.status === "pending" && !sel.approved_by_current_user,
        onClick: (sel) => approveRequest(sel.id, sel).catch(BB.showError),
      },
      {
        label: "Reject",
        variant: "danger",
        enabled: (sel) => Boolean(sel) && sel.status === "pending",
        onClick: (sel) => rejectRequest(sel.id).catch(BB.showError),
      },
      {
        label: "Assign Holder",
        enabled: (sel) => Boolean(sel) && sel.status === "pending",
        onClick: (sel) => openHolderModal(sel).catch(BB.showError),
      },
      {
        label: "Details",
        enabled: (sel) => Boolean(sel),
        onClick: (sel) => showRequestDetails(sel.id).catch(BB.showError),
      },
    ],
  });
  await refreshRequests();
}

async function refreshRequests() {
  const rows = await BB.api("/internal/certificate-requests");
  setOperatorNavPending("requests", rows.some((row) => row.status === "pending"));
  renderRequests(rows);
}

function renderRequests(rows) {
  BB.renderTable(
    BB.$("#request-table"),
    rows,
    [
      { header: "Created", render: (row) => new Date(row.created_at).toLocaleString() },
      { header: "Requester", render: (row) => row.requester_email || row.requested_by_user_id },
      { header: "Template", render: (row) => `${row.template_name} (${row.profile})` },
      { header: "Holder", render: (row) => holderLabel(row.holder) },
      { header: "Status", render: (row) => BB.badge(row.status) },
      { header: "Approvals", render: (row) => `${row.approval_count}/${row.required_approvals}` },
      { header: "Mine", render: (row) => (row.approved_by_current_user ? "approved" : "not yet") },
      {
        header: "Origin",
        render: (row) => {
          if (row.via_link_auth === "otp") {
            const badge = document.createElement("span");
            badge.className = "badge warn";
            badge.title = "Renewal authenticated by email code only — verify the holder before approving.";
            badge.textContent = "⚠ OTP renewal";
            return badge;
          }
          if (row.via_link_auth === "mtls") return "🔐 cert-verified";
          return "—";
        },
      },
    ],
    {
      selectable: true,
      emptyText: "No certificate requests yet.",
      onSelect: (row) => {
        if (!requestsBar) return;
        requestsBar.setSelection(
          row ? { ...row, label: `${row.template_name} — ${row.requester_email || row.requested_by_user_id}` } : null,
        );
      },
    },
  );
}

// Approval is the issuance trigger, so the operator whose approval reaches the
// threshold is the one who needs the token unlocked. Ask before the approval is
// recorded: an approval that cannot issue would strand the request in the queue.
async function hsmReadyForIssuance() {
  let status;
  try {
    status = await BB.api("/internal/hsm/status");
  } catch (error) {
    return true; // Advisory only; let the approval proceed and report any failure.
  }
  if (!status.pin_required || status.any_session_unlocked) return true;

  if (!status.may_unlock) {
    showDetails({
      warning: "The HSM token is locked, so this approval could not issue the certificate.",
      next_step:
        "Ask an administrator to unlock the HSM PIN, then approve again. Nothing has been recorded, so the request is unchanged.",
    });
    return false;
  }

  const { fragment, form } = cloneForm("#tpl-hsm-unlock-form");
  fragment.querySelector("#hsm-unlock-intro").textContent =
    "Yours is the approval that issues this certificate, and the HSM token is locked. Unlock it to continue \u2014 your approval is recorded only once the token is open.";
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    // BB.modal returns {close, card}, not a DOM node: dismissal is reported
    // through onClose, and closing without a PIN must not approve.
    const dialog = BB.modal({
      title: "Unlock the HSM to issue",
      content: form,
      onClose: () => finish(false),
    });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        await BB.api("/internal/hsm/pin/unlock", {
          method: "POST",
          body: JSON.stringify({ pin: form.elements.pin.value }),
        });
        finish(true);
        dialog.close();
      } catch (error) {
        BB.showError(error);
      }
    });
  });
}

function willBeFinalApproval(row) {
  if (!row || row.approved_by_current_user) return false;
  return (row.approval_count || 0) + 1 >= (row.required_approvals || 0);
}

async function approveRequest(requestId, row) {
  if (willBeFinalApproval(row) && !(await hsmReadyForIssuance())) return;
  const response = await BB.api(`/internal/certificate-requests/${requestId}/approvals`, { method: "POST" });
  if (response.auto_issue_error?.code === "cloud_signing_queued") {
    showDetails({ ...response, status: response.auto_issue_error.message });
  } else if (response.auto_issue_error) {
    showDetails({
      warning: response.auto_issue_error.message,
      next_step: "Review the issuance error with the CA administrator. Your approval is preserved.",
      ...response,
    });
  } else if (response.auto_issued) {
    showDetails({ success: "Approval recorded and certificate auto-issued.", ...response });
  } else {
    showDetails({ status: "Approval recorded; waiting for more distinct Certificate Operator approvals.", ...response });
  }
  await refreshRequests();
}

async function rejectRequest(requestId) {
  const response = await BB.api(`/internal/certificate-requests/${requestId}/reject`, { method: "POST" });
  showDetails({ status: "Request rejected. The owner can submit a new request later.", ...response });
  await refreshRequests();
}

async function showRequestDetails(requestId) {
  showDetails(await BB.api(`/internal/certificate-requests/${requestId}`));
}

async function openHolderModal(request) {
  const { fragment, form } = cloneForm("#tpl-holder-form");
  const typeSelect = fragment.querySelector("#holder-type-select");
  const personLabel = fragment.querySelector("#holder-person-label");
  const deviceLabel = fragment.querySelector("#holder-device-label");
  const personSelect = fragment.querySelector("#holder-person-select");
  const deviceSelect = fragment.querySelector("#holder-device-select");

  const [peopleList, deviceList] = await Promise.all([BB.api("/internal/people"), BB.api("/internal/devices")]);
  BB.fillSelect(personSelect, peopleList, {
    value: "id",
    label: (row) => `${row.full_name} (${row.email})`,
    placeholder: "Choose person",
  });
  BB.fillSelect(deviceSelect, deviceList, {
    value: "id",
    label: (row) => `${row.device_name}${row.fqdn ? ` (${row.fqdn})` : ""}`,
    placeholder: "Choose device",
  });

  const updateType = () => {
    const isPerson = typeSelect.value === "person";
    personLabel.classList.toggle("hidden", !isPerson);
    deviceLabel.classList.toggle("hidden", isPerson);
  };
  typeSelect.addEventListener("change", updateType);
  updateType();

  const dialog = BB.modal({ title: "Assign holder", content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = typeSelect.value === "person" ? { person_id: personSelect.value } : { device_id: deviceSelect.value };
    if (!(body.person_id || body.device_id)) {
      BB.showError(new Error("Choose a holder."));
      return;
    }
    try {
      const response = await BB.api(`/internal/certificate-requests/${request.id}/holder`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      showDetails(
        response.auto_issue_error?.code === "cloud_signing_queued"
          ? { ...response, status: response.auto_issue_error.message }
          : response.auto_issue_error
            ? { warning: response.auto_issue_error.message, ...response }
            : response.auto_issued
              ? { success: "Holder assigned and certificate auto-issued.", ...response }
              : { status: "Holder assigned.", ...response },
      );
      dialog.close();
      await refreshRequests();
    } catch (error) {
      BB.showError(error);
    }
  });
}

// -- Certificates view --------------------------------------------------------
async function loadCertificates() {
  certsBar = BB.actionBar(BB.$("#certs-actionbar"), {
    emptyLabel: "Select a certificate to enable actions",
    actions: [
      { label: "Create", variant: "accent", enabled: () => true, onClick: () => openCertCreateModal() },
      { label: "View", enabled: (s) => Boolean(s), onClick: (s) => viewCertificate(s).catch(BB.showError) },
      {
        label: "Export…",
        enabled: (s) => Boolean(s),
        onClick: (s) => BB.openExportModal(s, { onChange: () => refreshCertificates().catch(BB.showError) }),
      },
      {
        label: "Renew",
        enabled: (s) => Boolean(s) && s.status === "active",
        onClick: (s) => renewCertificate(s).catch(BB.showError),
      },
      { label: "Send", enabled: (s) => Boolean(s), onClick: (s) => openSendCertModal(s) },
      { label: "Send link…", enabled: (s) => Boolean(s), onClick: (s) => openCertLinkModal(s) },
      {
        label: "Revoke",
        variant: "danger",
        enabled: (s) => Boolean(s) && !s.archived_at && s.status !== "revoked",
        onClick: (s) => revokeCertificate(s).catch(BB.showError),
      },
      {
        label: "Revoke & archive",
        variant: "danger",
        enabled: (s) => Boolean(s) && !s.archived_at,
        onClick: (s) => BB.openArchiveCertificateModal(s, {
          onChange: () => refreshCertificates(),
        }).catch(BB.showError),
      },
    ],
  });
  BB.$("#certs-search").addEventListener("input", renderCertificates);
  BB.$("#certs-include-archived").addEventListener("change", () => refreshCertificates().catch(BB.showError));
  BB.$("#certs-refresh").addEventListener("click", () => refreshCertificates().catch(BB.showError));
  await refreshCertificates();
}

async function refreshCertificates() {
  const includeArchived = BB.$("#certs-include-archived").checked;
  certs = await BB.api(`/internal/certificate-inventory?include_archived=${includeArchived}`);
  setOperatorNavPending("certificates", certs.some(isExpiringSoon));
  renderCertificates();
  refreshCertsUsage().catch(() => {});
}

async function refreshCertsUsage() {
  const usage = BB.$("#certs-usage");
  if (!usage) return;
  const license = await BB.api("/internal/admin/license");
  BB.renderLicenseTier(license);
  const consumed = license.active_lineages + license.reserved_lineages;
  const remaining = license.lineage_limit - consumed;
  const tier = license.status === "valid"
    ? `Commercial Licence: ${license.licensed_to}`
    : "Personal Licence – NOT for commercial use";
  usage.textContent = `${license.active_lineages} active / ${license.lineage_limit} certificate lineages (${tier}).`;
  usage.classList.toggle("danger-text", remaining <= 0);
  if (remaining <= 0) {
    usage.textContent += " Limit reached — new issuance is blocked until you free a slot or raise the license tier.";
  } else if (remaining <= 2) {
    usage.textContent += ` Only ${remaining} left.`;
  }
}

function openCertCreateModal() {
  openCertCreateModalAsync().catch(BB.showError);
}

async function openCertCreateModalAsync() {
  const { fragment, form } = cloneForm("#tpl-cert-create-form");
  const templateSelect = fragment.querySelector("#cert-create-template");
  const typeSelect = fragment.querySelector("#cert-create-type");
  const personLabel = fragment.querySelector("#cert-create-person-label");
  const deviceLabel = fragment.querySelector("#cert-create-device-label");
  const personSelect = fragment.querySelector("#cert-create-person");
  const deviceSelect = fragment.querySelector("#cert-create-device");
  const cnInput = form.elements.common_name;
  const dnsSanInput = form.elements.dns_names;
  const emailSanInput = form.elements.email_addresses;
  const algorithmSelect = form.elements.algorithm;

  const [templates, peopleList, deviceList] = await Promise.all([
    BB.api("/internal/templates"),
    BB.api("/internal/people"),
    BB.api("/internal/devices"),
  ]);
  BB.fillSelect(templateSelect, templates, { value: "id", label: (row) => row.name, placeholder: "Choose template" });
  BB.fillSelect(personSelect, peopleList, { value: "id", label: (row) => `${row.full_name} (${row.email})`, placeholder: "Choose person" });
  BB.fillSelect(deviceSelect, deviceList, { value: "id", label: (row) => `${row.device_name}${row.fqdn ? ` (${row.fqdn})` : ""}`, placeholder: "Choose device" });

  const peopleById = new Map(peopleList.map((row) => [row.id, row]));
  const devicesById = new Map(deviceList.map((row) => [row.id, row]));
  const dirty = { common_name: false, dns_names: false, email_addresses: false };
  cnInput.addEventListener("input", () => { dirty.common_name = true; });
  dnsSanInput.addEventListener("input", () => { dirty.dns_names = true; });
  emailSanInput.addEventListener("input", () => { dirty.email_addresses = true; });

  const selectedProfile = () =>
    templates.find((template) => template.id === templateSelect.value)?.profile || null;
  const syncAlgorithms = () => {
    const allowed = templates.find((template) => template.id === templateSelect.value)
      ?.allowed_key_algorithms || [];
    const previous = algorithmSelect.value;
    algorithmSelect.replaceChildren(...allowed.map((algorithm) => {
      const option = document.createElement("option");
      option.value = algorithm;
      option.textContent = algorithm;
      return option;
    }));
    if (allowed.includes(previous)) algorithmSelect.value = previous;
  };

  const prefill = () => {
    let cn = "";
    let dnsSan = "";
    let emailSan = "";
    if (typeSelect.value === "person") {
      const person = peopleById.get(personSelect.value);
      if (person) {
        cn = person.full_name || "";
        emailSan = person.email || "";
      }
    } else {
      const device = devicesById.get(deviceSelect.value);
      if (device) {
        cn = device.fqdn || device.device_name || "";
        dnsSan = device.fqdn || "";
      }
    }
    if (!dirty.common_name) cnInput.value = cn;
    if (!dirty.dns_names) dnsSanInput.value = dnsSan;
    if (!dirty.email_addresses) emailSanInput.value = emailSan;
    BB.syncProfileSanFields(form, selectedProfile());
  };

  const updateType = () => {
    const isPerson = typeSelect.value === "person";
    personLabel.classList.toggle("hidden", !isPerson);
    deviceLabel.classList.toggle("hidden", isPerson);
    prefill();
  };
  typeSelect.addEventListener("change", updateType);
  templateSelect.addEventListener("change", () => { syncAlgorithms(); prefill(); });
  personSelect.addEventListener("change", prefill);
  deviceSelect.addEventListener("change", prefill);
  updateType();
  syncAlgorithms();

  const dialog = BB.modal({ title: "Create certificate", content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const isPerson = typeSelect.value === "person";
    const holderBody = isPerson ? { person_id: personSelect.value } : { device_id: deviceSelect.value };
    if (!(holderBody.person_id || holderBody.device_id)) {
      BB.showError(new Error("Choose a holder."));
      return;
    }
    const generateBody = {
      template_id: templateSelect.value,
      common_name: cnInput.value.trim(),
      ...BB.profileSanPayload(form, selectedProfile()),
      algorithm: form.elements.algorithm.value,
    };
    const needsApprovals = templates.find((row) => row.id === templateSelect.value)?.first_issuance_approvals || 0;
    // This single approval issues whenever the template needs only one, so the
    // token must be open before anything is written.
    if (needsApprovals <= 1 && !(await hsmReadyForIssuance())) return;
    try {
      const created = await BB.api("/internal/certificate-requests/generate", { method: "POST", body: JSON.stringify(generateBody) });
      let result = await BB.api(`/internal/certificate-requests/${created.id}/holder`, { method: "POST", body: JSON.stringify(holderBody) });
      if (result.status === "pending" && !result.auto_issued && !result.auto_issue_error) {
        result = await BB.api(`/internal/certificate-requests/${created.id}/approvals`, { method: "POST" });
      }
      if (result.auto_issue_error?.code === "cloud_signing_queued") {
        showDetails({ ...result, status: result.auto_issue_error.message });
      } else if (result.auto_issue_error) {
        showDetails({
          warning: result.auto_issue_error.message,
          next_step: result.approved_by_current_user
            ? "Review the issuance error with the CA administrator. Your approval is preserved and the request remains pending."
            : "Review the issuance error with the CA administrator. The request remains pending.",
          request_id: created.id,
          ...result,
        });
      } else if (result.auto_issued && result.issued_certificate) {
        showDetails({ status: "Certificate issued.", ...result.issued_certificate });
      } else {
        const approvalStatus = result.approved_by_current_user ? ", your approval recorded" : "";
        showDetails({
          status: `Request created — holder assigned${approvalStatus}. ${Math.max(result.required_approvals - result.approval_count, 0)} more approval(s) needed.`,
          request_id: created.id,
        });
      }
      dialog.close();
      await refreshCertificates();
    } catch (error) {
      BB.showError(error);
    }
  });
}

function renderCertificates() {
  const query = (BB.$("#certs-search").value || "").toLowerCase();
  const order = { person: 0, device: 1 };
  const rows = certs
    .filter((cert) =>
      !query ||
      [cert.subject, cert.requester_email, cert.requested_by_user_id, cert.serial_number].some((value) =>
        (value || "").toLowerCase().includes(query),
      ),
    )
    .slice()
    .sort((a, b) => (order[a.holder?.type] ?? 2) - (order[b.holder?.type] ?? 2));
  BB.renderTable(
    BB.$("#certs-table"),
    rows,
    [
      { header: "Type", render: (c) => (c.holder?.type === "person" ? "👤 User" : c.holder?.type === "device" ? "🖥 Device" : "—") },
      { header: "Subject", key: "subject" },
      { header: "Holder", render: (c) => holderLabel(c.holder) },
      { header: "Requester", render: (c) => c.requester_email || c.requested_by_user_id },
      { header: "Source", render: (c) => c.source === "imported" ? "Imported" : "Issued" },
      { header: "Issued", render: (c) => new Date(c.issued_at).toLocaleDateString() },
      { header: "Expires", render: (c) => (c.expires_at ? new Date(c.expires_at).toLocaleDateString() : "—") },
      { header: "Status", render: (c) => BB.badge(c.status) },
      { header: "Archived", render: (c) => c.archived_at ? new Date(c.archived_at).toLocaleDateString() : "—" },
      { header: "Key", render: (c) => (c.server_key_held ? "🔑 server" : "—") },
    ],
    {
      selectable: true,
      emptyText: "No issued certificates yet.",
      onSelect: (row) => certsBar && certsBar.setSelection(row ? { ...row, label: row.subject } : null),
    },
  );
}

function certificateApiPath(certificate, suffix = "") {
  const base = certificate.certificate_id
    ? `/internal/certificate-inventory/${encodeURIComponent(certificate.certificate_id)}`
    : `/internal/certificates/${encodeURIComponent(certificate.serial_number)}`;
  return `${base}${suffix}`;
}

function certificateDetailRow(list, label, value) {
  const term = document.createElement("dt");
  term.textContent = label;
  const definition = document.createElement("dd");
  if (value instanceof Node) definition.append(value);
  else definition.textContent = value || "—";
  list.append(term, definition);
}

function certificateDateTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function appendCertificatePemSection(content, title, pem, emptyMessage) {
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = title;
  const pre = document.createElement("pre");
  pre.className = "code-block";
  pre.textContent = pem || emptyMessage;
  details.append(summary, pre);
  content.append(details);
}

function openCertificateViewModal(certificate) {
  const content = document.createElement("section");
  content.className = "certificate-view";
  const intro = document.createElement("p");
  intro.className = "hint";
  intro.textContent = "This certificate record is read-only.";
  const details = document.createElement("dl");
  details.className = "certificate-view-summary";
  const holder = certificate.holder ? holderLabel(certificate.holder) : "—";
  const template = certificate.template_name
    ? `${certificate.template_name}${certificate.template_id ? ` (${certificate.template_id})` : ""}`
    : certificate.template_id;
  const source = certificate.source === "imported" ? "Imported" : "Issued";

  certificateDetailRow(details, "Subject", certificate.subject);
  certificateDetailRow(details, "Status", BB.badge(certificate.status || "unknown"));
  certificateDetailRow(details, "Holder", holder);
  certificateDetailRow(details, "Template", template);
  certificateDetailRow(details, "Profile", certificate.profile);
  certificateDetailRow(details, "Certificate ID", certificate.certificate_id);
  certificateDetailRow(details, "Serial number", certificate.serial_number);
  certificateDetailRow(details, "Requester", certificate.requester_email || certificate.requested_by_user_id);
  certificateDetailRow(details, "Request ID", certificate.request_id);
  certificateDetailRow(details, "Issued", certificateDateTime(certificate.issued_at));
  certificateDetailRow(details, "Expires", certificateDateTime(certificate.expires_at));
  certificateDetailRow(details, "Source", source);
  certificateDetailRow(details, "Issuer ID", certificate.issuer_id);
  certificateDetailRow(details, "Archived", certificate.archived_at ? certificateDateTime(certificate.archived_at) : "Not archived");
  certificateDetailRow(details, "Server key", certificate.server_key_held ? "Held by server" : "Not held by server");
  content.append(intro, details);
  appendCertificatePemSection(
    content,
    "Certificate PEM",
    certificate.certificate_pem,
    "Certificate PEM is unavailable.",
  );
  appendCertificatePemSection(
    content,
    "Issuer chain PEM",
    certificate.chain_pem,
    "No issuer chain is stored.",
  );
  BB.modal({ title: `View certificate — ${certificate.subject || certificate.serial_number}`, content });
}

async function viewCertificate(certificate) {
  openCertificateViewModal(await BB.api(certificateApiPath(certificate)));
}

async function renewCertificate(certificate) {
  if (!window.confirm(`Create a renewal request for ${certificate.serial_number}? It reuses the original CSR and follows the renewal approval policy.`)) return;
  showDetails({
    status: "Renewal request created — find it in the Requests queue for approval.",
    ...(await BB.api(certificateApiPath(certificate, "/renew"), { method: "POST" })),
  });
}

function openCertLinkModal(cert) {
  const { form } = cloneForm("#tpl-cert-link-form");
  form.querySelector("#cert-link-recipient").textContent = cert.holder
    ? `Recipient: ${holderLabel(cert.holder)} (the device's responsible person for device certs)`
    : "No holder assigned — assign one first, links need a recipient with an email address.";
  const dialog = BB.modal({ title: `Send link — ${cert.subject}`, content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const created = await BB.api("/internal/links", {
        method: "POST",
        body: JSON.stringify({
          ...(cert.certificate_id
            ? { certificate_id: cert.certificate_id }
            : { serial_number: cert.serial_number }),
          send_email: form.elements.send_email.checked,
        }),
      });
      showDetails(created);
      dialog.close();
      await showLinkResult(created);
    } catch (error) {
      BB.showError(error);
    }
  });
}

function openSendCertModal(cert) {
  const { form } = cloneForm("#tpl-cert-send-form");
  const format = form.elements.delivery_format;
  const p12Option = format.querySelector('option[value="pkcs12"]');
  const pemFields = [...form.querySelectorAll("[data-pem-fields]")];
  const p12Fields = [...form.querySelectorAll("[data-pkcs12-fields]")];
  const reauth = form.elements.sensitive_auth;
  const reauthLabel = form.querySelector("[data-pkcs12-reauth]");
  const reauthHint = form.querySelector("[data-pkcs12-reauth-hint]");
  if (!cert.server_key_held) {
    p12Option.disabled = true;
    p12Option.textContent += " — requires a server-held key";
  }

  function syncFormat() {
    const isPkcs12 = format.value === "pkcs12";
    pemFields.forEach((field) => field.classList.toggle("hidden", isPkcs12));
    p12Fields.forEach((field) => field.classList.toggle("hidden", !isPkcs12));
    form.elements.channel.disabled = isPkcs12;
    form.elements.recipient_override.disabled = isPkcs12;
    form.elements.password_channel.disabled = !isPkcs12;
    reauth.disabled = !isPkcs12;
    reauth.required = isPkcs12 && !Boolean(BB.currentUser?.sensitive_auth?.recent);
    const authIsTotp = BB.currentUser?.sensitive_auth?.method === "totp";
    reauth.type = authIsTotp ? "text" : "password";
    reauth.autocomplete = authIsTotp ? "one-time-code" : "current-password";
    if (authIsTotp) {
      reauth.inputMode = "numeric";
      reauth.pattern = "[0-9]{6}";
      reauth.maxLength = 6;
    } else {
      // The constraints must be REMOVED, not blanked. pattern="" compiles to
      // ^(?:)$, which matches only an empty value, so a typed password was
      // rejected with "Please match the requested format" and the bundle could
      // never be sent.
      reauth.removeAttribute("inputmode");
      reauth.removeAttribute("pattern");
      reauth.removeAttribute("maxlength");
    }
    reauthLabel.firstChild.textContent = authIsTotp
      ? "Current TOTP code "
      : "Current account password ";
    reauth.placeholder = authIsTotp ? "123456" : "";
    // Name the credential outright. Which one applies is decided by the role's
    // TOTP policy, not by what the operator personally enrolled, so "fresh
    // authentication" alone leaves them guessing -- and entering the wrong one
    // is rejected by the field's own format rule, which reads like a bug.
    if (BB.currentUser?.sensitive_auth?.recent) {
      reauthHint.textContent =
        "Recent authentication is active for this private-key delivery.";
    } else if (authIsTotp) {
      reauthHint.textContent =
        "This account signs sensitive actions with TOTP: enter the current " +
        "6-digit code from your authenticator app. Your account password is " +
        "not accepted here.";
    } else {
      reauthHint.textContent =
        "This account signs sensitive actions with its password: enter your " +
        "current portal password.";
    }
  }

  async function ensureFreshAuthentication() {
    const account = await BB.api("/internal/auth/me");
    const auth = account.sensitive_auth || { method: "password", recent: false };
    if (auth.recent) return;
    if (!reauth.value) {
      throw new Error(`Enter your current ${auth.method === "totp" ? "TOTP code" : "password"} before sending the private-key bundle.`);
    }
    await BB.api(
      auth.method === "totp"
        ? "/internal/auth/totp/reauthenticate"
        : "/internal/auth/password/reauthenticate",
      {
        method: "POST",
        body: JSON.stringify(auth.method === "totp" ? { code: reauth.value } : { password: reauth.value }),
      },
    );
  }

  format.addEventListener("change", syncFormat);
  syncFormat();
  const dialog = BB.modal({ title: `Send certificate — ${cert.subject}`, content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const serial = encodeURIComponent(cert.serial_number);
      let result;
      if (format.value === "pkcs12") {
        await ensureFreshAuthentication();
        result = await BB.api(`/internal/certificates/${serial}/send-pkcs12`, {
          method: "POST",
          body: JSON.stringify({
            password_channel: form.elements.password_channel.value,
            include_ca_certificates: form.elements.include_ca_certificates.checked,
          }),
        });
      } else {
        const body = BB.formPayload(form);
        if (!body.recipient_override) body.recipient_override = null;
        result = await BB.api(`/internal/certificates/${serial}/send`, { method: "POST", body: JSON.stringify(body) });
      }
      showDetails(result);
      dialog.close();
    } catch (error) {
      BB.showError(error);
    }
  });
}

async function revokeCertificate(certificate) {
  if (!window.confirm(`Revoke certificate ${certificate.serial_number}? This cannot be undone.`)) return;
  showDetails(
    await BB.api(certificateApiPath(certificate, "/revoke"), {
      method: "POST",
      body: JSON.stringify({ reason: "unspecified" }),
    }),
  );
  await refreshCertificates();
}

// -- People view (certificate holders) ---------------------------------------
async function loadPeople() {
  peopleBar = BB.actionBar(BB.$("#people-actionbar"), {
    emptyLabel: "Select a person, or add one",
    actions: [
      { label: "Add Person", variant: "accent", enabled: () => true, onClick: () => openPersonModal() },
      {
        label: "Add + Import",
        enabled: () => true,
        onClick: () => openLeafImport("person", null, "new").catch(BB.showError),
      },
      {
        label: "Import Certificate",
        enabled: (s) => Boolean(s),
        onClick: (s) => openLeafImport("person", s).catch(BB.showError),
      },
      { label: "Invite (link)", enabled: (s) => Boolean(s) && Boolean(s.email), onClick: (s) => inviteEnrollment(s).catch(BB.showError) },
      {
        label: "Send CA certs",
        enabled: (s) => Boolean(s) && Boolean(s.email),
        onClick: (s) => sendCaCertificates(s).catch(BB.showError),
      },
      { label: "Edit", enabled: (s) => Boolean(s), onClick: (s) => openPersonModal(s) },
      { label: "Remove", variant: "danger", enabled: (s) => Boolean(s), onClick: (s) => removePerson(s).catch(BB.showError) },
    ],
  });
  BB.$("#people-search").addEventListener("input", renderPeople);
  BB.$("#people-refresh").addEventListener("click", () => refreshPeople().catch(BB.showError));
  BB.$("#access-requests-refresh").addEventListener("click", () => refreshAccessRequests().catch(BB.showError));
  await refreshPeople();
  await refreshAccessRequests();
}

async function inviteEnrollment(person) {
  if (!window.confirm(`Send ${person.email} an enrollment invitation link?`)) return;
  const created = await BB.api("/internal/links", {
    method: "POST",
    body: JSON.stringify({ purpose: "enrollment", person_id: person.id, send_email: true }),
  });
  showDetails(created);
  await showLinkResult(created);
}

async function refreshAccessRequests() {
  const rows = await BB.api("/internal/access-requests");
  setOperatorNavPending("accessRequests", rows.some((row) => row.status === "pending"));
  BB.renderTable(BB.$("#access-requests-table"), rows, [
    { header: "Requested", render: (row) => new Date(row.created_at).toLocaleString() },
    { header: "Email", key: "email" },
    { header: "Name", key: "name" },
    { header: "Kind", key: "kind" },
    { header: "Message", key: "message" },
    { header: "Status", render: (row) => BB.badge(row.status) },
    {
      header: "Actions",
      render: (row) => {
        if (row.status !== "pending") return row.decided_by ? `by ${row.decided_by}` : "—";
        const actions = document.createElement("div");
        actions.className = "actions";
        actions.append(
          BB.actionButton("Approve", () => approveAccessRequest(row).catch(BB.showError)),
          BB.actionButton("Deny", () => denyAccessRequest(row).catch(BB.showError), "danger"),
        );
        return actions;
      },
    },
  ], { emptyText: "No access requests yet." });
}

async function approveAccessRequest(accessRequest) {
  showDetails(await BB.api(`/internal/access-requests/${encodeURIComponent(accessRequest.id)}/approve`, { method: "POST" }));
  await refreshAccessRequests();
  openAccessPersonModal(accessRequest);
}

async function denyAccessRequest(accessRequest) {
  if (!window.confirm(`Deny the access request from ${accessRequest.email}?`)) return;
  showDetails(await BB.api(`/internal/access-requests/${encodeURIComponent(accessRequest.id)}/deny`, { method: "POST" }));
  await refreshAccessRequests();
}

function openAccessPersonModal(accessRequest) {
  const { form } = cloneForm("#tpl-person-form");
  const [first, ...rest] = (accessRequest.name || "").trim().split(/\s+/);
  form.elements.name.value = first || "";
  form.elements.surname.value = rest.join(" ");
  form.elements.email.value = accessRequest.email;
  if (form.elements.comments) {
    form.elements.comments.value = `Access request (${accessRequest.kind}): ${accessRequest.message || ""}`.trim();
  }
  const dialog = BB.modal({ title: `Create person — ${accessRequest.email}`, content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      showDetails(await BB.api("/internal/people", { method: "POST", body: JSON.stringify(BB.formPayload(form)) }));
      dialog.close();
      await refreshPeople();
    } catch (error) {
      BB.showError(error);
    }
  });
}

async function refreshPeople() {
  people = await BB.api("/internal/people");
  peopleRows = people.map((person) => ({ ...person, displayName: person.full_name }));
  renderPeople();
}

function renderPeople() {
  const query = (BB.$("#people-search").value || "").toLowerCase();
  const rows = peopleRows.filter(
    (row) => !query || [row.displayName, row.email, row.slack_handle].some((value) => (value || "").toLowerCase().includes(query)),
  );
  BB.renderTable(
    BB.$("#people-table"),
    rows,
    [
      { header: "Name", render: (row) => row.displayName },
      { header: "Type", render: () => "Holder" },
      { header: "Email", key: "email" },
      { header: "Phone", render: (row) => row.phone || "—" },
      { header: "Slack", render: (row) => row.slack_handle || "—" },
    ],
    {
      selectable: true,
      emptyText: "No people yet.",
      onSelect: (row) => peopleBar && peopleBar.setSelection(row ? { ...row, label: row.displayName } : null),
    },
  );
}

function openPersonModal(existing) {
  const { form } = cloneForm("#tpl-person-form");
  if (existing) {
    for (const field of ["name", "surname", "email", "phone", "slack_handle", "company", "comments"]) {
      if (form.elements[field]) form.elements[field].value = existing[field] || "";
    }
  }
  const dialog = BB.modal({ title: existing ? "Edit person" : "Add person", content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = BB.formPayload(form);
    try {
      const response = existing
        ? await BB.api(`/internal/people/${encodeURIComponent(existing.id)}`, { method: "PUT", body: JSON.stringify(body) })
        : await BB.api("/internal/people", { method: "POST", body: JSON.stringify(body) });
      showDetails(response);
      dialog.close();
      await refreshPeople();
    } catch (error) {
      BB.showError(error);
    }
  });
}


// A device cannot trust anything this CA issues until the chain is installed,
// and the copies inside a PKCS#12 are not installable as trust anchors.
async function sendCaCertificates(person) {
  const label = person.full_name || person.email;
  if (!window.confirm(`Email the CA certificates (sub-CA and root) to ${label} at ${person.email}?`)) return;
  const response = await BB.api("/internal/ca-certificates/send", {
    method: "POST",
    body: JSON.stringify({ person_id: person.id }),
  });
  showDetails({
    status: `CA certificates sent to ${response.recipient}.`,
    next_step:
      "The holder installs these before the certificate bundle. On iOS the root " +
      "must then be enabled under Settings > General > About > Certificate Trust Settings.",
    ...response,
  });
}

async function removePerson(person) {
  if (!window.confirm(`Remove ${person.displayName}? Devices that reference them must be reassigned first.`)) return;
  showDetails(await BB.api(`/internal/people/${encodeURIComponent(person.id)}`, { method: "DELETE" }));
  await refreshPeople();
}

// -- Devices view -------------------------------------------------------------
async function loadDevices() {
  devicesBar = BB.actionBar(BB.$("#devices-actionbar"), {
    emptyLabel: "Select a device, or add one",
    actions: [
      { label: "Add", variant: "accent", enabled: () => true, onClick: () => openDeviceModal() },
      {
        label: "Add + Import",
        enabled: () => true,
        onClick: () => openLeafImport("device", null, "new").catch(BB.showError),
      },
      {
        label: "Import Certificate",
        enabled: (s) => Boolean(s),
        onClick: (s) => openLeafImport("device", s).catch(BB.showError),
      },
      { label: "View", enabled: (s) => Boolean(s), onClick: (s) => showDetails(s) },
      { label: "Edit", enabled: (s) => Boolean(s), onClick: (s) => openDeviceModal(s) },
      { label: "Remove", variant: "danger", enabled: (s) => Boolean(s), onClick: (s) => removeDevice(s).catch(BB.showError) },
    ],
  });
  BB.$("#devices-search").addEventListener("input", renderDevices);
  BB.$("#devices-refresh").addEventListener("click", () => refreshDevices().catch(BB.showError));
  await refreshDevices();
}

async function refreshDevices() {
  [devices, people] = await Promise.all([BB.api("/internal/devices"), BB.api("/internal/people")]);
  renderDevices();
}

function renderDevices() {
  const query = (BB.$("#devices-search").value || "").toLowerCase();
  const rows = devices.filter(
    (device) => !query || [device.device_name, device.fqdn, device.admin_name, device.admin_email].some((value) => (value || "").toLowerCase().includes(query)),
  );
  BB.renderTable(
    BB.$("#devices-table"),
    rows,
    [
      { header: "Device", key: "device_name" },
      { header: "FQDN", render: (device) => device.fqdn || "—" },
      { header: "Responsible", render: (device) => device.admin_name || device.admin_id },
    ],
    {
      selectable: true,
      emptyText: "No devices yet.",
      onSelect: (row) => devicesBar && devicesBar.setSelection(row ? { ...row, label: row.device_name } : null),
    },
  );
}

function openDeviceModal(existing) {
  const { fragment, form } = cloneForm("#tpl-device-form");
  const adminSelect = fragment.querySelector("#device-admin-select");
  BB.fillSelect(adminSelect, people, {
    value: "id",
    label: (row) => `${row.full_name} (${row.email})`,
    placeholder: "Choose responsible person",
  });
  if (existing) {
    form.elements.device_name.value = existing.device_name || "";
    form.elements.fqdn.value = existing.fqdn || "";
    adminSelect.value = existing.admin_id || "";
    if (form.elements.comments) form.elements.comments.value = existing.comments || "";
  }
  const dialog = BB.modal({ title: existing ? "Edit device" : "Add device", content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = BB.formPayload(form);
    try {
      const response = existing
        ? await BB.api(`/internal/devices/${encodeURIComponent(existing.id)}`, { method: "PUT", body: JSON.stringify(body) })
        : await BB.api("/internal/devices", { method: "POST", body: JSON.stringify(body) });
      showDetails(response);
      dialog.close();
      await refreshDevices();
    } catch (error) {
      BB.showError(error);
    }
  });
}

async function removeDevice(device) {
  if (!window.confirm(`Remove device ${device.device_name}?`)) return;
  showDetails(await BB.api(`/internal/devices/${encodeURIComponent(device.id)}`, { method: "DELETE" }));
  await refreshDevices();
}

async function openLeafImport(holderType, holder = null, initialMode = "existing") {
  await BB.openLeafImportModal({
    holderType,
    holder,
    initialMode,
    people,
    devices,
    onImported: async () => {
      await Promise.all([refreshPeople(), refreshDevices(), refreshCertificates()]);
    },
  });
}

// -- Dashboard view -----------------------------------------------------------
async function loadDashboard() {
  await BB.loadDashboardAlertMutes();
  const [issued, requests, svc, peopleList, deviceList, accessRequests, license] = await Promise.all([
    BB.api("/internal/certificates"),
    BB.api("/internal/certificate-requests"),
    BB.api("/internal/service-certs"),
    BB.api("/internal/people"),
    BB.api("/internal/devices"),
    BB.api("/internal/access-requests"),
    BB.api("/internal/admin/license"),
  ]);
  const active = issued.filter((c) => c.status === "active");
  const expiring = active.filter(isExpiringSoon);
  const pending = requests.filter((r) => r.status === "pending");
  const pendingServices = svc.filter((certificate) => certificate.status === "pending");
  const pendingAccessRequests = accessRequests.filter((request) => request.status === "pending");
  updatePendingNavigation({ issued, requests, serviceCertificates: svc, accessRequests });
  const cards = [
    { label: "Valid certificates", value: active.length, note: `${issued.length} issued total` },
    {
      label: "Pending requests",
      value: pending.length,
      note: `${requests.length} in queue`,
      alertId: DASHBOARD_ALERTS.requests.id,
      action: pending.length ? { label: "Review requests", href: "#/requests" } : null,
    },
    {
      label: "Expiring ≤30d",
      value: expiring.length,
      note: "renew soon",
      alertId: DASHBOARD_ALERTS.certificates.id,
      action: expiring.length ? { label: "Review certificates", href: "#/certificates" } : null,
    },
    {
      label: "External certs",
      value: svc.length,
      note: pendingServices.length ? `${pendingServices.length} awaiting signed import` : "service certificates",
      alertId: DASHBOARD_ALERTS.externalCertificates.id,
      action: pendingServices.length ? { label: "Import signed certificates", href: "#/external-certs" } : null,
    },
    {
      label: "People",
      value: peopleList.length,
      note: pendingAccessRequests.length ? `${pendingAccessRequests.length} access requests awaiting review` : "certificate holders",
      alertId: DASHBOARD_ALERTS.accessRequests.id,
      action: pendingAccessRequests.length ? { label: "Review access requests", href: "#/people" } : null,
    },
    { label: "Devices", value: deviceList.length, note: "registered" },
  ];
  BB.$("#dashboard-cards").replaceChildren(
    ...cards.map((card) => {
      const el = document.createElement("div");
      const muted = Boolean(card.action) && BB.isDashboardAlertMuted(card.alertId);
      el.className = `panel stat-card${card.action && !muted ? " has-pending-action" : ""}`;
      el.classList.toggle("is-muted-alert", muted);
      el.innerHTML = '<div class="stat-label"></div><div class="stat-value"></div><div class="stat-note"></div>';
      el.querySelector(".stat-label").textContent = card.label;
      el.querySelector(".stat-value").textContent = card.value;
      el.querySelector(".stat-note").textContent = card.note;
      if (card.action) {
        const actionContainer = document.createElement("div");
        actionContainer.className = `dashboard-card-action ${muted ? "muted-action-cta" : "pending-action-cta"}`;
        const action = document.createElement("a");
        action.className = "button-link secondary compact";
        action.href = card.action.href;
        action.textContent = card.action.label;
        const mute = BB.actionButton(
          muted ? "Unmute" : "Mute",
          () => toggleOperatorDashboardAlert(card.alertId, !muted).catch(BB.showError),
          "secondary compact",
        );
        mute.setAttribute("aria-label", `${muted ? "Unmute" : "Mute"} alert: ${card.label}`);
        actionContainer.append(action, mute);
        el.append(actionContainer);
      }
      return el;
    }),
  );
  BB.$("#dashboard-summary").textContent =
    `${active.length} active certificate(s), ${pending.length} request(s) awaiting review, ${expiring.length} expiring within 30 days. ` +
    `${peopleList.length} people and ${deviceList.length} devices are registered as holders.`;
  const licenceDisplay = BB.renderLicenseTier(license);
  const used = `${license.active_lineages} active of ${license.lineage_limit} certificate lineages`;
  BB.$("#dashboard-license-summary").textContent = license.status === "valid"
    ? `${licenceDisplay.label} · Licensed to ${license.licensed_to || "this organization"} · ${used}.`
    : `${licenceDisplay.label} · ${used}.`;
}

async function refreshLicenseTierIndicators() {
  BB.renderLicenseTier(await BB.api("/internal/admin/license"));
}

function isExpiringSoon(certificate) {
  if (certificate.status !== "active" || !certificate.expires_at) return false;
  const expiry = new Date(certificate.expires_at).getTime();
  return Number.isFinite(expiry) && expiry <= Date.now() + 30 * 24 * 3600 * 1000;
}

function updatePendingNavigation({ issued, requests, serviceCertificates, accessRequests }) {
  setOperatorNavPending("requests", requests.some((row) => row.status === "pending"));
  setOperatorNavPending("certificates", issued.some(isExpiringSoon));
  setOperatorNavPending("externalCertificates", serviceCertificates.some((row) => row.status === "pending"));
  setOperatorNavPending("accessRequests", accessRequests.some((row) => row.status === "pending"));
}

function setOperatorNavPending(alertKey, pending) {
  const alert = DASHBOARD_ALERTS[alertKey];
  BB.setNavPending(
    alert.view,
    pending && !BB.isDashboardAlertMuted(alert.id),
    alert.id,
  );
}

async function toggleOperatorDashboardAlert(alertId, muted) {
  await BB.setDashboardAlertMuted(alertId, muted);
  await loadDashboard();
}

async function refreshPendingNavigation() {
  await BB.loadDashboardAlertMutes();
  const [issued, requests, serviceCertificates, accessRequests] = await Promise.allSettled([
    BB.api("/internal/certificates"),
    BB.api("/internal/certificate-requests"),
    BB.api("/internal/service-certs"),
    BB.api("/internal/access-requests"),
  ]);
  if (issued.status === "fulfilled") {
    setOperatorNavPending("certificates", issued.value.some(isExpiringSoon));
  }
  if (requests.status === "fulfilled") {
    setOperatorNavPending("requests", requests.value.some((row) => row.status === "pending"));
  }
  if (serviceCertificates.status === "fulfilled") {
    setOperatorNavPending("externalCertificates", serviceCertificates.value.some((row) => row.status === "pending"));
  }
  if (accessRequests.status === "fulfilled") {
    setOperatorNavPending("accessRequests", accessRequests.value.some((row) => row.status === "pending"));
  }
}

// -- External certs view ------------------------------------------------------
async function loadExternalCerts() {
  svcBar = BB.actionBar(BB.$("#svc-actionbar"), {
    emptyLabel: "Select an external certificate to enable actions",
    actions: [
      { label: "View", enabled: (s) => Boolean(s), onClick: (s) => viewServiceCert(s.id).catch(BB.showError) },
      { label: "Import Signed Cert", enabled: (s) => Boolean(s) && s.status === "pending", onClick: (s) => openImportCertModal(s) },
      {
        label: "Renew",
        enabled: (s) => Boolean(s) && s.source === "acme" && s.status === "active",
        onClick: (s) => renewServiceCert(s.id).catch(BB.showError),
      },
      {
        label: "Use as portal TLS",
        enabled: (s) => Boolean(s) && s.key_backend === "software" && s.status === "active",
        onClick: (s) => usePortalTls(s.id).catch(BB.showError),
      },
      { label: "Delete", variant: "danger", enabled: (s) => Boolean(s), onClick: (s) => deleteServiceCert(s).catch(BB.showError) },
    ],
  });
  BB.$("#svc-refresh").addEventListener("click", () => refreshServiceCerts().catch(BB.showError));
  BB.$("#svc-new-csr").addEventListener("click", openCsrModal);
  BB.$("#svc-new-pem").addEventListener("click", openImportPemModal);
  BB.$("#svc-new-p12").addEventListener("click", openImportP12Modal);
  BB.$("#svc-acme-account").addEventListener("click", () => openAcmeAccountModal().catch(BB.showError));
  BB.$("#svc-acme-order").addEventListener("click", () => openAcmeOrderModal().catch(BB.showError));
  BB.$("#portal-tls-clear").addEventListener("click", () => clearPortalTls().catch(BB.showError));
  BB.$("#portal-tls-help-link").addEventListener("click", (event) => {
    event.preventDefault();
    openPortalTlsHelp();
  });
  BB.$("#svc-errors-refresh").addEventListener("click", () => refreshAcmeErrors().catch(BB.showError));
  BB.$("#svc-errors-clear").addEventListener("click", () => clearAcmeErrors().catch(BB.showError));
  acmeAccountBar = BB.actionBar(BB.$("#svc-acme-account-actionbar"), {
    emptyLabel: "Select an ACME account to view or delete",
    actions: [
      { label: "View", enabled: (s) => Boolean(s), onClick: (s) => showDetails(s) },
      { label: "Delete", variant: "danger", enabled: (s) => Boolean(s), onClick: (s) => deleteAcmeAccount(s).catch(BB.showError) },
    ],
  });
  BB.$("#svc-acme-account-refresh").addEventListener("click", () => refreshAcmeAccounts().catch(BB.showError));
  await refreshExternalCerts();
}

async function refreshServiceCerts() {
  serviceCerts = await BB.api("/internal/service-certs");
  setOperatorNavPending("externalCertificates", serviceCerts.some((row) => row.status === "pending"));
  renderServiceCerts();
}

async function refreshExternalCerts() {
  await refreshServiceCerts();
  await refreshPortalTls();
  await refreshAcmeErrors();
  await refreshAcmeAccounts();
}

function renderServiceCerts() {
  BB.renderTable(
    BB.$("#svc-table"),
    serviceCerts,
    [
      { header: "Name", key: "name" },
      { header: "Source", key: "source" },
      { header: "Status", render: (row) => BB.badge(row.status === "active" ? "active" : row.status) },
      { header: "Subject", key: "subject" },
      { header: "Expires", render: (row) => (row.not_after ? new Date(row.not_after).toLocaleDateString() : "—") },
    ],
    {
      selectable: true,
      emptyText: "No external certificates yet.",
      onSelect: (row) => svcBar && svcBar.setSelection(row ? { ...row, label: row.name } : null),
    },
  );
}

async function refreshAcmeAccounts() {
  acmeAccounts = await BB.api("/internal/service-certs/acme/accounts");
  BB.renderTable(
    BB.$("#svc-acme-account-table"),
    acmeAccounts,
    [
      { header: "Directory", key: "directory_url" },
      { header: "Contact", render: (r) => r.contact || "—" },
      { header: "DNS provider", render: (r) => (r.dns_configured ? r.dns_provider : "—") },
      { header: "Certs", render: (r) => (r.certificates ? r.certificates.length : 0) },
      { header: "Created", render: (r) => (r.created_at ? new Date(r.created_at).toLocaleDateString() : "—") },
    ],
    {
      selectable: true,
      emptyText: "No ACME accounts yet.",
      onSelect: (row) => acmeAccountBar && acmeAccountBar.setSelection(row ? { ...row, label: row.directory_url } : null),
    },
  );
}

async function deleteAcmeAccount(account) {
  const deps = account.certificates || [];
  if (deps.length === 0) {
    if (!window.confirm(`Delete ACME account ${account.directory_url}? This removes its stored account key and DNS credentials.`)) return;
    await BB.api(`/internal/service-certs/acme/accounts/${encodeURIComponent(account.id)}`, { method: "DELETE" });
  } else {
    const lines = deps
      .map((c) => `- ${c.name}${c.not_after ? ` (expires ${new Date(c.not_after).toLocaleDateString()})` : ""}`)
      .join("\n");
    if (!window.confirm(`This account still issues ${deps.length} certificate(s):\n${lines}\n\nThey keep working but lose auto-renewal and will expire on those dates. Delete the account anyway?`)) return;
    if (!window.confirm("This cannot be undone. Permanently delete the account and drop those certs' auto-renewal?")) return;
    await BB.api(`/internal/service-certs/acme/accounts/${encodeURIComponent(account.id)}?force=true`, { method: "DELETE" });
  }
  if (acmeAccountBar) acmeAccountBar.setSelection(null);
  await refreshAcmeAccounts();
  await refreshServiceCerts();
}

async function refreshAcmeErrors() {
  acmeErrors = await BB.api("/internal/service-certs/acme/errors");
  BB.renderTable(
    BB.$("#svc-errors-table"),
    acmeErrors,
    [
      { header: "When", render: (r) => (r.created_at ? new Date(r.created_at).toLocaleString() : "—") },
      { header: "Operation", key: "operation" },
      { header: "Target", key: "target" },
      { header: "Message", key: "message" },
    ],
    { emptyText: "No recent ACME errors." },
  );
}

async function clearAcmeErrors() {
  if (!window.confirm("Clear the recent ACME error log?")) return;
  await BB.api("/internal/service-certs/acme/errors", { method: "DELETE" });
  await refreshAcmeErrors();
}

async function viewServiceCert(id) {
  showDetails(await BB.api(`/internal/service-certs/${encodeURIComponent(id)}`));
}

async function renewServiceCert(id) {
  showDetails(await BB.api(`/internal/service-certs/${encodeURIComponent(id)}/renew`, { method: "POST" }));
  await refreshServiceCerts();
}

async function usePortalTls(id) {
  const status = await BB.api(
    `/internal/service-certs/${encodeURIComponent(id)}/use-as-portal-tls`,
    { method: "POST" },
  );
  showDetails(status);
  await refreshPortalTls();
}

async function refreshPortalTls() {
  renderPortalTls(await BB.api("/internal/portal-tls"));
}

function renderPortalTls(status) {
  const el = BB.$("#portal-tls-status");
  if (!el) return;
  if (status.service_cert_id) {
    if (status.missing) {
      el.textContent = `Selected certificate ${status.service_cert_id} is no longer present — clear and re-select.`;
    } else {
      const expires = status.not_after ? new Date(status.not_after).toLocaleDateString() : "—";
      el.textContent =
        `Serving ${status.name || status.service_cert_id} (${status.subject || "—"}), expires ${expires}. ` +
        `Files ${status.files_present ? "present" : "MISSING — re-apply"}.`;
    }
  } else {
    el.textContent = "No certificate is set as the portal TLS certificate.";
  }
  const crt = BB.$("#portal-tls-crt-path");
  if (crt) crt.textContent = status.crt_path || "";
  const key = BB.$("#portal-tls-key-path");
  if (key) key.textContent = status.key_path || "";
  const clearBtn = BB.$("#portal-tls-clear");
  if (clearBtn) clearBtn.disabled = !status.service_cert_id;
  portalTlsPaths = { crt: status.crt_path || "", key: status.key_path || "" };
}

// Remembered so the help can show this installation's real paths rather than a
// placeholder the operator has to translate.
let portalTlsPaths = { crt: "", key: "" };

function openPortalTlsHelp() {
  const content = BB.$("#tpl-portal-tls-help").content.cloneNode(true);
  const crt = portalTlsPaths.crt || "<state-dir>/tls/portal.crt";
  const key = portalTlsPaths.key || "<state-dir>/tls/portal.key";
  content.querySelectorAll("pre").forEach((block) => {
    // textContent keeps the paths inert: they are rendered as text, never markup.
    block.textContent = block.textContent
      .replace(/<crt path>/g, crt)
      .replace(/<key path>/g, key);
  });
  BB.modal({ title: "Serving HTTPS from the portal TLS files", content });
}

async function clearPortalTls() {
  if (!window.confirm("Stop using this certificate as the portal TLS cert and remove the materialized files?")) return;
  showDetails(await BB.api("/internal/portal-tls", { method: "DELETE" }));
  await refreshPortalTls();
}

async function deleteServiceCert(cert) {
  if (!window.confirm(`Delete external certificate ${cert.name}?`)) return;
  showDetails(await BB.api(`/internal/service-certs/${encodeURIComponent(cert.id)}`, { method: "DELETE" }));
  await refreshExternalCerts();
}

function openCsrModal() {
  const { form } = cloneForm("#tpl-svc-csr-form");
  const dialog = BB.modal({ title: "Generate CSR (external CA)", content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = BB.formPayload(form);
    body.dns_names = splitList(body.dns_names);
    try {
      showDetails(await BB.api("/internal/service-certs/csr", { method: "POST", body: JSON.stringify(body) }));
      dialog.close();
      await refreshServiceCerts();
    } catch (error) {
      BB.showError(error);
    }
  });
}

function openImportCertModal(cert) {
  const { form } = cloneForm("#tpl-svc-import-cert-form");
  const dialog = BB.modal({ title: `Import signed cert — ${cert.name}`, content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = { certificate_pem: form.elements.certificate_pem.value, chain_pem: form.elements.chain_pem.value || null };
    try {
      showDetails(await BB.api(`/internal/service-certs/${encodeURIComponent(cert.id)}/import-certificate`, { method: "POST", body: JSON.stringify(body) }));
      dialog.close();
      await refreshServiceCerts();
    } catch (error) {
      BB.showError(error);
    }
  });
}

function openImportPemModal() {
  const { form } = cloneForm("#tpl-svc-import-pem-form");
  const dialog = BB.modal({ title: "Import certificate + key (PEM)", content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = BB.formPayload(form);
    for (const key of ["chain_pem", "key_passphrase"]) if (!body[key]) body[key] = null;
    try {
      showDetails(await BB.api("/internal/service-certs/import-pem", { method: "POST", body: JSON.stringify(body) }));
      dialog.close();
      await refreshServiceCerts();
    } catch (error) {
      BB.showError(error);
    }
  });
}

function openImportP12Modal() {
  const { form } = cloneForm("#tpl-svc-import-p12-form");
  const dialog = BB.modal({ title: "Import PKCS#12 (.p12/.pfx)", content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const file = form.elements.p12_file.files[0];
    if (!file) {
      BB.showError(new Error("Choose a .p12 file"));
      return;
    }
    try {
      const p12_base64 = await fileToBase64(file);
      const body = { name: form.elements.name.value, p12_base64, password: form.elements.password.value || null };
      showDetails(await BB.api("/internal/service-certs/import-p12", { method: "POST", body: JSON.stringify(body) }));
      dialog.close();
      await refreshServiceCerts();
    } catch (error) {
      BB.showError(error);
    }
  });
}

async function openAcmeAccountModal() {
  const { form } = cloneForm("#tpl-acme-account-form");
  const dialog = BB.modal({ title: "New ACME account", content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const payload = BB.formPayload(form);
      let account = await BB.api("/internal/service-certs/acme/accounts", {
        method: "POST",
        body: JSON.stringify({ directory_url: payload.directory_url, contact: payload.contact }),
      });
      if (payload.dns_provider) {
        // The PUT returns the updated account (dns_configured: true) — show that, not the stale POST.
        account = await BB.api(`/internal/service-certs/acme/accounts/${encodeURIComponent(account.id)}/dns-provider`, {
          method: "PUT",
          body: JSON.stringify({ provider: payload.dns_provider, username: payload.dns_username, token: payload.dns_token }),
        });
      }
      showDetails(account);
      dialog.close();
      await refreshAcmeAccounts();
    } catch (error) {
      BB.showError(error);
    }
  });
  return dialog;
}

async function openAcmeOrderModal() {
  const { fragment, form } = cloneForm("#tpl-acme-order-form");
  const accountSelect = fragment.querySelector("#acme-account-select");
  const accounts = await BB.api("/internal/service-certs/acme/accounts");
  BB.fillSelect(accountSelect, accounts, {
    value: "id",
    label: (row) => `${row.directory_url}${row.contact ? ` (${row.contact})` : ""}`,
    placeholder: "Choose an ACME account",
  });
  const dialog = BB.modal({ title: "Request ACME certificate", content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = BB.formPayload(form, ["renew_before_days"]);
    body.domains = splitList(body.domains);
    try {
      showDetails(await BB.api("/internal/service-certs/acme/orders", { method: "POST", body: JSON.stringify(body) }));
      dialog.close();
      await refreshServiceCerts();
    } catch (error) {
      BB.showError(error);
    }
  });
}

// -- Settings view (notifications + recovery codes) ---------------------------
async function loadSettings() {
  notifTemplatesBar = BB.actionBar(BB.$("#notif-templates-actionbar"), {
    emptyLabel: "Select a notification template, or create one",
    actions: [
      { label: "Create", variant: "accent", enabled: () => true, onClick: () => openNotifTemplateModal(null, "create").catch(BB.showError) },
      { label: "Edit", enabled: (s) => Boolean(s), onClick: (s) => openNotifTemplateModal(s, "edit").catch(BB.showError) },
      { label: "Clone", enabled: (s) => Boolean(s), onClick: (s) => openNotifTemplateModal(s, "clone").catch(BB.showError) },
      { label: "Preview", enabled: (s) => Boolean(s), onClick: (s) => previewStoredTemplate(s).catch(BB.showError) },
      { label: "Delete", variant: "danger", enabled: (s) => Boolean(s), onClick: (s) => deleteNotifTemplate(s).catch(BB.showError) },
    ],
  });
  notifRulesBar = BB.actionBar(BB.$("#notif-rules-actionbar"), {
    emptyLabel: "Select a notification rule, or create one",
    actions: [
      { label: "Create", variant: "accent", enabled: () => true, onClick: () => openNotifRuleModal() },
      { label: "Edit", enabled: (s) => Boolean(s), onClick: (s) => openNotifRuleModal(s) },
      { label: "Delete", variant: "danger", enabled: (s) => Boolean(s), onClick: (s) => deleteNotifRule(s).catch(BB.showError) },
    ],
  });
  BB.$("#notif-templates-refresh").addEventListener("click", () => refreshNotifTemplates().catch(BB.showError));
  BB.$("#notif-rules-refresh").addEventListener("click", () => Promise.all([refreshNotifRules(), refreshNotifLog()]).catch(BB.showError));
  BB.$("#notif-run-now").addEventListener("click", async () => {
    try {
      showDetails(await BB.api("/internal/notifications/run", { method: "POST" }));
      await refreshNotifRules();
      await refreshNotifLog();
    } catch (error) {
      BB.showError(error);
    }
  });
  BB.$("#links-refresh").addEventListener("click", () => refreshSecureLinks().catch(BB.showError));
  await refreshSettings();
}

async function refreshSecureLinks() {
  const rows = await BB.api("/internal/links");
  BB.renderTable(BB.$("#links-table"), rows, [
    { header: "Created", render: (row) => new Date(row.created_at).toLocaleString() },
    { header: "Purpose", key: "purpose" },
    { header: "Recipient", render: (row) => row.person_email || row.person_id },
    { header: "Certificate", render: (row) => row.serial_number || "—" },
    { header: "Expires", render: (row) => new Date(row.expires_at).toLocaleDateString() },
    { header: "Sessions", render: (row) => `${row.use_count}/${row.max_uses}` },
    { header: "Status", render: (row) => BB.badge(row.status) },
    {
      header: "Actions",
      render: (row) => row.status === "active"
        ? BB.actionButton("Revoke", () => revokeSecureLink(row).catch(BB.showError), "danger")
        : "—",
    },
  ], { emptyText: "No secure links yet." });
}

async function revokeSecureLink(link) {
  if (!window.confirm(`Revoke the ${link.purpose} link for ${link.person_email || link.person_id}?`)) return;
  showDetails(await BB.api(`/internal/links/${encodeURIComponent(link.id)}/revoke`, { method: "POST" }));
  await refreshSecureLinks();
}

async function showLinkResult(created) {
  const wrapper = document.createElement("div");
  const info = document.createElement("p");
  info.textContent = created.email_sent
    ? `Link emailed to ${created.person_email}.`
    : created.email_error
      ? `Link created, but the email failed: ${created.email_error}`
      : "Link created (not emailed). Share it through a trusted channel.";
  wrapper.append(info);
  if (created.claim_url) {
    const urlBox = document.createElement("pre");
    urlBox.textContent = created.claim_url;
    wrapper.append(urlBox);
    wrapper.append(BB.actionButton("Copy URL", () => navigator.clipboard.writeText(created.claim_url)));
    try {
      const qr = await BB.apiDownload("/internal/links/qr", {
        method: "POST",
        body: JSON.stringify({ data: created.claim_url }),
      });
      const qrBox = document.createElement("div");
      qrBox.innerHTML = await qr.blob.text();
      const svg = qrBox.querySelector("svg");
      if (svg) {
        svg.setAttribute("width", "180");
        svg.setAttribute("height", "180");
      }
      wrapper.append(qrBox);
    } catch {
      /* QR is a nicety; the URL above is what matters */
    }
  } else {
    const note = document.createElement("p");
    note.className = "hint";
    note.textContent = `No portal base URL configured — relative path: ${created.claim_path}`;
    wrapper.append(note);
  }
  BB.modal({ title: "Secure link created", content: wrapper });
}

async function refreshSettings() {
  await NotificationScheduleControls.refresh(BB.$("#notification-schedule"));
  await refreshNotifTemplates();
  await refreshNotifRules();
  await refreshNotifLog();
  await refreshSecureLinks();
}

// -- Notification templates & rules --------------------------------------------
async function refreshNotifTemplates() {
  notifTemplates = await BB.api("/internal/notifications/templates");
  BB.renderTable(
    BB.$("#notif-template-table"),
    notifTemplates,
    [
      { header: "Name", key: "name" },
      { header: "Event", key: "event_type" },
      { header: "Format", key: "format" },
      { header: "Subject", key: "subject" },
      { header: "Updated", render: (row) => (row.updated_at ? new Date(row.updated_at).toLocaleString() : "—") },
    ],
    {
      selectable: true,
      emptyText: "No notification templates yet.",
      onSelect: (row) => notifTemplatesBar && notifTemplatesBar.setSelection(row ? { ...row, label: row.name } : null),
    },
  );
}

async function refreshNotifRules() {
  const rules = await BB.api("/internal/notifications/rules");
  BB.renderTable(
    BB.$("#notif-rule-table"),
    rules,
    [
      { header: "Event", key: "event_type" },
      { header: "Template", key: "template_name" },
      { header: "Channel", key: "channel" },
      { header: "Audience", key: "audience" },
      { header: "Rule interval (days)", key: "period_days" },
      { header: "Within (d)", key: "threshold_days" },
      { header: "Enabled", render: (row) => (row.enabled ? "yes" : "no") },
      { header: "Last run", render: (row) => (row.last_run_at ? new Date(row.last_run_at).toLocaleString() : "—") },
    ],
    {
      selectable: true,
      emptyText: "No notification rules yet.",
      onSelect: (row) => notifRulesBar && notifRulesBar.setSelection(row ? { ...row, label: `${row.event_type} → ${row.template_name}` } : null),
    },
  );
}

async function refreshNotifLog() {
  const log = await BB.api("/internal/notifications/log");
  BB.renderTable(BB.$("#notif-log-table"), log.slice(0, 20), [
    { header: "Sent", render: (row) => (row.sent_at ? new Date(row.sent_at).toLocaleString() : "—") },
    { header: "Event", key: "event_type" },
    { header: "Channel", key: "channel" },
    { header: "Recipient", key: "recipient" },
    { header: "Subject", key: "subject" },
    { header: "Result", render: (row) => (row.success ? "✓ sent" : `✗ ${row.detail || "failed"}`) },
  ], "No deliveries yet.");
}

async function openNotifTemplateModal(source, mode = "create") {
  const { form } = cloneForm("#tpl-notif-template-form");
  if (!notifVariables) notifVariables = await BB.api("/internal/notifications/variables");
  form.querySelector("#notif-variable-reference").textContent = Object.entries(notifVariables)
    .map(([name, hint]) => `$${name} — ${hint}`)
    .join("\n");
  if (source) {
    form.elements.name.value = mode === "clone" ? `${source.name}-copy` : source.name;
    form.elements.event_type.value = source.event_type;
    form.elements.format.value = source.format;
    form.elements.subject.value = source.subject;
    form.elements.body.value = source.body;
    if (mode === "edit") form.elements.name.readOnly = true;
  }
  const titles = { create: "Create notification template", clone: "Clone notification template", edit: "Edit notification template" };
  const dialog = BB.modal({ title: titles[mode], content: form });
  form.querySelector("#notif-preview-btn").addEventListener("click", async () => {
    try {
      const preview = await BB.api(
        `/internal/notifications/templates/${encodeURIComponent(form.elements.name.value || "draft")}/preview`,
        {
          method: "POST",
          body: JSON.stringify({
            subject: form.elements.subject.value,
            body: form.elements.body.value,
            format: form.elements.format.value,
          }),
        },
      );
      const output = form.querySelector("#notif-preview-output");
      output.hidden = false;
      output.textContent = `Subject: ${preview.subject}\n\n${preview.body}`;
    } catch (error) {
      BB.showError(error);
    }
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = BB.formPayload(form);
    try {
      if (mode === "edit") {
        delete body.name;
        showDetails(await BB.api(`/internal/notifications/templates/${encodeURIComponent(source.name)}`, { method: "PUT", body: JSON.stringify(body) }));
      } else {
        showDetails(await BB.api("/internal/notifications/templates", { method: "POST", body: JSON.stringify(body) }));
      }
      dialog.close();
      await refreshNotifTemplates();
    } catch (error) {
      BB.showError(error);
    }
  });
}

async function previewStoredTemplate(template) {
  const preview = await BB.api(
    `/internal/notifications/templates/${encodeURIComponent(template.name)}/preview`,
    { method: "POST", body: JSON.stringify({}) },
  );
  showDetails({ template: template.name, rendered_subject: preview.subject, rendered_body: preview.body });
}

async function deleteNotifTemplate(template) {
  if (!window.confirm(`Delete notification template "${template.name}"? This fails if a rule still references it.`)) return;
  showDetails(await BB.api(`/internal/notifications/templates/${encodeURIComponent(template.name)}`, { method: "DELETE" }));
  await refreshNotifTemplates();
}

function openNotifRuleModal(source) {
  const { form } = cloneForm("#tpl-notif-rule-form");
  const templateSelect = form.querySelector("#notif-rule-template-select");
  BB.fillSelect(templateSelect, notifTemplates, {
    value: "name",
    label: (row) => `${row.name} (${row.event_type})`,
    placeholder: "Choose template",
  });
  if (source) {
    form.elements.event_type.value = source.event_type;
    templateSelect.value = source.template_name;
    form.elements.channel.value = source.channel;
    form.elements.audience.value = source.audience;
    form.elements.enabled.checked = source.enabled;
    form.elements.include_renewal_link.checked = Boolean(source.include_renewal_link);
    form.elements.period_days.value = source.period_days;
    form.elements.threshold_days.value = source.threshold_days;
    form.elements.notification_text.value = source.notification_text || "";
  }
  const dialog = BB.modal({ title: source ? "Edit notification rule" : "Create notification rule", content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = BB.formPayload(form, ["period_days", "threshold_days"]);
    body.enabled = form.elements.enabled.checked;
    body.include_renewal_link = form.elements.include_renewal_link.checked;
    try {
      const response = source
        ? await BB.api(`/internal/notifications/rules/${encodeURIComponent(source.id)}`, { method: "PUT", body: JSON.stringify(body) })
        : await BB.api("/internal/notifications/rules", { method: "POST", body: JSON.stringify(body) });
      showDetails(response);
      dialog.close();
      await refreshNotifRules();
    } catch (error) {
      BB.showError(error);
    }
  });
}

async function deleteNotifRule(rule) {
  if (!window.confirm(`Delete the ${rule.event_type} rule using "${rule.template_name}"?`)) return;
  showDetails(await BB.api(`/internal/notifications/rules/${encodeURIComponent(rule.id)}`, { method: "DELETE" }));
  await refreshNotifRules();
}

async function regenerateRecoveryCodes() {
  if (!window.confirm("Generate a new set of recovery codes? This invalidates any previous codes.")) return;
  try {
    const body = await BB.api("/internal/auth/recovery/codes/regenerate", { method: "POST" });
    showDetails({ note: "Store these one-time recovery codes now — shown once.", recovery_codes: body.recovery_codes });
  } catch (error) {
    BB.showError(error);
  }
}

// -- Others view (CRL) --------------------------------------------------------
async function loadOthers() {
  const generate = BB.$("#crl-generate");
  generate.disabled = false;
  generate.addEventListener("click", () => generateCrl().catch(BB.showError));
  BB.$("#crl-download").addEventListener("click", downloadCrl);
  await refreshCrl();
}

async function refreshCrl() {
  const status = await BB.api("/internal/crls/status");
  BB.$("#crl-status").textContent = JSON.stringify(status, null, 2);
  try {
    latestCrl = await BB.api("/internal/crls/latest");
    BB.$("#crl-download").disabled = false;
  } catch (_error) {
    latestCrl = null;
    BB.$("#crl-download").disabled = true;
  }
}

async function generateCrl() {
  const job = await BB.api("/internal/crls", { method: "POST" });
  showDetails({ status: "CRL refresh queued.", ...job });
  await refreshCrl();
}

function downloadCrl() {
  if (!latestCrl) return;
  const link = BB.pemDownload(`crl-${latestCrl.number}.pem`, latestCrl.crl_pem);
  document.body.append(link);
  link.click();
  link.remove();
}

// -- Shared helpers -----------------------------------------------------------
function splitList(value) {
  return (value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",", 2)[1] || "");
    reader.onerror = () => reject(new Error("Could not read file"));
    reader.readAsDataURL(file);
  });
}

function holderLabel(holder) {
  if (!holder) return "—";
  if (holder.type === "device") {
    const who = holder.responsible_person_email ? ` · ${holder.responsible_person_email}` : "";
    return `🖥 ${holder.label}${who}`;
  }
  return `👤 ${holder.label}`;
}
