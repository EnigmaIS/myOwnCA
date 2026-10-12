// Standalone claim page: shared display helpers, without portal-login initialization.
// The URL token + an email OTP (cookie session) gate every call.
const token = decodeURIComponent(window.location.pathname.split("/").pop());
const $ = (selector) => document.querySelector(selector);
let enrollmentDefaults = { common_name: "", email_address: "" };
let enrollmentCommonNameDirty = false;
let enrollmentEmailSanDirty = false;

const KEYLESS_FORMATS = [
  { value: "pem", label: "PEM (.crt)" },
  { value: "pem-chain", label: "PEM chain (.pem)" },
  { value: "pkcs7", label: "PKCS#7 (.p7b)" },
  { value: "der", label: "DER (.cer)" },
];
const KEYED_FORMATS = [
  { value: "pkcs12", label: "PKCS#12 (.pfx)" },
  { value: "pem-pkcs8", label: "PEM + PKCS#8 (.pem)" },
  { value: "pem-key", label: "PEM + encrypted key (.pem)" },
];

const UNUSABLE_REASONS = {
  expired: "The link has expired.",
  revoked: "The link was revoked by an administrator.",
  locked: "The link was locked after too many failed verification attempts.",
  exhausted: "The link has already been used the maximum number of times.",
  recipient_missing: "The recipient on file no longer has an email address.",
};

function api(path, options = {}) {
  return fetch(`/internal/claim/${encodeURIComponent(token)}${path}`, {
    headers: options.body ? { "Content-Type": "application/json" } : {},
    ...options,
  });
}

async function detail(response, fallback) {
  try {
    return (await response.json())?.detail || fallback;
  } catch {
    return fallback;
  }
}

function show(panel) {
  for (const id of [
    "panel-unusable", "panel-otp", "panel-delivery", "panel-renewal",
    "panel-renewed", "panel-enroll", "panel-enrolled",
  ]) {
    $(`#${id}`).classList.toggle("hidden", id !== panel);
  }
}

async function refresh() {
  myOwnCA.renderLicenseIdentity({ status: "none" });
  const response = await api("/state");
  if (!response.ok) {
    $("#claim-subtitle").textContent = "This link does not exist. Check the address you received.";
    show("panel-unusable");
    $("#unusable-reason").textContent = "The link could not be found.";
    return;
  }
  const state = await response.json();
  if (state.status === "unusable") {
    $("#claim-subtitle").textContent = "This link is no longer active.";
    show("panel-unusable");
    $("#unusable-reason").textContent = UNUSABLE_REASONS[state.reason] || "The link is not usable.";
    return;
  }
  if (state.status === "otp_required") {
    $("#claim-subtitle").textContent =
      state.purpose === "renewal"
        ? "Verify with a code — or open this link from a device holding the certificate."
        : "One quick verification step before your download.";
    $("#recipient-hint").textContent = state.recipient_hint;
    if (state.otp_pending) {
      $("#otp-form").classList.remove("hidden");
      $("#otp-status").textContent = "A code was already sent — enter it below or request a new one.";
    }
    show("panel-otp");
    return;
  }
  if (state.status === "ready") myOwnCA.renderLicenseIdentity(state.license_identity);
  if (state.purpose === "renewal") {
    renderRenewal(state);
    return;
  }
  if (state.purpose === "enrollment") {
    renderEnrollment(state);
    return;
  }
  renderDelivery(state);
}

function renderEnrollment(state) {
  $("#claim-subtitle").textContent = "You're verified. Request your certificate below.";
  show("panel-enroll");
  enrollmentDefaults = state.holder_defaults || enrollmentDefaults;
  enrollmentCommonNameDirty = false;
  enrollmentEmailSanDirty = false;
  const templateSelect = $("#enroll-template");
  templateSelect.replaceChildren();
  for (const template of state.templates || []) {
    const option = document.createElement("option");
    option.value = template.id;
    option.dataset.profile = template.profile;
    option.dataset.algorithms = JSON.stringify(template.allowed_key_algorithms || []);
    option.textContent = `${template.name} (${template.profile})`;
    templateSelect.append(option);
  }
  syncEnrollmentAlgorithms();
  syncEnrollKeySource();
}

function syncEnrollmentAlgorithms() {
  const algorithmSelect = $("#enroll-algorithm");
  const allowed = JSON.parse(
    $("#enroll-template").selectedOptions[0]?.dataset.algorithms || "[]",
  );
  const previous = algorithmSelect.value;
  algorithmSelect.replaceChildren();
  for (const algorithm of allowed) {
    const option = document.createElement("option");
    option.value = algorithm;
    option.textContent = algorithm;
    algorithmSelect.append(option);
  }
  if (allowed.includes(previous)) algorithmSelect.value = previous;
}

function syncEnrollKeySource() {
  const serverMode = $("#enroll-key-source").value === "server";
  $("#enroll-server-fields").classList.toggle("hidden", !serverMode);
  $("#enroll-csr-fields").classList.toggle("hidden", serverMode);
  const form = $("#enroll-form");
  form.elements.common_name.required = serverMode;
  form.elements.csr_pem.required = !serverMode;
  const profile = $("#enroll-template").selectedOptions[0]?.dataset.profile || null;
  myOwnCA.syncProfileSanFields(form, profile, { enabled: serverMode });
  if (!enrollmentCommonNameDirty) {
    form.elements.common_name.value = profile === "host_tls"
      ? ""
      : enrollmentDefaults.common_name || "";
  }
  if (serverMode && profile !== "host_tls" && !enrollmentEmailSanDirty) {
    form.elements.email_addresses.value = enrollmentDefaults.email_address || "";
  }
}

$("#enroll-key-source").addEventListener("change", syncEnrollKeySource);
$("#enroll-template").addEventListener("change", () => {
  syncEnrollmentAlgorithms();
  syncEnrollKeySource();
});
$("#enroll-form").elements.common_name.addEventListener("input", () => {
  enrollmentCommonNameDirty = true;
});
$("#enroll-form").elements.email_addresses.addEventListener("input", () => {
  enrollmentEmailSanDirty = true;
});

$("#enroll-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const serverMode = $("#enroll-key-source").value === "server";
  const profile = $("#enroll-template").selectedOptions[0]?.dataset.profile || null;
  const status = $("#enroll-status");
  status.textContent = "Submitting your request…";
  const response = await api("/enroll", {
    method: "POST",
    body: JSON.stringify({
      template_id: form.elements.template_id.value,
      csr_pem: serverMode ? null : form.elements.csr_pem.value,
      common_name: serverMode ? form.elements.common_name.value : null,
      ...(serverMode
        ? myOwnCA.profileSanPayload(form, profile)
        : { dns_names: [], email_addresses: [] }),
      algorithm: form.elements.algorithm.value,
    }),
  });
  if (!response.ok) {
    status.textContent = await detail(response, "Submission failed.");
    return;
  }
  const result = await response.json();
  show("panel-enrolled");
  $("#claim-subtitle").textContent = "All done here.";
  $("#enrolled-message").textContent = result.requires_approval
    ? "Your request awaits Certificate Operator approval. Once issued, a download link will reach you by email."
    : "Your request was submitted. Once issued, a download link will reach you by email.";
});

function renderRenewal(state) {
  $("#claim-subtitle").textContent = "Renew your expiring certificate.";
  show("panel-renewal");
  const cert = state.certificate || {};
  $("#renew-subject").textContent = `Renew ${cert.subject || "certificate"}`;
  $("#renew-meta").textContent =
    `Serial ${cert.serial_number} — expires ${
      cert.expires_at ? new Date(cert.expires_at).toLocaleDateString() : "?"}`;
  $("#renew-auth-note").textContent =
    state.auth === "mtls"
      ? "✓ Your current certificate was verified — the renewal follows the standard policy."
      : "You verified by email code. Because possession of the certificate was not proven, " +
        "a Certificate Operator must approve this renewal before it is issued.";
  const rotate = document.querySelector("#renew-form input[value=rotate]");
  const reuse = document.querySelector("#renew-form input[value=reuse]");
  rotate.disabled = !state.server_key_held;
  $("#mode-rotate-label").classList.toggle("hidden", !state.server_key_held);
  if (state.server_key_held) {
    rotate.checked = true;
  } else {
    reuse.checked = true;
  }
  syncRenewMode();
}

function syncRenewMode() {
  const mode = document.querySelector("#renew-form input[name=mode]:checked")?.value;
  $("#renew-csr-field").classList.toggle("hidden", mode !== "csr");
  $("#renew-form").elements.csr_pem.required = mode === "csr";
}

document.querySelector("#renew-form").addEventListener("change", syncRenewMode);

document.querySelector("#renew-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const mode = form.elements.mode.value;
  const status = $("#renew-status");
  status.textContent = "Submitting the renewal…";
  const response = await api("/renew", {
    method: "POST",
    body: JSON.stringify({
      mode,
      csr_pem: mode === "csr" ? form.elements.csr_pem.value : null,
    }),
  });
  if (!response.ok) {
    status.textContent = await detail(response, "Renewal failed.");
    return;
  }
  const result = await response.json();
  show("panel-renewed");
  const issueError = result.auto_issue_error;
  $("#claim-subtitle").textContent = issueError && issueError.code !== "cloud_signing_queued"
    ? "Renewal submitted; issuance needs attention."
    : "All done here.";
  $("#renewed-message").textContent = result.issued_serial_number
    ? "Your renewed certificate was issued. A download link will reach you by email."
    : issueError
      ? issueError.message
      : result.requires_approval
        ? "Your renewal awaits Certificate Operator approval. Once issued, a download link will reach you by email."
        : "Your renewal was submitted. Once issued, a download link will reach you by email.";
});

function renderDelivery(state) {
  $("#claim-subtitle").textContent = "You're verified. Download your certificate below.";
  show("panel-delivery");
  const cert = state.certificate || {};
  $("#cert-subject").textContent = cert.subject || "Certificate";
  $("#cert-meta").textContent =
    `Serial ${cert.serial_number} — status ${cert.status} — expires ${
      cert.expires_at ? new Date(cert.expires_at).toLocaleDateString() : "?"}`;
  const keyless = $("#keyless-buttons");
  keyless.replaceChildren();
  for (const fmt of KEYLESS_FORMATS) {
    keyless.append(downloadButton(fmt, null));
  }
  $("#key-section").classList.toggle("hidden", !state.server_key_held);
  if (state.server_key_held) {
    const keyed = $("#keyed-buttons");
    keyed.replaceChildren();
    for (const fmt of KEYED_FORMATS) {
      keyed.append(downloadButton(fmt, () => $("#bundle-password").value));
    }
  }
}

function downloadButton(fmt, passwordGetter) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "secondary";
  button.textContent = fmt.label;
  button.addEventListener("click", () => download(fmt.value, passwordGetter));
  return button;
}

async function download(format, passwordGetter) {
  const status = $("#download-status");
  status.textContent = "Preparing download…";
  const password = passwordGetter ? passwordGetter() : null;
  if (passwordGetter && (password || "").length < 8) {
    status.textContent = "Choose a bundle password of at least 8 characters first.";
    return;
  }
  const response = await api("/download", {
    method: "POST",
    body: JSON.stringify({ format, password: password || null }),
  });
  if (!response.ok) {
    if (response.status === 401) {
      status.textContent = "Your verification session expired — verify again.";
      await refresh();
      return;
    }
    status.textContent = await detail(response, "Download failed.");
    return;
  }
  const disposition = response.headers.get("content-disposition") || "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const link = document.createElement("a");
  link.download = match ? match[1] : "certificate";
  link.href = URL.createObjectURL(await response.blob());
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(link.href);
  status.textContent = "Download started.";
}

$("#otp-send").addEventListener("click", async () => {
  const status = $("#otp-status");
  status.textContent = "Sending the code…";
  const response = await api("/otp/send", { method: "POST" });
  if (!response.ok) {
    status.textContent = await detail(response, "Could not send the code.");
    return;
  }
  $("#otp-form").classList.remove("hidden");
  $("#otp-form").elements.code.focus();
  status.textContent = "Code sent — check your inbox.";
});

$("#otp-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const status = $("#otp-status");
  const response = await api("/otp/verify", {
    method: "POST",
    body: JSON.stringify({ code: event.currentTarget.elements.code.value }),
  });
  if (!response.ok) {
    status.textContent = await detail(response, "Verification failed.");
    if (response.status === 423) await refresh();
    return;
  }
  await refresh();
});

refresh().catch(() => {
  $("#claim-subtitle").textContent = "Something went wrong loading this link.";
});
