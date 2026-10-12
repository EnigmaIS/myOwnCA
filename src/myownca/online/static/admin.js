const BB = myOwnCA;
let users = [];
let templates = [];
let adminPeople = [];
let adminDevices = [];
let commsChannels = [];
const supportedKeyUsages = [
  "digital_signature",
  "content_commitment",
  "key_encipherment",
  "data_encipherment",
  "key_agreement",
  "encipher_only",
  "decipher_only",
];
const supportedExtendedKeyUsages = ["client_auth", "server_auth", "email_protection"];
const supportedCertificateAlgorithms = [
  "rsa-2048", "rsa-3072", "rsa-4096",
  "ecdsa-p256", "ecdsa-p384", "ecdsa-p521",
];
const keyUsageLabels = {
  digital_signature: "Digital signature",
  content_commitment: "Content commitment",
  key_encipherment: "Key encipherment",
  data_encipherment: "Data encipherment",
  key_agreement: "Key agreement",
  encipher_only: "Encipher only",
  decipher_only: "Decipher only",
};
const extendedKeyUsageLabels = {
  client_auth: "Client authentication",
  server_auth: "Server authentication",
  email_protection: "Email protection",
};
const certificateAlgorithmLabels = {
  "rsa-2048": "RSA 2048",
  "rsa-3072": "RSA 3072",
  "rsa-4096": "RSA 4096",
  "ecdsa-p256": "ECDSA P-256",
  "ecdsa-p384": "ECDSA P-384",
  "ecdsa-p521": "ECDSA P-521",
};
const profileLabels = {
  host_tls: "server TLS",
  user_auth: "user / client authentication",
  smime: "email protection (S/MIME)",
};
const profileDescriptions = {
  host_tls: "For HTTPS, reverse proxies, APIs, and other TLS servers.",
  user_auth: "For people or devices authenticating with a client certificate.",
  smime: "For signing and encrypting email with S/MIME.",
};
let presets = [];
let templatesBar = null;
let loginAccountsBar = null;
let adminCsrPage = null;
let governanceState = null;
let pendingRoleGrantTargetIds = new Set();
const GOVERNANCE_API = {
  status: "/internal/admin/governance",
  enableDual: "/internal/admin/governance/enable-dual-control",
  requestSingle: "/internal/admin/governance/single-admin-proposals",
  approveSingle: (proposalId) => `/internal/admin/governance/single-admin-proposals/${encodeURIComponent(proposalId)}/approve`,
};

// -- View registry & router ---------------------------------------------------
const views = {
  dashboard: { title: "Dashboard", section: "#view-dashboard", load: AdminDashboard.mount, refresh: AdminDashboard.refresh },
  authentication: { title: "Authentication", section: "#view-authentication", load: loadAuthPolicy, refresh: loadAuthPolicy },
  privileged: { title: "Privileged users", section: "#view-privileged", load: loadPrivileged, refresh: loadPrivileged },
  hsm: { title: "HSM & Keys", section: "#view-hsm", load: loadHsmView, refresh: loadHsmView },
  entropy: { title: "Random number source", section: "#view-entropy", load: refreshEntropySource, refresh: refreshEntropySource },
  auditing: { title: "Auditing", section: "#view-auditing", load: loadSyslogConfig, refresh: loadSyslogConfig },
  ca: { title: "CA management", section: "#view-ca", load: loadCaView, refresh: loadCaView },
  people: { title: "People", section: "#view-people", load: loadAdminPeople, refresh: refreshAdminPeople },
  devices: { title: "Devices", section: "#view-devices", load: loadAdminDevices, refresh: refreshAdminDevices },
  templates: { title: "Templates", section: "#view-templates", load: loadTemplates, refresh: refreshTemplates },
  holder: { title: "Holder portal", section: "#view-holder", load: refreshHolderPortal, refresh: refreshHolderPortal },
  channels: { title: "Notifications & integrations", section: "#view-channels", load: loadChannels, refresh: loadChannels },
  backups: { title: "Backups", section: "#view-backups", load: AdminBackups.mount, refresh: AdminBackups.refresh },
  license: { title: "License", section: "#view-license", load: refreshLicense, refresh: refreshLicense },
  appearance: { title: "Appearance", section: "#view-appearance", load: refreshAppearance, refresh: refreshAppearance },
  user: { title: "Submit CSR", section: "#view-user", load: loadAdminCsrPage, refresh: refreshAdminCsrPage },
  "account/rec": { title: "Recovery codes", section: "#view-account-rec" },
  logs: {
    title: "Activity & diagnostics",
    section: "#view-logs",
    load: AdminDashboard.refreshActivity,
    refresh: AdminDashboard.refreshActivity,
  },
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

  BB.$(view.section).hidden = false;
  if (!view.mounted) {
    view.mounted = true;
    Promise.resolve(view.load && view.load()).catch(BB.showError);
  } else if (view.refresh) {
    view.refresh().catch(BB.showError);
  }
}

window.addEventListener("hashchange", () => navigate(currentViewId()));

BB.init("admin")
  .then(async () => {
    sensitiveAuthState = BB.currentUser;
    updateSensitiveAuthStatus();
    BB.$("#recovery-totp-status").textContent = BB.currentUser.totp_configured
      ? `TOTP is configured${BB.currentUser.totp_required ? " and required for Administrators" : ""}.`
      : "No TOTP factor is configured for this account.";
    BB.$("#recovery-codes").disabled = !BB.currentUser.totp_configured;
    await BB.loadDashboardAlertMutes().catch(() => {});
    const initialViewId = currentViewId();
    navigate(initialViewId);
    refreshLicenseTierIndicators().catch(() => BB.renderLicenseTier(null));
    return Promise.all([
      updateProposalBadge(),
      initialViewId === "dashboard"
        ? Promise.resolve()
        : AdminDashboard.refreshPendingNavigation().catch(() => {}),
    ]);
  })
  .catch((error) => BB.showError(error));

// -- Logs / details -----------------------------------------------------------
BB.$("#drawer-close").addEventListener("click", () => {
  BB.setOutput("Admin actions and setup responses appear here.");
});

function showDetails(value) {
  BB.showResult(value);
}

// -- People and devices ------------------------------------------------------
async function loadAdminPeople() {
  BB.$("#admin-people-refresh").addEventListener("click", () => {
    refreshAdminPeople().catch(BB.showError);
  });
  BB.$("#admin-people-add-import").addEventListener("click", () => {
    openAdminLeafImport("person", null, "new").catch(BB.showError);
  });
  await refreshAdminPeople();
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
      "On iOS the root must then be enabled under Settings > General > About > " +
      "Certificate Trust Settings; installing it alone does not make it trusted.",
    ...response,
  });
}

async function refreshAdminPeople() {
  adminPeople = await BB.api("/internal/people");
  BB.renderTable(
    BB.$("#admin-people-table"),
    adminPeople,
    [
      { header: "Name", render: (row) => row.full_name },
      { header: "Email", key: "email" },
      { header: "Company", render: (row) => row.company || "—" },
      {
        header: "Actions",
        render: (row) => {
          const actions = document.createElement("div");
          actions.className = "actions";
          actions.append(
            BB.actionButton(
              "Import certificate",
              () => openAdminLeafImport("person", row).catch(BB.showError),
            ),
          );
          if (row.email) {
            actions.append(
              BB.actionButton(
                "Send CA certs",
                () => sendCaCertificates(row).catch(BB.showError),
              ),
            );
          }
          return actions;
        },
      },
    ],
    { emptyText: "No people are registered." },
  );
}

async function loadAdminDevices() {
  BB.$("#admin-devices-refresh").addEventListener("click", () => {
    refreshAdminDevices().catch(BB.showError);
  });
  BB.$("#admin-devices-add-import").addEventListener("click", () => {
    openAdminLeafImport("device", null, "new").catch(BB.showError);
  });
  await refreshAdminDevices();
}

async function refreshAdminDevices() {
  adminDevices = await BB.api("/internal/devices");
  BB.renderTable(
    BB.$("#admin-devices-table"),
    adminDevices,
    [
      { header: "Device", key: "device_name" },
      { header: "FQDN", render: (row) => row.fqdn || "—" },
      { header: "Responsible", render: (row) => row.admin_name || row.admin_email || row.admin_id },
      {
        header: "Actions",
        render: (row) => BB.actionButton(
          "Import certificate",
          () => openAdminLeafImport("device", row).catch(BB.showError),
        ),
      },
    ],
    { emptyText: "No devices are registered." },
  );
}

async function openAdminLeafImport(holderType, holder = null, initialMode = "existing") {
  await BB.openLeafImportModal({
    holderType,
    holder,
    initialMode,
    onImported: async () => {
      await Promise.all([refreshAdminPeople(), refreshAdminDevices()]);
    },
  });
}

// Errors must surface even when the drawer is closed.
BB.showError = (error) => BB.showResult({ error: error?.message || String(error) }, { kind: "error" });

// -- Sensitive-action safety -------------------------------------------------
// Protected endpoints enforce this same top-level reason/confirmation contract
// and a session-bound TOTP-or-password step-up. The dialog mirrors those checks.
const SENSITIVE_REASON_MIN_LENGTH = 10;
let sensitiveAuthState = null;
let sensitiveDialogCounter = 0;

function sensitiveAuthStatusText(user = sensitiveAuthState || BB.currentUser) {
  if (!user) return "Authentication status is unavailable. Do not continue until the session can be verified.";
  const auth = user.sensitive_auth || {
    method: "totp",
    recent: Boolean(user.mfa_recent),
    verified_at: user.mfa_verified_at,
    valid_for_seconds: user.mfa_valid_for_seconds,
  };
  const methodLabel = auth.method === "password" ? "password" : "TOTP";
  if (auth.recent) {
    const remaining = Number(auth.valid_for_seconds);
    const validity = Number.isFinite(remaining)
      ? ` Step-up remains valid for about ${Math.max(1, Math.ceil(remaining / 60))} minute(s).`
      : "";
    return `Recent ${methodLabel} verification confirmed.${validity}`;
  }
  if (auth.verified_at) {
    const verifiedAt = new Date(auth.verified_at);
    if (!Number.isNaN(verifiedAt.getTime())) {
      const ageMinutes = Math.max(0, Math.floor((Date.now() - verifiedAt.getTime()) / 60_000));
      return `${methodLabel} was last verified ${ageMinutes} minute${ageMinutes === 1 ? "" : "s"} ago and is no longer recent. The confirmation dialog requires fresh ${methodLabel} verification.`;
    }
  }
  if (user.stage === "active") {
    return `Authenticated session active, but recent ${methodLabel} verification is not confirmed.`;
  }
  return `Session stage: ${user.stage || "unknown"}. Complete authentication before a sensitive action.`;
}

function updateSensitiveAuthStatus() {
  document.querySelectorAll(".sensitive-auth-status").forEach((status) => {
    status.textContent = sensitiveAuthStatusText();
    status.classList.toggle("is-unverified", !sensitiveAuthState?.sensitive_auth?.recent);
  });
}

async function refreshSensitiveAuthStatus() {
  sensitiveAuthState = await BB.api("/internal/auth/me");
  updateSensitiveAuthStatus();
  return sensitiveAuthState;
}

function withSafetyContext(payload, context) {
  return { ...payload, reason: context.reason, confirmation: context.confirmation };
}

function confirmSensitiveAction({
  title,
  impact,
  confirmation,
  actionLabel,
  perform,
  onSuccess = null,
  extraFields = [],
  requireSensitiveAuth = true,
}) {
  const form = document.createElement("form");
  form.className = "sensitive-action-form";
  let authStatusChecked = !requireSensitiveAuth;

  const impactBox = document.createElement("section");
  impactBox.className = "sensitive-impact";
  const impactTitle = document.createElement("h3");
  impactTitle.textContent = "Impact";
  impactBox.append(impactTitle);
  const impacts = Array.isArray(impact) ? impact : [impact];
  if (impacts.length > 1) {
    const list = document.createElement("ul");
    for (const item of impacts) {
      const entry = document.createElement("li");
      entry.textContent = item;
      list.append(entry);
    }
    impactBox.append(list);
  } else {
    const description = document.createElement("p");
    description.textContent = impacts[0];
    impactBox.append(description);
  }

  const mfa = document.createElement("p");
  mfa.className = "sensitive-auth-status";
  mfa.setAttribute("role", "status");
  mfa.textContent = "Checking current recent-MFA status…";

  const extraInputs = {};
  const extraNodes = extraFields.map((field) => {
    const label = document.createElement("label");
    label.textContent = field.label;
    const input = document.createElement("input");
    input.name = field.name;
    input.type = field.type || "text";
    input.required = field.required !== false;
    if (field.autocomplete) input.autocomplete = field.autocomplete;
    if (field.placeholder) input.placeholder = field.placeholder;
    extraInputs[field.name] = input;
    label.append(input);
    return label;
  });

  const reasonLabel = document.createElement("label");
  reasonLabel.textContent = "Operational reason";
  const reason = document.createElement("textarea");
  reason.name = "reason";
  reason.rows = 3;
  reason.minLength = SENSITIVE_REASON_MIN_LENGTH;
  reason.maxLength = 500;
  reason.required = true;
  reason.placeholder = "Change ticket, incident, recovery need, or maintenance justification (do not include secrets)";
  reasonLabel.append(reason);

  const confirmLabel = document.createElement("label");
  const confirmPrompt = document.createElement("span");
  confirmPrompt.append("Type ");
  const phrase = document.createElement("code");
  phrase.textContent = confirmation;
  confirmPrompt.append(phrase, " to continue");
  const typed = document.createElement("input");
  typed.name = "confirmation";
  typed.type = "text";
  typed.required = true;
  typed.autocomplete = "off";
  typed.spellcheck = false;
  const stateId = `sensitive-confirm-state-${++sensitiveDialogCounter}`;
  typed.setAttribute("aria-describedby", stateId);
  confirmLabel.append(confirmPrompt, typed);

  const totpLabel = document.createElement("label");
  totpLabel.textContent = "Current TOTP code";
  const totp = document.createElement("input");
  totp.name = "totp_code";
  totp.type = "text";
  totp.required = true;
  totp.inputMode = "numeric";
  totp.autocomplete = "one-time-code";
  totp.pattern = "[0-9]{6}";
  totp.maxLength = 6;
  totp.placeholder = "6-digit code";
  totp.setAttribute("aria-describedby", stateId);
  totpLabel.append(totp);

  const passwordLabel = document.createElement("label");
  passwordLabel.textContent = "Current password";
  const password = document.createElement("input");
  password.name = "current_password";
  password.type = "password";
  password.required = true;
  password.autocomplete = "current-password";
  password.setAttribute("aria-describedby", stateId);
  passwordLabel.append(password);

  const state = document.createElement("p");
  state.id = stateId;
  state.className = "form-state";
  state.setAttribute("role", "status");
  state.setAttribute("aria-live", "polite");
  state.textContent = requireSensitiveAuth
    ? `Complete recent authentication, enter at least ${SENSITIVE_REASON_MIN_LENGTH} characters of reason, and type the exact confirmation phrase.`
    : `Enter at least ${SENSITIVE_REASON_MIN_LENGTH} characters of reason and type the exact confirmation phrase.`;

  const submit = document.createElement("button");
  submit.type = "submit";
  submit.className = "danger";
  submit.textContent = actionLabel;
  submit.disabled = true;

  form.append(impactBox);
  if (requireSensitiveAuth) form.append(mfa);
  form.append(...extraNodes, reasonLabel, confirmLabel, totpLabel, passwordLabel, state, submit);
  const dialog = BB.modal({ title, content: form });
  const overlay = dialog.card.parentElement;
  const closeButton = dialog.card.querySelector(".modal-close");

  const preventBusyDismissal = (event) => {
    const isEscape = event.type === "keydown" && event.key === "Escape";
    const isBackdrop = event.type === "click" && event.target === overlay;
    if (isEscape || isBackdrop) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  };

  const setSubmitting = (busy) => {
    form.setAttribute("aria-busy", busy ? "true" : "false");
    if (closeButton) closeButton.disabled = busy;
    if (busy) {
      document.addEventListener("keydown", preventBusyDismissal, true);
      overlay.addEventListener("click", preventBusyDismissal, true);
    } else {
      document.removeEventListener("keydown", preventBusyDismissal, true);
      overlay.removeEventListener("click", preventBusyDismissal, true);
    }
  };

  const updateReadyState = () => {
    const reasonReady = reason.value.trim().length >= SENSITIVE_REASON_MIN_LENGTH;
    const phraseReady = typed.value === confirmation;
    const auth = sensitiveAuthState?.sensitive_auth;
    const authReady = !requireSensitiveAuth || (
      authStatusChecked && (
        Boolean(auth?.recent)
        || (auth?.method === "password" ? Boolean(password.value) : /^[0-9]{6}$/.test(totp.value))
      )
    );
    const extrasReady = Object.values(extraInputs).every((input) => !input.required || Boolean(input.value));
    submit.disabled = !(reasonReady && phraseReady && authReady && extrasReady);
    state.classList.remove("is-error");
    if (requireSensitiveAuth && !authStatusChecked) {
      state.textContent = "Checking the required recent-authentication method…";
    } else if (!extrasReady) {
      state.textContent = "Complete every required action field.";
    } else if (!reasonReady) {
      state.textContent = `Reason must contain at least ${SENSITIVE_REASON_MIN_LENGTH} characters after trimming.`;
    } else if (!phraseReady) {
      state.textContent = "The typed confirmation does not match.";
    } else if (!authReady) {
      state.textContent = auth?.method === "password"
        ? "Enter your current password."
        : "Enter the current 6-digit TOTP code.";
    } else {
      state.textContent = "All confirmations are ready. Review the impact once more before continuing.";
    }
  };

  const applyAuthRequirement = () => {
    if (!requireSensitiveAuth) {
      totpLabel.classList.add("hidden");
      passwordLabel.classList.add("hidden");
      totp.disabled = true;
      totp.required = false;
      password.disabled = true;
      password.required = false;
      updateReadyState();
      return;
    }
    if (!authStatusChecked) {
      totpLabel.classList.add("hidden");
      passwordLabel.classList.add("hidden");
      totp.disabled = true;
      totp.required = false;
      password.disabled = true;
      password.required = false;
      mfa.textContent = "Checking the required recent-authentication method…";
      mfa.classList.remove("is-unverified");
      updateReadyState();
      return;
    }
    const auth = sensitiveAuthState?.sensitive_auth || { method: "totp", recent: false };
    const recent = Boolean(auth.recent);
    const needsTotp = !recent && auth.method === "totp";
    const needsPassword = !recent && auth.method === "password";
    totpLabel.classList.toggle("hidden", !needsTotp);
    totp.disabled = !needsTotp;
    totp.required = needsTotp;
    passwordLabel.classList.toggle("hidden", !needsPassword);
    password.disabled = !needsPassword;
    password.required = needsPassword;
    mfa.textContent = sensitiveAuthStatusText();
    mfa.classList.toggle("is-unverified", !recent);
    updateReadyState();
  };
  applyAuthRequirement();
  if (requireSensitiveAuth) {
    refreshSensitiveAuthStatus()
      .then(() => {
        authStatusChecked = true;
        applyAuthRequirement();
      })
      .catch(() => {
        sensitiveAuthState = {
          ...sensitiveAuthState,
          sensitive_auth: { method: sensitiveAuthState?.totp_required ? "totp" : "password", recent: false },
        };
        authStatusChecked = true;
        updateSensitiveAuthStatus();
        applyAuthRequirement();
        mfa.textContent = "Could not refresh authentication status. The server remains authoritative.";
      });
  }

  reason.addEventListener("input", updateReadyState);
  typed.addEventListener("input", updateReadyState);
  totp.addEventListener("input", updateReadyState);
  password.addEventListener("input", updateReadyState);
  Object.values(extraInputs).forEach((input) => input.addEventListener("input", updateReadyState));

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const context = {
      reason: reason.value.trim(),
      confirmation: typed.value,
      values: Object.fromEntries(Object.entries(extraInputs).map(([name, input]) => [name, input.value])),
    };
    const auth = sensitiveAuthState?.sensitive_auth;
    const suppliedAuth = auth?.method === "password"
      ? Boolean(password.value)
      : /^[0-9]{6}$/.test(totp.value);
    if (
      (requireSensitiveAuth && !authStatusChecked)
      || context.reason.length < SENSITIVE_REASON_MIN_LENGTH
      || context.confirmation !== confirmation
      || (requireSensitiveAuth && !auth?.recent && !suppliedAuth)
      || Object.values(extraInputs).some((input) => input.required && !input.value)
    ) {
      updateReadyState();
      state.classList.add("is-error");
      return;
    }
    setSubmitting(true);
    submit.disabled = true;
    submit.textContent = `${actionLabel}…`;
    state.textContent = !requireSensitiveAuth
      ? "Submitting the confirmed action…"
      : auth?.recent
      ? "Recent authentication is active. Submitting the sensitive action…"
      : `Verifying ${auth?.method === "password" ? "password" : "TOTP"} before submitting…`;
    let result;
    try {
      if (requireSensitiveAuth && !auth?.recent) {
        const passwordMethod = auth?.method === "password";
        sensitiveAuthState = await BB.api(
          passwordMethod
            ? "/internal/auth/password/reauthenticate"
            : "/internal/auth/totp/reauthenticate",
          {
            method: "POST",
            body: JSON.stringify(passwordMethod ? { password: password.value } : { code: totp.value }),
          },
        );
        updateSensitiveAuthStatus();
        if (!sensitiveAuthState?.sensitive_auth?.recent) {
          sensitiveAuthState = await refreshSensitiveAuthStatus();
        }
      }
      if (requireSensitiveAuth && !sensitiveAuthState?.sensitive_auth?.recent) {
        throw new Error("The server did not confirm recent authentication.");
      }
      state.textContent = requireSensitiveAuth
        ? "Recent authentication confirmed. Submitting sensitive action…"
        : "Submitting the confirmed action…";
      result = await perform(context);
    } catch (error) {
      const errorMessage = `Action failed: ${error?.message || String(error)}`;
      totp.value = "";
      password.value = "";
      Object.values(extraInputs).forEach((input) => {
        if (input.type === "password") input.value = "";
      });
      if (requireSensitiveAuth) {
        authStatusChecked = false;
        applyAuthRequirement();
        try {
          await refreshSensitiveAuthStatus();
        } catch (_) {
          sensitiveAuthState = {
            ...sensitiveAuthState,
            sensitive_auth: { ...sensitiveAuthState?.sensitive_auth, recent: false },
          };
          updateSensitiveAuthStatus();
        }
        authStatusChecked = true;
        applyAuthRequirement();
      }
      state.textContent = errorMessage;
      state.classList.add("is-error");
      if (requireSensitiveAuth && !sensitiveAuthState?.sensitive_auth?.recent) {
        (sensitiveAuthState?.sensitive_auth?.method === "password" ? password : totp).focus();
      }
      BB.showError(error);
      return;
    } finally {
      setSubmitting(false);
      submit.textContent = actionLabel;
      submit.disabled = !(
        (!requireSensitiveAuth || authStatusChecked)
        && reason.value.trim().length >= SENSITIVE_REASON_MIN_LENGTH
        && typed.value === confirmation
        && (
          !requireSensitiveAuth
          || sensitiveAuthState?.sensitive_auth?.recent
          || (sensitiveAuthState?.sensitive_auth?.method === "password"
            ? Boolean(password.value)
            : /^[0-9]{6}$/.test(totp.value))
        )
        && Object.values(extraInputs).every((input) => !input.required || Boolean(input.value))
      );
    }

    dialog.close();
    showDetails(result);
    if (onSuccess) {
      try {
        await onSuccess(result);
      } catch (error) {
        BB.showError(new Error(`${actionLabel} completed, but refreshing the displayed state failed: ${error?.message || String(error)}`));
      }
    }
  });

  return dialog;
}

window.AdminSafety = {
  confirm: confirmSensitiveAction,
  withContext: withSafetyContext,
};

function formSnapshot(form) {
  return JSON.stringify([...form.elements]
    .filter((control) => control.name && !["button", "submit", "reset"].includes(control.type))
    .map((control) => [
      control.name,
      ["checkbox", "radio"].includes(control.type) ? control.checked : control.value,
    ]));
}

function trackPersistentForm(form, status, { loaded = "Saved settings loaded." } = {}) {
  const submit = form.querySelector('button[type="submit"]');
  const submitLabel = submit?.textContent || "Save";
  let baseline = null;

  const setStatus = (message, tone = "") => {
    status.textContent = message;
    status.classList.toggle("is-dirty", tone === "dirty");
    status.classList.toggle("is-error", tone === "error");
  };
  const setBusy = (busy) => {
    form.setAttribute("aria-busy", busy ? "true" : "false");
    if (submit) {
      submit.disabled = busy;
      submit.textContent = busy ? "Saving…" : submitLabel;
    }
  };
  const updateDirtyState = () => {
    if (baseline === null) return;
    const unchanged = formSnapshot(form) === baseline;
    setStatus(unchanged ? loaded : "Unsaved changes.", unchanged ? "" : "dirty");
  };
  form.addEventListener("input", updateDirtyState);
  form.addEventListener("change", updateDirtyState);

  return {
    loaded(message = loaded) {
      baseline = formSnapshot(form);
      setBusy(false);
      setStatus(message);
    },
    saving(message = "Saving settings…") {
      setBusy(true);
      setStatus(message);
    },
    failed(error) {
      setBusy(false);
      setStatus(`Could not save: ${error?.message || String(error)}`, "error");
    },
    message(message, tone = "") {
      setStatus(message, tone);
    },
  };
}

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const fallback = document.createElement("textarea");
  fallback.value = value;
  fallback.setAttribute("readonly", "");
  fallback.className = "clipboard-fallback";
  document.body.append(fallback);
  fallback.select();
  const copied = document.execCommand("copy");
  fallback.remove();
  if (!copied) throw new Error("Clipboard access is unavailable in this browser.");
}

async function loadAdminCsrPage() {
  adminCsrPage = BB.mountCsrPage(BB.$("#view-user"), { onDetails: showDetails });
  await adminCsrPage.refresh();
}

async function refreshAdminCsrPage() {
  if (!adminCsrPage) {
    await loadAdminCsrPage();
    return;
  }
  await adminCsrPage.refresh();
}

// -- Reverse proxy (mTLS) setup help popup ------------------------------------
function openMtlsHelp() {
  const content = BB.$("#tpl-mtls-proxy-help").content.cloneNode(true);
  BB.modal({ title: "Reverse proxy (mTLS) setup", content });
}

BB.$("#mtls-help-link").addEventListener("click", (event) => {
  event.preventDefault();
  openMtlsHelp();
});

function setProposalBadge(count) {
  const badge = BB.$("#proposal-badge");
  badge.textContent = count;
  badge.classList.toggle("hidden", !count);
  BB.setNavPending(
    "privileged",
    count > 0 && !BB.isDashboardAlertMuted("governance.pending_changes"),
    "admin-proposals",
  );
}

async function updateProposalBadge() {
  try {
    setProposalBadge((await BB.api("/internal/admin/proposals")).length);
  } catch {
    /* badge is a nicety; views surface real errors */
  }
}

// -- Privileged users -----------------------------------------------------------
async function loadPrivileged() {
  const [loadedUsers, loadedGovernance] = await Promise.all([
    BB.api("/internal/users"),
    BB.api(GOVERNANCE_API.status),
  ]);
  users = loadedUsers;
  governanceState = loadedGovernance;
  renderGovernanceMode();
  renderUserSelects();
  await renderProposals();
  if (!loginAccountsBar) {
    loginAccountsBar = BB.actionBar(BB.$("#login-accounts-actionbar"), {
      emptyLabel: "Select a login account, or create one",
      actions: [
        { label: "Create User", enabled: () => true, onClick: () => openUserModal() },
        { label: "Reset Password", enabled: (s) => Boolean(s) && !pendingRoleGrantTargetIds.has(s.id), onClick: (s) => openResetModal(s) },
        { label: "Reset TOTP", enabled: (s) => Boolean(s) && s.role === "user" && s.totp_configured, onClick: (s) => resetUserTotp(s).catch(BB.showError) },
        { label: "Deactivate", variant: "danger", enabled: (s) => Boolean(s) && s.is_active, onClick: (s) => setUserActive(s, false).catch(BB.showError) },
        { label: "Reactivate", enabled: (s) => Boolean(s) && !s.is_active && !pendingRoleGrantTargetIds.has(s.id), onClick: (s) => setUserActive(s, true).catch(BB.showError) },
      ],
    });
    BB.$("#login-accounts-refresh").addEventListener("click", () => loadPrivileged().catch(BB.showError));
  }
  renderLoginAccounts();
}

function governanceModeLabel(mode) {
  return mode === "dual_control" ? "Dual control" : mode === "single_admin" ? "Single administrator" : "Unknown";
}

function adminChangeTypeLabel(changeType) {
  const labels = {
    privileged_role_grant: "Privileged role grant",
    privileged_password_reset: "Privileged password reset",
    privileged_totp_reset: "Privileged TOTP reset",
    role_totp_policy_change: "Role TOTP policy change",
    governance_mode_downgrade: "Governance downgrade",
    hsm_raw_backup_export: "Native HSM backup export",
  };
  return labels[changeType] || String(changeType || "Unknown").replaceAll("_", " ");
}

function renderGovernanceMode() {
  const mode = governanceState?.mode;
  const dualControl = mode === "dual_control";
  const singleAdmin = mode === "single_admin";
  const labInstall = governanceState?.install_type === "lab" || governanceState?.lab_mode === true;
  const productionSingleAdmin = singleAdmin && !labInstall;
  const activeAdmins = Number(governanceState?.active_admin_count || 0);
  const dualControlOperational = dualControl
    && activeAdmins >= 2
    && governanceState?.dual_control_operational !== false;
  const pending = governanceState?.pending_downgrade || null;
  const badge = BB.$("#governance-mode-badge");
  const summary = BB.$("#governance-mode-summary");
  const prerequisite = BB.$("#governance-mode-prerequisite");
  const status = BB.$("#governance-mode-status");
  const enableDual = BB.$("#governance-enable-dual");
  const requestSingle = BB.$("#governance-request-single");
  const panel = BB.$("#governance-mode-panel");

  badge.textContent = governanceModeLabel(mode);
  badge.className = `status-pill ${dualControlOperational || (singleAdmin && labInstall) ? "status-pass" : dualControl || productionSingleAdmin ? "status-warn" : "status-unknown"}`;
  enableDual.classList.toggle("hidden", !singleAdmin);
  requestSingle.classList.toggle("hidden", !dualControl || Boolean(pending));
  enableDual.disabled = !governanceState?.can_enable_dual_control;
  requestSingle.disabled = dualControl && !dualControlOperational;
  panel.classList.toggle("is-single-admin-risk", productionSingleAdmin);
  panel.classList.toggle("is-governance-blocked", dualControl && !dualControlOperational);
  panel.classList.toggle("is-lab-single", singleAdmin && labInstall);
  panel.classList.toggle("is-dual-control", dualControlOperational);

  if (dualControl) {
    summary.textContent = dualControlOperational
      ? "Privileged role grants and privileged password/TOTP resets require a proposal from one administrator and approval by a different administrator before they take effect."
      : "Dual control is configured, but fewer than two administrators are active. Governed changes cannot receive the required independent approval.";
    prerequisite.textContent = dualControlOperational
      ? `${activeAdmins} active administrators. A downgrade request does not change the current mode; Dual control remains active until a different administrator approves it.`
      : governanceState?.warning || `${activeAdmins} active administrator${activeAdmins === 1 ? "" : "s"}. Reactivate a second administrator before proposing or approving governed changes.`;
    if (!dualControlOperational) {
      status.textContent = "Needs attention: restore two active administrator accounts. Dual control remains enabled and has not been weakened.";
    } else if (pending) {
      status.textContent = `Single-administrator downgrade proposal ${pending.id} is pending ${pending.approval_count || 0}/${pending.required_approvals || 1} approval. It must be approved by an administrator other than ${pending.proposer_email || "the proposer"}.`;
    } else {
      status.textContent = "Dual control is active. Requesting a downgrade only creates a pending proposal.";
    }
  } else if (singleAdmin) {
    summary.textContent = labInstall
      ? "Single administrator is the Test/Lab default. One administrator can apply privileged role grants and privileged password/TOTP resets immediately while evaluating this installation."
      : "This Production installation permits one administrator to apply privileged role grants and privileged password/TOTP resets immediately, without an independent second-person approval barrier.";
    prerequisite.textContent = governanceState?.can_enable_dual_control
      ? `${activeAdmins} active administrators are available. Enabling Dual control is an immediate safety upgrade.`
      : `${activeAdmins} active administrator${activeAdmins === 1 ? "" : "s"}. Add and activate a second Administrator before enabling Dual control.`;
    status.textContent = governanceState?.can_enable_dual_control
      ? labInstall
        ? "Single administrator is healthy for Test/Lab. Dual control remains available if you want to exercise the approval workflow."
        : "Ready to enable the Production-recommended Dual control mode. The upgrade takes effect immediately after confirmation."
      : labInstall
        ? "Single administrator is the Test/Lab default. Add a second active Administrator before opting into Dual control."
        : "Production recommends Dual control. Add a second active Administrator before it can be enabled.";
  } else {
    summary.textContent = "The server did not return a recognized governance mode.";
    prerequisite.textContent = "Refresh this view before attempting a governed role grant or password/TOTP reset.";
    status.textContent = "Governance status unavailable.";
    enableDual.classList.add("hidden");
    requestSingle.classList.add("hidden");
  }

  const proposalSummary = BB.$("#proposal-flow-summary");
  proposalSummary.textContent = dualControl && !dualControlOperational
    ? "Governed proposal creation is paused because no second active administrator is available to approve a change. Reactivate a second administrator first."
    : dualControl
      ? "The forms for privileged role grants and privileged password/TOTP resets create proposals that take effect only after a different administrator approves them. Pending proposals expire."
    : "In Single administrator mode, the forms for privileged role grants and privileged password/TOTP resets apply immediately; they do not wait for a second approval.";
  BB.$("#login-accounts-governance-note").textContent = dualControl
    ? "All portal login accounts. Privileged role grants and privileged password/TOTP resets use the two-distinct-administrator proposal flow above."
    : "All portal login accounts. In Single administrator mode, privileged role grants and privileged password/TOTP resets apply immediately.";
  document.querySelectorAll(".privileged-change-submit").forEach((button) => {
    button.textContent = dualControl ? "Create proposal" : "Apply change";
    button.disabled = dualControl && !dualControlOperational;
    if (button.disabled) {
      button.title = "Reactivate a second administrator before creating governed proposals";
    } else {
      button.removeAttribute("title");
    }
  });
}

function enableDualControl() {
  if (!governanceState?.can_enable_dual_control) {
    BB.showError(new Error("Add and activate a second Administrator before enabling Dual control."));
    return;
  }
  confirmSensitiveAction({
    title: "Enable Dual control",
    impact: [
      "Privileged role grants and privileged password/TOTP resets will require approval by an administrator other than the proposer.",
      "The upgrade applies immediately and strengthens governance; it does not invalidate current administrator sessions.",
    ],
    confirmation: "ENABLE DUAL CONTROL",
    actionLabel: "Enable Dual control",
    requireSensitiveAuth: false,
    perform: (context) => BB.api(GOVERNANCE_API.enableDual, {
      method: "POST",
      body: JSON.stringify(withSafetyContext({}, context)),
    }),
    onSuccess: loadPrivileged,
  });
}

function requestSingleAdminMode() {
  confirmSensitiveAction({
    title: "Request Single administrator mode",
    impact: [
      "This request does not change the current mode. Dual control remains enforced while the proposal is pending.",
      "A different administrator must approve the proposal before the second-person barrier is removed.",
      "After approval, one administrator can apply privileged role grants and privileged password/TOTP resets alone.",
    ],
    confirmation: "REQUEST SINGLE ADMIN",
    actionLabel: "Create downgrade proposal",
    perform: (context) => BB.api(GOVERNANCE_API.requestSingle, {
      method: "POST",
      body: JSON.stringify(withSafetyContext({}, context)),
    }),
    onSuccess: loadPrivileged,
  });
}

function approveSingleAdminMode(proposal) {
  confirmSensitiveAction({
    title: "Approve Single administrator downgrade",
    impact: [
      `Proposal ${proposal.id} was created by ${proposal.proposer_email || "another administrator"}.`,
      "Approval applies the downgrade immediately and removes independent approval for future privileged role grants and privileged password/TOTP resets.",
      "You must be a different administrator from the proposer.",
    ],
    confirmation: "APPROVE SINGLE ADMIN",
    actionLabel: "Approve and downgrade",
    perform: (context) => BB.api(GOVERNANCE_API.approveSingle(proposal.id), {
      method: "POST",
      body: JSON.stringify(withSafetyContext({}, context)),
    }),
    onSuccess: loadPrivileged,
  });
}

BB.$("#governance-enable-dual").addEventListener("click", enableDualControl);
BB.$("#governance-request-single").addEventListener("click", requestSingleAdminMode);

// -- Authentication policy --------------------------------------------------
let authPolicyState = null;

function authPolicyRoleLabel(role) {
  return visibleRoleLabel(role);
}

function authPolicySelection() {
  return [...BB.$("#totp-policy-form").querySelectorAll('input[name="required_roles"]:checked')]
    .map((input) => input.value);
}

function authPolicyRoleList(roles) {
  return roles.length ? roles.map(authPolicyRoleLabel).join(", ") : "No roles";
}

async function loadAuthPolicy() {
  authPolicyState = await BB.api("/internal/admin/auth-policy");
  const required = new Set(authPolicyState.required_roles || []);
  BB.$("#totp-policy-form").querySelectorAll('input[name="required_roles"]').forEach((input) => {
    input.checked = required.has(input.value);
    input.disabled = Boolean(authPolicyState.pending_change);
  });
  const dual = authPolicyState.governance_mode === "dual_control";
  BB.$("#totp-policy-governance").textContent = dual ? "Dual control" : "Single administrator";
  BB.$("#totp-policy-governance").className = `status-pill ${dual ? "status-pass" : "status-warn"}`;
  BB.$("#totp-policy-save").disabled = Boolean(authPolicyState.pending_change);
  BB.$("#totp-policy-status").textContent = authPolicyState.pending_change
    ? "A policy change is pending. Resolve it before creating another change."
    : dual
      ? "Saving creates a proposal that a different administrator must approve."
      : "Saving applies immediately. Disabling TOTP requires recent authentication.";

  const pendingPanel = BB.$("#totp-policy-pending");
  const pending = authPolicyState.pending_change;
  pendingPanel.classList.toggle("hidden", !pending);
  if (pending) {
    BB.$("#totp-policy-pending-summary").textContent =
      `${pending.proposer_email || pending.proposer_id} requested TOTP for: ${authPolicyRoleList(pending.requested_required_roles || [])}. Reason: ${pending.reason || "not supplied"}.`;
    const approve = BB.$("#totp-policy-approve");
    approve.disabled = pending.proposer_id === BB.currentUser?.user_id;
    approve.title = approve.disabled ? "The proposing administrator cannot approve this change" : "";
  }
  return authPolicyState;
}

function handleAppliedAuthPolicy(result, previousRequired) {
  const approved = result?.proposal?.status === "approved";
  const requested = new Set(result?.proposal?.requested_required_roles || []);
  const adminChanged = previousRequired.has("admin") !== requested.has("admin");
  if (approved && adminChanged) {
    window.location.assign("/login");
    return;
  }
  loadAuthPolicy().catch(BB.showError);
  updateProposalBadge().catch(BB.showError);
}

BB.$("#totp-policy-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const previousRequired = new Set(authPolicyState?.required_roles || []);
  const requested = authPolicySelection();
  const requestedSet = new Set(requested);
  if ([...previousRequired].every((role) => requestedSet.has(role)) && previousRequired.size === requestedSet.size) {
    BB.$("#totp-policy-status").textContent = "No policy changes to save.";
    return;
  }
  const disabled = [...previousRequired].filter((role) => !requestedSet.has(role));
  confirmSensitiveAction({
    title: "Change TOTP policy",
    impact: [
      `TOTP will be required for: ${authPolicyRoleList(requested)}.`,
      disabled.length
        ? `Disabling ${authPolicyRoleList(disabled)} signs out those accounts and permanently deletes their TOTP and recovery data.`
        : "Accounts in newly protected roles will be signed out and must enroll TOTP at next login.",
      authPolicyState?.governance_mode === "dual_control"
        ? "This creates a proposal for a different administrator."
        : "This change applies immediately.",
    ],
    confirmation: "CHANGE TOTP POLICY",
    actionLabel: authPolicyState?.governance_mode === "dual_control" ? "Create policy proposal" : "Apply policy",
    requireSensitiveAuth: disabled.length > 0,
    perform: (context) => BB.api("/internal/admin/auth-policy/changes", {
      method: "POST",
      body: JSON.stringify(withSafetyContext({ required_roles: requested }, context)),
    }),
    onSuccess: (result) => handleAppliedAuthPolicy(result, previousRequired),
  });
});

BB.$("#totp-policy-refresh").addEventListener("click", () => loadAuthPolicy().catch(BB.showError));
BB.$("#totp-policy-approve").addEventListener("click", () => {
  const pending = authPolicyState?.pending_change;
  if (!pending) return;
  const previousRequired = new Set(pending.previous_required_roles || []);
  confirmSensitiveAction({
    title: "Approve TOTP policy change",
    impact: [
      `${pending.proposer_email || pending.proposer_id} requested TOTP for: ${authPolicyRoleList(pending.requested_required_roles || [])}.`,
      "Approval applies the complete role policy atomically and signs out every changed role.",
      "Roles losing TOTP permanently lose their enrolled factors and recovery data.",
    ],
    confirmation: "APPROVE TOTP POLICY",
    actionLabel: "Approve policy change",
    requireSensitiveAuth: false,
    perform: (context) => BB.api(`/internal/admin/auth-policy/proposals/${encodeURIComponent(pending.id)}/approve`, {
      method: "POST",
      body: JSON.stringify(withSafetyContext({}, context)),
    }),
    onSuccess: (result) => handleAppliedAuthPolicy(result, previousRequired),
  });
});

function renderLoginAccounts() {
  BB.renderTable(
    BB.$("#login-accounts-table"),
    users,
    [
      { header: "Email", key: "email" },
      {
        header: "Role",
        render: (row) => {
          const badge = BB.badge(row.role);
          badge.textContent = visibleRoleLabel(row.role);
          return badge;
        },
      },
      {
        header: "Status",
        render: (row) => pendingRoleGrantTargetIds.has(row.id)
          ? "pending privileged-role approval"
          : row.is_active ? "active" : "inactive",
      },
    ],
    {
      selectable: true,
      emptyText: "No login accounts yet.",
      onSelect: (row) => loginAccountsBar && loginAccountsBar.setSelection(row ? { ...row, label: row.email } : null),
    },
  );
}

function visibleRoleLabel(role) {
  const labels = { admin: "Administrator", superuser: "Certificate Operator", auditor: "Auditor", user: "User" };
  return labels[role] || role;
}

function openUserModal() {
  const { form } = cloneForm("#tpl-user-form");
  const dialog = BB.modal({ title: "Create login user", content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      showDetails(await BB.api("/internal/users", { method: "POST", body: JSON.stringify(BB.formPayload(form)) }));
      dialog.close();
      await loadPrivileged();
    } catch (error) {
      BB.showError(error);
    }
  });
}

function openResetModal(user) {
  const { form } = cloneForm("#tpl-reset-form");
  const dialog = BB.modal({ title: `Reset password — ${user.email}`, content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      showDetails(await BB.api(`/internal/users/${encodeURIComponent(user.id)}/password-reset`, {
        method: "POST",
        body: JSON.stringify(BB.formPayload(form)),
      }));
      dialog.close();
    } catch (error) {
      BB.showError(error);
    }
  });
}

async function resetUserTotp(user) {
  if (!window.confirm(`Reset TOTP for ${user.email}? They will be signed out and must enroll again.`)) return;
  showDetails(await BB.api(`/internal/users/${encodeURIComponent(user.id)}/totp-reset`, { method: "POST" }));
  await loadPrivileged();
}

async function setUserActive(user, active) {
  const verb = active ? "reactivate" : "deactivate";
  if (!active && !window.confirm(`Deactivate ${user.email}? They will be signed out and unable to log in.`)) return;
  showDetails(await BB.api(`/internal/users/${encodeURIComponent(user.id)}/${verb}`, { method: "POST" }));
  await loadPrivileged();
}

BB.$("#refresh").addEventListener("click", () => loadPrivileged().catch(BB.showError));

BB.$("#privileged-role-form").addEventListener("submit", async (event) => proposalSubmit(event, "/internal/admin/proposals/privileged-role-grants"));
BB.$("#privileged-password-reset-form").addEventListener("submit", async (event) => proposalSubmit(event, "/internal/admin/proposals/privileged-password-resets"));
BB.$("#privileged-totp-reset-form").addEventListener("submit", async (event) => proposalSubmit(event, "/internal/admin/proposals/privileged-totp-resets"));

async function proposalSubmit(event, path) {
  event.preventDefault();
  // currentTarget is nulled once the handler yields — capture the form first.
  const form = event.currentTarget;
  try {
    showDetails(await BB.api(path, {
      method: "POST",
      body: JSON.stringify(BB.formPayload(form)),
    }));
    form.reset();
    await loadPrivileged();
  } catch (error) {
    BB.showError(error);
  }
}

function renderUserSelects() {
  const privilegedUsers = users.filter((user) => ["admin", "superuser", "auditor"].includes(user.role) && user.is_active);
  const totpUsers = users.filter((user) => ["admin", "superuser", "auditor"].includes(user.role) && user.is_active && user.totp_configured);
  BB.fillSelect(BB.$("#privileged-password-user-select"), privilegedUsers, {
    value: "id",
    label: (row) => `${row.email} (${visibleRoleLabel(row.role)})`,
    placeholder: "Choose privileged user",
  });
  BB.fillSelect(BB.$("#privileged-totp-user-select"), totpUsers, {
    value: "id",
    label: (row) => `${row.email} (${visibleRoleLabel(row.role)})`,
    placeholder: "Choose a privileged account",
  });
}

async function renderProposals() {
  const proposals = await BB.api("/internal/admin/proposals");
  pendingRoleGrantTargetIds = new Set(
    proposals
      .filter((row) => row.change_type === "privileged_role_grant")
      .map((row) => row.target_user_id),
  );
  setProposalBadge(proposals.length);
  BB.renderTable(BB.$("#proposal-table"), proposals, [
    {
      header: "Type",
      render: (row) => adminChangeTypeLabel(row.change_type),
    },
    {
      header: "Target",
      render: (row) => {
        if (row.change_type === "governance_mode_downgrade") {
          return `Governance mode → ${governanceModeLabel(row.requested_mode)}`;
        }
        if (row.change_type === "role_totp_policy_change") {
          return `TOTP roles → ${authPolicyRoleList(row.requested_required_roles || [])}`;
        }
        if (row.change_type === "hsm_raw_backup_export") {
          return "Entire SmartCard-HSM token";
        }
        return `${row.target_email || row.target_user_id} (${visibleRoleLabel(row.requested_role || row.target_role || "pending")})`;
      },
    },
    { header: "Proposer", render: (row) => row.proposer_email || row.proposer_id },
    { header: "Reason", render: (row) => row.reason || "Not supplied" },
    {
      header: "Approvals",
      render: (row) => `${row.approval_count ?? 0}/${row.required_approvals ?? 1}`,
    },
    { header: "Expires", render: (row) => new Date(row.expires_at).toLocaleString() },
    {
      header: "Actions",
      render: (row) => {
        const actions = document.createElement("div");
        actions.className = "actions";
        const governanceDowngrade = row.change_type === "governance_mode_downgrade";
        const totpPolicy = row.change_type === "role_totp_policy_change";
        const hsmBackup = row.change_type === "hsm_raw_backup_export";
        const approve = BB.actionButton(
          governanceDowngrade
            ? "Approve downgrade"
            : totpPolicy
              ? "Review policy"
              : hsmBackup
                ? "Approve & export"
                : "Approve",
          () => governanceDowngrade
            ? approveSingleAdminMode(row)
            : totpPolicy
              ? window.location.assign("#/authentication")
              : hsmBackup
                ? approveHsmBackupProposal(row)
                : resolveProposal(row.id, "approve"),
        );
        if (row.requires_different_admin && row.proposer_id === BB.currentUser?.user_id) {
          approve.disabled = true;
          approve.title = "The proposing administrator cannot approve this change";
          approve.setAttribute("aria-label", "Approve unavailable: a different administrator is required");
        }
        actions.append(approve, BB.actionButton("Reject", () => resolveProposal(row.id, "reject"), "danger"));
        return actions;
      },
    },
  ], { emptyText: "No pending proposals." });
}

async function resolveProposal(id, action) {
  try {
    showDetails(await BB.api(`/internal/admin/proposals/${id}/${action}`, { method: "POST" }));
    await loadPrivileged();
  } catch (error) {
    BB.showError(error);
  }
}

function approveHsmBackupProposal(proposal) {
  confirmSensitiveAction({
    title: "Approve native SmartCard-HSM backup export",
    impact: [
      `Proposal ${proposal.id} was created by ${proposal.proposer_email || "another administrator"}.`,
      "SmartCard-HSM wraps every live token key under the configured DKEK; private key material is never returned in plaintext.",
      "The approving administrator must have an unlocked User PIN. The ZIP contains only untouched native .bin files.",
      "You must be a different administrator from the proposer.",
    ],
    confirmation: "APPROVE EXPORT ENTIRE HSM",
    actionLabel: "Approve and export backups",
    perform: async (context) => {
      const download = await BB.apiDownload(
        `/internal/admin/hsm/token-backup/proposals/${encodeURIComponent(proposal.id)}/approve`,
        {
          method: "POST",
          body: JSON.stringify(withSafetyContext({}, context)),
        },
      );
      BB.fileDownload(download.filename, download.blob);
      return { downloaded: true, filename: download.filename, persisted: false };
    },
    onSuccess: async () => {
      await loadPrivileged();
      await refreshHsm();
    },
  });
}

// -- HSM & Keys -------------------------------------------------------------------
async function loadHsmView() {
  await refreshHsm();
}

const entropyFormState = trackPersistentForm(
  BB.$("#entropy-form"),
  BB.$("#entropy-form-state"),
  { loaded: "Saved random-source setting loaded." },
);

BB.$("#hsm-refresh").addEventListener("click", () => refreshHsm().catch(BB.showError));
BB.$("#hsm-keys-refresh").addEventListener("click", () => renderHsmKeys().catch(BB.showError));
BB.$("#hsm-dkek-refresh").addEventListener("click", () => refreshDkek().catch(BB.showError));
BB.$("#cloud-signing-refresh").addEventListener("click", () => refreshCloudSigning().catch(BB.showError));

function setHsmKeyFormBusy(form, busy) {
  const button = BB.$("#hsm-key-generate");
  const status = BB.$("#hsm-key-status");
  form.setAttribute("aria-busy", busy ? "true" : "false");
  for (const element of form.elements) {
    element.disabled = busy;
  }
  button.textContent = busy ? "Generating..." : "Generate key";
  status.textContent = busy ? "Generating key on the token. This can take a minute." : "";
}

BB.$("#hsm-self-test").addEventListener("click", async () => {
  try {
    showDetails(await BB.api("/internal/hsm/test", { method: "POST" }));
  } catch (error) {
    BB.showError(error);
  }
});

BB.$("#hsm-pin-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    showDetails(await BB.api("/internal/hsm/pin/unlock", {
      method: "POST",
      body: JSON.stringify(BB.formPayload(form)),
    }));
    form.reset();
    await refreshHsm();
  } catch (error) {
    BB.showError(error);
    await refreshHsm().catch(BB.showError);
  }
});

BB.$("#hsm-policy-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    showDetails(await BB.api("/internal/hsm/policy", {
      method: "PUT",
      body: JSON.stringify({ operator_unlock_allowed: BB.$("#hsm-operator-unlock").checked }),
    }));
    await refreshHsmPolicy();
  } catch (error) {
    BB.showError(error);
  }
});

async function refreshHsmPolicy() {
  try {
    const policy = await BB.api("/internal/hsm/policy");
    BB.$("#hsm-operator-unlock").checked = Boolean(policy.operator_unlock_allowed);
  } catch (error) {
    // The policy panel is advisory; a failure here must not block HSM status.
  }
}

BB.$("#hsm-pin-lock").addEventListener("click", async () => {
  try {
    showDetails(await BB.api("/internal/hsm/pin/lock", { method: "POST" }));
    await refreshHsm();
  } catch (error) {
    BB.showError(error);
  }
});

let hsmKeyGenerationInFlight = false;
let hsmDkekRecoveryAvailable = false;
BB.$("#hsm-key-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (hsmKeyGenerationInFlight) return;
  const form = event.currentTarget;
  const payload = BB.formPayload(form);
  hsmKeyGenerationInFlight = true;
  setHsmKeyFormBusy(form, true);
  try {
    showDetails(await BB.api("/internal/hsm/keys", {
      method: "POST",
      body: JSON.stringify(payload),
    }));
    form.reset();
    await renderHsmKeys();
  } catch (error) {
    BB.showError(error);
  } finally {
    hsmKeyGenerationInFlight = false;
    setHsmKeyFormBusy(form, false);
  }
});

let hsmPinUnlocked = false;

async function refreshHsm() {
  await refreshHsmPolicy();
  const body = await BB.api("/internal/hsm/status");
  hsmPinUnlocked = Boolean(body.pin_unlocked);
  const parts = [`Backend: ${body.backend}`];
  if (body.pin_required) parts.push(`PIN: ${hsmPinUnlocked ? "unlocked" : "locked"}`);
  if (body.token) {
    const token = body.token;
    parts.push(token.token_present ? `token "${token.token?.label ?? body.token.token_label}" present` : "no token present");
    if (token.pin_tries_left !== null && token.pin_tries_left !== undefined) {
      parts.push(`User PIN tries left: ${token.pin_tries_left}`);
    }
  } else if (body.token_error) {
    parts.push(`token error: ${body.token_error}`);
  }
  if (body.provider) parts.push("provider connection ready");
  if (body.provider_error) parts.push(`provider error: ${body.provider_error}`);
  if (body.signing_queue) {
    parts.push(`queue: ${body.signing_queue.queued} queued, ${body.signing_queue.failed} failed`);
    if (body.signing_queue.alerts) parts.push(`${body.signing_queue.alerts} alert(s)`);
  }
  BB.$("#hsm-status").textContent = parts.join(" | ");
  BB.$("#hsm-pin-form").classList.toggle("hidden", !body.pin_required);
  const cloudBackend = body.backend === "aws_kms" || body.backend === "azure_key_vault";
  BB.$("#cloud-signing-panel").classList.toggle("hidden", !cloudBackend);
  if (cloudBackend) await refreshCloudSigning();
  let dkekStatus = null;
  if (body.backend === "pkcs11") {
    try {
      dkekStatus = await refreshDkek();
    } catch (error) {
      hsmDkekRecoveryAvailable = false;
      BB.$("#hsm-dkek-status").textContent = `DKEK status error: ${error.message}`;
      BB.renderTable(BB.$("#hsm-dkek-table"), [], []);
    }
  } else {
    hsmDkekRecoveryAvailable = false;
    BB.$("#hsm-dkek-status").textContent = "DKEK applies to the PKCS#11 backend only.";
    BB.$("#hsm-raw-backup-status").textContent = "Native HSM backups require the PKCS#11 backend.";
    BB.renderTable(BB.$("#hsm-dkek-table"), [], []);
  }
  const initializedWithoutDkek = Boolean(
    body.backend === "pkcs11"
    && body.token?.token?.initialized
    && dkekStatus
    && dkekStatus.shares_total === 0,
  );
  BB.$("#hsm-dkek-disabled-notice").classList.toggle("hidden", !initializedWithoutDkek);
  BB.$("#hsm-dkek-controls").classList.toggle("hidden", initializedWithoutDkek);
  const rawBackupAvailable = Boolean(
    body.backend === "pkcs11"
    && hsmDkekRecoveryAvailable
    && !initializedWithoutDkek,
  );
  BB.$("#hsm-raw-backup-controls").classList.remove("hidden");
  BB.$("#hsm-raw-backup-export").disabled = !rawBackupAvailable;
  BB.$("#hsm-key-recovery-hint").classList.toggle("hidden", initializedWithoutDkek);

  if (body.backend === "pkcs11" && hsmPinUnlocked) {
    try {
      await renderHsmKeys();
    } catch (error) {
      BB.renderTable(BB.$("#hsm-key-table"), [], []);
      parts.push(`key listing error: ${error.message}`);
      BB.$("#hsm-status").textContent = parts.join(" | ");
    }
  } else {
    BB.renderTable(BB.$("#hsm-key-table"), [], []);
  }
  return body;
}

async function refreshCloudSigning() {
  const [keys, status, jobs] = await Promise.all([
    BB.api("/internal/cloud/keys"),
    BB.api("/internal/cloud/signing-status"),
    BB.api("/internal/cloud/signing-jobs?limit=100"),
  ]);
  const counts = status.counts || {};
  BB.$("#cloud-signing-status").textContent =
    `${counts.queued || 0} queued · ${counts.running || 0} running · ` +
    `${counts.failed || 0} failed · ${(status.alerts || []).length} alert(s)`;
  BB.renderTable(BB.$("#cloud-key-table"), keys, [
    { header: "Provider", key: "provider" },
    { header: "Label", key: "label" },
    { header: "Algorithm", key: "algorithm" },
    { header: "Purpose", key: "purpose" },
    { header: "Ownership", key: "ownership" },
    { header: "Status", key: "status" },
    {
      header: "Actions",
      render: (row) => {
        if (row.status === "pending_deletion" && row.ownership === "managed") {
          return BB.actionButton("Recover", () => recoverCloudKey(row));
        }
        if (row.status === "deleted" && row.ownership === "attached") {
          return BB.actionButton("Reattach", () => reattachCloudKey(row));
        }
        if (row.status !== "active" && row.status !== "disabled") return "—";
        return BB.actionButton(
          row.ownership === "attached" ? "Detach" : "Delete",
          () => deleteCloudKey(row),
          "danger",
        );
      },
    },
  ]);
  BB.renderTable(BB.$("#cloud-signing-job-table"), jobs, [
    { header: "Operation", key: "operation" },
    { header: "Resource", render: (row) => `${row.resource_type}:${row.resource_id}` },
    { header: "Status", key: "status" },
    { header: "Attempts", key: "attempt_count" },
    { header: "Last error", render: (row) => row.last_error_message || "—" },
    {
      header: "Actions",
      render: (row) => {
        if (row.status === "failed") {
          return BB.actionButton("Retry", () => retryCloudSigningJob(row.id));
        }
        if (row.status === "queued" || row.status === "running") {
          return BB.actionButton("Cancel", () => cancelCloudSigningJob(row.id), "danger");
        }
        return "—";
      },
    },
  ]);
}

function deleteCloudKey(key) {
  const attached = key.ownership === "attached";
  const confirmation = attached ? "DETACH CLOUD KEY" : "DELETE CLOUD KEY";
  confirmSensitiveAction({
    title: `${attached ? "Detach" : "Delete"} cloud key “${key.label || key.id}”`,
    impact: attached
      ? "myOwnCA will forget the key reference. The provider key is not deleted."
      : "Deletion is requested from the cloud provider only after all local consumers and active jobs are gone.",
    confirmation,
    actionLabel: attached ? "Detach key" : "Schedule deletion",
    perform: (context) => BB.api(`/internal/cloud/keys/${encodeURIComponent(key.id)}`, {
      method: "DELETE",
      body: JSON.stringify(withSafetyContext({}, context)),
    }),
    onSuccess: refreshCloudSigning,
  });
}

function recoverCloudKey(key) {
  confirmSensitiveAction({
    title: `Recover cloud key “${key.label || key.id}”`,
    impact: "The application asks the provider to cancel scheduled deletion or recover the soft-deleted key.",
    confirmation: "RECOVER CLOUD KEY",
    actionLabel: "Recover key",
    perform: (context) => BB.api(`/internal/cloud/keys/${encodeURIComponent(key.id)}/recover`, {
      method: "POST",
      body: JSON.stringify(withSafetyContext({}, context)),
    }),
    onSuccess: refreshCloudSigning,
  });
}

function reattachCloudKey(key) {
  confirmSensitiveAction({
    title: `Reattach cloud key “${key.label || key.id}”`,
    impact: "myOwnCA validates the same version-pinned provider key and makes its existing registry entry active again. No provider key is created.",
    confirmation: "REATTACH CLOUD KEY",
    actionLabel: "Reattach key",
    perform: (context) => BB.api(`/internal/cloud/keys/${encodeURIComponent(key.id)}/reattach`, {
      method: "POST",
      body: JSON.stringify(withSafetyContext({}, context)),
    }),
    onSuccess: refreshCloudSigning,
  });
}

async function retryCloudSigningJob(jobId) {
  showDetails(await BB.api(`/internal/cloud/signing-jobs/${encodeURIComponent(jobId)}/retry`, { method: "POST" }));
  await refreshCloudSigning();
}

async function cancelCloudSigningJob(jobId) {
  if (!window.confirm("Cancel this queued cloud signing operation?")) return;
  showDetails(await BB.api(`/internal/cloud/signing-jobs/${encodeURIComponent(jobId)}/cancel`, { method: "POST" }));
  await refreshCloudSigning();
}

async function renderHsmKeys() {
  const keys = await BB.api("/internal/hsm/keys");
  BB.renderTable(BB.$("#hsm-key-table"), keys, [
    { header: "Label", key: "label" },
    { header: "Type", key: "key_type" },
    { header: "Size", render: (row) => (row.key_size ? `${row.key_size}` : "—") },
    {
      header: "Actions",
      render: (row) => {
        const actions = document.createElement("div");
        actions.className = "actions";
        actions.append(BB.actionButton(
          "Retire key",
          () => deleteHsmKey(row.label),
          "danger",
        ));
        return actions;
      },
    },
  ]);
}

BB.$("#hsm-raw-backup-export").addEventListener("click", async () => {
  confirmSensitiveAction({
    title: "Request native SmartCard-HSM backup export",
    impact: [
      "SmartCard-HSM wraps every live token key under the configured DKEK; private key material is never returned in plaintext.",
      "The ZIP is only transport for the untouched native .bin files produced by sc-hsm-tool.",
      "Store it separately from the DKEK shares, their passwords, PINs, and database backup.",
      "A different administrator must approve the request before the ZIP is generated.",
    ],
    confirmation: "REQUEST EXPORT ENTIRE HSM",
    actionLabel: "Request export approval",
    perform: (context) => BB.api("/internal/hsm/token-backup/export-proposals", {
      method: "POST",
      body: JSON.stringify(withSafetyContext({}, context)),
    }),
    onSuccess: async () => {
      await updateProposalBadge();
      await refreshHsm();
    },
  });
});

function deleteHsmKey(label) {
  confirmSensitiveAction({
    title: `Retire HSM key “${label}”`,
    impact: [
      "The key is marked orphaned now and remains recoverable for the mandatory 30-day grace period.",
      "After the deadline, a managed key is destroyed by the cleanup worker; an attached key is only detached from myOwnCA.",
    ],
    confirmation: `DELETE KEY ${label}`,
    actionLabel: "Schedule key retirement",
    perform: (context) => BB.api(`/internal/hsm/keys/${encodeURIComponent(label)}`, {
      method: "DELETE",
      body: JSON.stringify(withSafetyContext({}, context)),
    }),
    onSuccess: renderHsmKeys,
  });
}

async function refreshDkek() {
  const status = await BB.api("/internal/hsm/dkek/status");
  hsmDkekRecoveryAvailable = Boolean(status.complete && status.kcv);
  BB.$("#hsm-dkek-status").textContent = status.shares_total
    ? `Shares ${status.shares_imported}/${status.shares_total} imported | complete: ${status.complete}${status.kcv ? ` | KCV ${status.kcv}` : ""}`
    : "No DKEK configured on this token.";
  BB.$("#hsm-raw-backup-status").textContent = hsmDkekRecoveryAvailable
    ? "Ready to request: a different administrator must approve, and the approving admin must unlock the User PIN to export."
    : "A complete DKEK is required to request native HSM backup export.";
  const shares = await BB.api("/internal/hsm/dkek/shares");
  BB.renderTable(BB.$("#hsm-dkek-table"), shares, [
    { header: "Filename", key: "filename" },
    { header: "Bytes", key: "size" },
    {
      header: "Actions",
      render: (row) => {
        const actions = document.createElement("div");
        actions.className = "actions";
        actions.append(
          BB.actionButton("Download", async () => {
            const download = await BB.apiDownload(
              `/internal/hsm/dkek/shares/${encodeURIComponent(row.filename)}/download`,
            );
            BB.fileDownload(download.filename, download.blob);
          }, "secondary"),
          BB.actionButton("Import", async () => importDkekShare(row.filename)),
          BB.actionButton("Delete", async () => deleteDkekShare(row.filename), "danger"),
        );
        return actions;
      },
    },
  ]);
  return status;
}

async function importDkekShare(filename) {
  confirmSensitiveAction({
    title: `Import DKEK share “${filename}”`,
    impact: [
      "This changes the token's DKEK recovery state and can complete a key-import quorum.",
      "Use only a share whose source, password, and KCV have been verified through the recovery procedure.",
    ],
    confirmation: `IMPORT DKEK ${filename}`,
    actionLabel: "Import DKEK share",
    extraFields: [{
      name: "password",
      label: "DKEK share password",
      type: "password",
      autocomplete: "off",
    }],
    perform: (context) => BB.api(`/internal/hsm/dkek/shares/${encodeURIComponent(filename)}/import`, {
      method: "POST",
      body: JSON.stringify(withSafetyContext({ password: context.values.password }, context)),
    }),
    onSuccess: refreshDkek,
  });
}

function deleteDkekShare(filename) {
  confirmSensitiveAction({
    title: `Delete DKEK share file “${filename}”`,
    impact: [
      "The server-side copy of this recovery share will be permanently removed.",
      "Because DKEK is N-of-N, recovery is impossible if any distinct share and all of its redundant copies are lost.",
    ],
    confirmation: `DELETE DKEK ${filename}`,
    actionLabel: "Delete DKEK share",
    perform: (context) => BB.api(`/internal/hsm/dkek/shares/${encodeURIComponent(filename)}`, {
      method: "DELETE",
      body: JSON.stringify(withSafetyContext({}, context)),
    }),
    onSuccess: refreshDkek,
  });
}

BB.$("#entropy-validate").addEventListener("click", async () => {
  try {
    const result = await BB.api("/internal/admin/entropy-source/validate", {
      method: "POST",
      body: JSON.stringify({ entropy_source: BB.$("#entropy-form").elements.entropy_source.value }),
    });
    entropyFormState.message("Validation passed. Save to make this the active source.");
    showDetails(result);
  } catch (error) {
    entropyFormState.message(`Validation failed: ${error?.message || String(error)}`, "error");
    BB.showError(error);
  }
});

BB.$("#entropy-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  entropyFormState.saving("Saving random-source setting…");
  try {
    showDetails(await BB.api("/internal/admin/entropy-source", {
      method: "PUT",
      body: JSON.stringify({ entropy_source: event.currentTarget.elements.entropy_source.value || null }),
    }));
    await refreshEntropySource();
  } catch (error) {
    entropyFormState.failed(error);
    BB.showError(error);
  }
});

async function refreshEntropySource() {
  const status = await BB.api("/internal/admin/entropy-source");
  const origins = { setting: "set in admin portal", env: "from environment", default: "default" };
  BB.$("#entropy-status").textContent = status.entropy_source
    ? `External source: ${status.entropy_source} (${origins[status.origin] || status.origin})`
    : `OS CSPRNG only (${origins[status.origin] || status.origin})`;
  BB.$("#entropy-form").elements.entropy_source.value = status.entropy_source || "";
  entropyFormState.loaded(`Saved setting loaded · source: ${origins[status.origin] || status.origin}.`);
}

// -- Auditing ---------------------------------------------------------------------
const syslogFormState = trackPersistentForm(
  BB.$("#syslog-form"),
  BB.$("#syslog-form-state"),
  { loaded: "Saved syslog settings loaded." },
);

BB.$("#syslog-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const body = BB.formPayload(form, ["port", "facility"]);
  body.enabled = form.elements.enabled.checked;
  syslogFormState.saving("Saving syslog settings…");
  try {
    const result = await BB.api("/internal/audit/syslog", { method: "PUT", body: JSON.stringify(body) });
    await loadSyslogConfig();
    showDetails(result);
  } catch (error) {
    syslogFormState.failed(error);
    BB.showError(error);
  }
});

BB.$("#audit-verify").addEventListener("click", async () => {
  try {
    const result = await BB.api("/internal/audit/verify");
    BB.$("#audit-integrity").textContent = result.ok
      ? "✓ Audit chain integrity verified."
      : `✗ Audit chain verification failed at sequence ${result.first_bad_sequence}.`;
    showDetails(result);
  } catch (error) {
    BB.showError(error);
  }
});

async function loadSyslogConfig() {
  const config = await BB.api("/internal/audit/syslog");
  const form = BB.$("#syslog-form");
  form.elements.enabled.checked = Boolean(config.enabled);
  form.elements.host.value = config.host || "";
  form.elements.port.value = config.port ?? 514;
  form.elements.protocol.value = config.protocol || "udp";
  form.elements.facility.value = config.facility ?? 13;
  syslogFormState.loaded();
}

// -- CA management ------------------------------------------------------------------
async function loadCaView() {
  await refreshIssuer();
  await refreshRootCert();
  await loadServiceUrls();
  await loadOcsp();
}

const ocspFormState = trackPersistentForm(
  BB.$("#ocsp-form"),
  BB.$("#ocsp-form-state"),
  { loaded: "Saved OCSP settings loaded." },
);
const serviceUrlsFormState = trackPersistentForm(
  BB.$("#service-urls-form"),
  BB.$("#service-urls-form-state"),
  { loaded: "Saved service URLs loaded." },
);
let effectiveServiceUrls = { crl: "", aia: "" };

async function loadOcsp() {
  const data = await BB.api("/internal/admin/ocsp");
  const form = BB.$("#ocsp-form");
  form.elements.enabled.checked = Boolean(data.enabled);
  form.elements.responder_validity_days.value = data.responder_validity_days || 30;
  const bits = [`OCSP ${data.enabled ? "enabled" : "disabled"}`];
  if (data.responder_not_after) bits.push(`responder cert valid until ${data.responder_not_after}`);
  if (data.warning) bits.push(`⚠ ${data.warning}`);
  BB.$("#ocsp-status").textContent = bits.join(" · ");
  ocspFormState.loaded();
}

BB.$("#ocsp-refresh").addEventListener("click", () => loadOcsp().catch(BB.showError));

BB.$("#ocsp-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  ocspFormState.saving("Saving OCSP settings…");
  try {
    const payload = {
      enabled: form.elements.enabled.checked,
      responder_validity_days: Number(form.elements.responder_validity_days.value),
    };
    showDetails(await BB.api("/internal/admin/ocsp", { method: "PUT", body: JSON.stringify(payload) }));
    await loadOcsp();
  } catch (error) {
    ocspFormState.failed(error);
    BB.showError(error);
  }
});

BB.$("#ocsp-generate").addEventListener("click", async () => {
  try {
    showDetails(await BB.api("/internal/ocsp", { method: "POST" }));
    await loadOcsp();
  } catch (error) {
    BB.showError(error);
  }
});

async function loadServiceUrls() {
  const data = await BB.api("/internal/admin/service-urls");
  const suggested = data.suggested || {};
  const form = BB.$("#service-urls-form");
  for (const key of ["crl_base_url", "aia_base_url", "ocsp_url", "admin_base_url", "superuser_base_url"]) {
    // Pre-fill empty fields with the portal-derived suggestion; stored values win.
    form.elements[key].value = data[key] || suggested[key] || "";
  }
  const crlBase = (data.crl_base_url || suggested.crl_base_url || "").replace(/\/$/, "");
  effectiveServiceUrls.crl = crlBase ? `${crlBase}/crl/<issuer>.crl` : "";
  BB.$("#service-urls-crl-effective").textContent = crlBase
    ? `Effective CRL URL: ${effectiveServiceUrls.crl}`
    : "No CRL base URL set — certificates are issued without a CRL distribution point.";
  const aiaBase = (data.aia_base_url || suggested.aia_base_url || "").replace(/\/$/, "");
  effectiveServiceUrls.aia = aiaBase ? `${aiaBase}/aia/<issuer>.cer` : "";
  BB.$("#service-urls-aia-effective").textContent = aiaBase
    ? `Effective AIA (issuer cert) URL: ${effectiveServiceUrls.aia}`
    : "No AIA base URL set — certificates are issued without a caIssuers pointer.";
  BB.$("#service-urls-copy-crl").disabled = !effectiveServiceUrls.crl;
  BB.$("#service-urls-copy-aia").disabled = !effectiveServiceUrls.aia;

  const labels = {
    crl_base_url: "CRL",
    aia_base_url: "AIA",
    ocsp_url: "OCSP",
    admin_base_url: "Admin",
    superuser_base_url: "Certificate Operator",
  };
  const saved = Object.keys(labels).filter((key) => Boolean(data[key])).map((key) => labels[key]);
  const suggestedOnly = Object.keys(labels)
    .filter((key) => !data[key] && suggested[key])
    .map((key) => labels[key]);
  const sourceParts = [
    saved.length ? `Saved in application database: ${saved.join(", ")}.` : "No service URLs are saved yet.",
    suggestedOnly.length ? `Suggested from the portal host (not active until saved): ${suggestedOnly.join(", ")}.` : "",
    "Install-time environment values seed missing settings once; later portal edits win across restarts.",
  ];
  BB.$("#service-urls-source").textContent = sourceParts.filter(Boolean).join(" ");
  serviceUrlsFormState.loaded(
    suggestedOnly.length ? "Suggestions loaded. Save to activate them." : "Saved service URLs loaded.",
  );
}

BB.$("#service-urls-refresh").addEventListener("click", () => loadServiceUrls().catch(BB.showError));
BB.$("#service-urls-copy-crl").addEventListener("click", () => copyServiceUrl("crl"));
BB.$("#service-urls-copy-aia").addEventListener("click", () => copyServiceUrl("aia"));

async function copyServiceUrl(kind) {
  const value = effectiveServiceUrls[kind];
  if (!value) return;
  try {
    await copyText(value);
    BB.showResult({ status: `${kind.toUpperCase()} URL copied.`, url: value });
  } catch (error) {
    BB.showError(error);
  }
}

BB.$("#service-urls-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  // currentTarget is nulled once the handler yields — capture the form first.
  const form = event.currentTarget;
  serviceUrlsFormState.saving("Saving service URLs…");
  try {
    const result = await BB.api("/internal/admin/service-urls", {
      method: "PUT",
      body: JSON.stringify(BB.formPayload(form)),
    });
    await loadServiceUrls();
    showDetails(result);
  } catch (error) {
    serviceUrlsFormState.failed(error);
    BB.showError(error);
  }
});

BB.$("#refresh-issuer").addEventListener("click", () => refreshIssuer().catch(BB.showError));
BB.$("#root-cert-refresh").addEventListener("click", () => refreshRootCert().catch(BB.showError));

BB.$("#crl-button").addEventListener("click", async () => {
  try {
    showDetails(await BB.api("/internal/crls", { method: "POST" }));
    await refreshCrlStatus();
  } catch (error) {
    BB.showError(error);
  }
});

async function refreshCrlStatus() {
  const status = await BB.api("/internal/crls/status");
  BB.$("#crl-status").textContent = JSON.stringify(status, null, 2);
}

async function refreshIssuer() {
  const body = await BB.api("/internal/admin/issuer");
  await refreshCrlStatus();
  if (!body.configured) {
    BB.$("#issuer-status").textContent = "No issuer configured.";
  } else {
    const profileText = body.allowed_profiles?.length ? ` | allowed profiles: ${body.allowed_profiles.join(", ")}` : "";
    const validity = body.not_after ? ` | valid until ${body.not_after}` : "";
    const fingerprint = body.certificate_sha256 ? ` | SHA-256 ${body.certificate_sha256}` : "";
    BB.$("#issuer-status").textContent = `${body.source}: ${body.subject}${profileText}${validity}${fingerprint}`;
  }
  return body;
}

async function refreshRootCert() {
  const status = await BB.api("/internal/admin/root-certificate");
  BB.$("#root-cert-status").textContent = status.configured
    ? `${status.subject} (${status.source === "stored" ? "stored" : "lab chain"})`
      + (status.not_after ? ` | valid until ${status.not_after}` : "")
      + (status.certificate_sha256 ? ` | SHA-256 ${status.certificate_sha256}` : "")
    : "No root certificate stored — chain exports will stop at the sub-CA.";
}

// -- Holder portal --------------------------------------------------------------------
BB.$("#holder-portal-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    showDetails(await BB.api("/internal/admin/holder-portal", {
      method: "PUT",
      body: JSON.stringify({
        portal_base_url: form.elements.portal_base_url.value,
        download_receipts: form.elements.download_receipts.checked,
        mtls_base_url: form.elements.mtls_base_url.value,
        // blank = keep the stored secret (write-only field)
        mtls_proxy_secret: form.elements.mtls_proxy_secret.value || null,
        server_key_purge_days: Number(form.elements.server_key_purge_days.value),
      }),
    }));
    form.elements.mtls_proxy_secret.value = "";
    await refreshHolderPortal();
  } catch (error) {
    BB.showError(error);
  }
});

async function refreshHolderPortal() {
  const status = await BB.api("/internal/admin/holder-portal");
  const base = status.portal_base_url
    ? `Links are composed against ${status.portal_base_url}.`
    : "No base URL set — secure links cannot be emailed yet.";
  const mtls = status.mtls_proxy_secret_set && status.mtls_base_url
    ? " mTLS renewal endpoint configured."
    : " mTLS not configured — link renewals use email codes + Certificate Operator approval.";
  BB.$("#holder-portal-status").textContent = base + mtls;
  const form = BB.$("#holder-portal-form");
  form.elements.portal_base_url.value = status.portal_base_url || "";
  form.elements.mtls_base_url.value = status.mtls_base_url || "";
  form.elements.download_receipts.checked = Boolean(status.download_receipts);
  form.elements.server_key_purge_days.value = status.server_key_purge_days ?? 30;
}

// -- License --------------------------------------------------------------------------
let currentLicenseSummary = null;
BB.$("#license-refresh").addEventListener("click", () => refreshLicense().catch(BB.showError));
BB.$("#license-copy-installation").addEventListener("click", async () => {
  try {
    await copyText(BB.$("#license-installation-id").textContent);
    BB.showResult({ status: "Installation ID copied." });
  } catch (error) {
    BB.showError(error);
  }
});

BB.$("#license-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const summary = await BB.api("/internal/admin/license", {
      method: "PUT",
      body: JSON.stringify({ token: form.elements.token.value.trim() }),
    });
    BB.renderLicenseTier(summary);
    showDetails(summary);
    form.reset();
    await refreshLicense();
  } catch (error) {
    BB.showError(error);
  }
});

BB.$("#license-remove").addEventListener("click", async () => {
  try {
    const summary = currentLicenseSummary || await BB.api("/internal/admin/license");
    const overFree = Number(summary.active_lineages) > Number(summary.free_tier);
    if (overFree) {
      const entered = window.prompt(
        `Removing this license lowers capacity to ${summary.free_tier}. With ${summary.active_lineages} active certificate identities, new identities will be blocked until usage falls below the free limit; renewals remain available. Type REMOVE LICENSE to continue.`,
      );
      if (entered !== "REMOVE LICENSE") return;
    } else if (!window.confirm("Remove the commercial license and revert to Personal Licence – NOT for commercial use?")) return;
    const removed = await BB.api("/internal/admin/license", { method: "DELETE" });
    BB.renderLicenseTier(removed);
    showDetails(removed);
    await refreshLicense();
  } catch (error) {
    BB.showError(error);
  }
});

async function refreshLicense() {
  const summary = await BB.api("/internal/admin/license");
  currentLicenseSummary = summary;
  BB.renderLicenseTier(summary);
  BB.$("#license-installation-id").textContent = summary.installation_id || "unavailable";
  const used = `${summary.active_lineages} active / ${summary.lineage_limit} lineages`;
  const headlines = {
    valid: `Licensed to ${summary.licensed_to} — ${used}; expires ${summary.expires_at ? new Date(summary.expires_at).toLocaleDateString() : "?"} (${summary.days_remaining}d left).`,
    expired: `License expired — Personal Licence – NOT for commercial use applies to new certificate identities; renewals remain available. ${used}.`,
    not_yet_valid: `License not yet active — Personal Licence – NOT for commercial use is in effect. ${used}.`,
    invalid: `Stored license failed verification (${summary.verification_error || "tampered"}) — Personal Licence – NOT for commercial use is in effect.`,
    none: `Personal Licence – NOT for commercial use — ${used}. Upload an installation-bound commercial licence to raise the ceiling.`,
  };
  BB.$("#license-status").textContent = summary.key_configuration_error
    ? `License public-key configuration error: ${summary.key_configuration_error} Personal Licence – NOT for commercial use capacity applies. Restore a valid producer-signed application release.`
    : !summary.production_key_configured
      ? `This development build has no embedded licensing public keys. Personal Licence – NOT for commercial use capacity applies; install a producer-signed release to accept signed licenses. ${used}.`
      : headlines[summary.status] || headlines.none;
  const detail = BB.$("#license-detail");
  if (summary.status === "none") {
    detail.replaceChildren();
  } else {
    detail.replaceChildren();
    BB.renderTable(detail, [
      { field: "Licensed to", value: summary.licensed_to || "—" },
      { field: "License ID", value: summary.license_id || "—" },
      { field: "Signing key", value: summary.key_id || "—" },
      { field: "Token schema", value: summary.schema || "—" },
      { field: "Installation ID", value: summary.installation_id || "—" },
      { field: "Tier (max lineages)", value: summary.max_certificate_lineages ?? "—" },
      { field: "Capacity", value: used },
      { field: "Valid from", value: summary.valid_from ? new Date(summary.valid_from).toLocaleString() : "—" },
      { field: "Expires", value: summary.expires_at ? new Date(summary.expires_at).toLocaleString() : "—" },
      { field: "New issuance", value: summary.new_issuance_allowed ? "Allowed" : "Blocked" },
      { field: "Renewals", value: "Always allowed for existing certificate identities" },
      { field: "Status", value: summary.status },
    ], [
      { header: "Field", key: "field" },
      { header: "Value", key: "value" },
    ]);
  }
  BB.$("#license-remove").classList.toggle("hidden", summary.status === "none");
}

async function refreshLicenseTierIndicators() {
  BB.renderLicenseTier(await BB.api("/internal/admin/license"));
}

// -- Templates view -----------------------------------------------------------
function cloneForm(templateId) {
  const fragment = BB.$(templateId).content.cloneNode(true);
  return { fragment, form: fragment.querySelector("form") };
}

async function loadTemplates() {
  presets = await BB.api("/internal/templates/presets");
  templatesBar = BB.actionBar(BB.$("#templates-actionbar"), {
    emptyLabel: "Select a template, or create one",
    actions: [
      { label: "Create", variant: "accent", enabled: () => true, onClick: () => openTemplateModal(null, "create") },
      { label: "Clone", enabled: (s) => Boolean(s), onClick: (s) => openTemplateModal(s, "clone") },
      { label: "Edit", enabled: (s) => Boolean(s), onClick: (s) => openTemplateModal(s, "edit") },
      { label: "View", enabled: (s) => Boolean(s), onClick: (s) => openTemplateModal(s, "view") },
      { label: "Delete", variant: "danger", enabled: (s) => Boolean(s), onClick: (s) => deleteTemplate(s).catch(BB.showError) },
    ],
  });
  BB.$("#templates-refresh").addEventListener("click", () => refreshTemplates().catch(BB.showError));
  await refreshTemplates();
}

async function refreshTemplates() {
  templates = await BB.api("/internal/templates");
  renderTemplates();
}

function renderTemplates() {
  BB.renderTable(
    BB.$("#template-table"),
    templates,
    [
      { header: "Name", key: "name" },
      { header: "Certificate purpose", render: (row) => profileLabels[row.profile] || row.profile },
      { header: "Key operations", render: (row) => row.key_usages.map((value) => keyUsageLabels[value] || value).join(", ") },
      { header: "Application purposes", render: (row) => row.extended_key_usages.map((value) => extendedKeyUsageLabels[value] || value).join(", ") },
      { header: "Validity", render: (row) => `${row.validity_days}d` },
      { header: "Approvals", render: (row) => `${row.first_issuance_approvals}/${row.renewal_approvals}` },
    ],
    {
      selectable: true,
      emptyText: "No certificate templates yet. Create one to define an issuance policy.",
      tableLabel: "Certificate templates",
      onSelect: (row) => templatesBar && templatesBar.setSelection(row ? { ...row, label: row.name } : null),
    },
  );
}

// mode: "create" (POST, blank) | "clone" (POST, prefilled copy) | "edit" (PUT, id locked) | "view" (read-only)
function openTemplateModal(source, mode = "create") {
  const isView = mode === "view";
  const { fragment, form } = cloneForm("#tpl-template-form");
  const profile = fragment.querySelector("#template-profile");
  renderCheckboxes(fragment.querySelector("#key-usage-options"), "key_usages", supportedKeyUsages);
  renderCheckboxes(fragment.querySelector("#extended-key-usage-options"), "extended_key_usages", supportedExtendedKeyUsages);
  renderCheckboxes(fragment.querySelector("#allowed-key-algorithm-options"), "allowed_key_algorithms", supportedCertificateAlgorithms);

  if (!isView) profile.addEventListener("change", () => applyPresetIn(form, profile.value));

  if (source) {
    form.elements.name.value = mode === "clone" ? `${source.name} copy` : source.name;
    profile.value = source.profile;
    form.elements.validity_days.value = source.validity_days;
    form.elements.first_issuance_approvals.value = source.first_issuance_approvals;
    form.elements.renewal_approvals.value = source.renewal_approvals;
    setCheckedIn(form, "key_usages", source.key_usages);
    setCheckedIn(form, "extended_key_usages", source.extended_key_usages);
    setCheckedIn(form, "allowed_key_algorithms", source.allowed_key_algorithms);
    if (mode === "edit" || isView) {
      form.elements.id.value = source.id;
      form.elements.id.readOnly = true;
    } else {
      form.elements.id.value = "";
    }
  } else {
    applyPresetIn(form, profile.value);
    setCheckedIn(form, "allowed_key_algorithms", supportedCertificateAlgorithms);
  }

  const summary = form.querySelector("#template-summary");
  const profileSummary = form.querySelector("#template-profile-summary");
  const dirtyState = form.querySelector("#template-dirty-state");
  const firstApprovalHelp = form.querySelector("#template-first-approval-help");
  const renewalApprovalHelp = form.querySelector("#template-renewal-approval-help");
  const initialSnapshot = templateFormSnapshot(form);
  const updateGuidance = () => {
    profileSummary.textContent = profileDescriptions[profile.value] || "Review the selected certificate purpose.";
    summary.textContent = templatePolicySummary(form);
    firstApprovalHelp.textContent = templateApprovalHelp(Number(form.elements.first_issuance_approvals.value) || 0);
    renewalApprovalHelp.textContent = templateApprovalHelp(Number(form.elements.renewal_approvals.value) || 0, true);
    if (isView) {
      dirtyState.textContent = "This template is read-only.";
      dirtyState.classList.remove("is-dirty");
      return;
    }
    const changed = templateFormSnapshot(form) !== initialSnapshot;
    dirtyState.textContent = changed
      ? "Unsaved changes. Review the policy summary before saving."
      : mode === "edit" ? "No unsaved changes." : "Review the settings before saving.";
    dirtyState.classList.toggle("is-dirty", changed);
  };
  if (!isView) {
    form.addEventListener("input", updateGuidance);
    form.addEventListener("change", updateGuidance);
  }
  updateGuidance();

  if (isView) {
    form.querySelectorAll("input, select, textarea, button").forEach((control) => {
      control.disabled = true;
    });
    const saveButton = form.querySelector('button[type="submit"]');
    saveButton.remove();
  }

  const titles = { create: "Create template", clone: "Clone template", edit: "Edit template", view: "View template" };
  const dialog = BB.modal({ title: titles[mode], content: form });
  if (isView) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = BB.formPayload(form, ["validity_days", "first_issuance_approvals", "renewal_approvals"]);
    body.key_usages = BB.checkedValues(form, "key_usages");
    body.extended_key_usages = BB.checkedValues(form, "extended_key_usages");
    body.allowed_key_algorithms = BB.checkedValues(form, "allowed_key_algorithms");
    if (!body.allowed_key_algorithms.length) {
      BB.showError(new Error("Select at least one certificate key algorithm."));
      return;
    }
    const saveButton = form.querySelector('button[type="submit"]');
    saveButton.disabled = true;
    saveButton.textContent = "Saving…";
    form.setAttribute("aria-busy", "true");
    dirtyState.textContent = "Saving template…";
    try {
      if (mode === "edit") {
        delete body.id;
        showDetails(await BB.api(`/internal/templates/${encodeURIComponent(source.id)}`, { method: "PUT", body: JSON.stringify(body) }));
      } else {
        showDetails(await BB.api("/internal/templates", { method: "POST", body: JSON.stringify(body) }));
      }
      dialog.close();
      await refreshTemplates();
    } catch (error) {
      dirtyState.textContent = `Could not save: ${error.message}`;
      BB.showError(error);
    } finally {
      saveButton.disabled = false;
      saveButton.textContent = "Save template";
      form.setAttribute("aria-busy", "false");
    }
  });
}

async function deleteTemplate(template) {
  if (!window.confirm(`Delete template "${template.name}"? This fails if any request or certificate still references it.`)) return;
  showDetails(await BB.api(`/internal/templates/${encodeURIComponent(template.id)}`, { method: "DELETE" }));
  await refreshTemplates();
}

function renderCheckboxes(container, name, values) {
  const labels = name === "key_usages"
    ? keyUsageLabels
    : name === "extended_key_usages"
      ? extendedKeyUsageLabels
      : certificateAlgorithmLabels;
  container.replaceChildren(
    ...values.map((value) => {
      const label = document.createElement("label");
      label.className = "checkbox";
      const input = document.createElement("input");
      input.name = name;
      input.type = "checkbox";
      input.value = value;
      label.append(input, document.createTextNode(` ${labels[value] || value}`));
      return label;
    }),
  );
}

function templateFormSnapshot(form) {
  return JSON.stringify({
    id: form.elements.id.value,
    name: form.elements.name.value,
    profile: form.elements.profile.value,
    validity_days: form.elements.validity_days.value,
    first_issuance_approvals: form.elements.first_issuance_approvals.value,
    renewal_approvals: form.elements.renewal_approvals.value,
    key_usages: BB.checkedValues(form, "key_usages"),
    extended_key_usages: BB.checkedValues(form, "extended_key_usages"),
    allowed_key_algorithms: BB.checkedValues(form, "allowed_key_algorithms"),
  });
}

function templateApprovalHelp(count, isRenewal = false) {
  if (count === 0) {
    return isRenewal
      ? "Allows automatic renewal without Certificate Operator approval. Renewals authenticated only by an email code still require at least one approval."
      : "No Certificate Operator approval is required. Assigning a holder can trigger issuance, including when an administrator assigns it. Other issuance checks still apply.";
  }
  const requirement = count === 1
    ? "Requires one Certificate Operator approval."
    : `Requires ${count} approvals from different Certificate Operators.`;
  if (isRenewal) return requirement;
  return count === 1
    ? `${requirement} Create certificate records the creating operator’s approval automatically.`
    : `${requirement} Create certificate records the creating operator’s approval; ${count - 1} additional approval${count === 2 ? " is" : "s are"} needed.`;
}

function templatePolicySummary(form) {
  const name = form.elements.name.value.trim() || "This template";
  const validity = Number(form.elements.validity_days.value) || 0;
  const firstApprovals = Number(form.elements.first_issuance_approvals.value) || 0;
  const renewalApprovals = Number(form.elements.renewal_approvals.value) || 0;
  const operations = BB.checkedValues(form, "key_usages").map((value) => keyUsageLabels[value] || value);
  const purposes = BB.checkedValues(form, "extended_key_usages").map((value) => extendedKeyUsageLabels[value] || value);
  const algorithms = BB.checkedValues(form, "allowed_key_algorithms").map((value) => certificateAlgorithmLabels[value] || value);
  return `${name} issues ${profileLabels[form.elements.profile.value] || "certificate"} certificates for ${validity || "an unspecified number of"} days. ` +
    `First issuance requires ${firstApprovals} approval${firstApprovals === 1 ? "" : "s"}; renewal requires ${renewalApprovals}. ` +
    "Email-code renewals require at least one Certificate Operator approval. " +
    `Key operations: ${operations.join(", ") || "none selected"}. Application purposes: ${purposes.join(", ") || "none selected"}. ` +
    `Key algorithms: ${algorithms.join(", ") || "none selected"}.`;
}

function applyPresetIn(form, profileValue) {
  const preset = presets.find((candidate) => candidate.profile === profileValue);
  if (!preset) return;
  setCheckedIn(form, "key_usages", preset.key_usages);
  setCheckedIn(form, "extended_key_usages", preset.extended_key_usages);
}

function setCheckedIn(form, name, values) {
  const allowed = new Set(values);
  form.querySelectorAll(`input[name="${name}"]`).forEach((input) => {
    input.checked = allowed.has(input.value);
  });
}

// -- Account --------------------------------------------------------------------------
BB.$("#recovery-codes").addEventListener("click", async () => {
  if (!window.confirm("Generate a new set of recovery codes? This invalidates any previous codes.")) return;
  try {
    const body = await BB.api("/internal/auth/recovery/codes/regenerate", { method: "POST" });
    showDetails({ note: "Store these one-time recovery codes now — shown once.", recovery_codes: body.recovery_codes });
  } catch (error) {
    BB.showError(error);
  }
});

// -- Self-service certificate request config ----------------------------------
const accessRequestSave = document.getElementById("access-request-save");
if (accessRequestSave) {
  const enabledEl = document.getElementById("access-request-enabled");
  const domainsEl = document.getElementById("access-request-domains");
  const apply = (cfg) => {
    enabledEl.checked = Boolean(cfg.enabled);
    domainsEl.value = (cfg.allowed_domains || []).join("\n");
  };
  (async () => {
    try {
      apply(await BB.api("/internal/access-request/config"));
    } catch {
      /* leave defaults; surfaced on save */
    }
  })();
  accessRequestSave.addEventListener("click", async () => {
    try {
      const saved = await BB.api("/internal/access-request/config", {
        method: "PUT",
        body: JSON.stringify({ enabled: enabledEl.checked, allowed_domains: domainsEl.value }),
      });
      apply(saved);
      showDetails({ status: "Self-service request settings saved.", ...saved });
    } catch (e) {
      BB.showError(e);
    }
  });
}

// -- Branding appearance -------------------------------------------------------
function refreshBrandingPreview() {
  const img = document.getElementById("branding-preview");
  if (img) img.src = "/branding/logo?t=" + Date.now();
}

async function refreshThemeStylesheet() {
  const css = await fetch("/theme.css?t=" + Date.now(), { cache: "no-store" })
    .then((response) => response.text());
  let style = document.getElementById("theme-override-style");
  if (!style) {
    style = document.createElement("style");
    style.id = "theme-override-style";
    document.head.append(style);
  }
  style.textContent = css;
}

function applyThemeForm(theme) {
  const color = theme.accent_color || "#246b5b";
  const colorEl = document.getElementById("theme-color");
  const hexEl = document.getElementById("theme-color-hex");
  if (colorEl) colorEl.value = color;
  if (hexEl) hexEl.value = color;
}

async function refreshThemeForm() {
  const theme = await BB.api("/internal/branding/theme");
  applyThemeForm(theme);
  await refreshThemeStylesheet();
}

async function refreshAppearance() {
  refreshBrandingPreview();
  await refreshThemeForm();
}

const brandingUpload = document.getElementById("branding-upload");
if (brandingUpload) {
  const bust = () => { document.getElementById("branding-preview").src = "/branding/logo?t=" + Date.now(); };
  brandingUpload.addEventListener("click", async () => {
    const file = document.getElementById("branding-file").files[0];
    if (!file) { BB.showError(new Error("Choose an image first")); return; }
    try {
      const data_b64 = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result).split(",")[1]);
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
      await BB.api("/internal/branding/logo", {
        method: "POST",
        body: JSON.stringify({ content_type: file.type, data_b64 }),
      });
      bust();
    } catch (e) { BB.showError(e); }
  });
  document.getElementById("branding-reset").addEventListener("click", async () => {
    try { await BB.api("/internal/branding/logo", { method: "DELETE" }); bust(); }
    catch (e) { BB.showError(e); }
  });
}

const themeSave = document.getElementById("theme-save");
if (themeSave) {
  const colorEl = document.getElementById("theme-color");
  const hexEl = document.getElementById("theme-color-hex");
  const syncFromColor = () => { hexEl.value = colorEl.value; };
  const syncFromHex = () => {
    const raw = hexEl.value.trim();
    if (/^#?[0-9a-fA-F]{6}$/.test(raw)) colorEl.value = raw.startsWith("#") ? raw : `#${raw}`;
  };
  colorEl.addEventListener("input", syncFromColor);
  hexEl.addEventListener("input", syncFromHex);
  themeSave.addEventListener("click", async () => {
    try {
      const saved = await BB.api("/internal/branding/theme", {
        method: "PUT",
        body: JSON.stringify({ accent_color: hexEl.value }),
      });
      applyThemeForm(saved);
      await refreshThemeStylesheet();
      showDetails({ status: "Theme saved.", ...saved });
    } catch (e) { BB.showError(e); }
  });
  document.getElementById("theme-reset").addEventListener("click", async () => {
    try {
      const saved = await BB.api("/internal/branding/theme", { method: "DELETE" });
      applyThemeForm(saved);
      await refreshThemeStylesheet();
      showDetails({ status: "Theme reset.", ...saved });
    } catch (e) { BB.showError(e); }
  });
}

// -- Channels view (communication channels) -----------------------------------
let channelsWired = false;
async function loadChannels() {
  await NotificationScheduleControls.refresh(BB.$("#notification-schedule"));
  if (!channelsWired) {
    channelsWired = true;
    BB.$("#comms-refresh").addEventListener("click", () => refreshComms().catch(BB.showError));
    BB.$("#comms-configure").addEventListener("click", openCommsConfigModal);
    BB.$("#comms-send-test").addEventListener("click", openCommsSendModal);
  }
  await refreshComms();
}

async function refreshComms() {
  commsChannels = await BB.api("/internal/comms/channels");
  BB.renderTable(BB.$("#comms-table"), commsChannels, [
    { header: "Channel", key: "channel" },
    { header: "Enabled", render: (row) => (row.enabled ? "yes" : "no") },
    {
      header: "Secrets set",
      render: (row) => Object.entries(row.secrets_set || {}).map(([k, v]) => `${k}:${v ? "✓" : "✗"}`).join(" ") || "—",
    },
    { header: "Updated", render: (row) => (row.updated_at ? new Date(row.updated_at).toLocaleString() : "—") },
  ], {
    emptyText: "No notification integrations are configured. Choose Configure integration to add one.",
    tableLabel: "Notification and delivery integrations",
  });
}

const CHANNEL_FIELDS = {
  email: {
    config: [
      { name: "host", label: "SMTP host", type: "text", required: true },
      { name: "port", label: "Port", type: "number", placeholder: "587 (STARTTLS) / 465 (SSL)", required: true },
      { name: "security", label: "Security", type: "select", options: ["starttls", "ssl", "none"] },
      { name: "from_address", label: "From address", type: "email", placeholder: "ca@example.test", required: true },
      { name: "username", label: "Username", type: "text" },
    ],
    secrets: [{ name: "password", label: "Password" }],
  },
  sms: {
    config: [
      { name: "url", label: "SMS broker HTTPS URL", type: "url", placeholder: "https://sms.example.test/send", required: true },
      { name: "method", label: "HTTP method", type: "select", options: ["POST", "GET", "PUT"] },
      { name: "recipient_param", label: "Phone number parameter", type: "text", placeholder: "to" },
      { name: "message_param", label: "Message text parameter", type: "text", placeholder: "message" },
      { name: "extra_params", label: "Extra parameters (one name=value per line; use {password} for the secret below)", type: "params", placeholder: "user=myaccount\npass={password}\nfrom=MyCompany" },
      { name: "headers", label: "HTTP headers (one Name: value per line — not broker parameters)", type: "headers" },
      { name: "body_template", label: "JSON body template (advanced — overrides the two parameters above)", type: "textarea", placeholder: '{"to":"{recipient}","message":"{body}"}' },
    ],
    secrets: [
      { name: "bearer_token", label: "Bearer token" },
      { name: "password", label: "Broker password (referenced as {password})" },
    ],
  },
  slack: { config: [], secrets: [{ name: "bot_token", label: "Bot token" }] },
  webhook: {
    config: [{ name: "url", label: "Webhook URL", type: "url", placeholder: "https://…", required: true }],
    secrets: [{ name: "signing_secret", label: "Signing secret" }],
  },
  https: {
    config: [
      { name: "url", label: "URL", type: "url", placeholder: "https://…", required: true },
      { name: "method", label: "Method", type: "select", options: ["POST", "GET", "PUT"] },
      { name: "headers", label: "Headers (one Name: value per line)", type: "headers" },
      { name: "body_template", label: "Body template", type: "textarea" },
    ],
    secrets: [{ name: "bearer_token", label: "Bearer token" }],
  },
};

function _headersToText(map) {
  return Object.entries(map || {}).map(([k, v]) => `${k}: ${v}`).join("\n");
}

// Per-channel setup help. These exist because both traps cost real time: broker
// request fields typed into the headers box (which silently dropped them), and a
// Slack bot token missing a scope, which fails one call at a time.
const CHANNEL_HELP = {
  sms: [
    { id: "tpl-sms-params-help", title: "SMS broker parameters", link: "How do I set the broker's parameters?" },
    { id: "tpl-sms-headers-help", title: "HTTP headers and secrets", link: "How do I send a secret in a header?" },
  ],
  slack: [
    { id: "tpl-slack-scopes-help", title: "Slack bot token scopes", link: "Which Slack scopes does the bot token need?" },
  ],
};

function renderChannelHelp(container, kind) {
  container.textContent = "";
  const topics = CHANNEL_HELP[kind] || [];
  topics.forEach((topic, index) => {
    if (index) container.append(document.createTextNode(" · "));
    const link = document.createElement("a");
    link.href = "#";
    link.textContent = topic.link;
    link.addEventListener("click", (event) => {
      event.preventDefault();
      BB.modal({
        title: topic.title,
        content: BB.$(`#${topic.id}`).content.cloneNode(true),
      });
    });
    container.append(link);
  });
  container.classList.toggle("hidden", topics.length === 0);
}

function _paramsToText(map) {
  return Object.entries(map || {}).map(([k, v]) => `${k}=${v}`).join("\n");
}

function _textToParams(text) {
  const out = {};
  for (const line of (text || "").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const i = trimmed.indexOf("=");
    if (i <= 0) {
      throw new Error(
        `Each extra parameter must be written as name=value. This line is not: "${trimmed}"`,
      );
    }
    out[trimmed.slice(0, i).trim()] = trimmed.slice(i + 1).trim();
  }
  return out;
}

function _textToHeaders(text) {
  const out = {};
  for (const line of (text || "").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const i = trimmed.indexOf(":");
    if (i === -1) continue;
    out[trimmed.slice(0, i).trim()] = trimmed.slice(i + 1).trim();
  }
  return out;
}

function renderChannelFields(container, kind, current) {
  container.textContent = "";
  const schema = CHANNEL_FIELDS[kind] || { config: [], secrets: [] };
  const config = (current && current.config) || {};
  const secretsSet = (current && current.secrets_set) || {};
  for (const field of schema.config) {
    const label = document.createElement("label");
    label.textContent = field.label + " ";
    let input;
    if (field.type === "select") {
      input = document.createElement("select");
      for (const opt of field.options) {
        const option = document.createElement("option");
        option.value = opt;
        option.textContent = opt;
        input.append(option);
      }
      input.value = config[field.name] != null ? String(config[field.name]) : field.options[0];
    } else if (field.type === "textarea" || field.type === "headers" || field.type === "params") {
      input = document.createElement("textarea");
      input.rows = 4;
      if (field.placeholder) input.placeholder = field.placeholder;
      if (field.type === "headers") {
        input.value = _headersToText(config[field.name]);
      } else if (field.type === "params") {
        input.value = _paramsToText(config[field.name]);
      } else {
        input.value = config[field.name] != null ? String(config[field.name]) : "";
      }
    } else {
      input = document.createElement("input");
      input.type = ["number", "url", "email"].includes(field.type) ? field.type : "text";
      if (field.placeholder) input.placeholder = field.placeholder;
      input.value = config[field.name] != null ? String(config[field.name]) : "";
    }
    if (field.required) input.dataset.requiredWhenEnabled = "true";
    input.name = `config.${field.name}`;
    input.dataset.cfg = field.name;
    input.dataset.cfgtype = field.type;
    label.append(input);
    container.append(label);
  }
  for (const secret of schema.secrets) {
    const label = document.createElement("label");
    const isSet = Boolean(secretsSet[secret.name]);
    label.textContent = `${secret.label} (${isSet ? "currently set ✓ — leave blank to keep" : "not set ✗"}) `;
    const input = document.createElement("input");
    input.type = "password";
    input.autocomplete = "new-password";
    input.name = `secret.${secret.name}`;
    input.dataset.secret = secret.name;
    label.append(input);
    container.append(label);
  }
}

function collectChannelPayload(container) {
  const config = {};
  container.querySelectorAll("[data-cfg]").forEach((el) => {
    const name = el.dataset.cfg;
    const type = el.dataset.cfgtype;
    if (type === "headers") {
      const headers = _textToHeaders(el.value);
      if (Object.keys(headers).length) config[name] = headers;
      return;
    }
    if (type === "params") {
      const params = _textToParams(el.value);
      if (Object.keys(params).length) config[name] = params;
      return;
    }
    const raw = el.value.trim();
    if (raw === "") return;
    config[name] = type === "number" ? Number(raw) : raw;
  });
  const secrets = {};
  container.querySelectorAll("[data-secret]").forEach((el) => {
    if (el.value !== "") secrets[el.dataset.secret] = el.value;
  });
  return { config, secrets };
}

function openCommsConfigModal() {
  const { fragment, form } = cloneForm("#tpl-comms-config-form");
  const channelSelect = fragment.querySelector("#comms-config-channel");
  const fieldsContainer = fragment.querySelector("#comms-config-fields");
  const helpContainer = fragment.querySelector("#comms-config-help");
  const configState = trackPersistentForm(form, fragment.querySelector("#comms-config-state"), {
    loaded: "Saved integration settings loaded.",
  });
  const updateRequiredState = () => {
    fieldsContainer.querySelectorAll('[data-required-when-enabled="true"]').forEach((input) => {
      input.required = form.elements.enabled.checked;
    });
  };
  const currentFor = (kind) => commsChannels.find((row) => row.channel === kind);
  const prefill = () => {
    const current = currentFor(channelSelect.value);
    renderChannelFields(fieldsContainer, channelSelect.value, current);
    renderChannelHelp(helpContainer, channelSelect.value);
    form.elements.enabled.checked = Boolean(current && current.enabled);
    updateRequiredState();
    configState.loaded(current ? "Saved integration settings loaded." : "No saved integration yet. Review settings before saving.");
  };
  channelSelect.addEventListener("change", prefill);
  form.elements.enabled.addEventListener("change", updateRequiredState);
  prefill();
  const dialog = BB.modal({ title: "Configure notification integration", content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const channel = channelSelect.value;
    configState.saving("Saving integration settings…");
    try {
      // Inside the try: collecting can reject a malformed parameter line, and
      // that message must reach the operator rather than escaping unhandled.
      const { config, secrets } = collectChannelPayload(fieldsContainer);
      showDetails(
        await BB.api(`/internal/comms/channels/${channel}`, {
          method: "PUT",
          body: JSON.stringify({ enabled: form.elements.enabled.checked, config, secrets }),
        }),
      );
      dialog.close();
      await refreshComms();
    } catch (error) {
      configState.failed(error);
      BB.showError(error);
    }
  });
}

function openCommsSendModal() {
  const { form } = cloneForm("#tpl-comms-send-form");
  const state = form.querySelector("#comms-test-state");
  const submit = form.querySelector('button[type="submit"]');
  const dialog = BB.modal({ title: "Send test notification", content: form });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    submit.textContent = "Sending test…";
    form.setAttribute("aria-busy", "true");
    state.textContent = "Sending test notification…";
    state.classList.remove("is-error");
    try {
      const result = await BB.api("/internal/comms/test", { method: "POST", body: JSON.stringify(BB.formPayload(form)) });
      if (!result.success) {
        const detail = result.detail || "The destination rejected the test notification.";
        state.textContent = `Test failed: ${detail}`;
        state.classList.add("is-error");
        BB.showResult({ error: detail, ...result }, { kind: "error", title: "Notification test failed" });
        return;
      }
      showDetails({ status: "Test notification delivered successfully.", ...result });
      dialog.close();
    } catch (error) {
      state.textContent = `Test failed: ${error?.message || String(error)}`;
      state.classList.add("is-error");
      BB.showError(error);
    } finally {
      submit.disabled = false;
      submit.textContent = "Send test";
      form.setAttribute("aria-busy", "false");
    }
  });
}
