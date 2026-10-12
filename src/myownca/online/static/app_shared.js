const myOwnCA = (() => {
  let csrfToken = null;
  let currentUser = null;
  let licenseIdentityRevision = 0;
  let modalCounter = 0;
  let activeToastClose = null;
  let firstLoginGuideDialog = null;
  let firstLoginGuideOpening = false;
  let firstLoginGuideForceRequested = false;
  const pendingNavSources = new WeakMap();
  const dashboardMutedAlertIds = new Set();

  const TOAST_DURATION_MS = 10_000;

  const $ = (selector) => document.querySelector(selector);

  function text(value) {
    return value === null || value === undefined || value === "" ? "—" : String(value);
  }

  function formPayload(form, numericFields = []) {
    const data = Object.fromEntries(new FormData(form).entries());
    for (const field of numericFields) {
      if (field in data) data[field] = Number(data[field]);
    }
    return data;
  }

  function splitCommaList(value) {
    return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
  }

  function syncProfileSanFields(form, profile, { enabled = true } = {}) {
    const dnsInput = form.elements.dns_names;
    const emailInput = form.elements.email_addresses;
    const dnsAllowed = profile !== "smime";
    const emailAllowed = profile !== "host_tls";
    const dnsField = form.querySelector(".dns-san-field");
    const emailField = form.querySelector(".email-san-field");
    if (dnsField) dnsField.classList.toggle("hidden", !dnsAllowed);
    if (emailField) emailField.classList.toggle("hidden", !emailAllowed);
    if (dnsInput) {
      if (!dnsAllowed) dnsInput.value = "";
      dnsInput.disabled = !enabled || !dnsAllowed;
      dnsInput.required = enabled && profile === "host_tls";
    }
    if (emailInput) {
      if (!emailAllowed) emailInput.value = "";
      emailInput.disabled = !enabled || !emailAllowed;
      emailInput.required = enabled && profile === "smime";
    }
  }

  function profileSanPayload(form, profile) {
    return {
      dns_names: profile === "smime" ? [] : splitCommaList(form.elements.dns_names?.value),
      email_addresses: profile === "host_tls"
        ? []
        : splitCommaList(form.elements.email_addresses?.value),
    };
  }

  function checkedValues(form, name) {
    return [...form.querySelectorAll(`input[name="${name}"]:checked`)].map((input) => input.value);
  }

  function apiErrorMessage(body, response) {
    const fallback = `Request failed with ${response.status} ${response.statusText}`;
    const detail = body?.detail ?? body?.error ?? body?.message;
    if (!detail) return fallback;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map((item) => {
        const location = Array.isArray(item?.loc) ? `${item.loc.join(".")}: ` : "";
        return `${location}${item?.msg || JSON.stringify(item)}`;
      }).join("; ");
    }
    if (typeof detail === "object" && typeof detail.message === "string") {
      return detail.message;
    }
    return JSON.stringify(detail);
  }

  function syncCopyrightRange() {
    const firstYear = 2026;
    const currentYear = Math.max(firstYear, new Date().getFullYear());
    const range = currentYear === firstYear ? String(firstYear) : `${firstYear}–${currentYear}`;
    document.querySelectorAll("[data-copyright-range]").forEach((target) => {
      target.textContent = range;
    });
  }

  // -- HSM busy indicator -----------------------------------------------------
  // Hardware tokens are slow: an RSA-4096 keygen or a signing operation on a
  // SmartCard-HSM can take many seconds, during which the portal looked idle and
  // invited a second click. These are the routes that can reach the signing
  // backend, derived from the call graph of create_app and kept honest by
  // tests/test_hsm_busy_routes.py -- add a route that touches the HSM and that
  // test fails until it is listed here.
  const HSM_BUSY_ROUTES = [
    ["POST", "/internal/admin/hsm/token-backup/proposals/[^/]+/approve"],
    ["GET", "/internal/admin/ocsp"],
    ["PUT", "/internal/admin/ocsp"],
    ["POST", "/internal/certificate-requests/[^/]+/approvals"],
    ["POST", "/internal/certificate-requests/[^/]+/holder"],
    ["POST", "/internal/ca-certificates/send"],
    ["POST", "/internal/certificates/[^/]+/send-pkcs12"],
    ["POST", "/internal/certificates/import"],
    ["POST", "/internal/certificates/import/analyze"],
    ["POST", "/internal/claim/[^/]+/renew"],
    ["POST", "/internal/cloud/keys/[^/]+/reattach"],
    ["POST", "/internal/cloud/keys/[^/]+/recover"],
    ["GET", "/internal/cloud/signing-status"],
    ["POST", "/internal/crls"],
    ["GET", "/internal/crls/latest"],
    ["POST", "/internal/hsm/dkek/shares/[^/]+/import"],
    ["GET", "/internal/hsm/dkek/status"],
    ["GET", "/internal/hsm/keys"],
    ["POST", "/internal/hsm/keys"],
    ["POST", "/internal/hsm/keys/wrapped-backup"],
    ["DELETE", "/internal/hsm/keys/[^/]+"],
    ["POST", "/internal/hsm/pin/unlock"],
    ["GET", "/internal/hsm/status"],
    ["POST", "/internal/hsm/test"],
    ["POST", "/internal/hsm/token-backup/export-proposals"],
    ["POST", "/internal/ocsp"],
    ["POST", "/internal/service-certs/acme/orders"],
    ["POST", "/internal/service-certs/csr"],
    ["POST", "/internal/service-certs/[^/]+/renew"],
  ].map(([method, pattern]) => [method, new RegExp(`^${pattern}$`)]);

  // Long enough that a software backend or a cached read never flashes the
  // overlay, short enough that a real token wait is announced before the user
  // wonders whether the click registered.
  const HSM_BUSY_DELAY_MS = 350;

  // A token that never answers -- card pulled, reader wedged, driver hung -- must
  // not strand the operator behind a permanent overlay. Cancelling the request
  // frees the portal, but it does NOT stop the server: the operation may still
  // complete, so the message must not imply that nothing happened.
  // 120s, not 30s: RSA-4096 key generation on a SmartCard-HSM and a native token
  // backup can legitimately run past half a minute, and cutting those off would
  // report a failure for work that is proceeding normally. This bound is only
  // here to catch a token that is not answering at all.
  const HSM_TIMEOUT_MS = 120000;
  // Derived from the constant so the two can never disagree.
  const HSM_TIMEOUT_MESSAGE =
    `No response from the HSM after ${Math.round(HSM_TIMEOUT_MS / 1000)} seconds, ` +
    "so the request was cancelled. Check the token and reader. The operation may " +
    "still have completed on the server \u2014 refresh and check before retrying, " +
    "so you do not repeat it.";

  let hsmBusyDepth = 0;
  let hsmBusyTimer = null;
  let hsmBusyNode = null;

  window.addEventListener("unhandledrejection", (event) => {
    // Scoped to HSM timeouts only: every other rejection keeps its existing
    // handling. This fires solely when no call site caught it.
    if (event.reason && event.reason.hsmTimeout) {
      showError(event.reason);
      event.preventDefault();
    }
  });

  function isHsmRoute(path, method) {
    const verb = (method || "GET").toUpperCase();
    const clean = String(path).split("?")[0];
    return HSM_BUSY_ROUTES.some(([routeMethod, pattern]) =>
      routeMethod === verb && pattern.test(clean));
  }

  function swallowKeys(event) {
    // The overlay stops pointer input; this stops keyboard input reaching the
    // controls underneath it.
    event.preventDefault();
    event.stopPropagation();
  }

  function showHsmBusy() {
    if (hsmBusyNode) return;
    const overlay = document.createElement("div");
    overlay.className = "busy-overlay";
    overlay.setAttribute("role", "alert");
    overlay.setAttribute("aria-live", "assertive");
    overlay.setAttribute("aria-busy", "true");
    const card = document.createElement("div");
    card.className = "busy-card";
    const spinner = document.createElement("div");
    spinner.className = "busy-spinner";
    spinner.setAttribute("aria-hidden", "true");
    const label = document.createElement("p");
    label.className = "busy-label";
    label.textContent = "Waiting for HSM response\u2026";
    const hint = document.createElement("p");
    hint.className = "busy-hint";
    hint.textContent = "Hardware tokens can take a few seconds. Do not remove the card.";
    card.append(spinner, label, hint);
    overlay.append(card);
    document.body.append(overlay);
    document.addEventListener("keydown", swallowKeys, true);
    hsmBusyNode = overlay;
  }

  function hideHsmBusy() {
    if (hsmBusyTimer) {
      clearTimeout(hsmBusyTimer);
      hsmBusyTimer = null;
    }
    if (!hsmBusyNode) return;
    document.removeEventListener("keydown", swallowKeys, true);
    hsmBusyNode.remove();
    hsmBusyNode = null;
  }

  function beginHsmBusy() {
    hsmBusyDepth += 1;
    if (hsmBusyDepth === 1 && !hsmBusyTimer && !hsmBusyNode) {
      hsmBusyTimer = setTimeout(() => {
        hsmBusyTimer = null;
        if (hsmBusyDepth > 0) showHsmBusy();
      }, HSM_BUSY_DELAY_MS);
    }
  }

  function endHsmBusy() {
    // Concurrent HSM calls share one overlay; it lifts when the last completes.
    hsmBusyDepth = Math.max(0, hsmBusyDepth - 1);
    if (hsmBusyDepth === 0) hideHsmBusy();
  }

  async function api(path, options = {}) {
    if (!isHsmRoute(path, options.method)) return apiRequest(path, options);
    return withHsmGuards(options, (guarded) => apiRequest(path, guarded));
  }

  async function withHsmGuards(options, run) {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, HSM_TIMEOUT_MS);
    beginHsmBusy();
    try {
      return await run({ ...options, signal: controller.signal });
    } catch (error) {
      // An aborted fetch reports "The user aborted a request", which tells the
      // operator nothing. Replace it with what actually happened.
      if (timedOut) {
        const timeout = new Error(HSM_TIMEOUT_MESSAGE);
        timeout.hsmTimeout = true;
        throw timeout;
      }
      throw error;
    } finally {
      clearTimeout(timer);
      endHsmBusy();
    }
  }

  async function apiRequest(path, options = {}) {
    const response = await fetch(path, {
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
        ...(options.headers || {}),
      },
      ...options,
    });
    const text = response.status === 204 ? "" : await response.text();
    let body = null;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        // Non-JSON response (e.g. an nginx 502/504 error page, or an empty body).
        // Surface the status + a snippet so the real failure is legible instead of
        // a "JSON.parse: unexpected character" riddle.
        const snippet = text.trim().slice(0, 300);
        throw new Error(
          response.ok
            ? `Unexpected non-JSON response (${response.status}): ${snippet}`
            : `Request failed with ${response.status} ${response.statusText} — ${snippet}`,
        );
      }
    }
    if (!response.ok) {
      throw new Error(apiErrorMessage(body, response));
    }
    return body;
  }

  async function init(requiredRole) {
    currentUser = await api("/internal/auth/me");
    csrfToken = currentUser.csrf_token;
    syncCopyrightRange();
    const identity = $("#identity");
    if (identity) identity.textContent = `${currentUser.email} (${roleLabel(currentUser.role)})`;
    document.querySelectorAll("[data-app-version]").forEach((target) => {
      target.textContent = `Version ${currentUser.app_version}`;
    });
    if (requiredRole && currentUser.role !== requiredRole) {
      window.location.assign("/app");
    }
    const logout = $("#logout");
    if (logout) {
      logout.addEventListener("click", async () => {
        await api("/internal/auth/logout", { method: "POST" });
        window.location.assign("/login");
      });
    }
    const gettingStarted = $("#getting-started");
    if (gettingStarted) {
      gettingStarted.addEventListener("click", (event) => {
        event.preventDefault();
        openFirstLoginGuide({ force: true }).catch(showError);
      });
    }
    const sideNav = $(".side-nav");
    if (sideNav) {
      sideNav.addEventListener("click", (event) => {
        const link = event.target.closest("a");
        if (!link || !sideNav.contains(link) || link === gettingStarted) return;
        refreshGettingStartedNavigation().catch(showError);
      });
    }
    if (["admin", "superuser"].includes(currentUser.role)) {
      window.setTimeout(() => {
        openFirstLoginGuide().catch(showError);
      }, 0);
    }
    if (currentUser.stage === "active") refreshLicenseIdentity();
    return currentUser;
  }

  function formatOutput(value) {
    if (typeof value === "string") return value;
    if (value && typeof value === "object" && typeof value.crl_pem === "string") {
      const { crl_pem: pem, ...metadata } = value;
      const metadataText = Object.keys(metadata).length
        ? `${JSON.stringify(metadata, null, 2)}\n\n`
        : "";
      return `${metadataText}${pem}`;
    }
    return JSON.stringify(value, null, 2);
  }

  function setOutput(value) {
    const output = $("#output");
    if (output) output.textContent = formatOutput(value);
  }

  function showError(error) {
    setOutput({ error: error.message });
  }

  function resultSummary(value) {
    if (typeof value === "string") return value;
    if (!value || typeof value !== "object") return "Action completed.";
    if (value.error) return text(value.error);
    if (value.success === false || value.ok === false) {
      return text(value.detail || value.message || "The action did not succeed.");
    }
    if (value.success) return text(value.success);
    if (value.status) return text(value.status);
    if (value.note) return text(value.note);
    if (value.message) return text(value.message);
    return "Action completed.";
  }

  function resultTitle(value, kind = null) {
    const failed = value && typeof value === "object"
      && (value.error || value.success === false || value.ok === false);
    if (kind === "error" || failed) return "Action failed";
    return "Action result";
  }

  function licenseTierDisplay(summary) {
    if (!summary || typeof summary !== "object") {
      return { label: "Licence status unavailable", tone: "status-unknown" };
    }
    return summary.status === "valid"
      ? { label: "Commercial Licence", tone: "status-pass" }
      : { label: "Personal Licence – NOT for commercial use", tone: "status-warn" };
  }

  function renderLicenseTier(summary, root = document) {
    const display = licenseTierDisplay(summary);
    root.querySelectorAll("[data-license-tier]").forEach((target) => {
      target.classList.remove("status-pass", "status-warn", "status-unknown");
      target.classList.add(display.tone);
      target.textContent = display.label;
    });
    renderLicenseIdentity(summary && {
      licensed_to: summary.licensed_to,
      status: summary.status,
      verification_warning: Boolean(summary.verification_error),
    }, root);
    return display;
  }

  function renderLicenseIdentity(identity, root = document) {
    licenseIdentityRevision += 1;
    const hasName = ["valid", "expired", "not_yet_valid"].includes(identity?.status)
      && typeof identity?.licensed_to === "string" && identity.licensed_to.length > 0;
    const unavailable = !identity || identity.verification_warning
      || (!hasName && identity.status !== "none");
    root.querySelectorAll("[data-license-identity]").forEach((target) => {
      target.replaceChildren();
      target.hidden = !hasName && !unavailable;
      const append = (tag, className, value) => {
        const element = document.createElement(tag);
        element.className = className;
        element.textContent = value;
        target.append(element);
      };
      if (hasName) {
        append("span", "license-identity-label", "Licensed to");
        append("strong", "license-identity-name", identity.licensed_to);
        if (identity.status === "expired") {
          append("span", "license-identity-status", "Licence expired");
        } else if (identity.status === "not_yet_valid") {
          append("span", "license-identity-status", "Licence not yet active");
        }
      }
      if (unavailable) {
        append("span", "license-identity-status", "Licence details unavailable");
      }
    });
  }

  async function refreshLicenseIdentity() {
    const revision = licenseIdentityRevision;
    let identity = null;
    try {
      identity = await api("/internal/license/identity");
    } catch {
      // Identity display must not prevent the portal from initializing.
    }
    // A licence-management response may already have supplied fresher state.
    if (revision === licenseIdentityRevision) renderLicenseIdentity(identity);
  }

  function setNavPending(viewId, pending, source = "default") {
    const link = [...document.querySelectorAll(".side-nav a[data-view]")]
      .find((candidate) => candidate.dataset.view === viewId);
    if (!link) return;

    const sources = pendingNavSources.get(link) || new Set();
    if (pending) sources.add(source);
    else sources.delete(source);
    pendingNavSources.set(link, sources);

    const active = sources.size > 0;
    link.classList.toggle("has-pending-action", active);
    let indicator = link.querySelector(".nav-pending-indicator");
    if (active && !indicator) {
      indicator = document.createElement("span");
      indicator.className = "nav-pending-indicator hidden";
      indicator.textContent = "!";
      indicator.setAttribute("aria-label", "Action needed");
      link.append(indicator);
    }
    if (indicator) indicator.classList.toggle("hidden", !active);
  }

  function replaceDashboardAlertMutes(response) {
    const ids = response?.muted_alert_ids;
    if (!Array.isArray(ids)) throw new Error("Dashboard alert mute state was not returned by the server.");
    dashboardMutedAlertIds.clear();
    ids.forEach((id) => dashboardMutedAlertIds.add(String(id)));
    return new Set(dashboardMutedAlertIds);
  }

  async function loadDashboardAlertMutes() {
    return replaceDashboardAlertMutes(await api("/internal/dashboard-alert-mutes"));
  }

  async function setDashboardAlertMuted(alertId, muted) {
    const id = String(alertId || "");
    if (!id) throw new Error("Dashboard alert id is required.");
    return replaceDashboardAlertMutes(await api(
      `/internal/dashboard-alert-mutes/${encodeURIComponent(id)}`,
      { method: "PUT", body: JSON.stringify({ muted: Boolean(muted) }) },
    ));
  }

  function isDashboardAlertMuted(alertId) {
    return dashboardMutedAlertIds.has(String(alertId || ""));
  }

  function showResultDetails(value, { title = "Action details" } = {}) {
    const pre = document.createElement("pre");
    pre.className = "result-details";
    pre.textContent = formatOutput(value);
    return modal({ title, content: pre });
  }

  function showResult(value, { kind = null, title = null } = {}) {
    setOutput(value);
    const existing = $(".result-toast");
    if (activeToastClose) activeToastClose();
    else if (existing) existing.remove();

    const toast = document.createElement("section");
    const failed = value && typeof value === "object"
      && (value.error || value.success === false || value.ok === false);
    const severity = kind || (failed ? "error" : "success");
    toast.className = `result-toast ${severity === "error" ? "is-error" : "is-success"}`;
    toast.setAttribute("role", severity === "error" ? "alert" : "status");
    toast.setAttribute("aria-live", severity === "error" ? "assertive" : "polite");
    toast.style.setProperty("--toast-duration", `${TOAST_DURATION_MS}ms`);

    const progress = document.createElement("div");
    progress.className = "result-toast-progress";
    progress.setAttribute("aria-hidden", "true");

    const heading = document.createElement("h2");
    heading.textContent = title || resultTitle(value, kind);
    const body = document.createElement("p");
    body.textContent = resultSummary(value);

    const actions = document.createElement("div");
    actions.className = "result-toast-actions";
    const detailsButton = actionButton("Details", () => showResultDetails(value, { title: title || "Action details" }), "secondary");
    let removalTimer = null;
    const close = () => {
      window.clearTimeout(removalTimer);
      toast.remove();
      if (activeToastClose === close) activeToastClose = null;
    };
    const closeButton = actionButton("Close", close, "secondary");
    actions.append(detailsButton, closeButton);

    toast.append(progress, heading, body, actions);
    document.body.append(toast);
    activeToastClose = close;
    removalTimer = window.setTimeout(close, TOAST_DURATION_MS);
    return { close, toast };
  }

  function fillSelect(select, rows, { value = "id", label = "name", placeholder = null } = {}) {
    select.replaceChildren();
    if (placeholder) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = placeholder;
      select.append(option);
    }
    for (const row of rows) {
      const option = document.createElement("option");
      option.value = row[value];
      option.textContent = typeof label === "function" ? label(row) : row[label];
      select.append(option);
    }
  }

  // The 4th argument accepts either a plain emptyText string (legacy callers) or
  // an options bag: { emptyText, selectable, onSelect }. When selectable, clicking
  // a row toggles single-selection and invokes onSelect(row | null).
  function renderTable(container, rows, columns, options = {}) {
    const opts = typeof options === "string" ? { emptyText: options } : options || {};
    const {
      emptyText = "Nothing to show yet.",
      selectable = false,
      onSelect = null,
      tableLabel = "Data table",
      sortable = true,
    } = opts;
    container.replaceChildren();
    if (!rows.length) {
      const p = document.createElement("p");
      p.textContent = emptyText;
      container.append(p);
      if (selectable && onSelect) onSelect(null);
      return;
    }
    const table = document.createElement("table");
    if (selectable) table.classList.add("selectable");
    const thead = document.createElement("thead");
    const headerRow = document.createElement("tr");
    const tbody = document.createElement("tbody");
    let selectedRow = null;
    let sortColumn = null;
    let sortDirection = "ascending";

    const sortValue = (column, row) => {
      if (typeof column.sortValue === "function") return column.sortValue(row);
      if (typeof column.sortKey === "function") return column.sortKey(row);
      return row[column.sortKey || column.key];
    };

    const compareValues = (left, right) => {
      if (left === right) return 0;
      if (left === null || left === undefined || left === "") return 1;
      if (right === null || right === undefined || right === "") return -1;
      if (typeof left === "number" && typeof right === "number") return left - right;
      return String(left).localeCompare(String(right), undefined, { numeric: true, sensitivity: "base" });
    };

    const renderRows = (displayRows) => {
      tbody.replaceChildren();
      selectedRow = null;
      if (selectable && onSelect) onSelect(null);
      for (const row of displayRows) {
        const tr = document.createElement("tr");
        for (const column of columns) {
          const td = document.createElement("td");
          const rendered = column.render ? column.render(row) : text(row[column.key]);
          if (rendered instanceof Node) td.append(rendered);
          else td.textContent = text(rendered);
          tr.append(td);
        }
        if (selectable) {
          tr.classList.add("data-row");
          tr.tabIndex = 0;
          tr.setAttribute("aria-selected", "false");
          const toggle = () => {
            const deselect = selectedRow === row;
            for (const sibling of tbody.children) {
              sibling.classList.remove("is-selected");
              sibling.setAttribute("aria-selected", "false");
            }
            if (deselect) {
              selectedRow = null;
            } else {
              tr.classList.add("is-selected");
              tr.setAttribute("aria-selected", "true");
              selectedRow = row;
            }
            if (onSelect) onSelect(selectedRow);
          };
          tr.addEventListener("click", (event) => {
            if (event.target.closest("button, a, input, select, textarea")) return;
            toggle();
          });
          tr.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              toggle();
            }
          });
        }
        tbody.append(tr);
      }
    };

    for (const column of columns) {
      const th = document.createElement("th");
      th.scope = "col";
      const canSort = sortable && column.sortable !== false && Boolean(column.key || column.sortKey || column.sortValue);
      if (canSort) {
        th.setAttribute("aria-sort", "none");
        const button = document.createElement("button");
        button.type = "button";
        button.className = "table-sort";
        button.textContent = column.header;
        button.addEventListener("click", () => {
          sortDirection = sortColumn === column && sortDirection === "ascending" ? "descending" : "ascending";
          sortColumn = column;
          headerRow.querySelectorAll("th[aria-sort]").forEach((header) => header.setAttribute("aria-sort", "none"));
          th.setAttribute("aria-sort", sortDirection);
          const multiplier = sortDirection === "ascending" ? 1 : -1;
          const sorted = [...rows].sort((left, right) => multiplier * compareValues(sortValue(column, left), sortValue(column, right)));
          renderRows(sorted);
        });
        th.append(button);
      } else {
        th.textContent = column.header;
      }
      headerRow.append(th);
    }
    thead.append(headerRow);
    renderRows(rows);
    table.append(thead, tbody);
    const scroll = document.createElement("div");
    scroll.className = "table-scroll";
    scroll.setAttribute("role", "region");
    scroll.setAttribute("aria-label", tableLabel);
    scroll.tabIndex = 0;
    scroll.append(table);
    container.append(scroll);
  }

  // A sticky action bar bound to a single selection. Returns { setSelection }.
  // actions: [{ label, variant?: "accent"|"danger", enabled?: (sel)=>bool, onClick: (sel)=>void }]
  function actionBar(container, { emptyLabel = "Select a row to enable actions", selectedLabel = (sel) => `Selected: ${sel.label}`, actions = [] } = {}) {
    container.replaceChildren();
    container.classList.add("action-bar");
    let current = null;
    const status = document.createElement("span");
    status.className = "action-bar-status";
    container.append(status);
    const bound = actions.map((action) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = action.label;
      if (action.variant === "danger") button.classList.add("danger");
      else if (action.variant !== "accent") button.classList.add("secondary");
      button.addEventListener("click", () => action.onClick(current));
      container.append(button);
      return { action, button };
    });
    function setSelection(selection) {
      current = selection || null;
      status.textContent = current ? selectedLabel(current) : emptyLabel;
      for (const { action, button } of bound) {
        button.disabled = !(action.enabled ? action.enabled(current) : Boolean(current));
      }
    }
    setSelection(null);
    return { setSelection };
  }

  // Minimal modal dialog. content is a Node (usually a <form>). Returns { close }.
  function modal({ title = "", content = null, onClose = null, dismissible = true } = {}) {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    const card = document.createElement("div");
    card.className = "modal-card";
    card.setAttribute("role", "dialog");
    card.setAttribute("aria-modal", "true");
    card.tabIndex = -1;
    const head = document.createElement("div");
    head.className = "modal-head";
    const heading = document.createElement("h2");
    heading.id = `modal-title-${++modalCounter}`;
    heading.textContent = title;
    card.setAttribute("aria-labelledby", heading.id);
    const closeButton = document.createElement("button");
    closeButton.type = "button";
    closeButton.className = "secondary modal-close";
    closeButton.textContent = "Close";
    head.append(heading);
    if (dismissible) head.append(closeButton);
    const body = document.createElement("div");
    body.className = "modal-body";
    if (content) body.append(content);
    card.append(head, body);
    overlay.append(card);
    const previousFocus = document.activeElement;
    let closed = false;
    const focusableSelector = [
      "a[href]",
      "button:not([disabled])",
      "input:not([disabled])",
      "select:not([disabled])",
      "textarea:not([disabled])",
      "[tabindex]:not([tabindex='-1'])",
    ].join(",");
    const onKey = (event) => {
      if (event.key === "Escape" && dismissible) {
        event.preventDefault();
        close();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = [...card.querySelectorAll(focusableSelector)]
        .filter((node) => !node.hidden && node.getAttribute("aria-hidden") !== "true");
      if (!focusable.length) {
        event.preventDefault();
        card.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && (document.activeElement === first || !card.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    function close() {
      if (closed) return;
      closed = true;
      overlay.remove();
      document.removeEventListener("keydown", onKey);
      if (previousFocus && previousFocus.focus && previousFocus.isConnected) previousFocus.focus();
      if (onClose) onClose();
    }
    if (dismissible) closeButton.addEventListener("click", close);
    overlay.addEventListener("click", (event) => {
      if (dismissible && event.target === overlay) close();
    });
    document.addEventListener("keydown", onKey);
    document.body.append(overlay);
    const bodyFocusable = body.querySelector(`[autofocus], ${focusableSelector}`);
    (bodyFocusable || (dismissible ? closeButton : card)).focus();
    return { close, card };
  }

  function actionButton(label, handler, className = "secondary") {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = label;
    button.addEventListener("click", handler);
    return button;
  }

  function roleLabel(role) {
    return {
      admin: "Administrator",
      auditor: "Auditor",
      superuser: "Certificate Operator",
      user: "User",
    }[role] || role;
  }

  function firstLoginReadinessRow(title, detail, ready) {
    const row = document.createElement("div");
    row.className = "first-login-guide-check";
    row.classList.toggle("is-action-needed", !ready);
    const copy = document.createElement("div");
    const heading = document.createElement("strong");
    heading.textContent = title;
    const description = document.createElement("small");
    description.textContent = detail;
    copy.append(heading, description);
    const state = document.createElement("span");
    state.className = `badge ${ready ? "ok" : "danger"}`;
    state.textContent = ready ? "Ready" : "Action needed";
    row.append(copy, state);
    return row;
  }

  function updateGettingStartedNavigation(status) {
    const link = $("#getting-started");
    if (!link) return;
    const actionNeeded = Boolean(status.action_needed);
    link.hidden = !actionNeeded;
    link.classList.toggle("hidden", !actionNeeded);
    link.classList.toggle("has-pending-action", actionNeeded);
    let indicator = link.querySelector(".nav-pending-indicator");
    if (actionNeeded && !indicator) {
      indicator = document.createElement("span");
      indicator.className = "nav-pending-indicator";
      indicator.textContent = "!";
      indicator.setAttribute("aria-label", "Action needed");
      link.append(indicator);
    }
    if (indicator) indicator.classList.toggle("hidden", !actionNeeded);
  }

  async function refreshGettingStartedNavigation() {
    const status = await api("/internal/auth/first-login-guide", { cache: "no-store" });
    updateGettingStartedNavigation(status);
    return status;
  }

  async function openFirstLoginGuide({ force = false } = {}) {
    if (firstLoginGuideDialog) return;
    if (firstLoginGuideOpening) {
      firstLoginGuideForceRequested ||= force;
      return;
    }
    firstLoginGuideOpening = true;
    let status;
    try {
      status = await refreshGettingStartedNavigation();
    } finally {
      firstLoginGuideOpening = false;
    }
    const forced = force || firstLoginGuideForceRequested;
    firstLoginGuideForceRequested = false;
    if (!status.eligible || (!forced && !status.show) || firstLoginGuideDialog) return;

    const isAdmin = status.role === "admin";
    const certificateOperatorStatus = status.prerequisites.certificate_operator || {
      ready: false,
      count: 0,
    };
    const templateStatus = status.prerequisites.certificate_templates;
    const recoveryStatus = status.prerequisites.password_recovery;
    const guide = document.createElement("div");
    guide.className = "first-login-guide";
    const progress = document.createElement("ol");
    progress.className = "first-login-guide-progress";
    progress.setAttribute("aria-label", "Getting started progress");
    const labels = isAdmin
      ? ["Welcome", "Certificate Operator", "Templates", "Recovery"]
      : ["Welcome", "Templates", "Recovery"];
    const markers = labels.map((label) => {
      const marker = document.createElement("li");
      marker.textContent = label;
      progress.append(marker);
      return marker;
    });
    const step = document.createElement("section");
    step.className = "first-login-guide-step";
    step.setAttribute("aria-live", "polite");
    const error = document.createElement("p");
    error.className = "first-login-guide-error hidden";
    error.setAttribute("role", "alert");
    const actions = document.createElement("div");
    actions.className = "actions first-login-guide-actions";
    const skip = actionButton("Skip wizard", () => dismiss("skipped"), "secondary skip");
    const back = actionButton("Back", () => {
      page = Math.max(0, page - 1);
      render();
    });
    const next = actionButton("Next", () => {
      if (page < labels.length - 1) {
        page += 1;
        render();
      } else {
        dismiss("completed");
      }
    }, "");
    actions.append(skip, back, next);
    guide.append(progress, step, error, actions);

    let page = 0;
    let busy = false;

    function paragraph(value, className = "") {
      const item = document.createElement("p");
      if (className) item.className = className;
      item.textContent = value;
      return item;
    }

    function heading(value) {
      const item = document.createElement("h3");
      item.textContent = value;
      return item;
    }

    function continueLaterAction(label, destination) {
      return actionButton(label, () => {
        const dialog = firstLoginGuideDialog;
        if (dialog) dialog.close();
        window.location.hash = destination;
      }, "secondary");
    }

    function render() {
      markers.forEach((marker, index) => {
        marker.classList.toggle("is-active", index === page);
        marker.classList.toggle("is-complete", index < page);
        if (index === page) marker.setAttribute("aria-current", "step");
        else marker.removeAttribute("aria-current");
      });
      back.hidden = page === 0;
      next.textContent = page === labels.length - 1 ? "Finish" : "Next";
      step.replaceChildren();

      if (page === 0) {
        step.append(
          heading(`Welcome, ${isAdmin ? "Administrator" : "Certificate Operator"}`),
          paragraph(
            "This short guide covers the prerequisites that make certificate operations and account recovery usable.",
          ),
          paragraph(
            "You can skip it now and reopen it at any time from Getting started in the sidebar.",
            "notice",
          ),
        );
      } else if (isAdmin && page === 1) {
        const hasOperator = certificateOperatorStatus.ready;
        const count = certificateOperatorStatus.count;
        step.append(
          heading(hasOperator ? "Certificate Operator access is ready" : "Add a Certificate Operator"),
          hasOperator
            ? paragraph(
              "Certificate actions are performed from the separate Certificate Operator portal.",
              "hint",
            )
            : paragraph(
              "This is the technical administration panel. Certificates cannot be issued or managed from here. Add at least one privileged user with the Certificate Operator role, then use the Certificate Operator portal.",
            ),
          firstLoginReadinessRow(
            "Certificate Operator",
            hasOperator
              ? `${count} active account${count === 1 ? "" : "s"}`
              : "Create and activate a Certificate Operator account",
            hasOperator,
          ),
        );
        step.append(
          paragraph("Create or manage Certificate Operator accounts in Privileged users.", "hint"),
        );
        if (hasOperator) {
          step.append(
            paragraph(
              `${count} active Certificate Operator${count === 1 ? " is" : "s are"} available to issue and manage certificates.`,
            ),
          );
        }
        step.append(continueLaterAction("Open Privileged users", "#/privileged"));
      } else if (page === (isAdmin ? 2 : 1)) {
        step.append(
          heading("Define certificate templates before creating certificates"),
          paragraph(
            "At least one certificate template must be defined before anyone can request or create a certificate. Templates set the certificate profile, allowed usages, validity, and approval rules.",
          ),
          firstLoginReadinessRow(
            "Certificate templates",
            templateStatus.ready
              ? `${templateStatus.count} template${templateStatus.count === 1 ? "" : "s"} already defined`
              : "Define at least one template to unlock certificate creation",
            templateStatus.ready,
          ),
          paragraph(
            isAdmin
              ? "Create or review certificate templates in Templates."
              : "An Administrator defines templates. Confirm that one matches the certificates you will operate before accepting requests.",
            "hint",
          ),
        );
        if (isAdmin) {
          step.append(continueLaterAction("Open Templates", "#/templates"));
        }
      } else if (page === (isAdmin ? 3 : 2)) {
        step.append(
          heading("Enable a channel for password recovery"),
          paragraph(
            "Self-service password recovery needs at least one enabled notification channel. Without one, an administrative lockout can occur if the sole Administrator—or, under Dual control, fewer than two Administrators—can access their accounts.",
          ),
          firstLoginReadinessRow(
            "Password recovery channel",
            recoveryStatus.ready
              ? `Enabled: ${recoveryStatus.channels.join(", ")}`
              : "Enable at least one notification channel",
            recoveryStatus.ready,
          ),
          paragraph(
            isAdmin
              ? "Configure and test a channel in Notifications & integrations."
              : "Ask an Administrator to configure and test a recovery channel. This protects Certificate Operator accounts too.",
            "hint",
          ),
        );
        if (isAdmin) {
          step.append(continueLaterAction("Open Notifications & integrations", "#/channels"));
        }
      }
    }

    async function dismiss(outcome, destination = null) {
      if (busy) return;
      busy = true;
      error.classList.add("hidden");
      [skip, back, next, ...step.querySelectorAll("button")].forEach((button) => {
        button.disabled = true;
      });
      try {
        const dismissedStatus = await api("/internal/auth/first-login-guide/dismiss", {
          method: "POST",
          body: JSON.stringify({ outcome }),
        });
        updateGettingStartedNavigation(dismissedStatus);
        const dialog = firstLoginGuideDialog;
        if (dialog) dialog.close();
        if (destination) window.location.hash = destination;
      } catch (requestError) {
        busy = false;
        error.textContent = requestError.message;
        error.classList.remove("hidden");
        [skip, back, next, ...step.querySelectorAll("button")].forEach((button) => {
          button.disabled = false;
        });
        back.hidden = page === 0;
      }
    }

    render();
    firstLoginGuideDialog = modal({
      title: "Getting started",
      content: guide,
      dismissible: false,
      onClose: () => {
        firstLoginGuideDialog = null;
      },
    });
    firstLoginGuideDialog.card.classList.add("first-login-guide-modal");
  }

  function badge(value) {
    const span = document.createElement("span");
    const roles = ["admin", "auditor", "superuser", "user"];
    const tone = roles.includes(value) ? "role" : value === "active" || value === "issued" ? "ok" : "warn";
    span.className = `badge ${tone}`;
    span.textContent = roleLabel(value);
    return span;
  }

  function pemDownload(filename, pem) {
    const link = document.createElement("a");
    link.className = "button-link secondary";
    link.textContent = "Download PEM";
    link.download = filename;
    link.href = URL.createObjectURL(new Blob([pem], { type: "application/x-pem-file" }));
    return link;
  }

  // Binary-safe download fetch (BB.api assumes JSON). Resolves to
  // { blob, filename } where filename comes from Content-Disposition.
  async function apiDownload(path, options = {}) {
    if (!isHsmRoute(path, options.method)) return apiDownloadRequest(path, options);
    return withHsmGuards(options, (guarded) => apiDownloadRequest(path, guarded));
  }

  async function apiDownloadRequest(path, options = {}) {
    const response = await fetch(path, {
      headers: {
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
        ...(options.headers || {}),
      },
      ...options,
    });
    if (!response.ok) {
      let detail = `Request failed with ${response.status}`;
      try {
        detail = (await response.json())?.detail || detail;
      } catch {
        /* non-JSON error body */
      }
      throw new Error(detail);
    }
    const disposition = response.headers.get("content-disposition") || "";
    const match = disposition.match(/filename="?([^";]+)"?/i);
    return { blob: await response.blob(), filename: match ? match[1] : "download" };
  }

  function fileDownload(filename, blob) {
    const link = document.createElement("a");
    link.download = filename;
    link.href = URL.createObjectURL(blob);
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(link.href);
  }

  function mountRecoveryCodes(selector) {
    const root = $(selector);
    if (!root) return;
    const status = root.querySelector(".account-totp-status");
    const button = root.querySelector(".account-recovery-generate");
    const output = root.querySelector(".account-recovery-output");
    const configured = Boolean(currentUser?.totp_configured);
    const required = Boolean(currentUser?.totp_required);
    if (status) {
      status.textContent = configured
        ? `TOTP is configured${required ? " and required for your role" : ""}.`
        : required
          ? "TOTP is required but enrollment is not complete. Sign out and complete enrollment."
          : "TOTP is not required for your role and no factor is configured.";
    }
    if (!button) return;
    button.disabled = !configured;
    button.addEventListener("click", async () => {
      if (!window.confirm("Generate a new set of recovery codes? This invalidates all previous codes.")) return;
      try {
        const body = await api("/internal/auth/recovery/codes/regenerate", { method: "POST" });
        if (output) {
          output.textContent = body.recovery_codes.join("\n");
          output.classList.remove("hidden");
        }
      } catch (error) {
        showError(error);
      }
    });
  }

  const EXPORT_FORMATS = [
    { value: "pem", label: "PEM (.crt) — certificate only", keyed: false, password: false },
    { value: "pem-chain", label: "PEM chain (.pem) — certificate + CA chain", keyed: false, password: false },
    { value: "pkcs7", label: "PKCS#7 (.p7b) — single certificate", keyed: false, password: false },
    { value: "der", label: "DER (.cer) — binary certificate", keyed: false, password: false },
    { value: "pkcs12", label: "PKCS#12 (.pfx) — certificate + private key + chain, encrypted", keyed: true, password: true },
    { value: "pem-key", label: "PEM + key (.pem) — certificate + encrypted private key", keyed: true, password: true },
    { value: "pem-pkcs8", label: "PEM + PKCS#8 (.pem) — certificate + encrypted private key", keyed: true, password: true },
  ];

  // Export dialog shared by the user and superuser portals. `certificate` is a
  // row from /internal/certificates (needs serial_number, subject, request_id,
  // server_key_held). onChange fires after a key-retirement state change so
  // callers can refresh.
  function openExportModal(certificate, { onChange = null } = {}) {
    const form = document.createElement("form");
    const formatLabel = document.createElement("label");
    formatLabel.textContent = "Format";
    const select = document.createElement("select");
    select.name = "format";
    for (const fmt of EXPORT_FORMATS) {
      const option = document.createElement("option");
      option.value = fmt.value;
      option.textContent = fmt.label;
      if (fmt.keyed && !certificate.server_key_held) {
        option.disabled = true;
        option.textContent += " — requires a server-held key";
      }
      select.append(option);
    }
    formatLabel.append(select);

    const passwordLabel = document.createElement("label");
    passwordLabel.textContent = "Export password (min 8 characters)";
    const password = document.createElement("input");
    password.type = "password";
    password.name = "password";
    password.minLength = 8;
    password.autocomplete = "new-password";
    passwordLabel.append(password);

    const reauthLabel = document.createElement("label");
    const reauthPrompt = document.createElement("span");
    const reauthInput = document.createElement("input");
    const reauthStatus = document.createElement("p");
    reauthStatus.className = "form-state";
    reauthStatus.setAttribute("role", "status");
    reauthLabel.append(reauthPrompt, reauthInput);

    function configureReauthentication(auth) {
      const method = auth?.method === "totp" ? "totp" : "password";
      reauthPrompt.textContent = (
        method === "totp" ? "Current TOTP code" : "Current account password"
      );
      reauthInput.name = method === "totp" ? "totp_code" : "current_password";
      reauthInput.type = method === "totp" ? "text" : "password";
      reauthInput.autocomplete = method === "totp" ? "one-time-code" : "current-password";
      if (method === "totp") {
        reauthInput.inputMode = "numeric";
        reauthInput.pattern = "[0-9]{6}";
        reauthInput.maxLength = 6;
      } else {
        reauthInput.removeAttribute("inputmode");
        reauthInput.removeAttribute("pattern");
        reauthInput.removeAttribute("maxlength");
      }
      return method;
    }
    configureReauthentication(currentUser?.sensitive_auth);

    const exportError = document.createElement("p");
    exportError.className = "form-state is-error hidden";
    exportError.setAttribute("role", "alert");

    const submit = document.createElement("button");
    submit.type = "submit";
    submit.textContent = "Download";

    form.append(formatLabel, passwordLabel, reauthLabel, reauthStatus, exportError, submit);

    function syncFields() {
      const fmt = EXPORT_FORMATS.find((candidate) => candidate.value === select.value);
      passwordLabel.classList.toggle("hidden", !fmt.password);
      password.required = fmt.password;
      const requiresFreshAuthentication = fmt.keyed
        && !Boolean(currentUser?.sensitive_auth?.recent);
      reauthLabel.classList.toggle("hidden", !requiresFreshAuthentication);
      reauthStatus.classList.toggle("hidden", !fmt.keyed);
      reauthInput.required = requiresFreshAuthentication;
      reauthStatus.textContent = requiresFreshAuthentication
        ? "Key-bearing export requires fresh authentication."
        : "Recent authentication is active for this key-bearing export.";
    }
    select.addEventListener("change", syncFields);
    syncFields();

    const certificateExpired = certificate.expires_at
      && new Date(certificate.expires_at).getTime() <= Date.now();
    const canRetireKey = certificate.server_key_held
      && (certificate.archived_at || certificate.status !== "active" || certificateExpired);
    if (canRetireKey) {
      const retire = document.createElement("button");
      retire.type = "button";
      retire.className = "danger";
      retire.textContent = "Schedule key retirement";
      retire.addEventListener("click", async () => {
        if (!window.confirm(
          "Schedule this server-held key for retirement? It is removed 30 days after its final active binding is removed; re-binding it during that grace period cancels cleanup.",
        )) return;
        try {
          const result = await api(`/internal/certificate-requests/${encodeURIComponent(certificate.request_id)}/server-key`, {
            method: "DELETE",
          });
          dialog.close();
          showResult({ status: "Key retirement scheduled.", ...result });
          if (onChange) await onChange(result);
        } catch (error) {
          showError(error);
        }
      });
      form.append(retire);
    }

    const dialog = modal({ title: `Export — ${certificate.subject}`, content: form });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      exportError.textContent = "";
      exportError.classList.add("hidden");
      const fmt = EXPORT_FORMATS.find((candidate) => candidate.value === select.value);
      const serial = encodeURIComponent(certificate.serial_number);
      const exportBase = certificate.certificate_id
        ? `/internal/certificate-inventory/${encodeURIComponent(certificate.certificate_id)}/export`
        : `/internal/certificates/${serial}/export`;
      try {
        if (fmt.keyed) {
          currentUser = await api("/internal/auth/me");
          csrfToken = currentUser.csrf_token;
          const auth = currentUser.sensitive_auth || { method: "password", recent: false };
          const method = configureReauthentication(auth);
          if (!auth.recent) {
            reauthLabel.classList.remove("hidden");
            reauthStatus.classList.remove("hidden");
            reauthInput.required = true;
            if (!reauthInput.value) {
              throw new Error(
                `Enter your current ${method === "totp" ? "TOTP code" : "password"} to export the private key.`,
              );
            }
            const refreshed = await api(
              method === "totp"
                ? "/internal/auth/totp/reauthenticate"
                : "/internal/auth/password/reauthenticate",
              {
                method: "POST",
                body: JSON.stringify(
                  method === "totp"
                    ? { code: reauthInput.value }
                    : { password: reauthInput.value },
                ),
              },
            );
            currentUser = refreshed;
            csrfToken = refreshed.csrf_token;
            reauthInput.value = "";
            if (!refreshed.sensitive_auth?.recent) {
              throw new Error("The server did not confirm recent authentication.");
            }
          }
        }
        const result = fmt.keyed
          ? await apiDownload(exportBase, {
              method: "POST",
              body: JSON.stringify({ format: fmt.value, password: password.value || null }),
            })
          : await apiDownload(
              `${exportBase}?format=${encodeURIComponent(fmt.value)}`,
            );
        fileDownload(result.filename, result.blob);
        dialog.close();
      } catch (error) {
        exportError.textContent = `Export failed: ${error?.message || String(error)}`;
        exportError.classList.remove("hidden");
        showError(error);
      }
    });
  }

  async function openArchiveCertificateModal(certificate, { onChange = null } = {}) {
    if (!certificate || !certificate.serial_number) {
      throw new Error("Choose a certificate to archive.");
    }
    if (certificate.archived_at) {
      throw new Error("This certificate is already archived.");
    }

    currentUser = await api("/internal/auth/me");
    csrfToken = currentUser.csrf_token;
    const confirmation = `ARCHIVE CERTIFICATE ${certificate.serial_number}`;
    const auth = currentUser.sensitive_auth || { method: "password", recent: false };

    const form = document.createElement("form");
    form.className = "sensitive-action-form";

    const impact = document.createElement("p");
    impact.className = "sensitive-impact";
    impact.textContent = certificate.status === "active"
      ? "The active certificate will be revoked with reason cessationOfOperation and retained in the archive. Its now-orphaned managed key enters the fixed 30-day grace period."
      : "The certificate record and audit history will be retained in the archive. Any now-orphaned managed key enters the fixed 30-day grace period.";

    const reasonLabel = document.createElement("label");
    reasonLabel.textContent = "Operational reason";
    const reason = document.createElement("textarea");
    reason.name = "reason";
    reason.rows = 3;
    reason.minLength = 10;
    reason.maxLength = 500;
    reason.required = true;
    reason.placeholder = "Why this certificate is being retired (do not include secrets)";
    reasonLabel.append(reason);

    const confirmationLabel = document.createElement("label");
    const confirmationPrompt = document.createElement("span");
    confirmationPrompt.append("Type ");
    const code = document.createElement("code");
    code.textContent = confirmation;
    confirmationPrompt.append(code, " to continue");
    const typed = document.createElement("input");
    typed.name = "confirmation";
    typed.required = true;
    typed.autocomplete = "off";
    typed.spellcheck = false;
    confirmationLabel.append(confirmationPrompt, typed);

    const authLabel = document.createElement("label");
    const authInput = document.createElement("input");
    const needsReauthentication = !auth.recent;
    if (auth.method === "totp") {
      authLabel.prepend("Current TOTP code");
      authInput.name = "totp_code";
      authInput.type = "text";
      authInput.inputMode = "numeric";
      authInput.autocomplete = "one-time-code";
      authInput.pattern = "[0-9]{6}";
      authInput.maxLength = 6;
    } else {
      authLabel.prepend("Current password");
      authInput.name = "current_password";
      authInput.type = "password";
      authInput.autocomplete = "current-password";
    }
    authInput.required = needsReauthentication;
    authLabel.append(authInput);
    authLabel.classList.toggle("hidden", !needsReauthentication);

    const authStatus = document.createElement("p");
    authStatus.className = "form-state";
    authStatus.setAttribute("role", "status");
    authStatus.textContent = needsReauthentication
      ? `Fresh ${auth.method === "totp" ? "TOTP" : "password"} verification is required.`
      : "Recent authentication is active.";

    const submit = document.createElement("button");
    submit.type = "submit";
    submit.className = "danger";
    submit.textContent = "Revoke and archive";

    form.append(impact, reasonLabel, confirmationLabel, authLabel, authStatus, submit);
    const dialog = modal({ title: `Archive — ${certificate.subject}`, content: form });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (reason.value.trim().length < 10) {
        authStatus.textContent = "Reason must contain at least 10 characters.";
        authStatus.classList.add("is-error");
        return;
      }
      if (typed.value !== confirmation) {
        authStatus.textContent = "The typed confirmation does not match.";
        authStatus.classList.add("is-error");
        return;
      }
      submit.disabled = true;
      authStatus.classList.remove("is-error");
      try {
        if (needsReauthentication) {
          const response = await api(
            auth.method === "totp"
              ? "/internal/auth/totp/reauthenticate"
              : "/internal/auth/password/reauthenticate",
            {
              method: "POST",
              body: JSON.stringify(
                auth.method === "totp"
                  ? { code: authInput.value }
                  : { password: authInput.value },
              ),
            },
          );
          currentUser = response;
          csrfToken = response.csrf_token;
          if (!response.sensitive_auth?.recent) {
            throw new Error("The server did not confirm recent authentication.");
          }
        }
        const archived = await api(
          `/internal/certificate-inventory/${encodeURIComponent(certificate.certificate_id)}`,
          {
            method: "DELETE",
            body: JSON.stringify({
              reason: reason.value.trim(),
              confirmation: typed.value,
            }),
          },
        );
        dialog.close();
        showResult({ status: "Certificate revoked and archived.", ...archived });
        if (onChange) {
          try {
            await onChange(archived);
          } catch (refreshError) {
            showError(new Error(
              `Certificate was archived, but refreshing the displayed inventory failed: ${refreshError?.message || String(refreshError)}`,
            ));
          }
        }
      } catch (error) {
        authStatus.textContent = `Action failed: ${error?.message || String(error)}`;
        authStatus.classList.add("is-error");
        showError(error);
      } finally {
        authInput.value = "";
        submit.disabled = false;
      }
    });
    reason.focus();
    return dialog;
  }

  function mountCsrPage(root, { onDetails = setOutput } = {}) {
    if (!root || root.dataset.mounted === "true") return { refresh: async () => {} };
    root.dataset.mounted = "true";
    let templates = [];
    let certificates = [];
    const local = (selector) => root.querySelector(selector);
    const form = local(".csr-request-form");
    const templateSelect = local(".csr-template-select");
    const requestKind = local(".csr-request-kind");
    const renewalField = local(".csr-renewal-certificate-field");
    const renewalSelect = local(".csr-renewal-certificate-select");
    const renewalHint = local(".csr-renewal-hint");
    const keySource = local(".csr-key-source");
    const csrFields = local(".csr-fields");
    const serverKeyFields = local(".csr-server-key-fields");
    const templateTable = local(".csr-template-table");
    const requestTable = local(".csr-request-table");
    const certificateTable = local(".csr-certificate-table");
    const refreshButton = local(".csr-refresh");
    let emailSanDirty = false;

    function selectedProfile() {
      return templates.find((template) => template.id === templateSelect.value)?.profile || null;
    }

    function syncAlgorithmOptions() {
      const allowed = templates.find((template) => template.id === templateSelect.value)
        ?.allowed_key_algorithms || [];
      const select = form.elements.algorithm;
      const previous = select.value;
      select.replaceChildren(...allowed.map((algorithm) => {
        const option = document.createElement("option");
        option.value = algorithm;
        option.textContent = algorithm;
        return option;
      }));
      if (allowed.includes(previous)) select.value = previous;
    }

    function syncSanFields(serverMode) {
      const profile = selectedProfile();
      syncProfileSanFields(form, profile, { enabled: serverMode });
      if (
        serverMode
        && profile !== "host_tls"
        && !emailSanDirty
        && form.elements.email_addresses
      ) {
        form.elements.email_addresses.value = currentUser?.email || "";
      }
    }

    function handleError(error) {
      onDetails({ error: error?.message || String(error) });
    }

    function ownRows(rows) {
      if (!currentUser?.id) return rows;
      return rows.filter((row) => row.requested_by_user_id === currentUser.id);
    }

    function syncRenewalTemplate() {
      const certificate = certificates.find(
        (candidate) => candidate.serial_number === renewalSelect.value,
      );
      if (certificate) templateSelect.value = certificate.template_id;
    }

    function syncKeySource() {
      const serverMode = keySource.value === "server";
      csrFields.classList.toggle("hidden", serverMode);
      serverKeyFields.classList.toggle("hidden", !serverMode);
      form.elements.csr_pem.required = !serverMode;
      form.elements.common_name.required = serverMode;
      syncAlgorithmOptions();
      syncSanFields(serverMode);
    }

    function syncRenewalMode() {
      const isRenewal = requestKind.value === "renewal";
      renewalField.classList.toggle("hidden", !isRenewal);
      renewalHint.classList.toggle("hidden", !isRenewal);
      renewalSelect.required = isRenewal;
      templateSelect.disabled = isRenewal;
      if (isRenewal) keySource.value = "csr";
      keySource.disabled = isRenewal;
      syncKeySource();
      if (isRenewal) syncRenewalTemplate();
    }

    function renderTemplates() {
      renderTable(templateTable, templates, [
        { header: "Name", key: "name" },
        { header: "Profile", key: "profile" },
        { header: "KU", render: (row) => row.key_usages.join(", ") },
        { header: "EKU", render: (row) => row.extended_key_usages.join(", ") },
        { header: "Key algorithms", render: (row) => row.allowed_key_algorithms.join(", ") },
      ]);
    }

    function renderRequests(rows) {
      renderTable(requestTable, ownRows(rows), [
        { header: "Created", render: (row) => new Date(row.created_at).toLocaleString() },
        { header: "Template", render: (row) => `${row.template_name} (${row.profile})` },
        { header: "Kind", key: "kind" },
        { header: "Renews", render: (row) => row.renewal_of_serial_number || "—" },
        { header: "Status", render: (row) => badge(row.status) },
        { header: "Approvals", render: (row) => `${row.approval_count}/${row.required_approvals}` },
        { header: "Certificate", render: (row) => row.issued_serial_number || "pending" },
        {
          header: "Actions",
          render: (row) => {
            const actions = document.createElement("div");
            actions.className = "actions";
            if (row.status === "pending") {
              actions.append(actionButton("Withdraw", async () => {
                try {
                  await rejectRequest(row.id);
                } catch (error) {
                  handleError(error);
                }
              }, "danger"));
            }
            actions.append(actionButton("Details", async () => {
              onDetails(await api(`/internal/certificate-requests/${row.id}`));
            }));
            return actions;
          },
        },
      ]);
    }

    function renderCertificates(rows) {
      renderTable(certificateTable, rows, [
        { header: "Issued", render: (row) => new Date(row.issued_at).toLocaleString() },
        { header: "Subject", key: "subject" },
        { header: "Template", key: "template_name" },
        { header: "Status", render: (row) => badge(row.status) },
        { header: "Key", render: (row) => (row.server_key_held ? "server" : "—") },
        {
          header: "Actions",
          render: (row) => {
            const actions = document.createElement("div");
            actions.className = "actions";
            actions.append(actionButton("View PEM", async () => {
              const certificate = await api(`/internal/certificates/${row.serial_number}`);
              onDetails(certificate.certificate_pem);
            }));
            actions.append(actionButton("Export…", () =>
              openExportModal(row, { onChange: () => refresh().catch(handleError) }),
            ));
            return actions;
          },
        },
        {
          header: "Renew",
          render: (row) => row.status === "active"
            ? actionButton("Renew", () => selectRenewal(row))
            : "—",
        },
      ]);
    }

    async function rejectRequest(requestId) {
      const response = await api(`/internal/certificate-requests/${requestId}/reject`, {
        method: "POST",
      });
      onDetails({
        status: "Request withdrawn. Submit a new CSR request when ready.",
        ...response,
      });
      await refresh();
    }

    function selectRenewal(certificate) {
      requestKind.value = "renewal";
      syncRenewalMode();
      renewalSelect.value = certificate.serial_number;
      syncRenewalTemplate();
      form.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    async function refresh() {
      templates = await api("/internal/templates");
      certificates = ownRows(await api("/internal/certificates"));
      fillSelect(templateSelect, templates, {
        value: "id",
        label: (row) => `${row.name} (${row.profile})`,
        placeholder: "Choose template",
      });
      fillSelect(
        renewalSelect,
        certificates.filter((certificate) => certificate.status === "active"),
        {
          value: "serial_number",
          label: (row) => `${row.subject} — ${row.template_name} (${row.serial_number})`,
          placeholder: "Choose certificate to renew",
        },
      );
      syncRenewalMode();
      renderTemplates();
      renderRequests(await api("/internal/certificate-requests"));
      renderCertificates(certificates);
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        const body = formPayload(form);
        let created;
        if (keySource.value === "server" && body.kind !== "renewal") {
          const profile = selectedProfile();
          created = await api("/internal/certificate-requests/generate", {
            method: "POST",
            body: JSON.stringify({
              template_id: body.template_id,
              common_name: body.common_name,
              ...profileSanPayload(form, profile),
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
              (candidate) => candidate.serial_number === body.renewal_of_serial_number,
            );
            if (!certificate) {
              throw new Error("Choose one of your active issued certificates to renew.");
            }
            body.template_id = certificate.template_id;
          } else {
            delete body.renewal_of_serial_number;
          }
          created = await api("/internal/certificate-requests", {
            method: "POST",
            body: JSON.stringify(body),
          });
        }
        onDetails(created);
        form.reset();
        emailSanDirty = false;
        syncKeySource();
        await refresh();
      } catch (error) {
        handleError(error);
      }
    });

    refreshButton.addEventListener("click", () => refresh().catch(handleError));
    requestKind.addEventListener("change", syncRenewalMode);
    renewalSelect.addEventListener("change", syncRenewalTemplate);
    keySource.addEventListener("change", syncKeySource);
    templateSelect.addEventListener("change", syncKeySource);
    form.elements.email_addresses?.addEventListener("input", () => { emailSanDirty = true; });

    return { refresh };
  }

  return {
    $,
    api,
    init,
    formPayload,
    profileSanPayload,
    syncProfileSanFields,
    checkedValues,
    fillSelect,
    renderTable,
    actionBar,
    modal,
    actionButton,
    roleLabel,
    badge,
    pemDownload,
    apiDownload,
    fileDownload,
    mountRecoveryCodes,
    openExportModal,
    openArchiveCertificateModal,
    mountCsrPage,
    setOutput,
    showResult,
    showResultDetails,
    showError,
    licenseTierDisplay,
    renderLicenseTier,
    renderLicenseIdentity,
    refreshLicenseIdentity,
    setNavPending,
    loadDashboardAlertMutes,
    setDashboardAlertMuted,
    isDashboardAlertMuted,
    text,
    get currentUser() { return currentUser; },
  };
})();
