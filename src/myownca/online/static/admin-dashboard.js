// Action-oriented administrator overview. Kept separate from admin.js so the
// operational dashboard can evolve without coupling the rest of the portal.
(function (global, BB) {
  "use strict";
  const REGION_KEYS = ["attention", "readiness", "lifecycle", "capacity"];
  const REGION_IDS = {
    attention: "dashboard-attention",
    readiness: "dashboard-readiness",
    lifecycle: "dashboard-lifecycle",
    capacity: "dashboard-capacity",
    changes: "activity-changes",
  };
  const REGION_LOADING_LABELS = {
    attention: "Checking operational health…",
    readiness: "Loading readiness progress…",
    lifecycle: "Loading lifecycle health…",
    capacity: "Loading capacity…",
    changes: "Loading recent administrative activity…",
  };
  const BACKUP_CHECK_ID = "backup.application";
  const STATUS_LABELS = {
    healthy: "Healthy",
    attention: "Needs attention",
    critical: "Critical",
    pass: "Pass",
    warn: "Warning",
    fail: "Failed",
    unknown: "Unknown",
  };
  const OWNER_LABELS = {
    administrator: "Administrator",
    certificate_operator: "Certificate Operator",
  };
  const PROFILE_DATE_OPTIONS = { dateStyle: "medium", timeStyle: "short" };

  let mounted = false;
  let refreshSequence = 0;
  let latestAttentionOverview = null;

  const element = (id) => document.getElementById(id);
  const regionElement = (regionKey, suffix = "") => {
    const baseId = REGION_IDS[regionKey] || `dashboard-${regionKey}`;
    return element(suffix ? `${baseId}-${suffix}` : baseId);
  };

  function asArray(value, label) {
    if (!Array.isArray(value)) throw new Error(`${label} was not returned by the server.`);
    return value;
  }

  function asObject(value, label) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`${label} was not returned by the server.`);
    }
    return value;
  }

  function humanize(value) {
    return String(value || "unknown")
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  }

  function formatDate(value) {
    if (!value) return "Not recorded";
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString(undefined, PROFILE_DATE_OPTIONS);
  }

  function latestChecked(items, fallback) {
    const timestamps = (Array.isArray(items) ? items : [])
      .map((item) => Date.parse(item?.checked_at || ""))
      .filter(Number.isFinite);
    return timestamps.length ? new Date(Math.max(...timestamps)).toISOString() : fallback;
  }

  function freshnessText(overview, checkedAt) {
    const freshness = overview?.freshness || {};
    const checked = checkedAt || freshness.checked_at || overview?.generated_at;
    const age = checked ? `Checked ${formatDate(checked)}` : "Check time unavailable";
    const cadence = Number(freshness.stale_after_seconds);
    const expected = Number.isFinite(cadence) && cadence > 0 ? ` · considered stale after ${cadence}s` : "";
    return `${freshness.is_stale ? "Data may be stale · " : ""}${age}${expected}`;
  }

  function setFreshness(regionKey, overview, checkedAt) {
    const target = regionElement(regionKey, "freshness");
    if (!target) return;
    target.textContent = freshnessText(overview, checkedAt);
    target.classList.toggle("is-stale", Boolean(overview?.freshness?.is_stale));
  }

  function makeStatus(value) {
    const status = document.createElement("span");
    const normalized = String(value || "unknown").toLowerCase();
    status.className = `status-pill status-${normalized}`;
    status.textContent = STATUS_LABELS[normalized] || humanize(normalized);
    return status;
  }

  function makeEmptyState(title, detail) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    const heading = document.createElement("h3");
    heading.textContent = title;
    const description = document.createElement("p");
    description.textContent = detail;
    empty.append(heading, description);
    return empty;
  }

  function setRegionLoading(regionKey) {
    const content = regionElement(regionKey);
    if (!content) return;
    content.setAttribute("aria-busy", "true");
    const loading = document.createElement("p");
    loading.className = "loading-state";
    loading.textContent = REGION_LOADING_LABELS[regionKey];
    content.replaceChildren(loading);
    const freshness = regionElement(regionKey, "freshness");
    if (freshness) freshness.textContent = "";
  }

  function showRegionError(regionKey, error, retry = refresh) {
    const content = regionElement(regionKey);
    if (!content) return;
    content.setAttribute("aria-busy", "false");
    const state = makeEmptyState("This section could not be loaded", error?.message || String(error));
    state.classList.add("error-state");
    const button = BB.actionButton("Retry this section", () => retry().catch(() => {}), "secondary");
    state.append(button);
    content.replaceChildren(state);
    const freshness = regionElement(regionKey, "freshness");
    if (freshness) freshness.textContent = "The last successful check is unavailable.";
  }

  function renderRegion(regionKey, renderer, retry = refresh) {
    const content = regionElement(regionKey);
    try {
      renderer();
      if (content) content.setAttribute("aria-busy", "false");
    } catch (error) {
      showRegionError(regionKey, error, retry);
    }
  }

  function itemCard(item) {
    const card = document.createElement("article");
    const statusValue = String(item?.status || "unknown").toLowerCase();
    const severity = String(item?.severity || "none").toLowerCase();
    const alertId = String(item?.id || "");
    const isAlert = Boolean(alertId) && statusValue !== "pass";
    const muted = isAlert && BB.isDashboardAlertMuted(alertId);
    card.className = `check-item check-${statusValue} severity-${severity}`;
    card.classList.toggle("is-muted-alert", muted);

    const header = document.createElement("div");
    header.className = "check-item-header";
    const title = document.createElement("h3");
    title.textContent = item?.title || humanize(item?.id || "Check");
    header.append(title, makeStatus(statusValue));

    const summary = document.createElement("p");
    summary.textContent = item?.summary || "No detail was returned for this check.";

    const footer = document.createElement("div");
    footer.className = "check-item-footer";
    const meta = document.createElement("span");
    meta.className = "check-meta";
    const owner = OWNER_LABELS[item?.owner] || humanize(item?.owner || "administrator");
    meta.textContent = `Owner: ${owner} · ${item?.checked_at ? `checked ${formatDate(item.checked_at)}` : "not checked"}`;
    const controls = document.createElement("div");
    controls.className = "check-item-actions";
    footer.append(meta, controls);

    if (isAlert && !muted) footer.classList.add("pending-action-cta");

    if (item?.action?.label && item?.action?.href) {
      const href = String(item.action.href);
      // Admin and Certificate Operator portals are deliberately role-isolated.
      // Only same-portal hash routes are safe for an authenticated administrator.
      if (href.startsWith("#/")) {
        const action = document.createElement("a");
        action.className = "button-link secondary compact";
        action.href = href;
        action.textContent = item.action.label;
        controls.append(action);
      }
    } else if (item?.owner === "certificate_operator" && statusValue !== "pass") {
      const handoff = document.createElement("span");
      handoff.className = "next-action";
      handoff.textContent = "Next: hand off to a Certificate Operator in their separate portal.";
      controls.append(handoff);
    }

    if (isAlert) {
      const mute = BB.actionButton(
        muted ? "Unmute" : "Mute",
        () => toggleAdminAlertMute(alertId, !muted).catch(BB.showError),
        "secondary compact",
      );
      mute.setAttribute("aria-label", `${muted ? "Unmute" : "Mute"} alert: ${title.textContent}`);
      controls.append(mute);
    }

    card.append(header, summary, footer);
    return card;
  }

  function renderCheckList(container, items, emptyTitle, emptyDetail) {
    if (!items.length) {
      container.replaceChildren(makeEmptyState(emptyTitle, emptyDetail));
      return;
    }
    const list = document.createElement("div");
    list.className = "check-list";
    list.replaceChildren(...items.map(itemCard));
    container.replaceChildren(list);
  }

  function renderAttention(overview) {
    latestAttentionOverview = overview;
    const items = asArray(overview.attention_items, "Attention checks")
      .filter((item) => item.status !== "pass");
    updatePendingNavigation(items);
    renderCheckList(
      element("dashboard-attention"),
      items,
      "Nothing needs immediate action",
      "All current readiness checks are passing. Keep the restore drill and certificate lifecycle under review.",
    );
    const overall = element("dashboard-overall-status");
    overall.className = `status-pill status-${overview.overall_status || "unknown"}`;
    overall.textContent = STATUS_LABELS[overview.overall_status] || humanize(overview.overall_status);
    setFreshness("attention", overview, latestChecked(items, overview.generated_at));
  }

  function updatePendingNavigation(items) {
    const pendingViews = new Set(
      items
        .filter((item) => (
          item?.status !== "pass"
          && !BB.isDashboardAlertMuted(item?.id)
          && String(item?.action?.href || "").startsWith("#/")
        ))
        .map((item) => String(item.action.href).slice(2)),
    );
    document.querySelectorAll(".side-nav a[data-view]").forEach((link) => {
      BB.setNavPending(link.dataset.view, pendingViews.has(link.dataset.view), "admin-operations");
    });
    const proposalCount = Number(element("proposal-badge")?.textContent || 0);
    BB.setNavPending(
      "privileged",
      proposalCount > 0 && !BB.isDashboardAlertMuted("governance.pending_changes"),
      "admin-proposals",
    );
  }

  async function toggleAdminAlertMute(alertId, muted) {
    await BB.setDashboardAlertMuted(alertId, muted);
    if (latestAttentionOverview) renderAttention(latestAttentionOverview);
  }

  function renderReadiness(overview) {
    const readiness = asObject(overview.readiness, "Production readiness");
    const items = asArray(readiness.items, "Readiness checks");
    const total = readiness.total === null || readiness.total === undefined ? NaN : Number(readiness.total);
    const completedCount = readiness.completed === null || readiness.completed === undefined
      ? NaN
      : Number(readiness.completed);
    if (!Number.isFinite(total) || !Number.isFinite(completedCount)) {
      throw new Error("Readiness progress was not returned by the server.");
    }

    const container = element("dashboard-readiness");
    const progressGroup = document.createElement("div");
    progressGroup.className = "readiness-progress";
    const progress = document.createElement("progress");
    progress.max = Math.max(total, 1);
    progress.value = Math.min(completedCount, progress.max);
    progress.setAttribute("aria-label", `${completedCount} of ${total} readiness checks complete`);
    const progressText = document.createElement("strong");
    progressText.textContent = `${completedCount} of ${total} checks complete`;
    const progressNote = document.createElement("span");
    progressNote.className = "metric-note";
    const outstanding = Math.max(0, total - completedCount);
    progressNote.textContent = outstanding
      ? `${outstanding} non-passing check${outstanding === 1 ? " is" : "s are"} listed once under Needs attention.`
      : "No readiness checks currently need attention.";
    progressGroup.append(progress, progressText, progressNote);

    const completedItems = items.filter((item) => item.status === "pass" && item.id !== BACKUP_CHECK_ID);
    const completedChecks = document.createElement("details");
    completedChecks.className = "completed-checks";
    const completedSummary = document.createElement("summary");
    completedSummary.textContent = `Other completed checks (${completedItems.length})`;
    const completedList = document.createElement("div");
    completedList.className = "completed-checks-list";
    renderCheckList(
      completedList,
      completedItems,
      "No completed checks yet",
      "Resolve the items under Needs attention, then refresh the overview.",
    );
    completedChecks.append(completedSummary, completedList);

    const backup = document.createElement("section");
    backup.className = "recovery-evidence";
    const backupTitle = document.createElement("h3");
    backupTitle.textContent = "Application backup";
    const backupList = document.createElement("div");
    const backupItem = items.find((item) => item.id === BACKUP_CHECK_ID);
    renderCheckList(
      backupList,
      backupItem ? [backupItem] : [],
      "Backup status unavailable",
      "Open System → Backups to inspect the governed backup workflow.",
    );
    backup.append(backupTitle, backupList);
    container.replaceChildren(progressGroup, backup, completedChecks);

    const count = element("dashboard-readiness-count");
    count.className = `status-pill status-${readiness.status || "unknown"}`;
    count.textContent = `${completedCount}/${total}`;
    count.setAttribute("aria-label", STATUS_LABELS[readiness.status] || humanize(readiness.status));
    setFreshness("readiness", overview, latestChecked(items, overview.generated_at));
  }

  async function refreshReadinessRegion() {
    setRegionLoading("readiness");
    const readinessResult = await Promise.resolve(BB.api("/internal/admin/readiness"))
      .then((value) => ({ status: "fulfilled", value }))
      .catch((reason) => ({ status: "rejected", reason }));
    if (readinessResult.status === "rejected") {
      showRegionError("readiness", readinessResult.reason, refreshReadinessRegion);
      return;
    }
    const readinessResponse = readinessResult.value;
    const overview = {
      generated_at: readinessResponse.generated_at,
      freshness: readinessResponse.freshness,
      readiness: readinessResponse.readiness || readinessResponse,
    };
    renderRegion("readiness", () => renderReadiness(overview), refreshReadinessRegion);
  }

  function metricCard(label, value, note, tone = "neutral") {
    const card = document.createElement("div");
    card.className = `metric-card metric-${tone}`;
    const heading = document.createElement("span");
    heading.className = "metric-label";
    heading.textContent = label;
    const number = document.createElement("strong");
    number.className = "metric-value";
    number.textContent = value === null || value === undefined ? "—" : String(value);
    const detail = document.createElement("span");
    detail.className = "metric-note";
    detail.textContent = note;
    card.append(heading, number, detail);
    return card;
  }

  function metricTone(value, warningAt = 1) {
    if (value === null || value === undefined || value === "") return "unknown";
    const number = Number(value);
    if (!Number.isFinite(number)) return "unknown";
    return number >= warningAt ? "warning" : "ok";
  }

  function renderLifecycle(overview) {
    const lifecycle = asObject(overview.lifecycle, "Lifecycle posture");
    const risk = asObject(lifecycle.risk_summary, "Certificate risk summary");
    const metrics = document.createElement("div");
    metrics.className = "metric-grid";
    metrics.append(
      metricCard("Expired", risk.expired, "Active certificates past validity", metricTone(risk.expired)),
      metricCard("Expiring in 7 days", risk.expiring_7_days, "Urgent renewals", metricTone(risk.expiring_7_days)),
      metricCard("Expiring in 30 days", risk.expiring_30_days, "Plan renewals this month", metricTone(risk.expiring_30_days)),
      metricCard("Pending approval", risk.pending_approval, "Certificate Operator queue", metricTone(risk.pending_approval)),
      metricCard("Renewal failures", risk.failed_renewals_30_days, "Last 30 days", metricTone(risk.failed_renewals_30_days)),
      metricCard("Notification failures", risk.failed_notifications_30_days, "Last 30 days", metricTone(risk.failed_notifications_30_days)),
    );
    element("dashboard-lifecycle").replaceChildren(metrics);
    setFreshness("lifecycle", overview, overview.generated_at);
  }

  function licenseNote(license) {
    const personalLicence = BB.licenseTierDisplay({ status: "none" }).label;
    if (license.key_configuration_error) {
      return `Embedded licensing key error: ${license.key_configuration_error} ${personalLicence} capacity applies.`;
    }
    if (!license.production_key_configured) {
      return `This development build has no embedded licensing public keys. ${personalLicence} capacity applies.`;
    }
    if (license.status === "valid") {
      const remaining = license.days_remaining === null || license.days_remaining === undefined
        ? "expiry unavailable"
        : `${license.days_remaining} days remaining`;
      return `Commercial Licence · Licensed to ${license.licensed_to || "this organization"} · ${remaining}`;
    }
    if (license.status === "expired") {
      return `License expired; ${personalLicence} capacity applies. Renewals and automation remain available.`;
    }
    if (license.status === "invalid") {
      return `Stored license is invalid; ${personalLicence} capacity applies. Renewals and automation remain available.`;
    }
    if (license.status === "not_yet_valid") {
      return `License is not active yet; ${personalLicence} capacity applies. Renewals and automation remain available.`;
    }
    return `${personalLicence} · All lifecycle and automation features are available.`;
  }

  function renderCapacity(overview) {
    const lifecycle = asObject(overview.lifecycle, "Capacity posture");
    const license = asObject(lifecycle.license, "License capacity");
    const risk = lifecycle.risk_summary || {};
    const active = license.active_lineages === null || license.active_lineages === undefined ? NaN : Number(license.active_lineages);
    const pending = risk.pending_approval === null || risk.pending_approval === undefined
      ? null
      : Number(risk.pending_approval);
    const limit = license.lineage_limit === null || license.lineage_limit === undefined ? NaN : Number(license.lineage_limit);
    if (!Number.isFinite(active) || !Number.isFinite(limit) || (pending !== null && !Number.isFinite(pending))) {
      throw new Error("License capacity was not returned by the server.");
    }
    const container = element("dashboard-capacity");
    const usage = document.createElement("div");
    usage.className = "capacity-usage";
    const headline = document.createElement("strong");
    headline.textContent = `${active} active of ${limit} certificate identities`;

    const meterMaximum = Math.max(limit, 1);
    const activeWidth = Math.min(Math.max(active, 0), meterMaximum);
    const pendingWidth = pending === null
      ? 0
      : Math.min(Math.max(pending, 0), Math.max(meterMaximum - activeWidth, 0));
    const meter = document.createElement("div");
    meter.className = "capacity-meter";
    meter.setAttribute("role", "progressbar");
    meter.setAttribute("aria-valuemin", "0");
    meter.setAttribute("aria-valuemax", String(limit));
    meter.setAttribute("aria-valuenow", String(active));
    meter.setAttribute(
      "aria-valuetext",
      pending === null
        ? `${active} active of ${limit} certificate identities; pending approvals unavailable`
        : `${active} active of ${limit} certificate identities; ${pending} pending approval and not included in active usage`,
    );
    const activeSegment = document.createElement("span");
    activeSegment.className = "capacity-meter-active";
    activeSegment.style.width = `${(activeWidth / meterMaximum) * 100}%`;
    meter.append(activeSegment);

    if (pending !== null && pending > 0) {
      const pendingSegment = document.createElement("span");
      pendingSegment.className = "capacity-meter-pending";
      pendingSegment.style.left = `${(activeWidth / meterMaximum) * 100}%`;
      pendingSegment.style.width = `${(pendingWidth / meterMaximum) * 100}%`;
      pendingSegment.setAttribute("aria-hidden", "true");
      meter.append(pendingSegment);
    }

    const note = document.createElement("p");
    note.textContent = licenseNote(license);
    BB.renderLicenseTier(license);
    usage.append(headline, meter);
    if (pending !== null && pending > 0) {
      const pendingSummary = document.createElement("div");
      pendingSummary.className = "capacity-pending-summary";
      const pendingMarker = document.createElement("span");
      pendingMarker.className = "capacity-pending-marker";
      pendingMarker.setAttribute("aria-hidden", "true");
      const pendingText = document.createElement("span");
      pendingText.textContent = `${pending} pending approval${pending === 1 ? "" : "s"} · not included in active usage`;
      pendingSummary.append(pendingMarker, pendingText);
      usage.append(pendingSummary);
    }
    usage.append(note);
    container.replaceChildren(usage);
    setFreshness("capacity", overview, overview.generated_at);
  }

  function outcomeBadge(outcome) {
    const normalized = String(outcome || "unknown").toLowerCase();
    const badge = document.createElement("span");
    const ok = ["success", "succeeded", "completed", "approved", "created", "updated"].includes(normalized);
    const failed = ["failed", "failure"].includes(normalized);
    const tone = ok ? "status-pass" : failed ? "status-fail" : normalized === "denied" ? "status-warn" : "status-unknown";
    badge.className = `status-pill ${tone}`;
    badge.textContent = humanize(normalized);
    return badge;
  }

  function renderChanges(overview) {
    const administrativeCategories = new Set(["system", "user", "permission", "issuer", "hsm", "audit"]);
    const changes = asArray(overview.recent_changes, "Recent changes")
      .filter((row) => row.actor_role === "admin" || administrativeCategories.has(row.category))
      .slice(0, 10);
    BB.renderTable(regionElement("changes"), changes, [
      { header: "When", sortValue: (row) => Date.parse(row.occurred_at || ""), render: (row) => formatDate(row.occurred_at) },
      { header: "Change", sortValue: (row) => `${row.category || ""} ${row.action || ""}`, render: (row) => `${humanize(row.category)} · ${humanize(row.action)}` },
      { header: "Object", sortValue: (row) => `${row.object_type || ""} ${row.object_id || ""}`, render: (row) => `${humanize(row.object_type)}${row.object_id ? ` · ${row.object_id}` : ""}` },
      { header: "Actor", sortValue: (row) => row.actor_email || row.actor_role || "System", render: (row) => row.actor_email || humanize(row.actor_role || "system") },
      { header: "Outcome", sortKey: "outcome", render: (row) => outcomeBadge(row.outcome) },
    ], {
      emptyText: "No recent administrative changes. New configuration and governance activity will appear here.",
      tableLabel: "Recent administrative changes",
    });
    setFreshness("changes", overview, overview.generated_at);
  }

  function setRefreshBusy(busy) {
    const button = element("dashboard-refresh");
    if (!button) return;
    button.disabled = busy;
    button.setAttribute("aria-busy", busy ? "true" : "false");
    button.textContent = busy ? "Refreshing…" : "Refresh overview";
  }

  function endpointOverview(payload = {}) {
    const checkedAt = new Date().toISOString();
    return {
      generated_at: checkedAt,
      freshness: { checked_at: checkedAt, is_stale: false },
      ...payload,
    };
  }

  async function refreshAttentionRegion() {
    setRegionLoading("attention");
    try {
      const [overview] = await Promise.all([
        BB.api("/internal/admin/operations"),
        BB.loadDashboardAlertMutes(),
      ]);
      renderRegion("attention", () => renderAttention(overview), refreshAttentionRegion);
    } catch (error) {
      showRegionError("attention", error, refreshAttentionRegion);
      const overall = element("dashboard-overall-status");
      overall.className = "status-pill status-unknown";
      overall.textContent = "Unavailable";
    }
  }

  async function refreshPendingNavigation() {
    const [overview] = await Promise.all([
      BB.api("/internal/admin/operations"),
      BB.loadDashboardAlertMutes(),
    ]);
    updatePendingNavigation(asArray(overview.attention_items, "Attention checks"));
  }

  async function refreshLifecycleRegion() {
    setRegionLoading("lifecycle");
    try {
      const risk = await BB.api("/internal/admin/risk-summary");
      const overview = endpointOverview({ lifecycle: { risk_summary: risk } });
      renderRegion("lifecycle", () => renderLifecycle(overview), refreshLifecycleRegion);
    } catch (error) {
      showRegionError("lifecycle", error, refreshLifecycleRegion);
    }
  }

  async function refreshCapacityRegion() {
    setRegionLoading("capacity");
    try {
      const [license, risk] = await Promise.all([
        BB.api("/internal/admin/license"),
        BB.api("/internal/admin/risk-summary").catch(() => null),
      ]);
      const overview = endpointOverview({
        lifecycle: {
          license,
          ...(risk ? { risk_summary: risk } : {}),
        },
      });
      renderRegion("capacity", () => renderCapacity(overview), refreshCapacityRegion);
    } catch (error) {
      showRegionError("capacity", error, refreshCapacityRegion);
    }
  }

  async function refreshActivity() {
    setRegionLoading("changes");
    try {
      const changes = await BB.api("/internal/audit/events?limit=40");
      const overview = endpointOverview({ recent_changes: changes });
      renderRegion("changes", () => renderChanges(overview), refreshActivity);
    } catch (error) {
      showRegionError("changes", error, refreshActivity);
    }
  }

  async function refresh() {
    const sequence = ++refreshSequence;
    REGION_KEYS.forEach(setRegionLoading);
    setRefreshBusy(true);
    element("dashboard-refresh-status").textContent = "Refreshing operational checks…";
    const [operations, readiness, risk, license] = await Promise.allSettled([
      BB.api("/internal/admin/operations"),
      BB.api("/internal/admin/readiness"),
      BB.api("/internal/admin/risk-summary"),
      BB.api("/internal/admin/license"),
      BB.loadDashboardAlertMutes(),
    ]);
    if (sequence !== refreshSequence) return;

    let unavailable = 0;
    if (operations.status === "fulfilled") {
      renderRegion("attention", () => renderAttention(operations.value), refreshAttentionRegion);
    } else {
      unavailable += 1;
      showRegionError("attention", operations.reason, refreshAttentionRegion);
      const overall = element("dashboard-overall-status");
      overall.className = "status-pill status-unknown";
      overall.textContent = "Unavailable";
    }

    if (readiness.status === "fulfilled") {
      const readinessResponse = readiness.value;
      const readinessOverview = {
        generated_at: readinessResponse.generated_at,
        freshness: readinessResponse.freshness,
        readiness: readinessResponse.readiness || readinessResponse,
      };
      renderRegion("readiness", () => renderReadiness(readinessOverview), refreshReadinessRegion);
    } else {
      unavailable += 1;
      showRegionError("readiness", readiness.reason, refreshReadinessRegion);
    }

    if (risk.status === "fulfilled") {
      const riskOverview = endpointOverview({ lifecycle: { risk_summary: risk.value } });
      renderRegion("lifecycle", () => renderLifecycle(riskOverview), refreshLifecycleRegion);
    } else {
      unavailable += 1;
      showRegionError("lifecycle", risk.reason, refreshLifecycleRegion);
    }

    if (license.status === "fulfilled") {
      const licenseOverview = endpointOverview({
        lifecycle: {
          license: license.value,
          ...(risk.status === "fulfilled" ? { risk_summary: risk.value } : {}),
        },
      });
      renderRegion("capacity", () => renderCapacity(licenseOverview), refreshCapacityRegion);
    } else {
      unavailable += 1;
      showRegionError("capacity", license.reason, refreshCapacityRegion);
    }

    const status = element("dashboard-refresh-status");
    status.textContent = unavailable
      ? `${REGION_KEYS.length - unavailable} of ${REGION_KEYS.length} dashboard sections updated · ${unavailable} unavailable · ${formatDate(new Date())}`
      : `All dashboard sections updated · ${formatDate(new Date())}`;
    status.classList.toggle("is-stale", unavailable > 0);
    setRefreshBusy(false);
  }

  function mount() {
    if (!mounted) {
      mounted = true;
      element("dashboard-refresh")?.addEventListener("click", () => refresh().catch(() => {}));
    }
    return refresh();
  }

  global.AdminDashboard = { mount, refresh, refreshActivity, refreshPendingNavigation };
})(window, myOwnCA);
