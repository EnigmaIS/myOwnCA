(function (global, BB) {
  "use strict";

  let mounted = false;
  let latest = null;

  function formatDate(value) {
    return value ? new Date(value).toLocaleString() : "—";
  }

  function formatBytes(value) {
    const bytes = Number(value || 0);
    if (!Number.isFinite(bytes) || bytes <= 0) return "—";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let amount = bytes;
    let unit = 0;
    while (amount >= 1024 && unit < units.length - 1) {
      amount /= 1024;
      unit += 1;
    }
    return `${amount.toFixed(unit ? 1 : 0)} ${units[unit]}`;
  }

  function renderList(id, values) {
    const root = BB.$(`#${id}`);
    root.replaceChildren(...(values || []).map((value) => {
      const item = document.createElement("li");
      item.textContent = value;
      return item;
    }));
  }

  function freshness(deliveredAt, freshDays, staleDays) {
    if (!deliveredAt) return { label: "No completed backup", tone: "fail" };
    const ageDays = Math.max(0, (Date.now() - Date.parse(deliveredAt)) / 86_400_000);
    if (ageDays <= freshDays) return { label: "Current", tone: "pass" };
    if (ageDays <= staleDays) return { label: "Due soon", tone: "warn" };
    return { label: "Overdue", tone: "fail" };
  }

  function renderPending(pending) {
    const root = BB.$("#backups-pending");
    if (!pending) {
      root.replaceChildren();
      const empty = document.createElement("p");
      empty.className = "hint";
      empty.textContent = "No application backup request is awaiting approval.";
      root.append(empty);
      return;
    }
    const selfProposed = pending.proposer_id === BB.currentUser?.user_id;
    const summary = document.createElement("p");
    summary.textContent = `Requested by ${pending.proposer_email} at ${formatDate(pending.created_at)}; expires ${formatDate(pending.expires_at)}.`;
    const reason = document.createElement("p");
    reason.className = "hint";
    reason.textContent = `Reason: ${pending.reason}`;
    const actions = document.createElement("div");
    actions.className = "actions";
    const approve = BB.actionButton("Approve, create & download", () => approveBackup(pending));
    approve.disabled = selfProposed;
    approve.title = selfProposed ? "A different administrator must approve this request" : "";
    actions.append(approve, BB.actionButton("Reject", () => rejectBackup(pending), "danger"));
    root.replaceChildren(summary, reason, actions);
  }

  function renderHistory(items) {
    BB.renderTable(BB.$("#backups-history"), items || [], [
      { header: "Created", render: (row) => formatDate(row.created_at) },
      { header: "Requester", render: (row) => row.requester_email },
      { header: "Approver", render: (row) => row.approver_email },
      { header: "Database", key: "database_dialect" },
      { header: "Size", render: (row) => formatBytes(row.size_bytes) },
      { header: "SHA-256", render: (row) => row.sha256 || "—" },
      { header: "Status", key: "status" },
      { header: "Delivered", render: (row) => formatDate(row.delivered_at) },
      {
        header: "Action",
        render: (row) => {
          if (!row.download_href) return "—";
          return BB.actionButton("Download", () => beginDownload(row));
        },
      },
    ], { emptyText: "No application backup exports have been generated." });
  }

  function render(body) {
    latest = body;
    renderList("backups-included", body.included);
    renderList("backups-excluded", body.excluded);
    renderPending(body.pending);
    renderHistory(body.exports);
    const completed = body.latest_delivered;
    const state = freshness(completed?.delivered_at, body.fresh_days, body.stale_days);
    const badge = BB.$("#backups-freshness");
    badge.className = `status-pill status-${state.tone}`;
    badge.textContent = state.label;
    BB.$("#backups-status").textContent = completed
      ? `Latest encrypted archive delivered ${formatDate(completed.delivered_at)} by ${completed.approver_email}; ${formatBytes(completed.size_bytes)}, SHA-256 ${completed.sha256}. Off-host storage and restore success are not verified.`
      : body.active_admin_count < 2
        ? `No completed application backup. Two active administrators are required; ${body.active_admin_count} is currently available.`
        : `No completed application backup. Database: ${body.database_dialect}; issuer backend: ${body.issuer_backend}.`;
    BB.$("#backups-request").disabled = Boolean(body.pending) || body.active_admin_count < 2;
  }

  async function refresh() {
    BB.$("#backups-status").textContent = "Loading backup status…";
    render(await BB.api("/internal/admin/backups"));
  }

  function requestBackup() {
    global.AdminSafety.confirm({
      title: "Request encrypted application backup",
      impact: [
        "The archive contains the complete database, software private keys, and recovery secrets.",
        "Keep your passphrase share separate. A different administrator supplies the second share and receives the archive.",
        "HSM/DKEK material, cloud private keys, and Offline Root private material are excluded.",
      ],
      confirmation: "REQUEST APPLICATION BACKUP",
      actionLabel: "Create approval request",
      extraFields: [
        { name: "requester_passphrase", label: "Requester passphrase share (16+ characters)", type: "password", autocomplete: "new-password" },
        { name: "requester_passphrase_confirmation", label: "Confirm requester passphrase share", type: "password", autocomplete: "new-password" },
      ],
      perform: (context) => {
        if (context.values.requester_passphrase.length < 16) throw new Error("Requester passphrase share must contain at least 16 characters.");
        if (context.values.requester_passphrase !== context.values.requester_passphrase_confirmation) throw new Error("Requester passphrase shares do not match.");
        return BB.api("/internal/admin/backups/proposals", {
          method: "POST",
          body: JSON.stringify(global.AdminSafety.withContext({
            requester_passphrase: context.values.requester_passphrase,
            requester_passphrase_confirmation: context.values.requester_passphrase_confirmation,
          }, context)),
        });
      },
      onSuccess: refresh,
    });
  }

  function approveBackup(proposal) {
    global.AdminSafety.confirm({
      title: "Approve and create application backup",
      impact: [
        `Request ${proposal.id} was created by ${proposal.proposer_email}.`,
        "Your passphrase share is never stored. Both administrators' original shares are required to verify or restore the archive.",
        "Generation may take several minutes for a large database. The encrypted file remains downloadable for 30 minutes.",
      ],
      confirmation: "APPROVE APPLICATION BACKUP",
      actionLabel: "Approve and generate",
      extraFields: [
        { name: "approver_passphrase", label: "Approver passphrase share (16+ characters)", type: "password", autocomplete: "new-password" },
        { name: "approver_passphrase_confirmation", label: "Confirm approver passphrase share", type: "password", autocomplete: "new-password" },
      ],
      perform: async (context) => {
        if (context.values.approver_passphrase.length < 16) throw new Error("Approver passphrase share must contain at least 16 characters.");
        if (context.values.approver_passphrase !== context.values.approver_passphrase_confirmation) throw new Error("Approver passphrase shares do not match.");
        const result = await BB.api(`/internal/admin/backups/proposals/${encodeURIComponent(proposal.id)}/approve`, {
          method: "POST",
          body: JSON.stringify(global.AdminSafety.withContext({
            approver_passphrase: context.values.approver_passphrase,
            approver_passphrase_confirmation: context.values.approver_passphrase_confirmation,
          }, context)),
        });
        beginDownload(result);
        return result;
      },
      onSuccess: () => pollForDelivery(),
    });
  }

  async function rejectBackup(proposal) {
    if (!global.confirm(`Reject application backup request ${proposal.id}? The stored requester share will be destroyed.`)) return;
    await BB.api(`/internal/admin/backups/proposals/${encodeURIComponent(proposal.id)}/reject`, { method: "POST" });
    await refresh();
  }

  function beginDownload(item) {
    const link = document.createElement("a");
    link.href = item.download_href || `/internal/admin/backups/exports/${encodeURIComponent(item.id)}/download`;
    link.download = item.filename || "myownca-application-backup.myownca-backup";
    document.body.append(link);
    link.click();
    link.remove();
  }

  async function pollForDelivery() {
    for (let attempt = 0; attempt < 60; attempt += 1) {
      await new Promise((resolve) => global.setTimeout(resolve, 1000));
      const body = await BB.api("/internal/admin/backups");
      render(body);
      if (body.exports?.[0]?.status !== "ready") return;
    }
  }

  function mount() {
    if (!mounted) {
      mounted = true;
      BB.$("#backups-refresh").addEventListener("click", () => refresh().catch(BB.showError));
      BB.$("#backups-request").addEventListener("click", requestBackup);
    }
    return refresh();
  }

  global.AdminBackups = { mount, refresh, get latest() { return latest; } };
})(window, myOwnCA);
