const BB = myOwnCA;

BB.init("auditor").then(() => {
  BB.mountRecoveryCodes("#account-security");
  return loadAudit();
}).catch(BB.showError);
BB.$("#audit-refresh").addEventListener("click", () => loadAudit().catch(BB.showError));
BB.$("#audit-category").addEventListener("change", () => loadAudit().catch(BB.showError));
BB.$("#clear-output").addEventListener("click", () => BB.setOutput("Select an event to inspect its full record."));

BB.$("#audit-verify").addEventListener("click", async () => {
  try {
    const result = await BB.api("/internal/audit/verify");
    const node = BB.$("#audit-integrity");
    node.textContent = result.ok
      ? "✓ Audit chain integrity verified."
      : `✗ Audit chain verification failed at sequence ${result.first_bad_sequence}.`;
    BB.setOutput(result);
  } catch (error) {
    BB.showError(error);
  }
});

async function loadAudit() {
  const category = BB.$("#audit-category").value;
  const params = new URLSearchParams({ limit: "200" });
  if (category) params.set("category", category);
  const events = await BB.api(`/internal/audit/events?${params.toString()}`);
  BB.renderTable(BB.$("#audit-table"), events, [
    { header: "When", render: (row) => new Date(row.occurred_at).toLocaleString() },
    { header: "Category", key: "category" },
    { header: "Action", key: "action" },
    { header: "Outcome", key: "outcome" },
    { header: "Actor", render: (row) => row.actor_email || row.actor_id || row.actor_role || "—" },
    { header: "Source IP", render: (row) => row.source_ip || "—" },
    {
      header: "Object",
      render: (row) => (row.object_type ? `${row.object_type}:${row.object_id ?? ""}` : "—"),
    },
    { header: "", render: (row) => BB.actionButton("Detail", () => BB.setOutput(row)) },
  ]);
}
