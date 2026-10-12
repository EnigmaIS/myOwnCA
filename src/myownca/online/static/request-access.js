// Public access-request form: submit -> email code -> confirm. No login.
const $ = (selector) => document.querySelector(selector);
let requestId = null;

function show(panel) {
  for (const id of ["panel-form", "panel-verify", "panel-done"]) {
    $(`#${id}`).classList.toggle("hidden", id !== panel);
  }
}

async function detail(response, fallback) {
  try {
    return (await response.json())?.detail || fallback;
  } catch {
    return fallback;
  }
}

$("#access-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const status = $("#form-status");
  status.textContent = "Submitting…";
  const response = await fetch("/internal/access-requests", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: form.elements.email.value,
      name: form.elements.name.value,
      kind: form.elements.kind.value,
      message: form.elements.message.value,
      website: form.elements.website.value,
    }),
  });
  if (!response.ok) {
    status.textContent = await detail(response, "Submission failed.");
    return;
  }
  const body = await response.json();
  requestId = body.request_id;
  $("#access-subtitle").textContent = "One step left.";
  show("panel-verify");
  $("#verify-form").elements.code.focus();
});

$("#verify-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const status = $("#verify-status");
  const response = await fetch(`/internal/access-requests/${encodeURIComponent(requestId)}/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code: event.currentTarget.elements.code.value }),
  });
  if (!response.ok) {
    status.textContent = await detail(response, "Verification failed.");
    return;
  }
  $("#access-subtitle").textContent = "All done.";
  show("panel-done");
});
