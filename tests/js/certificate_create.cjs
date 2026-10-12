// Run the real creation dialog with a minimal DOM and controlled API results.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

class Element {
  constructor(value = "") {
    this.value = value;
    this.listeners = {};
    this.classList = { toggle() {} };
  }
  addEventListener(name, handler) { this.listeners[name] = handler; }
  replaceChildren(...options) { this.value = options[0]?.value || ""; }
}

const pending = (required, extra = {}) => ({
  id: "request-1", status: "pending", required_approvals: required,
  approval_count: 0, approved_by_current_user: false,
  auto_issued: false, auto_issue_error: null, issued_certificate: null,
  ...extra,
});
const issued = (required, extra = {}) => pending(required, {
  status: "issued", auto_issued: true,
  issued_certificate: { request_id: "request-1", serial_number: "123" }, ...extra,
});
const approval = { approval_count: 1, approved_by_current_user: true };

async function run(required, holderResult, approvalResult, options = {}) {
  const fields = {
    common_name: new Element(), dns_names: new Element(),
    email_addresses: new Element(), algorithm: new Element(),
  };
  const form = new Element();
  form.elements = fields;
  const nodes = {
    "#cert-create-template": new Element(),
    "#cert-create-type": new Element(options.holderType || "person"),
    "#cert-create-person-label": new Element(),
    "#cert-create-device-label": new Element(),
    "#cert-create-person": new Element(),
    "#cert-create-device": new Element(),
  };
  const fragment = { querySelector: (selector) => selector === "form" ? form : nodes[selector] };
  const queue = [{ id: "request-1" }, holderResult];
  if (approvalResult) queue.push(approvalResult);
  const state = { calls: [], details: [], closed: false, refreshed: 0 };
  const app = {
    init: () => new Promise(() => {}),
    $: (selector) => selector === "#tpl-cert-create-form"
      ? { content: { cloneNode: () => fragment } } : new Element(),
    fillSelect: (select, rows) => { select.value = rows[0].id; },
    syncProfileSanFields() {},
    profileSanPayload: () => ({ dns_names: ["cert.example.test"] }),
    modal: ({ content }) => {
      assert.equal(content, form);
      return { close: () => { state.closed = true; } };
    },
    showResult: (details) => state.details.push(details),
    api: async (path, config) => {
      state.calls.push({ path, config });
      if (path === "/internal/templates") return [{
        id: "template-1", profile: "host_tls", first_issuance_approvals: required,
        allowed_key_algorithms: ["rsa-2048"],
      }];
      if (path === "/internal/people") return [{ id: "person-1", full_name: "Alice" }];
      if (path === "/internal/devices") return [{ id: "device-1", fqdn: "cert.example.test" }];
      if (path === "/internal/hsm/status") return { pin_required: false };
      assert.ok(queue.length, `Unexpected request: ${path}`);
      const result = queue.shift();
      if (result instanceof Error) throw result;
      return result;
    },
  };
  const context = vm.createContext({
    myOwnCA: app, window: { addEventListener() {} },
    document: { createElement: () => new Element() }, state,
  });
  vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), context);
  vm.runInContext("refreshCertificates = async () => { state.refreshed += 1; };", context);
  await vm.runInContext("openCertCreateModalAsync()", context);
  await form.listeners.submit({ preventDefault() {} });
  assert.equal(queue.length, 0, "Consume the expected responses exactly once");
  const posts = state.calls.filter(({ config }) => config?.method === "POST");
  assert.deepEqual(posts.map(({ path }) => path), [
    "/internal/certificate-requests/generate",
    "/internal/certificate-requests/request-1/holder",
    ...(approvalResult ? ["/internal/certificate-requests/request-1/approvals"] : []),
  ]);
  assert.deepEqual(JSON.parse(posts[1].config.body), options.holderType === "device"
    ? { device_id: "device-1" } : { person_id: "person-1" });
  assert.equal(state.closed, true);
  assert.equal(state.refreshed, 1);
  assert.equal(state.details.length, 1);
  assert.equal(state.details[0].error, undefined);
  assert.equal(state.calls.some(({ path }) => path === "/internal/hsm/status"), required <= 1);
  return state.details[0];
}

async function check() {
  for (const holderType of ["person", "device"]) {
    const success = await run(0, issued(0), null, { holderType });
    assert.equal(success.status, "Certificate issued.");
    assert.equal(success.serial_number, "123");
  }
  const single = await run(1, pending(1), issued(1, approval));
  assert.equal(single.status, "Certificate issued.");
  // Use the server's current threshold rather than the template fetched on open.
  const multiple = await run(2, pending(3), pending(3, approval));
  assert.equal(multiple.status,
    "Request created — holder assigned, your approval recorded. 2 more approval(s) needed.");

  const queued = { code: "cloud_signing_queued", message: "Queued for cloud signing.", job_id: "job-1" };
  const holderQueued = await run(0, pending(0, { auto_issue_error: queued }));
  assert.equal(holderQueued.status, queued.message);
  assert.equal(holderQueued.auto_issue_error.job_id, "job-1");
  const approvalQueued = await run(1, pending(1), pending(1, { ...approval, auto_issue_error: queued }));
  assert.equal(approvalQueued.status, queued.message);

  for (const code of ["duplicate_certificate_identity", "hsm_locked", "no_issuer"]) {
    const error = { code, message: `Issuance failed: ${code}` };
    const holderError = await run(0, pending(0, { auto_issue_error: error }));
    assert.equal(holderError.warning, error.message);
    assert.equal(holderError.request_id, "request-1");
    assert.equal(holderError.next_step.includes("approval is preserved"), false);
    assert.ok(holderError.next_step.includes("request remains pending"));
    const approvalError = await run(1, pending(1), pending(1, { ...approval, auto_issue_error: error }));
    assert.equal(approvalError.warning, error.message);
    assert.ok(approvalError.next_step.includes("Your approval is preserved"));
  }
}

check().catch((error) => { console.error(error); process.exitCode = 1; });
