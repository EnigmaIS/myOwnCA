const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const elements = new Map();
function element(selector) {
  if (!elements.has(selector)) {
    elements.set(selector, {
      textContent: "", value: "reuse", handlers: {},
      classList: { toggle() {}, remove() {} },
      addEventListener(event, handler) { this.handlers[event] = handler; },
      elements: new Proxy({}, { get: (_, key) => element(`${selector}:${String(key)}`) }),
    });
  }
  return elements.get(selector);
}

let result;
const context = vm.createContext({
  window: { location: { pathname: "/claim/test-token" } },
  document: { querySelector: element },
  myOwnCA: { renderLicenseIdentity() {} },
  fetch: async (path) => path.endsWith("/state")
    ? new Promise(() => {})
    : { ok: true, json: async () => result },
});
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), context);

async function check() {
  const form = element("#renew-form");
  const submit = () => form.handlers.submit({ preventDefault() {}, currentTarget: form });
  for (const code of ["issuer_expired", "issuer_not_yet_valid", "issuer_validity_exceeded"]) {
    const message = "Contact the CA administrator; <test> is plain text.";
    result = { issued_serial_number: null, auto_issue_error: { code, message } };
    await submit();
    assert.equal(element("#renewed-message").textContent, message);
    assert.match(element("#claim-subtitle").textContent, /needs attention/);
  }
  result = { auto_issue_error: { code: "cloud_signing_queued", message: "Queued for signing." } };
  await submit();
  assert.equal(element("#renewed-message").textContent, "Queued for signing.");
  assert.doesNotMatch(element("#claim-subtitle").textContent, /needs attention/);
  result = { requires_approval: true, auto_issue_error: null };
  await submit();
  assert.match(element("#renewed-message").textContent, /awaits Certificate Operator approval/);
  result = { issued_serial_number: "abc", auto_issue_error: null };
  await submit();
  assert.match(element("#renewed-message").textContent, /certificate was issued/);

  let displayed;
  const operatorContext = vm.createContext({
    window: { addEventListener() {} },
    myOwnCA: {
      $: element,
      init: () => new Promise(() => {}),
      api: async () => result,
      showResult: (value) => { displayed = value; },
    },
  });
  vm.runInContext(fs.readFileSync(path.join(path.dirname(process.argv[2]), "superuser.js"), "utf8"), operatorContext);
  // Table refresh is independent of the issuance result displayed to the operator.
  vm.runInContext("refreshRequests = async () => {};", operatorContext);
  result = { status: "pending", auto_issue_error: {
    code: "issuer_validity_exceeded", message: "Ask the CA administrator to review validity.",
  } };
  await operatorContext.approveRequest("request-1");
  assert.equal(displayed.warning, result.auto_issue_error.message);
  assert.match(displayed.next_step, /approval is preserved/);
  result = { status: "pending", auto_issue_error: {
    code: "cloud_signing_queued", message: "Queued for signing.",
  } };
  await operatorContext.approveRequest("request-1");
  assert.equal(displayed.status, "Queued for signing.");
  assert.equal(displayed.warning, undefined);
}
check().catch((error) => { console.error(error); process.exitCode = 1; });
