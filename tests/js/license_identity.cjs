// Run the real shared renderer with a minimal DOM, without a browser dependency.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

class Element {
  constructor(tag = "div") { this.tagName = tag; this.children = []; this.hidden = true; this.value = ""; }
  set textContent(value) { this.value = value; this.children = []; }
  get textContent() { return this.value + this.children.map((child) => child.textContent).join(" "); }
  replaceChildren() { this.children = []; this.value = ""; }
  append(child) { this.children.push(child); }
}

const target = new Element();
const context = vm.createContext({
  document: {
    querySelectorAll: (selector) => selector === "[data-license-identity]" ? [target] : [],
    querySelector: () => null,
    createElement: (tag) => new Element(tag),
  },
  window: { addEventListener() {} },
  setTimeout, clearTimeout,
});
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), context);
const app = vm.runInContext("myOwnCA", context);
const identity = (status, company = "Acme Corp", verification_warning = false) => ({
  licensed_to: company, status, verification_warning,
});

async function check() {
  for (const company of ["Acme Corp", "Żółć & 株式会社", "A".repeat(256), "<img src=x onerror=alert(1)>"]) {
    app.renderLicenseIdentity(identity("valid", company));
    assert.equal(target.hidden, false);
    assert.equal(target.children[1].textContent, company);
    assert.equal(target.children[1].tagName, "strong");
    assert.equal(target.children[1].children.length, 0);
  }
  for (const [status, label] of [["expired", "Licence expired"], ["not_yet_valid", "Licence not yet active"]]) {
    app.renderLicenseIdentity(identity(status));
    assert.equal(target.textContent, `Licensed to Acme Corp ${label}`);
    app.renderLicenseIdentity(identity(status, "Acme Corp", true));
    assert.equal(target.textContent, `Licensed to Acme Corp ${label} Licence details unavailable`);
  }
  app.renderLicenseIdentity(identity("valid", "Cached company", true));
  assert.equal(target.textContent, "Licensed to Cached company Licence details unavailable");
  for (const state of [null, identity("invalid", "Untrusted company", true), { status: "unknown" }]) {
    app.renderLicenseIdentity(state);
    assert.equal(target.hidden, false);
    assert.equal(target.textContent, "Licence details unavailable");
  }
  app.renderLicenseTier({ status: "valid", licensed_to: "Replacement company" });
  assert.equal(target.textContent, "Licensed to Replacement company");
  app.renderLicenseTier({ status: "none", licensed_to: null });
  assert.equal(target.hidden, true);
  assert.equal(target.textContent, "");

  context.fetch = async () => { throw new Error("offline"); };
  await app.refreshLicenseIdentity();
  assert.equal(target.textContent, "Licence details unavailable");

  let resolveFetch;
  context.fetch = () => new Promise((resolve) => { resolveFetch = resolve; });
  const pending = app.refreshLicenseIdentity();
  app.renderLicenseTier({ status: "none", licensed_to: null });
  resolveFetch({ ok: true, status: 200, text: async () => JSON.stringify(identity("valid", "Old company")) });
  await pending;
  assert.equal(target.hidden, true, "late initial response must not undo licence removal");
  assert.equal(target.textContent, "");

  context.fetch = async (path) => {
    if (path === "/internal/auth/me") return {
      ok: true, status: 200,
      text: async () => JSON.stringify({ role: "user", stage: "active", email: "user@example.test" }),
    };
    throw new Error("identity unavailable");
  };
  const user = await app.init();
  assert.equal(user.role, "user", "identity failure must not prevent account initialization");
  console.log("Licence identity rendering, replacement, failure, and refresh-race checks passed.");
}
check().catch((error) => { console.error(error); process.exitCode = 1; });
