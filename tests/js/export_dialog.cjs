// Exercise the real export handler with a minimal DOM and controlled responses.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

class Element {
  constructor(tag) {
    this.tagName = tag;
    this.children = [];
    this.attributes = {};
    this.listeners = {};
    this.className = "";
    this.value = "";
    this.textContent = "";
    this.classList = {
      contains: (name) => this.className.split(" ").includes(name),
      add: (name) => {
        if (!this.classList.contains(name)) this.className += ` ${name}`;
      },
      remove: (name) => {
        this.className = this.className.split(" ").filter((item) => item !== name).join(" ");
      },
      toggle: (name, force) => {
        const enabled = force ?? !this.classList.contains(name);
        this.classList[enabled ? "add" : "remove"](name);
        return enabled;
      },
    };
  }
  append(...children) {
    children.forEach((child) => { child.parent = this; this.children.push(child); });
    if (this.tagName === "select" && !this.value) this.value = this.children[0].value;
  }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; }
  addEventListener(name, handler) { this.listeners[name] = handler; }
  querySelector() { return find(this, (node) => node.tagName === "input"); }
  focus() {}
  click() { this.clicked = true; }
  remove() { this.parent.children = this.parent.children.filter((child) => child !== this); }
}

function find(root, matches) {
  for (const child of root.children) {
    if (matches(child)) return child;
    const found = find(child, matches);
    if (found) return found;
  }
  return null;
}

const user = (method = "password", recent = true) => ({
  role: "user", csrf_token: "csrf", sensitive_auth: { method, recent },
});
const response = (body, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  statusText: "",
  text: async () => JSON.stringify(body),
  json: async () => body,
  blob: async () => "certificate bundle",
  headers: { get: () => 'attachment; filename="u1.pfx"' },
});

async function setup(format = "pkcs12", method = "password", inventory = true) {
  const body = new Element("body");
  const output = new Element("pre");
  const queue = [];
  const requests = [];
  const downloads = [];
  const context = vm.createContext({
    document: {
      body,
      querySelector: (selector) => selector === "#output" ? output : null,
      querySelectorAll: () => [],
      createElement: (tag) => {
        const node = new Element(tag);
        if (tag === "a") downloads.push(node);
        return node;
      },
      addEventListener() {}, removeEventListener() {},
    },
    window: { addEventListener() {} },
    URL: { createObjectURL: () => "blob:export", revokeObjectURL() {} },
    fetch: async (path, options) => {
      requests.push({ path, options });
      assert.ok(queue.length, `Unexpected request: ${path}`);
      const next = queue.shift();
      if (next instanceof Error) throw next;
      return await next;
    },
    setTimeout, clearTimeout,
  });
  vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), context);
  const app = vm.runInContext("myOwnCA", context);
  queue.push(response(user(method)));
  await app.init();
  app.openExportModal({
    subject: "CN=u1", serial_number: "123", server_key_held: true, status: "active",
    ...(inventory ? { certificate_id: "cert-1" } : {}),
  });
  const overlay = body.children[0];
  const form = find(overlay, (node) => node.tagName === "form");
  const select = find(form, (node) => node.tagName === "select");
  select.value = format;
  await select.listeners.change();
  const password = find(form, (node) => node.name === "password");
  password.value = "export-secret";
  const credential = find(form, (node) => ["current_password", "totp_code"].includes(node.name));
  const error = find(form, (node) => node.attributes.role === "alert");
  assert.ok(error.classList.contains("hidden"), "error is hidden initially");
  const submit = () => form.listeners.submit({ preventDefault() {} });
  const failed = (message) => {
    assert.equal(error.textContent, `Export failed: ${message}`);
    assert.equal(error.classList.contains("hidden"), false);
    assert.ok(error.classList.contains("is-error"));
    assert.ok(body.children.includes(overlay), "failure keeps the dialog open");
    assert.equal(password.value, "export-secret");
    assert.equal(downloads.length, 0, "failure must not start a download");
    assert.equal(JSON.parse(output.textContent).error, message);
    assert.equal(queue.length, 0);
  };
  return { queue, requests, downloads, body, overlay, password, credential, error, submit, failed };
}

async function check() {
  // Fresh authentication can expire between opening the dialog and submitting.
  const expired = await setup();
  expired.queue.push(response(user("password", false)));
  await expired.submit();
  expired.failed("Enter your current password to export the private key.");
  assert.equal(expired.credential.required, true);
  assert.equal(expired.requests.length, 2, "missing credentials prevent export");

  // Error clears at retry start, while the request is still pending.
  expired.credential.value = "account-secret";
  let resolveMe;
  expired.queue.push(new Promise((resolve) => { resolveMe = resolve; }));
  const retry = expired.submit();
  assert.equal(expired.error.classList.contains("hidden"), true);
  assert.equal(expired.error.textContent, "");
  expired.queue.push(response(user()), response(null));
  resolveMe(response(user("password", false)));
  await retry;
  assert.equal(expired.body.children.includes(expired.overlay), false);
  assert.equal(expired.downloads[0].clicked, true);
  assert.equal(expired.downloads[0].download, "u1.pfx");
  const reauth = expired.requests[3];
  assert.equal(reauth.path, "/internal/auth/password/reauthenticate");
  assert.deepEqual(JSON.parse(reauth.options.body), { password: "account-secret" });
  assert.deepEqual(JSON.parse(expired.requests[4].options.body), {
    format: "pkcs12", password: "export-secret",
  });

  for (const method of ["password", "totp"]) {
    const rejected = await setup("pkcs12", method);
    rejected.credential.value = method === "totp" ? "123456" : "wrong-password";
    rejected.queue.push(response(user(method, false)), response({ detail: "Invalid credentials" }, 401));
    await rejected.submit();
    rejected.failed("Invalid credentials");
    assert.equal(rejected.requests[2].path, `/internal/auth/${method}/reauthenticate`);
    assert.equal(rejected.credential.value, method === "totp" ? "123456" : "wrong-password");
  }

  const signedOut = await setup();
  signedOut.queue.push(response({ detail: "Not authenticated" }, 401));
  await signedOut.submit();
  signedOut.failed("Not authenticated");

  for (const format of ["pkcs12", "pem"]) {
    for (const inventory of [true, false]) {
      const rejected = await setup(format, "password", inventory);
      if (format === "pkcs12") rejected.queue.push(response(user()));
      rejected.queue.push(response({ detail: "Export unavailable" }, 403));
      await rejected.submit();
      rejected.failed("Export unavailable");
      assert.equal(rejected.requests.at(-1).options.method || "GET", format === "pem" ? "GET" : "POST");
      assert.ok(rejected.requests.at(-1).path.startsWith(
        inventory ? "/internal/certificate-inventory/cert-1/export" : "/internal/certificates/123/export",
      ));
      if (format === "pkcs12") rejected.queue.push(response(user()));
      rejected.queue.push(response(null));
      await rejected.submit();
      assert.equal(rejected.body.children.includes(rejected.overlay), false);
      assert.equal(rejected.downloads[0].clicked, true);
    }
  }

  const offline = await setup();
  offline.queue.push(new Error("Failed to fetch"));
  await offline.submit();
  offline.failed("Failed to fetch");
  console.log("Export dialog authentication, failure feedback, and retry checks passed.");
}

check().catch((error) => { console.error(error); process.exitCode = 1; });
