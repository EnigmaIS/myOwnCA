// Exercise the real template editor, including initial guidance and form events.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

class Element {
  constructor(value = "") {
    this.value = value;
    this.textContent = "";
    this.children = [];
    this.listeners = {};
    this.classList = { toggle() {}, remove() {} };
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  addEventListener(name, handler) { this.listeners[name] = handler; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  remove() { this.removed = true; }
}

function setup(mode, count = 0) {
  const form = new Element();
  form.elements = Object.fromEntries(Object.entries({
    id: "", name: "", profile: "host_tls", validity_days: "365",
    first_issuance_approvals: "2", renewal_approvals: "1",
  }).map(([name, value]) => [name, new Element(value)]));
  const nodes = Object.fromEntries([
    "key-usage-options", "extended-key-usage-options", "allowed-key-algorithm-options",
    "template-summary", "template-profile-summary", "template-dirty-state",
    "template-first-approval-help", "template-renewal-approval-help",
  ].map((id) => [`#${id}`, new Element()]));
  nodes["#template-profile"] = form.elements.profile;
  const save = new Element();
  form.querySelector = (selector) => selector === 'button[type="submit"]' ? save : nodes[selector];
  const checkboxes = () => Object.values(nodes).flatMap((node) => node.children)
    .flatMap((label) => label.children || []).filter((child) => child.type === "checkbox");
  form.querySelectorAll = (selector) => {
    if (selector === "input, select, textarea, button") return [...Object.values(form.elements), ...checkboxes(), save];
    const name = /input\[name="([^"]+)"\]/.exec(selector)?.[1];
    assert.ok(name, `Unexpected selector: ${selector}`);
    return checkboxes().filter((box) => box.name === name);
  };
  const fragment = { querySelector: (selector) => selector === "form" ? form : form.querySelector(selector) };
  let title;
  const app = {
    init: () => new Promise(() => {}),
    $: (selector) => selector === "#tpl-template-form"
      ? { content: { cloneNode: () => fragment } } : new Element(),
    checkedValues: (target, name) => target.querySelectorAll(`input[name="${name}"]`)
      .filter((box) => box.checked).map((box) => box.value),
    modal: (options) => { title = options.title; return { close() {} }; },
    api: () => { throw new Error("Guidance must not make API calls"); },
  };
  const source = mode === "create" ? null : {
    id: "test", name: "Test", profile: "host_tls", validity_days: 365,
    first_issuance_approvals: count, renewal_approvals: count,
    key_usages: ["digital_signature"], extended_key_usages: ["server_auth"],
    allowed_key_algorithms: ["rsa-2048"],
  };
  const context = vm.createContext({
    myOwnCA: app, AdminDashboard: {}, AdminBackups: {}, source, mode,
    window: { addEventListener() {} },
    document: {
      getElementById: () => null,
      createElement: () => new Element(), createTextNode: (text) => ({ textContent: text }),
    },
  });
  vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), context);
  vm.runInContext("openTemplateModal(source, mode)", context);
  assert.equal(title, `${mode[0].toUpperCase() + mode.slice(1)} template`);
  return { form, nodes, save };
}

function checkHelp(nodes, first, renewal) {
  const firstText = nodes["#template-first-approval-help"].textContent;
  const renewalText = nodes["#template-renewal-approval-help"].textContent;
  if (first === 0) {
    assert.match(firstText, /No Certificate Operator approval is required/);
    assert.match(firstText, /Assigning a holder can trigger issuance/);
    assert.match(firstText, /administrator/);
    assert.match(firstText, /Other issuance checks still apply/);
  } else {
    assert.ok(firstText.includes(first === 1 ? "Requires one Certificate Operator approval." : `Requires ${first} approvals from different Certificate Operators.`));
    assert.match(firstText, /Create certificate records the creating operator’s approval/);
    assert.ok(firstText.includes(first === 1 ? "automatically" : `${first - 1} additional approval${first === 2 ? " is" : "s are"} needed`));
  }
  if (renewal === 0) {
    assert.match(renewalText, /Allows automatic renewal without Certificate Operator approval/);
    assert.match(renewalText, /email code still require at least one approval/);
  } else {
    assert.equal(renewalText, renewal === 1 ? "Requires one Certificate Operator approval." : `Requires ${renewal} approvals from different Certificate Operators.`);
  }
  assert.match(nodes["#template-summary"].textContent,
    /Email-code renewals require at least one Certificate Operator approval/);
}

for (const mode of ["create", "clone", "edit", "view"]) {
  for (const count of mode === "create" ? [2] : [0, 1, 3]) {
    const { form, nodes, save } = setup(mode, count);
    checkHelp(nodes, count, mode === "create" ? 1 : count);
    if (mode === "view") {
      assert.equal(save.removed, true);
      assert.equal(form.listeners.input, undefined);
      assert.equal(form.listeners.change, undefined);
      for (const field of Object.values(form.elements)) assert.equal(field.disabled, true);
      continue;
    }
    for (const value of [0, 1, 2, 3]) {
      form.elements.first_issuance_approvals.value = String(value);
      form.listeners.input();
      checkHelp(nodes, value, Number(form.elements.renewal_approvals.value));
      form.elements.renewal_approvals.value = String(value);
      form.listeners.change();
      checkHelp(nodes, value, value);
    }
    assert.equal(save.removed, undefined);
  }
}
