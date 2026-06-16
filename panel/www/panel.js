// Vanilla JS for the secS permission control panel (M13.4b).
// Loads the wasm-bindgen module and drives the shared secs-permissions model.
// The policy is held in the browser (localStorage); there is no server.

import init, { grant, revoke, evaluate, list } from "./pkg/panel.js";

const STORAGE_KEY = "secs.permission.policy";

const $ = (id) => document.getElementById(id);

function loadPolicy() {
  return localStorage.getItem(STORAGE_KEY) || "[]";
}

function savePolicy(json) {
  localStorage.setItem(STORAGE_KEY, json);
  renderRecords();
}

function renderRecords() {
  const policy = loadPolicy();
  try {
    const lines = list(policy);
    $("records").textContent = lines.length ? lines : "(no permission records)";
  } catch (err) {
    $("records").textContent = String(err);
  }
}

function parseOpcode(value) {
  const text = value.trim();
  const n = text.startsWith("0x") || text.startsWith("0X")
    ? parseInt(text.slice(2), 16)
    : parseInt(text, 10);
  if (Number.isNaN(n) || n < 0 || n > 255) {
    throw new Error(`invalid opcode "${value}" (use 0x50 or 80)`);
  }
  return n;
}

function fields() {
  return {
    caller: $("caller").value,
    opcode: parseOpcode($("opcode").value),
    operation: $("operation").value,
    resource: $("resource").value,
  };
}

function appendFeed(text, kind) {
  const div = document.createElement("div");
  div.textContent = `${new Date().toLocaleTimeString()}  ${text}`;
  if (kind) div.className = kind;
  $("feed").prepend(div);
}

function withErrors(fn) {
  try {
    fn();
  } catch (err) {
    appendFeed(`error: ${err.message || err}`, "deny");
  }
}

$("grant").addEventListener("click", () =>
  withErrors(() => {
    const f = fields();
    const updated = grant(
      loadPolicy(),
      f.caller,
      f.opcode,
      f.operation,
      f.resource,
      $("prefix").checked,
      $("deny").checked,
      BigInt($("not_before").value || "0"),
      BigInt($("not_after").value || "0"),
    );
    savePolicy(updated);
    appendFeed(`granted ${$("deny").checked ? "deny" : "allow"} for ${f.caller} on ${f.operation}`, "allow");
  }),
);

$("revoke").addEventListener("click", () =>
  withErrors(() => {
    const f = fields();
    const updated = revoke(loadPolicy(), f.caller, f.opcode, f.operation, f.resource);
    savePolicy(updated);
    appendFeed(`revoked matching records for ${f.caller} on ${f.resource}`);
  }),
);

$("evaluate").addEventListener("click", () =>
  withErrors(() => {
    const f = fields();
    const nowField = $("now").value.trim();
    const now = nowField ? BigInt(nowField) : BigInt(Math.floor(Date.now() / 1000));
    const decision = evaluate(loadPolicy(), f.caller, f.opcode, f.operation, f.resource, now);
    const allowed = decision === "ALLOW";
    appendFeed(`${decision}  (${f.caller} → ${f.operation} ${f.resource})`, allowed ? "allow" : "deny");
  }),
);

$("clear").addEventListener("click", () => {
  savePolicy("[]");
  appendFeed("cleared policy");
});

init().then(renderRecords);
