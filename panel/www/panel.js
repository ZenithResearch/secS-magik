// Vanilla JS for the secS permission control panel (M13.4b).
// Loads the wasm-bindgen module and drives the shared secs-permissions model.
// The policy is held in the browser (localStorage); there is no server.

import init, { grant, revoke, evaluate, list } from "./pkg/panel.js";

const STORAGE_KEY = "secs.permission.policy";
const DEMO_RESOURCE_CHOICES = [
  "demo.txt",
  "notes/example.md",
  "scripts/run-demo.sh",
];

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

function fileUriJoin(prefix, filename) {
  const base = prefix.trim() || "file:///tmp/secs-demo/";
  const root = base.endsWith("/") ? base : `${base.replace(/\/[^/]*$/, "")}/`;
  return `${root}${filename.split("/").map(encodeURIComponent).join("/")}`;
}

function selectedResourcePath(file) {
  return file.webkitRelativePath || file.name;
}

function resetResourceChoices(files = []) {
  const choice = $("resource_file_choice");
  choice.replaceChildren();
  const seen = new Set();
  for (const name of DEMO_RESOURCE_CHOICES) {
    seen.add(name);
    choice.append(new Option(name, name));
  }
  for (const file of files.sort((a, b) => selectedResourcePath(a).localeCompare(selectedResourcePath(b)))) {
    const relativePath = selectedResourcePath(file);
    if (!seen.has(relativePath)) {
      seen.add(relativePath);
      choice.append(new Option(relativePath, relativePath));
    }
  }
}

function populateResourceChoices() {
  const files = Array.from($("resource_files").files || []);
  resetResourceChoices(files);
  if (files.length) {
    appendFeed(`loaded ${files.length} visual resource candidate${files.length === 1 ? "" : "s"}`);
  }
}

function applySelectedResourceChoice() {
  const relativePath = $("resource_file_choice").value;
  if (!relativePath) {
    throw new Error("choose a file from the selected demo folder first");
  }
  const resource = fileUriJoin($("resource").value, relativePath);
  $("resource").value = resource;
  appendFeed(`selected visual resource ${resource}`);
}

function applyOpcodeSelection() {
  const select = $("opcode");
  const option = select.selectedOptions && select.selectedOptions[0];
  if (!option || !select.value) return;
  const operation = option.dataset.operation;
  if (operation) $("operation").value = operation;
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

$("resource_files").addEventListener("change", () =>
  withErrors(populateResourceChoices),
);

$("use_selected_resource").addEventListener("click", () =>
  withErrors(applySelectedResourceChoice),
);

$("opcode").addEventListener("change", () =>
  withErrors(applyOpcodeSelection),
);

init().then(() => {
  applyOpcodeSelection();
  resetResourceChoices();
  renderRecords();
});
