const cases = {
  success: {
    title: "SUCCESS — membership.provision accepted",
    decision: "EXECUTE ACCEPTED",
    steps: [
      ["pass", "bounded ingress / session", "caller packet is well-formed and within local demo bounds"],
      ["pass", "caller proof", "caller Ed25519 proof verifies for secS://caller-a"],
      ["pass", "receiver-local permission policy", "receiver policy allows membership.provision on castalia://member/alice"],
      ["pass", "Dregg-shaped authority evidence", "authority evidence is present and admitted through typed local checks"],
      ["pass", "wallet + trusted issuer", "wallet proof-of-possession and issuer credential checks pass"],
      ["pass", "resource lock", "resource_lock:verified — requested resource exactly matches the authority-bound resource"],
      ["pass", "handler + receipts", "VERIFY ACCEPTED and EXECUTE ACCEPTED receipts are emitted for operator inspection"],
    ],
    receipt: {
      demo_case: "success",
      operation: "membership.provision",
      requested_resource: "castalia://member/alice",
      verified_resource: "castalia://member/alice",
      verify_decision: "VERIFY ACCEPTED",
      execute_decision: "EXECUTE ACCEPTED",
      resource_lock_status: "resource_lock:verified",
      evidence_layers: [
        "caller_ed25519_proof",
        "receiver_local_permission_policy",
        "dregg_authority_evidence_adapter",
        "wallet_proof_of_possession",
        "trusted_issuer_membership_credential",
      ],
      receipt_claim: "local signed verify + execute receipts are inspectable and redaction-safe",
      production_boundary: "production-shaped local verifier path; no live Castalia/Dregg network call",
    },
  },
  resourceFailure: {
    title: "FAILURE — wrong resource rejected",
    decision: "VERIFY REJECTED",
    steps: [
      ["pass", "bounded ingress / session", "caller packet is well-formed and within local demo bounds"],
      ["pass", "caller proof", "caller Ed25519 proof verifies for secS://caller-a"],
      ["pass", "receiver-local permission policy", "policy would allow membership.provision only for the authority-bound resource"],
      ["pass", "Dregg-shaped authority evidence", "authority evidence is present, but binds a different resource"],
      ["fail", "resource lock", "resource_lock_violation — requested castalia://member/bob but evidence binds castalia://member/alice"],
      ["skip", "handler + execute receipt", "handler does not run after verification rejection"],
    ],
    receipt: {
      demo_case: "resource_lock_failure",
      operation: "membership.provision",
      requested_resource: "castalia://member/bob",
      verified_resource: "castalia://member/alice",
      verify_decision: "VERIFY REJECTED",
      reject_reason: "resource_lock_violation",
      execute_decision: "NOT RUN",
      receipt_claim: "wrong-resource requests fail closed before handler execution",
      production_boundary: "local deterministic check; no runtime Dregg finality or BLS threshold QC verification",
    },
  },
  missingEvidence: {
    title: "FAILURE — missing Dregg-shaped evidence rejected",
    decision: "VERIFY REJECTED",
    steps: [
      ["pass", "bounded ingress / session", "caller packet is well-formed and within local demo bounds"],
      ["pass", "caller proof", "caller Ed25519 proof verifies for secS://caller-a"],
      ["pass", "receiver-local permission policy", "receiver policy expects Dregg-shaped authority evidence for membership.provision"],
      ["fail", "Dregg-shaped authority evidence", "missing_dregg_authority_evidence — required evidence layer is absent"],
      ["skip", "wallet + trusted issuer", "later checks are not enough to replace the missing Dregg-shaped authority layer"],
      ["skip", "handler + execute receipt", "handler does not run after verification rejection"],
    ],
    receipt: {
      demo_case: "missing_evidence_failure",
      operation: "membership.provision",
      requested_resource: "castalia://member/alice",
      verify_decision: "VERIFY REJECTED",
      reject_reason: "missing_dregg_authority_evidence",
      execute_decision: "NOT RUN",
      receipt_claim: "broad caller packets or wallet proof alone do not become sufficient authority",
      production_boundary: "production-shaped evidence requirement; no public auditability or chain anchoring claimed",
    },
  },
};

function $(id) {
  return document.getElementById(id);
}

function renderCase(key) {
  const data = cases[key];
  $("case-title").textContent = `${data.title} · ${data.decision}`;
  const trace = $("trace");
  trace.replaceChildren();
  for (const [kind, title, detail] of data.steps) {
    const node = document.createElement("div");
    node.className = `step ${kind}`;
    node.innerHTML = `<b>${title}</b><span>${detail}</span>`;
    trace.appendChild(node);
  }
  $("receipt").textContent = JSON.stringify(data.receipt, null, 2);
}

$("run-success-case").addEventListener("click", () => renderCase("success"));
$("run-resource-lock-failure").addEventListener("click", () => renderCase("resourceFailure"));
$("run-missing-evidence-failure").addEventListener("click", () => renderCase("missingEvidence"));

renderCase("success");
