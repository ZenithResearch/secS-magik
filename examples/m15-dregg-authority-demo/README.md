# M15.8 Dregg authority demo

This is the demo surface for secS-magik as a receiver-held authority gate consuming Dregg-shaped evidence.

It is intentionally local and deterministic. It uses fixture-backed Dregg authority material and in-memory/local test state so the demo can be reproduced cold without secrets, external services, or live network calls.

## The claim

secS-magik can accept or reject a `membership.provision` call by verifying a caller-owned packet against receiver-held policy and Dregg-shaped authority evidence, then producing inspectable signed receipts for the verification and execution path.

That is the demo.

## What the demo shows

The demo proves this bounded pipeline:

```text
caller packet
  -> bounded ingress / session checks
  -> caller ed25519 proof verification
  -> receiver-local permission policy
  -> Dregg authority evidence adapter
  -> wallet proof-of-possession
  -> trusted issuer / root membership credential checks
  -> membership.provision handler
  -> signed verify + execute receipts
  -> operator inspection
```

In operational terms:

1. A caller cannot invoke the operation with only a broad bearer token.
2. The receiver chooses the operation policy and authority registry.
3. Dregg-shaped authority evidence is admitted only through typed adapter checks.
4. Resource-lock mismatch rejects instead of widening authority.
5. Delegated or requested authority cannot amplify beyond the trusted/decrypted call material.
6. The accepted path produces redaction-safe, inspectable receipts.

## What the demo does not claim

This demo does not prove:

- live outbound Castalia Dregg network operation;
- production deployment proof;
- public auditability or chain anchoring;
- Dregg blocklace finality or BLS threshold QC verification at runtime;
- Midnight proof verification;
- Cardano settlement/finality;
- full Castalia wallet-core parity;
- network-facing TLS, DoS resistance, or multi-node consensus.

Those are post-demo rails. The current demo proves the receiver-held authority gate and the Dregg-shaped evidence boundary.

## Quick run

From a clean checkout:

```bash
cd /Users/bananawalnut/repos/secS-magik

cargo test -p server --test production_federated \
  membership_provision_e2e_contract_reaches_verify_execute_and_ledger_inspection \
  -- --nocapture

cargo test -p server --test production_federated \
  m15_8_finalizer_binds_resource_locked_dregg_authority_into_signed_context \
  -- --nocapture

cargo test -p server --test ready_for_prod_docs \
  dregg_authority_docs_record_144_finalizer_and_demo_without_live_proof_overclaim \
  -- --nocapture
```

Expected result: all three tests pass.

## Web demo

The runnable browser walkthrough lives in:

```text
examples/m15-dregg-authority-demo/web/index.html
```

Run it locally:

```bash
cd /Users/bananawalnut/repos/secS-magik/examples/m15-dregg-authority-demo/web
python3 -m http.server 8765
```

Then open:

```text
http://127.0.0.1:8765/
```

The web demo guides an operator through three cases:

1. **Success:** all local policy, Dregg-shaped evidence, wallet/issuer, and resource-lock checks line up, so the simulated trace reaches `VERIFY ACCEPTED` and `EXECUTE ACCEPTED`.
2. **Failure — wrong resource:** the caller asks for a resource different from the Dregg-shaped authority-bound resource, so the trace rejects with `resource_lock_violation` before execution.
3. **Failure — missing evidence:** the caller has a packet, but the required Dregg-shaped authority evidence is absent, so the trace rejects with `missing_dregg_authority_evidence` before execution.

The web page is an explanatory static UI over the same bounded demo claim. It does not call the Rust verifier, does not call a live Castalia/Dregg network, and does not replace the executable evidence tests below. Use it for pitch walkthroughs and use the Rust tests for executable proof.

## Full verification

```bash
cd /Users/bananawalnut/repos/secS-magik

cargo test --workspace --all-targets --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

At the current verified demo point, the full workspace has passed with 579 tests and Rust CI has passed on `main`.

## Human-readable checklist

Run:

```bash
cd /Users/bananawalnut/repos/secS-magik
./examples/m15-dregg-authority-demo.sh
```

This script prints the bounded demo checklist and the exact local executable evidence commands. It does not start a live service.

## Deeper runbook

The operator runbook is:

```text
docs/ops/demo-runbook.md
```

Use it when someone needs a colder reproduction path, the test-by-layer matrix, or the standalone-gateway fixture setup notes.

## Current post-demo state

Issue #206 is closed under its no-live-network source-client boundary. The live source client now has:

- explicit config/readiness gates;
- deterministic no-network request building;
- source-authentication and source-trust checks;
- injectable transport seam;
- fail-closed response validation;
- response-to-authority snapshot mapping;
- persistent cache integration;
- no live HTTP transport wired into the verification path.

The next settlement rail is Cardano #75. Devgraph continues as an application-layer work graph; it is not a dependency for this demo.