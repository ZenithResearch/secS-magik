# secS-magik implementation progress checklist

Use this as the running checklist for the current implementation train. Keep one commit per issue/slice.

## CI / quality gate

- [x] Confirm GitHub Actions workflow exists: `.github/workflows/rust.yml`.
- [x] Align local verification with CI commands:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo build --workspace --all-targets --all-features --verbose`
  - `cargo test --workspace --all-targets --all-features --verbose`
- [x] Fix strict Clippy blocker: `VerificationDecision` large enum variant.
- [x] Make CI cache key product-neutral.
- [x] Verify merged `main` locally with the full CI-equivalent command sequence.
- [x] Verify GitHub Actions green on `main`: Rust CI run `26790706460` succeeded for `test: lock packet and opcode regressions`.

## Phase 0

- [x] Issue 0.0 — Add the current spec to repo docs.
- [x] Issue 0.1 — Align codebase layout with the current secS direction.
- [x] Issue 0.2 — Add regression tests for preserved packet and opcode behavior.

## Phase 1

- [x] Issue 1.1 — Introduce typed verification results and signed context types without changing routing yet.
- [x] Issue 1.2 — Route prototype proof envelope through typed verifier result.
- [x] Issue 1.3 — Make runtime mode explicit and remove silent plaintext fallback.
- [x] Issue 1.4 / plan Issue 2.1 — Receiver-local manifest and OperationDescriptor.
- [x] Issue 1.5 / plan Issue 2.2 — Manifest-aware verifier lookup.

## Phase 3

- [x] Issue 3.1 — Define receipt and event types.
- [x] Issue 3.2 — Replace thin telemetry with receipt/event SQLite tables.

## Phase 4

- [x] Issue 4.1 — Introduce `EvidenceAdapter` trait and `local_static` adapter.

Issue 4.1 scope lock before implementation:

- Document first, then write failing tests, then implement.
- Keep the first adapter deterministic and labeled `local_static` / local-dev-test only.
- Shape the request/result contract for later wallet presentation, Midnight/ZK, and Dregg/federation adapters without importing those dependencies.
- Connect descriptor `accepted_evidence` into verifier output for signed contexts/receipts, but stop before wallet, Midnight, Dregg, Cardano, or execution-broker work.

## Next recommended issue

Issue 4.2 — Add `wallet_presentation` adapter shell. The `local_static` seam now exists; the next slice should define wallet presentation request/response fields and typed unsupported/shape failures without importing Midnight, Dregg, or Cardano rails.
