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

- [ ] Issue 4.1 — Introduce `EvidenceAdapter` trait and `local_static` adapter.

## Next recommended issue

Issue 4.1 — Introduce `EvidenceAdapter` trait and `local_static` adapter. Receipt/event types and SQLite persistence now exist; the next slice should add typed evidence verification with deterministic local/dev/test `local_static` while keeping Dregg, Midnight, and Cardano optional.
