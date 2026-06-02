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

## Phase 0

- [x] Issue 0.0 — Add the current spec to repo docs.
- [x] Issue 0.1 — Align codebase layout with the current secS direction.
- [x] Issue 0.2 — Add regression tests for preserved packet and opcode behavior.

## Phase 1

- [x] Issue 1.1 — Introduce typed verification results and signed context types without changing routing yet.
- [x] Issue 1.2 — Route prototype proof envelope through typed verifier result.
- [x] Issue 1.3 — Make runtime mode explicit and remove silent plaintext fallback.
- [ ] Issue 1.4 — Receiver-local manifest and OperationDescriptor.
- [ ] Issue 1.5 — Manifest-aware verifier lookup.

## Next recommended issue

Issue 1.4 — Receiver-local manifest and OperationDescriptor. The codebase now has `server/src/manifest.rs` as the module home, and Issue 0.2 regression tests protect packet/opcode compatibility before manifest semantics land.
