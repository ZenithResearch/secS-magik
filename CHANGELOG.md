# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

### Changed

- Aligned the CI gate with the current Rust workspace by fixing the strict Clippy surface (`VerificationDecision` now boxes the large verified context variant) so `cargo clippy --workspace --all-targets --all-features -- -D warnings` matches local test expectations.
- Executed Phase 0.1 layout alignment: moved reusable prototype gateway, ingress, and payload handling out of `server/src/bin/secz.rs` into library modules; added a canonical `secs-gateway` binary and kept `secz` as a compatibility wrapper.
- Added placeholder module homes for manifest, evidence, receipt, and ledger responsibilities so future verifier work has explicit boundaries before semantics land.
- Made the public README product-neutral and reader-oriented: removed Gallery/Zenith product framing and moved away from agent/self-guidance language.
- Added Phase 0.1 to the implementation slices for aligning the codebase/module layout with the current secS direction before more verifier behavior accumulates in legacy locations.
- Made payload decryption mode explicit — `SECZ_RUNTIME_MODE`/`SECS_RUNTIME_MODE` now defaults to `production_verified`, `local_dev_tunnel` still requires a tunnel key, and only `local_dev_plaintext` permits plaintext local testing.
- Routed the current secZ-named gateway through the typed `Verifier::verify_prototype_envelope` check — replaces the old boolean `validate_zk_proof` helper with explicit prototype-envelope errors while preserving current accept/reject behavior.
- Realigned README, AGENTS, and docs surfaces with the corrected secS-magik boundary — secS is the verifier/RPC substrate, local Hermes/secC/secZ are client-side/outgoing surfaces, and the current `server/src/bin/secz.rs` is treated as a prototype compatibility surface rather than verifier ownership.

### Added

- Added receiver-local manifest descriptors in `server/src/manifest.rs`, including `OperationDescriptor`, `ReceiverManifest`, seeded descriptors for `0x01`, `0x02`, `0x10`, `0x20`, and `0x30`, opcode range governance, dev-binding flags, and typed unknown-opcode lookup errors.
- Added manifest tests for descriptor lookup, unknown-opcode rejection, seeded operation coverage, dev-binding labels, and reserved/core/candidate/operator range classification.
- Added an implementation progress checklist at `docs/plans/2026-06-01-implementation-progress-checklist.md` so CI alignment and issue-by-issue progress are trackable.
- Added explicit Issue 0.2 packet/opcode regression tests covering non-empty packet round trip, maximum `u8` opcode, and serialization-valid-but-verifier-rejected empty proof / zero TTL envelopes.
- Added typed verifier result and signed `VerifiedCallContext` primitives — establishes the Phase 1 handoff contract with audience, expiry, signer metadata, and Ed25519 tamper/wrong-key checks before routing code depends on it.
- Added an implementation status ledger — makes every docs surface distinguish solid implemented behavior, partial prototype behavior, planned next work, future rails, and out-of-scope responsibilities.
- Added a repository schema doc and repo-local copies of the current objectives spec and implementation issue slices — gives future coding agents a concrete file-system/module map before verifier implementation begins.
