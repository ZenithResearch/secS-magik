# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

### Changed

- Bound handler execution to `VerifiedCallContext` — machine programs now receive verified context plus payload bytes, unverified routes no longer execute handlers, and the router enforces payload-size and timeout limits before emitting signed execution receipts so local dev handlers cannot run from raw opcode/payload assumptions.
- Routed prototype gateway execution through manifest-aware signed verification contexts: ingress now looks up receiver-local descriptors, signs `VerifiedCallContext`, and calls `ConfigurableRouter::route_verified` before handler execution.
- Extended local telemetry with operation names for verified routing while preserving prototype opcode/payload-size records.
- Aligned the CI gate with the current Rust workspace by fixing the strict Clippy surface (`VerificationDecision` now boxes the large verified context variant) so `cargo clippy --workspace --all-targets --all-features -- -D warnings` matches local test expectations.
- Executed Phase 0.1 layout alignment: moved reusable prototype gateway, ingress, and payload handling out of `server/src/bin/secz.rs` into library modules; added a canonical `secs-gateway` binary and kept `secz` as a compatibility wrapper.
- Added placeholder module homes for manifest, evidence, receipt, and ledger responsibilities so future verifier work has explicit boundaries before semantics land.
- Made the public README product-neutral and reader-oriented: removed Gallery/Zenith product framing and moved away from agent/self-guidance language.
- Added Phase 0.1 to the implementation slices for aligning the codebase/module layout with the current secS direction before more verifier behavior accumulates in legacy locations.
- Made payload decryption mode explicit — `SECZ_RUNTIME_MODE`/`SECS_RUNTIME_MODE` now defaults to `production_verified`, `local_dev_tunnel` still requires a tunnel key, and only `local_dev_plaintext` permits plaintext local testing.
- Routed the current secZ-named gateway through the typed `Verifier::verify_prototype_envelope` check — replaces the old boolean `validate_zk_proof` helper with explicit prototype-envelope errors while preserving current accept/reject behavior.
- Realigned README, AGENTS, and docs surfaces with the corrected secS-magik boundary — secS is the verifier/RPC substrate, local Hermes/secC/secZ are client-side/outgoing surfaces, and the current `server/src/bin/secz.rs` is treated as a prototype compatibility surface rather than verifier ownership.

### Added

- Added A2 rail taxonomy and non-goals to the ready-for-prod checklist — separates secS-magik-owned verifier/RPC work from Castalia Wallet UI, Dregg consensus, Matrix federation, Gallery policy, Midnight circuits, Cardano settlement, and Hub orchestration before later slices become implementation issues.
- Added A0–A9 slice acceptance criteria to the ready-for-prod checklist — each slice now carries explicit acceptance evidence and forbidden claims before the phase/branch/PR issue checklist is generated.
- Added A1 status reconciliation to the ready-for-prod checklist and implementation ledger — records the completed/partial/planned surfaces through Issue 4.2 so the production train starts from the actual repo checkpoint instead of stale planned/done contradictions.
- Added the ready-for-prod checklist A0 production definition — locks the first-prod target to all three rails (local production-shaped deployment, Castalia Wallet-backed app/user auth, and cross-Hub/federated evidence) so later implementation phases cannot collapse readiness into local smoke tests alone.
- Added the `wallet_presentation` adapter shell — defines typed subject/audience/origin/challenge/signature/public-key/replay fields, fail-closed shape checks, distinguishable `invalid_presentation` / `wrong_audience` / `wrong_origin` failures, and explicit `shape_validated_signature_unsupported` status without importing Midnight, Dregg, or Cardano rails.
- Added `docs/client-surfaces.md` — records local Hermes/secC/secZ as client-side ways to call secS, prevents secZ/verifier boundary regression, and anchors the shared verifier-free packet-builder boundary.
- Added a verifier-free `core::packet_builder` helper — gives local Hermes/secC/secZ-style client surfaces a shared `ZenithPacket` v0 construction path without importing server-side authority checks.
- Added the Issue 4.1 evidence seam — `server/src/evidence.rs` now defines typed evidence requests/results and the deterministic `local_static` local-dev-test adapter; verifier tests prove descriptor evidence requirements can flow into signed contexts and receipts without claiming public proof or adding Dregg/Midnight/Cardano dependencies.
- Added the local SQLite receipt/event ledger — `server/src/ledger.rs` now creates runtime-SQL `events` and `receipts` tables, gateway/ingress persist reject/verify/execution records and handler lifecycle events, signed receipt metadata is stored, and tests verify payload content is not stored by default.
- Added typed in-memory receipt and event objects — reject, verify, execute, and forward receipts now have typed decisions/reasons/authenticator kinds, stable event names, Ed25519 signing/verification helpers, and tests proving payload bytes are not included by default before SQLite ledger persistence lands.
- Added receiver-local manifest descriptors in `server/src/manifest.rs`, including `OperationDescriptor`, `ReceiverManifest`, seeded descriptors for `0x01`, `0x02`, `0x10`, `0x20`, and `0x30`, opcode range governance, dev-binding flags, and typed unknown-opcode lookup errors.
- Added manifest tests for descriptor lookup, unknown-opcode rejection, seeded operation coverage, dev-binding labels, and reserved/core/candidate/operator range classification.
- Added an implementation progress checklist at `docs/plans/2026-06-01-implementation-progress-checklist.md` so CI alignment and issue-by-issue progress are trackable.
- Added explicit Issue 0.2 packet/opcode regression tests covering non-empty packet round trip, maximum `u8` opcode, and serialization-valid-but-verifier-rejected empty proof / zero TTL envelopes.
- Added typed verifier result and signed `VerifiedCallContext` primitives — establishes the Phase 1 handoff contract with audience, expiry, signer metadata, and Ed25519 tamper/wrong-key checks before routing code depends on it.
- Added an implementation status ledger — makes every docs surface distinguish solid implemented behavior, partial prototype behavior, planned next work, future rails, and out-of-scope responsibilities.
- Added a repository schema doc and repo-local copies of the current objectives spec and implementation issue slices — gives future coding agents a concrete file-system/module map before verifier implementation begins.
