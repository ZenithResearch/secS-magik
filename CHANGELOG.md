# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

### Changed

- Realigned README, AGENTS, and docs surfaces with the corrected secS-magik boundary — secS is the verifier/RPC substrate, local Hermes/secC/secZ are client-side/outgoing surfaces, and the current `server/src/bin/secz.rs` is treated as a prototype compatibility surface rather than verifier ownership.

### Added

- Added typed verifier result and signed `VerifiedCallContext` primitives — establishes the Phase 1 handoff contract with audience, expiry, signer metadata, and Ed25519 tamper/wrong-key checks before routing code depends on it.
- Added an implementation status ledger — makes every docs surface distinguish solid implemented behavior, partial prototype behavior, planned next work, future rails, and out-of-scope responsibilities.
- Added a repository schema doc and repo-local copies of the current objectives spec and implementation issue slices — gives future coding agents a concrete file-system/module map before verifier implementation begins.
