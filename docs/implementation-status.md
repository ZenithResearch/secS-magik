# secS-magik implementation status

This document is the status ledger for this repository. It separates what is implemented today from what is partially implemented, planned next, or only future/vision. Keep this file current whenever code or docs change.

## Status labels

| Label | Meaning |
|---|---|
| Solid / implemented | Present in current code and covered by tests or direct inspection. Safe to describe as implemented. |
| Partial / prototype | Present in current code, but incomplete, misleadingly named, local-only, or not strong enough for production/security claims. |
| Planned / next implementation | Accepted design direction for the next coding pass. Not yet present in current code. |
| Future / optional rail | Directional or later-stage work. Do not block the first implementation pass on it unless explicitly promoted. |
| Out of scope | This repository should not own it. Reference only as a boundary. |

## Current solid / implemented surface

| Surface | Location | Status | What is solid |
|---|---|---|---|
| Rust workspace | `Cargo.toml` | Solid / implemented | Workspace members are `core`, `client`, and `server`. `cargo test --workspace` passes in the docs realignment worktree. |
| `ZenithPacket` v0 shape | `core/src/lib.rs` | Solid / implemented | The packet has `session_id`, `nonce`, `opcode: u8`, `proof`, `claim_ttl`, `encrypted_payload`, and `mac`; serialization round-trip tests pass. |
| Standard opcode constants | `core/src/lib.rs` | Solid / implemented | `OPCODE_GENERATE = 0x01` and `OPCODE_CHAT = 0x02` exist and are tested. |
| CLI decimal opcode parsing | `client/src/main.rs` | Solid / implemented | `hub 16 ...` parses as decimal `u8`; `0x10` and values above `255` are rejected by current tests. |
| Client packet construction | `client/src/main.rs` | Solid / implemented | CLI builds and sends `ZenithPacket` over TCP using current proof helper. |
| Tunnel helper functions | `core/src/tunnel.rs` | Solid / implemented | ChaCha20Poly1305 helper tests cover round trips and tamper/wrong-key rejection. |
| Ed25519 helper primitives | `core/src/zk.rs` | Solid / implemented as primitive | Signature/proof helper tests pass. These primitives are not yet a full server verifier. |
| Session store | `server/src/session.rs` | Solid / implemented as local utility | In-memory session-store tests pass. This is not yet replay/session binding for the verifier pipeline. |
| Current secS binary | `server/src/main.rs`, `server/src/lib.rs` | Partial / prototype | Runs a TCP listener and routes packet fields. It is not yet the full verifier pipeline. |
| Current secZ-named binary | `server/src/bin/secz.rs` | Partial / prototype | Runs a configurable gateway, does prototype proof/TTL check, explicit runtime-mode payload handling, SQLite telemetry, and opcode routing. It should not be described as verifier ownership. |
| SQLite telemetry | `server/src/bin/secz.rs` | Partial / prototype | Stores opcode and payload size in `node_telemetry`. It is not yet a receipt/event ledger. |
| MachineProgram routing | `server/src/bin/secz.rs` | Partial / prototype | Bounded opcode routing exists. It does not yet receive signed verified context or emit signed execution receipts. |

## Current partial / prototype behavior to name carefully

| Behavior | Current fact | How to describe it |
|---|---|---|
| Proof verification | Current gateway accepts non-empty `proof` plus positive `claim_ttl`. | “Prototype proof envelope check,” not real ZK verification. |
| Payload security | Tunnel decrypt works if key is configured; plaintext is only allowed when `SECZ_RUNTIME_MODE=local_dev_plaintext` or `SECS_RUNTIME_MODE=local_dev_plaintext`. | “Explicit runtime-mode payload handling,” not silent production plaintext fallback. |
| secZ server file | `server/src/bin/secz.rs` exists and performs prototype gateway behavior. | “Historical/secZ-named prototype gateway,” not the corrected architectural secZ client surface. |
| secS verifier | secS parses/inspects and routes; full staged verifier does not exist. | “Target verifier substrate,” not fully implemented verifier. |
| Manifest | Hardcoded `register()` calls exist; no typed `OperationDescriptor` module yet. | “Prototype bindings,” not a real receiver-local manifest. |
| Telemetry/audit | `node_telemetry` stores opcode and payload size. | “Thin local telemetry,” not receipt ledger or audit proof. |
| Dregg/Midnight/Cardano | No runtime dependency in current workspace. | “Future optional evidence/anchor rails,” not current implementation. |

## Planned / next implementation surface

These are accepted next-pass targets from the current objectives spec and issue-slices plan. They are not yet implemented unless a later code change lands them.

| Target | Planned location | Status |
|---|---|---|
| Repository schema | `docs/repository-schema.md` | Implemented as docs; code not yet reorganized. |
| OperationDescriptor / ReceiverManifest | `server/src/manifest.rs` | Planned / next implementation. |
| Opcode range governance | `server/src/manifest.rs`, docs; possibly `core/src/lib.rs` constants | Planned; docs define ranges now. |
| VerificationError / verifier pipeline | `server/src/verifier.rs` | Partially implemented: typed errors and prototype envelope/signature context helpers exist; full staged verifier pipeline still planned. |
| SignedVerifiedCallContext | `server/src/verifier.rs` | Implemented for Ed25519 context signing/verification; receipt integration still planned. |
| Identity/signature helpers for contexts/receipts | `server/src/identity.rs` | Planned / next implementation; low-level Ed25519 primitives exist in `core/src/zk.rs`. |
| Explicit runtime modes | `server/src/runtime_mode.rs` | Implemented for current gateway; local plaintext requires explicit `local_dev_plaintext`, default is `production_verified`. |
| Receipt types | `server/src/receipt.rs` | Planned / next implementation. |
| Event/receipt ledger | `server/src/ledger.rs` | Planned / next implementation. |
| EvidenceAdapter trait | `server/src/evidence.rs` | Planned / next implementation. |
| `local_static` evidence adapter | `server/src/evidence.rs` | Planned first adapter; local/dev/test scaffold only. |
| Bounded execution broker accepting verified context | `server/src/execution.rs` | Planned / next implementation. |
| Packet-builder helper | `core/src/packet_builder.rs` | Optional planned helper if it reduces duplication without importing verifier logic into core. |

## Future / optional rails

| Rail | Status | Do not claim |
|---|---|---|
| Wallet presentation adapter | Future after `local_static` proves the adapter interface. | Do not claim wallet auth is currently implemented in secS-magik. |
| Midnight / generic ZK proof adapter | Future after public inputs and statement meaning are defined. | Do not claim current proof bytes are a meaningful ZK proof. |
| Dregg receipt / federation adapter | Future after capability, revocation, and root semantics are defined. | Do not make Dregg mandatory for the current verifier. |
| Cardano settlement evidence | Future for capital/settlement operations only. | Do not treat Cardano as generic RPC verification. |
| Public chain anchoring of receipts | Future external proof/settlement rail. | Do not claim current SQLite telemetry is public auditability. |

## Out-of-scope for this repo

secS-magik does not own:

- Gallery product policy;
- app/browser login UX;
- ordinary WalletAuth HTTP sessions;
- Dregg consensus;
- Midnight circuits themselves;
- Cardano settlement/business logic;
- auction/business logic;
- arbitrary shell access;
- centralized Hub orchestration;
- Castalia membership semantics as a product authority.

## Required language discipline

Use these phrases:

- “current prototype” for code that exists but is incomplete;
- “target verifier pipeline” for accepted architecture not yet implemented;
- “signed context/receipt planned” until code lands;
- “local/dev/test scaffold” for `local_static` and plaintext modes;
- “client-side / outgoing-call surface” for local Hermes/secC/secZ;
- “secS verifier/RPC substrate” for the corrected server-side boundary.

Avoid these phrases unless code proves them:

- “production-secure”;
- “fully ZK-verified”;
- “secZ verifies authority”;
- “Dregg implements this path”;
- “WalletAuth is part of secS-magik”;
- “manifest is the firewall” without caveating that current bindings are prototype hardcoded registrations;
- “receipt ledger” before signed receipt/event tables exist.
