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
| Canonical prototype gateway binary | `server/src/bin/secs-gateway.rs` | Partial / prototype | Thin wrapper over library modules for prototype ingress, proof/TTL check, explicit runtime-mode payload handling, manifest descriptor lookup, signed context creation, SQLite receipt/event ledger, legacy telemetry, and opcode routing. |
| Historical secZ compatibility binary | `server/src/bin/secz.rs` | Partial / prototype | Thin compatibility wrapper for the old command name; not canonical verifier ownership. |
| Prototype ingress | `server/src/ingress.rs` | Partial / prototype | Deserializes packets, calls the prototype verifier/payload path, decrypts payloads by runtime mode, looks up manifest descriptors, signs a `VerifiedCallContext`, emits reject receipts for typed verifier/payload/manifest failures, and hands verified payloads to the gateway router. |
| Prototype gateway/router | `server/src/gateway.rs` | Partial / prototype | Preserves legacy `node_telemetry`, persists verify/execution receipts and handler lifecycle events in the ledger, and routes configured machine programs from signed verified contexts. It is not yet a durable execution broker. |
| Receipt/event types | `server/src/receipt.rs`, `server/tests/receipt.rs` | Solid / implemented | Defines typed receipt kinds, decisions, authenticator kinds, stable event names, reject/verify/execution receipt constructors, and Ed25519 signing/verification tests. Payload bytes are not included in receipts by default. |
| Receipt/event ledger | `server/src/ledger.rs`, `server/tests/ledger.rs` | Solid / implemented as local ledger | Creates `events` and `receipts` tables with runtime SQL, stores signed receipt metadata including `authenticator_kind`, `signer_key_id`, and `signature`, and keeps payload content out of default persistence. |
| Receiver-local manifest descriptors | `server/src/manifest.rs` | Solid / implemented as descriptor layer | Defines `OperationDescriptor`, `ReceiverManifest`, opcode range classification, seeded v0 descriptors for `0x01`, `0x02`, `0x10`, `0x20`, and `0x30`, and typed unknown-opcode lookup errors. |
| Payload handling | `server/src/payload.rs` | Solid / implemented | Parses tunnel keys and enforces explicit runtime-mode payload behavior. |

## Current partial / prototype behavior to name carefully

| Behavior | Current fact | How to describe it |
|---|---|---|
| Proof verification | Current gateway accepts non-empty `proof` plus positive `claim_ttl`. | “Prototype proof envelope check,” not real ZK verification. |
| Payload security | Tunnel decrypt works if key is configured; plaintext is only allowed when `SECZ_RUNTIME_MODE=local_dev_plaintext` or `SECS_RUNTIME_MODE=local_dev_plaintext`. | “Explicit runtime-mode payload handling,” not silent production plaintext fallback. |
| secZ compatibility file | `server/src/bin/secz.rs` exists as a thin compatibility wrapper. | “Historical command compatibility wrapper,” not the canonical verifier or client architecture. |
| secS verifier | secS parses/inspects and routes; typed evidence adapter calls can now feed signed contexts, but the full staged verifier does not exist. | “Target verifier substrate with local evidence seam,” not fully implemented verifier. |
| Manifest-to-execution wiring | The prototype gateway now creates a signed context from descriptor lookup before calling `route_verified`, but handler registration is still hardcoded. | “Manifest-aware prototype routing,” not “final execution broker.” |
| Telemetry/audit | `node_telemetry` still stores opcode and payload size for compatibility; `events` and `receipts` now persist typed local audit records with signed receipt metadata. | “Local SQLite receipt/event ledger plus legacy telemetry,” not public audit proof. |
| Dregg/Midnight/Cardano | No runtime dependency in current workspace. | “Future optional evidence/anchor rails,” not current implementation. |

## Planned / next implementation surface

These are accepted next-pass targets from the current objectives spec and issue-slices plan. They are not yet implemented unless a later code change lands them.

| Target | Planned location | Status |
|---|---|---|
| Repository schema / module layout | `docs/repository-schema.md`, `server/src/{ingress,gateway,payload,manifest,evidence,receipt,ledger}.rs` | Phase 0.1 implemented: reusable gateway/payload/ingress code moved out of binaries, and placeholder module homes exist for manifest/evidence/receipt/ledger. |
| OperationDescriptor / ReceiverManifest | `server/src/manifest.rs` | Implemented as a receiver-local descriptor/lookup layer; execution wiring still planned. |
| Opcode range governance | `server/src/manifest.rs`, docs; possibly `core/src/lib.rs` constants | Implemented in the manifest descriptor layer for reserved/core/candidate/operator ranges. |
| VerificationError / verifier pipeline | `server/src/verifier.rs` | Partially implemented: typed errors and prototype envelope/signature context helpers exist; full staged verifier pipeline still planned. |
| SignedVerifiedCallContext | `server/src/verifier.rs` | Implemented for Ed25519 context signing/verification; verify receipts can now be constructed from signed contexts. |
| Identity/signature helpers for contexts/receipts | `server/src/identity.rs` | Planned / next implementation; low-level Ed25519 primitives exist in `core/src/zk.rs`. |
| Explicit runtime modes | `server/src/runtime_mode.rs` | Implemented for current gateway; local plaintext requires explicit `local_dev_plaintext`, default is `production_verified`. |
| Receipt types | `server/src/receipt.rs` | Implemented for reject, verify, execute, and forward receipts; persisted by the local ledger slice. |
| Event/receipt ledger | `server/src/ledger.rs` | Implemented with runtime SQL and in-memory SQLite tests; gateway/ingress write reject, verify, execution, and handler lifecycle audit records. |
| EvidenceAdapter trait | `server/src/evidence.rs`, `server/tests/evidence.rs` | Solid / implemented | Typed adapter boundary with request/result fields for subject, audience, operation, resource, evidence refs, public inputs, and reason codes. |
| `local_static` evidence adapter | `server/src/evidence.rs`, `server/tests/evidence.rs` | Solid / implemented as local-dev-test only | Deterministic local/dev/test scaffold that can satisfy descriptor evidence requirements and flow into signed contexts/receipts without claiming production authority or adding Dregg/Midnight/Cardano dependencies. |
| Wallet presentation adapter shell | `server/src/evidence.rs`, `server/tests/wallet_presentation.rs` | Partial / prototype | Defines typed wallet presentation fixture fields for subject, audience, origin, challenge, signature, public key, replay nonce, and validity window; fails closed for missing/invalid shape and distinguishes wrong audience/origin. Full cryptographic wallet signature verification remains explicitly unsupported. |
| Bounded execution broker accepting verified context | `server/src/execution.rs` | Planned / next implementation. |
| Packet-builder helper | `core/src/packet_builder.rs` | Solid / implemented as verifier-free construction helper | Builds `ZenithPacket` v0 from caller-provided envelope fields without validating capabilities, credentials, evidence, authority, replay, or verifier receipts. |

## Future / optional rails

| Rail | Status | Do not claim |
|---|---|---|
| Wallet presentation adapter | Implemented as a typed shell after `local_static`; full wallet signature verification remains unsupported. | Do not claim production wallet auth or verified wallet signatures are implemented in secS-magik. |
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
