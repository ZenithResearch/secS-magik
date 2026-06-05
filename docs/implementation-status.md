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
| Rust workspace | `Cargo.toml` | Solid / implemented | Workspace members are `core`, `client`, and `server`. Workspace tests passed after Issue 4.2; A0/A1 are docs-only checklist/status reconciliation slices and do not change runtime code. |
| `ZenithPacket` v0 shape | `core/src/lib.rs` | Solid / implemented | The packet has `session_id`, `nonce`, `opcode: u8`, `proof`, `claim_ttl`, `encrypted_payload`, and `mac`; serialization round-trip tests pass. |
| Standard opcode constants | `core/src/lib.rs` | Solid / implemented | `OPCODE_GENERATE = 0x01` and `OPCODE_CHAT = 0x02` exist and are tested. |
| CLI decimal opcode parsing | `client/src/main.rs` | Solid / implemented | `hub 16 ...` parses as decimal `u8`; `0x10` and values above `255` are rejected by current tests. |
| Client packet construction | `client/src/main.rs` | Solid / implemented | CLI builds and sends `ZenithPacket` over TCP using current proof helper. |
| Tunnel helper functions | `core/src/tunnel.rs` | Solid / implemented | ChaCha20Poly1305 helper tests cover round trips and tamper/wrong-key rejection. |
| Ed25519 helper primitives | `core/src/zk.rs` | Solid / implemented as primitive | Signature/proof helper tests pass. These primitives are not yet a full server verifier. |
| Session store | `server/src/session.rs` | Solid / implemented as local utility | In-memory session-store tests pass. This is not yet replay/session binding for the verifier pipeline. |
| Retired legacy direct TCP entrypoint | `server/src/lib.rs`, removed `server/src/main.rs` | Solid / implemented as entrypoint hardening | The old `run_node` / `PayloadRouter` direct opcode dispatch path and implicit `server` binary are gone, so the packaged server no longer exposes that bypass around verifier/replay/receipt boundaries. |
| Canonical prototype gateway binary | `server/src/bin/secs-gateway.rs` | Partial / prototype | Thin wrapper over library modules for prototype ingress, proof/TTL check, explicit runtime-mode payload handling, manifest descriptor lookup, signed context creation, SQLite receipt/event ledger, legacy telemetry, and opcode routing. |
| Historical secZ compatibility binary | `server/src/bin/secz.rs` | Partial / prototype | Thin compatibility wrapper for the old command name; not canonical verifier ownership. |
| Prototype ingress | `server/src/ingress.rs` | Partial / prototype with targeted audit hardening | Deserializes packets only after bounded wire reads and explicit logical `proof` / `encrypted_payload` length prechecks, decrypts payloads by the validated runtime config instead of ambient env, rejects production use of dev/prototype or legacy prototype-evidence descriptors before signed-context issuance, emits reject receipts for typed verifier/payload/manifest failures, and hands verified payloads to the gateway router. The read/memory and accepted-task boundaries are hardened, but this remains a prototype verifier path rather than production wallet/federated evidence verification. |
| Prototype gateway/router / bounded execution broker | `server/src/gateway.rs` | Solid / implemented as receiver-local bounded handler routing | Preserves legacy `node_telemetry`, persists verify/execution receipts and handler lifecycle events in the ledger, carries an explicit expected receiver audience from runtime config, revalidates signed contexts against the active manifest before execution, selects handlers by descriptor `handler_id`, enforces payload/output size and timeout limits, streams subprocess output under a hard byte cap, kills timed-out subprocess process groups where supported, emits execution receipts for success/failure/unavailable/timeout/oversized outcomes, and gates dev subprocess handlers out of `production_verified` runtime bindings. This is not a durable distributed broker or broad shell authority. |
| Production-shaped gateway runtime config/readiness | `server/src/config.rs`, `server/src/bin/secs-gateway.rs`, `server/tests/{runtime_config,readiness}.rs`, `scripts/production-gateway-smoke.sh` | Solid / implemented as local runtime hardening | Canonical gateway startup reads typed runtime config; `production_verified` requires explicit non-fixture receiver audience, verifier key path, trust-registry path, bind address, DB/ledger path, ingress/handler/output limits, and max in-flight connection cap before serving; startup rejects missing/malformed/empty/fixture-only trust registries and `local_static` adapters unless the operator explicitly enables fixture-only smoke; readiness can distinguish config-loaded, ledger-ready, and trust-registry-ready/fixture-only state; the smoke script starts the real gateway binary and sends malformed/oversized TCP input under fixture-only env without real secrets. This is not deployed production and does not complete wallet crypto or federated trusted issuer/root policy. |
| Receipt/event ledger | `server/src/{ledger,receipt,schema}.rs`, `server/tests/{ledger,receipt,gateway_layout}.rs` | Solid / implemented as local ledger | Creates `events` and versioned `receipts` tables with runtime SQL, stores signed receipt metadata including `authenticator_kind`, `signer_key_id`, signature length/digest for operator inspection, and `context_id` where a verified context exists; exposes redacted operator inspection by receipt id or context id while keeping raw payload/private evidence and raw signature bytes out of the export surface. |
| Node/verifier identity and public-key seam | `server/src/identity.rs`, `server/tests/identity.rs` | Solid / implemented for explicit local file config plus B4 own-verifier lifecycle seam | `production_verified` requires an explicit regular owner-private verifier key file before signing; missing, inaccessible, malformed, world-readable, and symlink key files fail as typed identity config errors; default signer ids are deterministic Ed25519 public-key fingerprints; unsafe override ids that look like paths or secret material reject; the public identity API exposes signer id/public key/signing helpers without exposing raw secret bytes; contexts/receipts can be verified through a receiver-held `PublicVerifierKeyRegistry` with duplicate-key-id fail-closed behavior and explicit receipt-signing-time validity checks; registry checks fail unknown ids, wrong-key signatures, revoked keys including effective `revoked_at` metadata, expired keys, unknown-status keys, and not-yet-valid keys; key entries carry `status`, `not_before`, `not_after`, `revoked_at`, `replaced_by`, and a fail-closed `production_authority` flag; replacement metadata is not automatic trust transfer; production-authority verification accepts configured non-local `ed25519_node_and_verifier` identities with `ed25519` key metadata and rejects local/dev/test fixture keys or other authenticator/algorithm metadata. |
| Receiver-local manifest descriptors | `server/src/manifest.rs` | Solid / implemented as descriptor layer | Defines `OperationDescriptor`, `ReceiverManifest`, opcode range classification, seeded v0 descriptors for `0x01`, `0x02`, `0x10`, `0x20`, and `0x30`, and typed unknown-opcode lookup errors. |
| Payload handling | `server/src/payload.rs` | Solid / implemented | Parses tunnel keys and enforces explicit runtime-mode payload behavior. |
| Ready-for-prod checklist A0–A9 | `docs/plans/2026-06-02-ready-for-prod-checklist.md` | Solid / implemented as docs/control surface | Track A is complete through A9 as a docs/control-surface phase: production definition, status reconciliation, rail taxonomy/non-goals, identity/key lifecycle gate, wallet-core gate, federated evidence model, production policy matrix, first E2E shape, phase/branch/PR issue checklist, and future-rail deferral. This does not implement Tracks B–I runtime behavior. |

## Current partial / prototype behavior to name carefully

| Behavior | Current fact | How to describe it |
|---|---|---|
| Proof verification | Current gateway accepts non-empty `proof` plus positive `claim_ttl`. | “Prototype proof envelope check,” not real ZK verification. |
| Payload security | Tunnel decrypt works if key is configured; plaintext is only allowed when `SECZ_RUNTIME_MODE=local_dev_plaintext` or `SECS_RUNTIME_MODE=local_dev_plaintext`. | “Explicit runtime-mode payload handling,” not silent production plaintext fallback. |
| secZ compatibility file | `server/src/bin/secz.rs` exists as a thin compatibility wrapper. | “Historical command compatibility wrapper,” not the canonical verifier or client architecture. |
| secS verifier | secS parses/inspects and routes; typed evidence adapter calls can now feed signed contexts, but the full staged verifier does not exist. | “Target verifier substrate with local evidence seam,” not fully implemented verifier. |
| Manifest-to-execution wiring | The gateway creates a signed context from descriptor lookup, refuses production-signed dev/prototype descriptors and legacy descriptors backed only by prototype proof evidence, revalidates signed context opcode/operation/handler consistency against the active manifest, and handler selection uses the descriptor `handler_id`, with production runtime bindings withholding dev subprocess handlers by default. | “Descriptor-bound local execution broker,” not a durable distributed broker, arbitrary shell surface, or production trusted-issuer/wallet evidence verifier. |
| Telemetry/audit | `node_telemetry` still stores opcode and payload size for compatibility; `events` and versioned `receipts` now persist typed local audit records with signed receipt metadata and redacted operator inspection/export helpers. Retention is local SQLite database retention until operator rotation/deletion; no automatic remote retention or anchoring exists. | “Local SQLite receipt/event ledger plus legacy telemetry,” not public audit proof. |
| Trusted issuer/root lifecycle | Own-verifier public keys have B4 status/validity checks and production startup now validates the trust-registry file is non-empty JSON unless fixture-only smoke is explicitly enabled, but static trusted issuer/root entries and federated credential status policy remain Track E work. | “Own configured verifier-key lifecycle seam plus startup registry readiness,” not complete production issuer/root registry. |
| Dregg/Midnight/Cardano | No runtime dependency in current workspace. | “Future optional evidence/anchor rails,” not current implementation. |

## Planned / next implementation surface

These are accepted next-pass targets after the completed issue train and the A0/A1 ready-for-prod reconciliation. They are not yet implemented unless a later code change lands them.

| Target | Planned location | Status |
|---|---|---|
| Repository schema / module layout | `docs/repository-schema.md`, `server/src/{ingress,gateway,payload,manifest,evidence,receipt,ledger}.rs` | Phase 0.1 implemented: reusable gateway/payload/ingress code moved out of binaries, and placeholder module homes exist for manifest/evidence/receipt/ledger. |
| OperationDescriptor / ReceiverManifest | `server/src/manifest.rs` | Implemented as a receiver-local descriptor/lookup layer; signed-context creation and local bounded handler routing now consume descriptor operation/handler metadata. |
| Opcode range governance | `server/src/manifest.rs`, docs; possibly `core/src/lib.rs` constants | Implemented in the manifest descriptor layer for reserved/core/candidate/operator ranges. |
| VerificationError / verifier pipeline | `server/src/verifier.rs` | Partially implemented: typed errors and prototype envelope/signature context helpers exist; full staged verifier pipeline still planned. |
| SignedVerifiedCallContext | `server/src/verifier.rs` | Implemented for Ed25519 context signing/verification; verify receipts can now be constructed from signed contexts. |
| Identity/signature helpers for contexts/receipts | `server/src/identity.rs` | Implemented through B4: production identity loading requires an operator-provided key path, default `signer_key_id` is derived as `ed25519:<sha256-public-key-fingerprint>`, safe explicit overrides reject path/secret-shaped ids, contexts/receipts sign with the configured identity, the gateway verifies signed contexts against its local own-verifier registry before emitting verify/execute receipts or running handlers, local/dev receipts remain stamped `local_dev_untrusted`, and `PublicVerifierKeyRegistry` provides a local own-verifier key-status seam for unknown-id, wrong-key, revoked, expired, unknown-status, not-yet-valid, and local-dev-as-production-authority rejection. Trusted issuer/root registry policy remains Track E. |
| Explicit runtime modes | `server/src/runtime_mode.rs` | Implemented for current gateway; local plaintext requires explicit `local_dev_plaintext`, default is `production_verified`. |
| Receipt types | `server/src/receipt.rs` | Implemented for reject, verify, execute, and forward receipts with explicit `RECEIPT_SCHEMA_VERSION = 1`; receipts derived from verified contexts carry `context_id` for local chain inspection and future migration/export compatibility. |
| Event/receipt ledger | `server/src/ledger.rs` | Implemented with runtime SQL and in-memory SQLite tests; gateway/ingress write reject, verify, execution, and handler lifecycle audit records. DDL is centralized in `server/src/schema.rs` rather than embedded inline in ledger/gateway runtime methods. Operator inspection returns redacted local rows by receipt id or context id with export schema version, receipt schema version, reason codes, metadata hashes/hex, and signature digest/length rather than raw payload, private evidence, or raw signature bytes. |
| Runtime schema ontology | `server/src/schema.rs`, `server/tests/schema.rs` | Implemented as a central runtime SQLite schema ontology for `events`, `receipts`, `replay_reservations`, and legacy `node_telemetry`; preserves the Track C unique replay boundary while keeping telemetry separate from the receipt/replay ledger table set. |
| Prototype receiver ontology | `server/src/ontology.rs` | Implemented as a central home for prototype receiver constants currently reused across ingress/gateway/verifier: default receiver audience, local prototype subject, local test audience/origin, local prototype signer id, and replay/prototype operation reason strings. Future work should continue moving repeated semantic constants here or into a typed configuration surface rather than duplicating string literals. |
| EvidenceAdapter trait | `server/src/evidence.rs`, `server/tests/evidence.rs` | Solid / implemented | Typed adapter boundary with request/result fields for subject, audience, operation, resource, evidence refs, public inputs, and reason codes. |
| `local_static` evidence adapter | `server/src/evidence.rs`, `server/tests/evidence.rs` | Solid / implemented as local-dev-test only | Deterministic local/dev/test scaffold that can satisfy descriptor evidence requirements and flow into signed contexts/receipts without claiming production authority or adding Dregg/Midnight/Cardano dependencies. |
| Track C replay/session/expiry enforcement | `server/src/{ledger,gateway,verifier}.rs`, `server/tests/{gateway_layout,verifier_context}.rs` | Solid / implemented as receiver-local/local durable replay/session/expiry enforcement | Track C is implemented with bounded claims: Duplicate `(session_id, opcode, nonce, replay_scope)` verified contexts reserve atomically in local SQLite, including concurrent identical routes, and duplicates reject with `replay_detected` before handler execution; descriptor max TTL overclaims reject with `claim_ttl_exceeds_descriptor_max` before signed context issuance; all-zero session IDs reject with `invalid_session` before signed context issuance; Expired/wrong-audience/invalid-signature signed contexts emit signed reject receipts/events before replay reservation and before handler execution; Pre-verification/signature failures do not consume replay slots. This is within the configured receiver-local replay store/scope, not distributed/global/cross-Hub/cluster-wide replay protection. |
| Wallet presentation adapter shell | `server/src/evidence.rs`, `server/tests/wallet_presentation.rs` | Partial / prototype | Defines typed wallet presentation fixture fields for subject, audience, origin, challenge, signature, public key, replay nonce, and validity window; fails closed for missing/invalid shape and distinguishes wrong audience/origin. Full cryptographic wallet signature verification remains explicitly unsupported. |
| Bounded execution broker accepting verified context | `server/src/gateway.rs`; future `server/src/execution.rs` | Solid / implemented as local bounded broker: handlers consume `VerifiedCallContext`, signed contexts are revalidated against active manifest descriptors, dev/prototype descriptors cannot execute in production runtime, handlers are selected by descriptor `handler_id`, subprocess output is streamed under a hard cap, timed-out subprocess process groups are killed where supported, max in-flight gateway tasks are configurable, execution receipts cover every routed handler outcome, and dev subprocess handlers are not exposed in `production_verified` bindings. Future work may extract this local bounded routing code into a dedicated execution module without widening durability or distribution claims. |
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
- “configured signed context/receipt posture through B4” for current Ed25519 contexts/receipts plus own-verifier key status checks, while still caveating that issuer/root trust policy and live registry discovery are not complete;
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
- “production receipt ledger” or “public auditability” for the current local SQLite receipt/event ledger.
