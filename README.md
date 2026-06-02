# secS-magik

secS-magik is a Rust workspace for a permissioned machine-to-machine RPC and verifier substrate.

Status: active prototype being realigned toward the 2026-06-01 objectives spec. The current code preserves the v0 packet shape and `u8` opcode dispatch, and Phase 1 has added typed verifier/context primitives. Phase 0.1 has moved reusable gateway/payload/ingress code out of binary entrypoints. A receiver-local manifest descriptor layer now exists, the prototype gateway signs manifest-aware verified contexts before routing, and typed receipt/event objects are persisted to a local SQLite ledger. Evidence adapters and the full verifier pipeline are still implementation work.

Current source of truth:

- `docs/implementation-status.md` — status ledger: implemented vs partial vs planned vs future vs out-of-scope.
- `docs/repository-schema.md` — objective file-system schema and repository boundary map.
- `docs/specs/2026-06-01-secs-magik-objectives-spec.md` — current architecture/objectives spec.
- `docs/plans/2026-06-01-implementation-progress-checklist.md` — running checklist for CI alignment and phase/issue progress.
- `docs/announcement-thread.md` — public-language draft, intentionally caveated until verifier work lands.


## Status Taxonomy

Use these labels across all docs:

| Label | Meaning in this repo |
|---|---|
| Solid / implemented | Present in current code and covered by tests or direct inspection. |
| Partial / prototype | Present, but incomplete, local-only, misleadingly named, or not strong enough for production/security claims. |
| Planned / next implementation | Accepted next-pass design; not yet in code. |
| Future / optional rail | Later-stage direction. |
| Out of scope | This repository should not own it. |

Short current status:

- Solid: v0 packet shape, `u8` opcode field, `0x01`/`0x02` constants, CLI decimal opcode parsing, packet round-trip tests, tunnel helper tests, Ed25519 helper primitives, signed verifier context helpers, explicit runtime payload modes, receiver-local manifest descriptors, typed receipt/event objects, local SQLite receipt/event persistence, and the deterministic `local_static` evidence seam.
- Partial/prototype: current `secS` TCP listener, secS prototype gateway with `server/src/bin/secz.rs` compatibility wrapper, prototype proof/TTL check, manifest-aware signed context routing, legacy `node_telemetry`, and hardcoded handler registration.
- Planned next: wallet-presentation contract shell and/or bounded execution broker, after the `local_static` seam is reviewed.
- Future/optional: external proof, federation receipt, and settlement evidence adapters.
- Out of scope: product policy, app/browser login UX, external consensus, settlement logic, centralized orchestration, arbitrary shell access.

## Current Boundary

The corrected role split is:

```text
client-side surfaces
  CLI, library, local tool, or service client
  constructs outgoing secS-compatible calls from user/local/app/node intent

secS-magik / secS
  permissioned RPC and verifier substrate
  validates envelope, signatures, presentations, replay/expiry, capabilities, credentials, evidence, and receipts

receiver-local manifest
  binds local u8 opcodes to operation descriptors and local handlers after secS verification
```

Important boundaries:

- Client surfaces construct outbound packets; they are not the verifier.
- secS verifies packets and produces typed handoff/audit objects.
- Receiver-local manifests bind verified operations to local handlers.
- External proof, federation, and settlement systems enter through typed evidence adapters or anchors; they do not replace the secS verifier boundary.
- Browser/app login is separate from secS internal RPC.

## At a Glance

- What it does now: defines the v0 packet type, sends packets from a CLI, runs prototype TCP listeners, checks prototype proof/TTL envelopes, handles payload decryption through explicit runtime modes, describes receiver-local operations, signs/verifies typed verifier contexts, persists typed receipt/event records to local SQLite without storing payload content by default, preserves legacy `node_telemetry`, and routes verified bounded opcodes to configured machine programs.
- What it is becoming: a typed secS verifier pipeline with receiver-local operation manifests, signed `VerifiedCallContext`, signed receipts, local event ledger, and evidence adapters.
- Who it is for: developers and operators building owned machine-call rails instead of broad bearer-token APIs.
- Primary stack: Rust workspace with `core`, `client`, and `server`; Tokio TCP; bincode packet serialization; optional ChaCha20Poly1305 tunnel decryption; SQLite through SQLx runtime queries.

## Repository Map

| Path | Responsibility | Boundary |
|---|---|---|
| `README.md` | Root orientation map. | Broad/shallow; link deeper docs instead of becoming the full spec. |
| `Cargo.toml` | Workspace definition. | Current members: `core`, `client`, `server`. |
| `core/` | Shared packet and verifier-free core primitives. | Owns the v0 packet shape and constants; should not own product policy or receiver-local dispatch semantics. |
| `client/` | CLI packet sender; current secC-like client surface. | Builds and sends packets; does not verify inbound authority. |
| `server/src/lib.rs` | Current TCP node loop and shared server library surface. | To evolve into secS verifier substrate modules. |
| `server/src/main.rs` | Current basic secS daemon binary on port `9000`. | Prototype ingress; not yet the full verifier pipeline. |
| `server/src/ingress.rs` | Prototype TCP ingress and gateway connection handling. | Owns packet decode/prototype verification/decrypt handoff for the current gateway. |
| `server/src/gateway.rs` | Configurable router, prototype telemetry schema, and prototype machine-program bindings. | Shared gateway library code; binary wrappers should stay thin. |
| `server/src/payload.rs` | Tunnel-key parsing and runtime-mode payload decryption. | Payload handling policy separated from binary entrypoints. |
| `server/src/manifest.rs` | Receiver-local operation descriptors and opcode governance. | Descriptor semantics exist; execution wiring lands in a later issue. |
| `server/src/evidence.rs` | Evidence adapter seam. | Defines typed evidence requests/results and deterministic `local_static` local-dev-test adapter; Dregg, Midnight, Cardano, and wallet presentation stay optional/future adapters. |
| `server/src/receipt.rs` | Typed receipt/event objects. | Defines reject/verify/execute/forward receipt kinds, typed decisions/reasons/authenticator kinds, stable event names, and Ed25519 receipt signing helpers. |
| `server/src/ledger.rs` | Event/receipt ledger. | Persists events and receipts with runtime SQL; does not store payload content by default. |
| `server/src/bin/secs-gateway.rs` | Canonical current prototype configurable gateway binary on port `9001`. | Thin wrapper over library modules. |
| `server/src/bin/secz.rs` | Compatibility wrapper for the historical secZ-named gateway command. | Kept for current command compatibility, not as canonical verifier ownership. |
| `docs/repository-schema.md` | Objective file-system schema. | Defines where verifier, manifest, receipts, evidence, docs, and client surfaces should live. |
| `docs/specs/` | Current architecture/objective specs. | Reviewable source of truth for implementation. |
| `docs/reviews/` | Historical/current code reviews if tracked. | Evidence and provenance for architecture and implementation reviews. |
| `docs/announcement-thread.md` | Draft external messaging. | Public-language sketch for verifier/signature/receipt claims as they land. |
| `AGENTS.md` | Contributor/agent rules. | Internal editing conventions for future automated work. |

Untracked local directories such as `hub/`, `ops/`, or `docs/reviews/` in a working checkout are not part of the current Cargo workspace unless deliberately added and documented.

## Packet v0

The v0 packet remains the compatibility anchor:

```rust
pub struct ZenithPacket {
    pub session_id: [u8; 16],
    pub nonce: [u8; 12],
    pub opcode: u8,
    pub proof: Vec<u8>,
    pub claim_ttl: u64,
    pub encrypted_payload: Vec<u8>,
    pub mac: [u8; 16],
}
```

Rules:

- Preserve `opcode: u8`.
- Preserve current bincode round-trip compatibility.
- The CLI parses opcodes as decimal `u8`; use `16`, not `0x10`.
- Current prototype proof bytes are not real ZK verification. Treat them as a `PrototypeProofEnvelope` until replaced by typed verification stages.
- `encrypted_payload` remains opaque to secS except for cryptographic/tunnel verification and handler handoff rules.

## Opcode Governance

The implementation plan reserves opcode ranges by governance tier:

| Range | Governance | Meaning |
|---:|---|---|
| `0x01`–`0x0A` | secS/core standardized | Very small cross-runtime baseline operations and legacy examples. |
| `0x0B`–`0x3F` | Portable candidate | Ecosystem operations whose names/evidence expectations should become portable across compliant receivers. |
| `0x40`–`0xFF` | Operator-defined | Receiver/operator local operations declared by the receiver manifest. |

Current legacy/core examples:

- `0x01` / decimal `1`: `OPCODE_GENERATE`
- `0x02` / decimal `2`: `OPCODE_CHAT`

Current prototype/dev bindings:

- `0x10` / decimal `16`: Bash echo pipe.
- `0x20` / decimal `32`: native Rust queue stub.
- `0x30` / decimal `48`: `jq .` JSON formatter/parser.

These `0x10`/`0x20`/`0x30` bindings are portable candidates or dev bindings, not final ratified global semantics.

## Target Verifier Pipeline

The target secS verifier path is:

```text
RawBytes
  -> FrameBoundsCheck
  -> PacketDecode
  -> PacketShapeCheck
  -> VersionCompatibilityCheck
  -> SessionBindingCheck
  -> NonceReplayCheck
  -> ExpiryCheck
  -> MacOrTunnelCheck
  -> PresentationProofCheck
  -> AudienceOriginEndpointCheck
  -> OperationDescriptorLookup
  -> CredentialEvidenceCheck
  -> CapabilityCaveatCheck
  -> RevocationEvidenceCheck
  -> SignedVerifiedCallContext | RejectReceipt
```

The target handoff object is a signed serialized `VerifiedCallContext`, not a raw trust assumption. The target audit object is a signed receipt. Production-shaped verification should use portable public-key signatures, not shared-secret MACs as the main trust path.

## Running Locally

Build and test the workspace:

```bash
cargo test --workspace
cargo build --workspace
```

Run the current secS prototype on port `9000`:

```bash
cargo run -p server --bin server
```

Run the canonical current prototype gateway on port `9001`:

```bash
cargo run -p server --bin secs-gateway
```

The historical `secz` binary remains as a compatibility wrapper for the same prototype gateway:

```bash
cargo run -p server --bin secz
```

Send a packet with a decimal opcode:

```bash
cargo run -p client -- \
  --server 127.0.0.1:9001 \
  hub 16 'hello from secC'
```

The CLI currently accepts decimal `16`, `32`, or `48` for the prototype bindings. Hex input such as `0x10` is not accepted unless CLI parsing is deliberately extended later.

## Testing and Verification

Primary checks:

```bash
cargo test --workspace
cargo build --workspace
```

Docs/path consistency check:

```bash
for p in Cargo.toml core/ client/ server/ docs/ docs/repository-schema.md docs/specs/2026-06-01-secs-magik-objectives-spec.md; do
  test -e "$p" || echo "missing $p"
done
```

If telemetry or ledger code is added, keep SQL runtime-checkable unless the repo also commits and maintains the required SQLx offline cache.

## Current Non-Goals

This repo does not own:

- product policy;
- app/browser login UX;
- external consensus;
- public settlement logic;
- auction or business logic;
- arbitrary shell access;
- centralized orchestration;
- application membership semantics.

## Operational Boundaries

The public API boundary is the packet/verifier/manifest/receipt path. Application policy, login UX, consensus, settlement, and orchestration systems should integrate through explicit adapters or client surfaces rather than becoming core verifier logic.

## License

See `LICENSE`.
