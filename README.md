# secS-magik

secS-magik is the Rust workspace for the secS permissioned RPC / verifier substrate in the Zenith and Castalia stack.

Status: active prototype being realigned toward the 2026-06-01 objectives spec. The current code preserves `ZenithPacket` v0 and `u8` opcode dispatch, but the verifier, manifest, signed context, receipt ledger, and evidence adapter layers are still implementation work. Do not describe the current runtime as production-secure or fully ZK-verified.

Current source of truth:

- `docs/implementation-status.md` — status ledger: implemented vs partial vs planned vs future vs out-of-scope.
- `docs/repository-schema.md` — objective file-system schema and repository boundary map.
- `docs/specs/2026-06-01-secs-magik-objectives-spec.md` — current architecture/objectives spec.
- `docs/announcement-thread.md` — public-language draft, intentionally caveated until verifier work lands.


## Status Taxonomy

Use these labels across all docs:

| Label | Meaning in this repo |
|---|---|
| Solid / implemented | Present in current code and covered by tests or direct inspection. |
| Partial / prototype | Present, but incomplete, local-only, misleadingly named, or not strong enough for production/security claims. |
| Planned / next implementation | Accepted next-pass design; not yet in code. |
| Future / optional rail | Later-stage direction; do not block the first pass on it. |
| Out of scope | This repository should not own it. |

Short current status:

- Solid: `ZenithPacket` v0 shape, `u8` opcode field, `0x01`/`0x02` constants, CLI decimal opcode parsing, packet round-trip tests, tunnel helper tests, Ed25519 helper primitives.
- Partial/prototype: current `secS` TCP listener, current `server/src/bin/secz.rs` gateway, prototype proof/TTL check, optional plaintext fallback, `node_telemetry`, hardcoded opcode bindings.
- Planned next: typed verifier, receiver manifest, signed `VerifiedCallContext`, signed receipts, event/receipt ledger, explicit runtime modes, `local_static` evidence adapter, bounded execution broker.
- Future/optional: wallet presentation, Midnight/ZK proof adapter, Dregg/federation receipt adapter, Cardano settlement evidence.
- Out of scope: Gallery policy, app login/WalletAuth sessions, Dregg consensus, Midnight circuits, Cardano settlement logic, Hub orchestration, arbitrary shell access.

## Current Boundary

The corrected role split is:

```text
client-side surfaces
  local Hermes secS tool/script/skill, secC, or secZ
  construct outgoing secS-compatible calls from user/local/app/node intent

secS-magik / secS
  permissioned RPC and verifier substrate
  validates envelope, signatures, presentations, replay/expiry, capabilities, credentials, evidence, and receipts

receiver-local manifest
  binds local u8 opcodes to operation descriptors and local handlers after secS verification
```

Important corrections:

- secZ is not the generic Castalia interface.
- secZ is not the verifier.
- secZ is a Zenith-oriented client-side / outgoing-call surface to secS.
- secC is the more generic / non-Zenith client form.
- A local Hermes operator may invoke secS through a local tool/script/skill without running a node or hitting a secZ server.
- Dregg, Midnight, and Cardano enter through typed evidence adapters or anchors; they do not replace the secS verifier boundary.
- WalletAuth / browser app login is separate from secS-magik internal RPC.

## At a Glance

- What it does now: defines `ZenithPacket`, sends packets from a CLI, runs prototype TCP listeners, checks prototype proof/TTL envelopes in the current secZ binary, optionally decrypts payload bytes when a tunnel key is configured, records local SQLite telemetry, and routes bounded opcodes to configured machine programs.
- What it is becoming: a typed secS verifier pipeline with receiver-local operation manifests, signed `VerifiedCallContext`, signed receipts, local event ledger, and evidence adapters.
- Who it is for: local Hermes operators, secC/secZ clients, agents, local workers, homelab/cloud nodes, and Zenith/Castalia runtimes that need owned machine-call rails instead of broad bearer-token APIs.
- Primary stack: Rust workspace with `core`, `client`, and `server`; Tokio TCP; bincode packet serialization; optional ChaCha20Poly1305 tunnel decryption; SQLite through SQLx runtime queries.

## Repository Map

| Path | Responsibility | Boundary |
|---|---|---|
| `README.md` | Root orientation map. | Broad/shallow; link deeper docs instead of becoming the full spec. |
| `Cargo.toml` | Workspace definition. | Current members: `core`, `client`, `server`. |
| `core/` | Shared packet and verifier-free core primitives. | Owns `ZenithPacket` v0 and constants; should not own product policy or receiver-local dispatch semantics. |
| `client/` | CLI packet sender; current secC-like client surface. | Builds and sends packets; does not verify inbound authority. |
| `server/src/lib.rs` | Current TCP node loop and shared server library surface. | To evolve into secS verifier substrate modules. |
| `server/src/main.rs` | Current basic secS daemon binary on port `9000`. | Prototype ingress; not yet the full verifier pipeline. |
| `server/src/bin/secz.rs` | Current prototype configurable gateway binary on port `9001`. | Historical/secZ-named execution prototype; should be refactored under the corrected boundary rather than treated as verifier ownership. |
| `docs/repository-schema.md` | Objective file-system schema. | Defines where verifier, manifest, receipts, evidence, docs, and client surfaces should live. |
| `docs/specs/` | Current architecture/objective specs. | Reviewable source of truth for implementation. |
| `docs/reviews/` | Historical/current code reviews if tracked. | Evidence and provenance; do not silently rewrite history as current architecture. |
| `docs/announcement-thread.md` | Draft external messaging. | Must stay caveated until verifier/signature/receipt claims are implemented. |
| `AGENTS.md` | Agent/editor rules. | Must describe current boundaries and avoid stale secZ/server-side claims. |

Untracked local directories such as `hub/`, `ops/`, or `docs/reviews/` in a working checkout are not part of the current Cargo workspace unless deliberately added and documented.

## ZenithPacket v0

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
| `0x0B`–`0x3F` | Castalia standardized candidates | Castalia ecosystem operations whose names/evidence expectations should become portable across compliant receivers. |
| `0x40`–`0xFF` | Operator-defined | Receiver/operator local operations declared by the receiver manifest. |

Current legacy/core examples:

- `0x01` / decimal `1`: `OPCODE_GENERATE`
- `0x02` / decimal `2`: `OPCODE_CHAT`

Current prototype/dev bindings:

- `0x10` / decimal `16`: Bash echo pipe.
- `0x20` / decimal `32`: native Rust queue stub.
- `0x30` / decimal `48`: `jq .` JSON formatter/parser.

These `0x10`/`0x20`/`0x30` bindings are Castalia-standard candidates or dev bindings, not final ratified global semantics.

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

Run the current secZ-named prototype gateway on port `9001`:

```bash
cargo run -p server --bin secz
```

Send a packet with a decimal opcode:

```bash
cargo run -p client -- \
  --server 127.0.0.1:9001 \
  hub 16 'hello from secC'
```

Use decimal `16`, `32`, or `48` for current prototype bindings. Do not pass `0x10` unless the CLI is intentionally changed to parse hex.

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

- Gallery product policy;
- app/browser login UX;
- ordinary WalletAuth HTTP sessions;
- Dregg consensus;
- public settlement;
- auction/business logic;
- arbitrary shell access;
- centralized Hub orchestration;
- Castalia membership semantics as a product authority.

## Operational Boundaries

Do not commit real tunnel keys, local telemetry databases, production packet captures, machine-specific secrets, bearer tokens, or private operator config.

Do not present the prototype as production-secure. Until the verifier/signature/receipt/evidence layers land, describe current behavior as compatibility-preserving prototype infrastructure on the path to the secS verifier substrate.

## License

See `LICENSE`.
