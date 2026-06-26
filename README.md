# secS-magik

secS-magik is a Rust workspace for a permissioned machine-to-machine RPC and verifier substrate.

Status: active prototype being realigned toward the 2026-06-01 objectives spec. Current code preserves the v0 packet shape and `u8` opcode dispatch; exposes client, core, and server crates; hardens the canonical gateway with bounded ingress, explicit runtime config/readiness, receiver-local manifest routing, signed context/receipt posture, local SQLite receipt/event persistence, redacted operator inspection, bounded handler execution, cryptographic wallet-presentation verification through an explicitly temporary minimal-equivalent secS challenge contract, Track E static trusted issuer/root policy on `main`, and Track I local production-shaped `membership.provision` E2E on `main` via PR #76. Issue #77 adds a fail-closed descriptor-only `production_verified` runtime guard for canonical `0x44` `membership.provision`, while the evidence-backed helper path still covers the local E2E. Live runtime ingress now accepts a versioned request envelope carrying bounded evidence refs/public inputs for `membership.provision`; handler binding is still not authority, and those refs route through the canonical evidence adapter path. M15.2–M15.6 plus #159 provide bounded static Dregg policy-admission, fail-closed proof/finality blocker posture, and local operator-inspection; #144/M15.8 closes the bounded in-repo #73 finalizer while live proof/finality rails remain non-goals. This is not production deployment, public auditability, live Castalia/Dregg discovery, Midnight proof verification, Cardano authority, or full Castalia Wallet wallet-core parity.

## Table of Contents

- [Status / Updates](#status--updates)
- [Overview](#overview)
- [Current Boundary](#current-boundary)
- [System Architecture](#system-architecture)
- [Components / Repository Map](#components--repository-map)
- [Directory READMEs / Wiki Map](#directory-readmes--wiki-map)
- [Demoable Milestone (M12)](#demoable-milestone-m12)
- [How It Works](#how-it-works)
- [Key Design Decisions](#key-design-decisions)
- [Packet v0](#packet-v0)
- [Opcode Governance](#opcode-governance)
- [Running Locally](#running-locally)
- [Testing and Verification](#testing-and-verification)
- [Documentation Map](#documentation-map)
- [Current Non-Goals](#current-non-goals)
- [Operational Boundaries](#operational-boundaries)
- [License](#license)

## Status / Updates

Use these labels across all docs:

| Label | Meaning in this repo |
|---|---|
| Solid / implemented | Present in current code and covered by tests or direct inspection. |
| Partial / prototype | Present, but incomplete, local-only, misleadingly named, or not strong enough for production/security claims. |
| Planned / next implementation | Accepted next-pass design; not yet in code. |
| Future / optional rail | Later-stage direction. |
| Out of scope | This repository should not own it. |

Short current status:

- Solid on `main`: v0 packet shape, `u8` opcode field, `0x01`/`0x02` constants, CLI decimal opcode parsing, packet round-trip tests, tunnel helper tests, Ed25519 helper primitives, signed verifier context helpers, explicit runtime payload modes, receiver-local manifest descriptors, descriptor-bound local handler routing, receiver-local permission policy loading/readiness for canonical gateway startup, receiver-local durable replay/session/expiry enforcement within the configured local replay store/scope, typed receipt/event objects, local SQLite receipt/event persistence, redacted local/operator inspection by receipt/context id, own-verifier key lifecycle seam, production-shaped runtime config/readiness, deterministic `local_static` local-dev-test evidence seam, cryptographic `wallet_presentation` verification over the temporary minimal-equivalent secS challenge contract, Track E static trusted issuer/root policy for signed membership/provisioning credentials, and Track I local production-shaped `membership.provision` E2E.
- Partial / prototype: current secS TCP listener/prototype verifier path, `server/src/bin/secz.rs` compatibility wrapper, prototype proof/TTL envelope checks, legacy `node_telemetry`, and local/dev handler bindings.
- Planned next: replacement/reconciliation of the temporary wallet challenge contract with full Castalia Wallet wallet-core parity, #144 finalizer reconciliation for #73 after the landed #169 trusted requested-authority attenuation seam and #160 bounded Dregg resource-lock scope; #169 is only the trusted requested-authority no-widening seam, #77 is only the fail-closed descriptor-only runtime guard, and #162 is the live ingress evidence-ref wire path.
- Future / optional: external proof, federation receipt, and settlement evidence adapters.
- Out of scope: product policy, app/browser login UX, external consensus, settlement logic, centralized orchestration, arbitrary shell access, and application membership semantics.

## Overview

- What it does now: defines the v0 packet type, sends packets from a CLI, runs prototype TCP listeners, bounds ingress wire reads before packet deserialization, checks prototype proof/TTL envelopes, handles payload decryption through explicit runtime modes, describes receiver-local operations, signs/verifies typed verifier contexts, enforces descriptor max TTL/session validity and receiver-local replay reservation before handler execution, routes verified bounded opcodes to configured local machine programs, persists typed receipt/event records to local SQLite without storing payload content by default, and exposes redacted local/operator receipt inspection.
- What production-shaped gateway startup additionally requires now: `production_verified` must provide `SECS_PERMISSION_POLICY_PATH`; the file is parsed as receiver-local `PermissionPolicy` during readiness and installed into the canonical ingress router before local handler dispatch. When `SECS_ALLOWED_EVIDENCE_ADAPTERS` includes `dregg_authority`, startup/readiness also requires `SECS_DREGG_AUTHORITY_REGISTRY_PATH` and parses it as the receiver-held Dregg issuer/root/epoch policy registry. Missing or invalid policy files fail startup/readiness closed.
- What it is becoming: a typed secS verifier pipeline with receiver-local operation manifests, signed `VerifiedCallContext`, signed receipts, local event ledger, and evidence adapters.
- Who it is for: developers and operators building owned machine-call rails instead of broad bearer-token APIs.
- Primary stack: Rust workspace with `core`, `client`, and `server`; Tokio TCP; bincode packet serialization; optional ChaCha20Poly1305 tunnel decryption; SQLite through SQLx runtime queries.

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
- External proof, federation, and settlement systems enter through typed evidence adapters or anchors; they do not replace the secS verifier boundary. The current Dregg-shaped adapter verifies envelope **shape + author signature only** (`secs-dregg-receipt-shape-v1`, a temporary minimal-equivalent contract); it is not Dregg blocklace finality, capability, nullifier, CapTP, or revocation authority — the earlier M12.3 shape-only seam is superseded by the bounded #144/M15.8 #73 finalizer; live Dregg proof/finality remains unsupported.
- #177 adds only the live-Dregg contract/fail-closed seam: versioned DTOs, verifier traits, stable missing-live-verifier reason codes, and production readiness rejection when live verifier modes are required but no live dependency is configured. Live revocation roots (#178) now verify against explicit trusted-root/non-membership proof refs; BLS threshold finality (#179) now verifies typed QC refs against explicit committee/epoch config; rotated replay/full-turn proofs (#180) now verify bounded typed proof refs, resource/turn hashes, nullifier sets, and composition with revocation + BLS finality.
- Browser/app login is separate from secS internal RPC.

## System Architecture

```text
client / local tool / service
  -> ZenithPacket v0
  -> bounded TCP ingress
  -> frame/decode/prototype envelope/runtime checks
  -> receiver-local descriptor lookup
  -> signed VerifiedCallContext or reject receipt
  -> receiver-local replay/session/expiry gate
  -> bounded local handler routing
  -> signed receipt + event pair
  -> local SQLite operator ledger
  -> redacted operator inspection/export
```

This is local/operator evidence. It is not public chain anchoring, public auditability, or production deployment proof.


### Public audit bundle contract (#181)

#181 defines `secs-public-audit-bundle-v1`, a redacted local export bundle and local verifier contract for complete signed receipt chains. The bundle includes receipt ids, context ids, receipt signatures, signer public-key material, redacted evidence summaries, and deterministic chain metadata. This is local public-bundle verification, not external anchoring, immutable publication, chain settlement, or production deployment proof; #182-#185 continue the public-audit train beyond this first contract slice.


## Components / Repository Map

| Path | Responsibility | Boundary |
|---|---|---|
| `README.md` | Root orientation map. | Broad/shallow; link deeper docs instead of becoming the full spec. |
| `Cargo.toml` | Workspace definition. | Current members: `core`, `client`, `server`. |
| `core/` | Shared packet and verifier-free core primitives. | Owns the v0 packet shape and constants; should not own product policy or receiver-local dispatch semantics. |
| `client/` | CLI packet sender; current secC-like client surface. | Builds and sends packets; does not verify inbound authority. |
| `server/` | secS prototype gateway/verifier substrate. | Owns current ingress, verifier helpers, manifests, evidence seam, receipts, local ledger, runtime config, and bounded local routing. |
| `server/src/bin/secs-gateway.rs` | Canonical current prototype configurable gateway binary on port `9001` unless configured otherwise. | Thin wrapper over library modules. |
| `server/src/bin/secz.rs` | Compatibility wrapper for the historical secZ-named gateway command. | Kept for current command compatibility, not canonical verifier ownership. |
| `server/src/manifest.rs` | Receiver-local operation descriptors and opcode governance. | Descriptor semantics are wired into signed-context creation and receiver-local bounded handler routing; this is not final global opcode ratification. |
| `server/src/evidence.rs` | Evidence adapter seam. | Defines typed evidence requests/results, deterministic `local_static` local-dev-test adapter, cryptographic `wallet_presentation` proof-of-possession for the claimed subject using the explicitly temporary minimal-equivalent secS challenge contract, receiver-held `TrustedIssuerEntry` registry policy, and signed `membership_credential` / `provisioning_credential` verification against static fixture roots. Track D alone remains not trusted issuer/root/registry policy; Track E supplies the separate static trusted-issuer fixture policy on this phase branch. Full Castalia Wallet wallet-core import, live Castalia/Dregg discovery, Midnight/Cardano authority, public auditability, and deployment proof remain outside this repo-local Track E branch. |
| `server/src/receipt.rs` | Typed receipt/event objects. | Defines reject/verify/execute/forward receipt kinds, typed decisions/reasons/authenticator kinds, stable event names, and Ed25519 receipt signing helpers. |
| `server/src/ledger.rs` | Event/receipt ledger. | Persists events and receipts with runtime SQL; exports `secs-public-audit-bundle-v1` redacted public-audit bundles for local public-bundle verification, not external anchoring; does not store payload content by default. |
| `docs/` | Specs, plans, status ledgers, and external-language drafts. | Docs must distinguish implemented behavior from target/planned behavior. |
| `AGENTS.md` | Contributor/agent rules. | Internal editing conventions for future automated work. |

Untracked local directories such as `hub/`, `ops/`, or `docs/reviews/` in a working checkout are not part of the current Cargo workspace unless deliberately added and documented.

## Directory READMEs / Wiki Map

Each repository directory owns its local map. Start here, then follow the child README for depth:

| Directory | README | Purpose |
|---|---|---|
| `core/` | [core/README.md](core/README.md) | Shared verifier-free packet and crypto primitives. |
| `client/` | [client/README.md](client/README.md) | CLI / secC-like outgoing packet sender. |
| `server/` | [server/README.md](server/README.md) | secS gateway/verifier substrate, manifests, receipts, local ledger, runtime modes, and bounded routing. |
| `docs/` | [docs/README.md](docs/README.md) | Documentation index and status/spec/plan navigation. |
| `docs/specs/` | [docs/specs/README.md](docs/specs/README.md) | Current architecture/objective specifications. |
| `docs/plans/` | [docs/plans/README.md](docs/plans/README.md) | Implementation plans, checklists, and issue-slice control surfaces. |
| `examples/` | [examples/README.md](examples/README.md) | Runnable local examples and demos. |
| `scripts/` | [scripts/README.md](scripts/README.md) | Smoke and local verification helper scripts. |

## Demoable Milestone (M12)

`./examples/m12-demo.sh` demonstrates the end-to-end verifier state against
the live local gateway: authenticated caller accept (with the signed decision
returned to the caller), forged-proof and unknown-caller typed rejects,
replay and expiry rejects, wallet + Dregg-shaped evidence composition at the
adapter seam, and operator inspection of the verify/execute/reject receipt
chain. The demo proves local verifier behavior only — not production
deployment (#33), public auditability (#37), wallet-core parity (#71), live
registry discovery (#72), or Dregg/Midnight/Cardano authority (#73-#75);
live evidence-aware ingress is the #162 rail, while trusted requested-authority attenuation is bounded to #169 and resource locks remain #160.

## How It Works

Current request lifecycle:

1. A client constructs a `ZenithPacket` v0.
2. The gateway accepts bounded TCP input and rejects oversize/malformed frames before unsafe decode behavior.
3. Prototype envelope, TTL, runtime-mode payload, and descriptor checks run.
4. The gateway creates a signed verified context or a typed reject receipt.
5. Receiver-local replay/session/expiry checks run before handler execution.
6. The receiver-local manifest selects the local handler by descriptor metadata.
7. Bounded handler routing enforces payload, output, timeout, and production/dev binding limits.
8. Receipts and events are persisted to local SQLite, with receipt+event pairs written atomically where required.
9. Operators inspect redacted local receipt/event chains by receipt id, context id, packet hash, or related tuple depending on the helper/test surface.

## Key Design Decisions

- Preserve the v0 packet shape and `u8` opcode compatibility until an explicit versioned migration is approved.
- Keep client packet construction separate from server-side authority verification.
- Treat receiver-local manifests as local opcode-to-operation/handler maps, not global product policy.
- Mark local/dev evidence and plaintext modes as visibly non-authoritative.
- Keep current ledger claims bounded to local/operator SQLite evidence.
- Keep the Track D wallet cryptographic verifier bounded to the temporary minimal-equivalent secS challenge contract until full Castalia Wallet wallet-core parity replaces or reconciles it; wallet proof-of-possession remains necessary where required but never sufficient issuer/root authority.
- Keep Track E authority receiver-held: static fixture `TrustedIssuerEntry` registry metadata, signed membership/provisioning credentials, `trust_root_ref` / `registry_root_ref` matching, and descriptor-local policy decide production evidence acceptance. Caller-supplied keys/root refs, `local_static`, plaintext/prototype evidence, and wallet-only evidence do not become sufficient authority.
- Keep Dregg, Midnight, and Cardano as future adapter/anchor rails. M15.2 adds the receiver-held static `dregg_authority` issuer/root/epoch registry and production startup/readiness requirement when that adapter is enabled; it still does not verify Dregg token admission, revocation proofs, finality, Midnight, Cardano, public auditability, or deployment proof.

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
- Preserve current bincode round-trip compatibility while using bounded ingress decode for externally supplied frames.
- The CLI parses opcodes as decimal `u8`; use `16`, not `0x10`.
- Current prototype proof bytes are not real ZK verification. Treat them as a `PrototypeProofEnvelope` until replaced by a proof adapter with defined statements and public inputs. With a configured caller registry, `proof` additionally carries the versioned caller proof-of-origin envelope (M12.1).
- `encrypted_payload` remains opaque to secS except for cryptographic/tunnel verification and handler handoff rules. The local client can encrypt payloads with either the static local-dev tunnel key (`SECS_TUNNEL_KEY_HEX`) or the v2 per-session tunnel path (`SECS_TUNNEL_SERVER_X25519_PUBLIC_HEX` client-side, `SECS_TUNNEL_X25519_SECRET_HEX` gateway-side); the latter derives the AEAD key via X25519 + HKDF and carries only the client ephemeral public key in the ingress envelope.
- `mac` is **reserved and zeroed** (M12.6, option b). It is kept only for v0 byte-layout compatibility, is never verified, and provides no authentication — do not mistake it for a MAC. Caller authenticity comes from the caller proof envelope (M12.1); payload integrity under tunnel keys comes from ChaCha20Poly1305 AEAD bound to the envelope (M12.4). Making it a real verified MAC or removing it would be an explicit, owned wire-format migration.

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

## Running Locally

Build and test the workspace:

```bash
cargo test --workspace
cargo build --workspace
```

Run the canonical current prototype gateway for local development on port `9001`:

```bash
SECS_RUNTIME_MODE=local_dev_plaintext cargo run -p server --bin secs-gateway
```

The bare command defaults to `production_verified`, which intentionally fails fast unless the operator provides explicit `SECS_*` runtime limits, verifier key, ledger path, trust registry, receiver audience, and bind address. For a no-real-secret production-shaped fixture smoke, use:

```bash
./scripts/production-gateway-smoke.sh
```

Fixture smoke output is not `membership.provision` success by itself. For the Track I membership-provisioning contract, success requires an inspectable receipt chain for the same context with both `verify accepted` and `execute accepted`; verifier-only acceptance, handler-unavailable routing, stdout/stderr/log output, or fixture smoke output without an accepted execute receipt remains non-success.

The historical `secz` binary remains as a compatibility wrapper for the same prototype gateway:

```bash
SECS_RUNTIME_MODE=local_dev_plaintext cargo run -p server --bin secz
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

## Documentation Map

Current source of truth:

- [docs/implementation-status.md](docs/implementation-status.md) — status ledger: implemented vs partial vs planned vs future vs out-of-scope.
- [docs/repository-schema.md](docs/repository-schema.md) — objective file-system schema and repository boundary map.
- [docs/client-surfaces.md](docs/client-surfaces.md) — client-side local Hermes/secC/secZ packet-construction boundary.
- [docs/specs/2026-06-01-secs-magik-objectives-spec.md](docs/specs/2026-06-01-secs-magik-objectives-spec.md) — current architecture/objectives spec.
- [docs/plans/2026-06-02-ready-for-prod-checklist.md](docs/plans/2026-06-02-ready-for-prod-checklist.md) — current ready-for-prod track checklist and completion checkpoints.
- [docs/announcement-thread.md](docs/announcement-thread.md) — public-language draft, intentionally caveated until verifier work lands.

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

The verifier-facing protocol boundary is the packet/verifier/manifest/receipt path. Application policy, login UX, consensus, settlement, and orchestration systems should integrate through explicit adapters or client surfaces rather than becoming core verifier logic.

## License

See [LICENSE](LICENSE).


#160 implements bounded Dregg-provisioned resource locks: a Dregg authority token may bind an exact verifier-derived trusted requested resource as `resource_lock:verified`, reject mismatches as `resource_lock_violation`, and propagate the locked resource into the signed context for handler/policy use. This is separate from #169 trusted requested-authority attenuation, does not implement live Dregg revocation proof/BLS finality/rotated-replay proof verification, and #159 remains fail-closed blocker posture only. #144/M15.8 reconciles the bounded #73 finalizer.


#144/M15.8 reconciles the bounded #73 finalizer across #162 live ingress evidence refs/public inputs, #167 delegated attenuation / non-amplification, #169 trusted requested-authority attenuation, and #160 implements bounded Dregg-provisioned resource locks. The finalizer preserves `resource_lock:verified` acceptance, `resource_lock_violation` rejection, redaction-safe operator summaries, and signed-context propagation of the verified locked resource for handler/policy use. See `examples/m15-dregg-authority-demo.sh` for the bounded production-shaped demo/checklist. This is not deployment proof, not public auditability, not live Dregg revocation proof, not BLS threshold finality, not rotated-replay proof verification, not Midnight, and not Cardano.

- Tunnel key lifecycle (#175): v2 session-key clients may pin `SECS_TUNNEL_SERVER_X25519_PUBLIC_ID`, while gateways expose redacted `tunnel:x25519:<hash>` identities for current/next X25519 keys and record accepted v2 key ids in verify receipts.
