# secS-magik repository schema

This document records the current file-system schema plus the next target seams for secS-magik. It exists to keep the README, docs, and code aligned with the corrected boundaries as verifier work lands.

## Boundary rule

The repository should be organized around this split:

```text
core/
  verifier-free packet and crypto primitives

client/
  outgoing packet construction and CLI sending

server/
  secS verifier/RPC substrate, receiver manifests, signed contexts, receipts, evidence adapters, and bounded execution

docs/
  source-of-truth specs, current plans, current status, specs, plans, and public messaging drafts
```

Do not organize the repo as though secZ is the server-side verifier. secZ is a client-side / outgoing-call vocabulary surface in the corrected architecture. The existing `server/src/bin/secz.rs` file is now a thin compatibility wrapper. Canonical reusable gateway behavior lives in library modules and the canonical prototype binary is `server/src/bin/secs-gateway.rs`.

## Target tree

```text
secS-magik/
├── README.md
├── docs/implementation-status.md     # status ledger: implemented/partial/planned/future/out-of-scope
├── AGENTS.md
├── CHANGELOG.md
├── Cargo.toml
├── Cargo.lock
├── core/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                  # ZenithPacket v0, standard opcode constants, core exports
│       ├── packet_builder.rs        # verifier-free packet construction helper
│       ├── tunnel.rs                # tunnel crypto helpers
│       ├── zk.rs                    # signature/proof helper primitives; not the full server verifier
│       └── ffi.rs                   # UniFFI bindings behind feature flag
├── client/
│   ├── Cargo.toml
│   └── src/
│       └── main.rs                  # current CLI / secC-like outgoing sender
├── server/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                   # server module exports and shared server entry points
│       ├── config.rs                # typed runtime config/readiness inputs
│       ├── identity.rs              # verifier identity, key IDs, local public-key registry seam
│       ├── verifier.rs              # typed verifier errors, prototype envelope check, signed context helpers
│       ├── ingress.rs               # bounded prototype TCP ingress and verifier/payload handoff
│       ├── gateway.rs               # configurable router, legacy telemetry, local bounded handler routing
│       ├── payload.rs               # tunnel key parsing and runtime-mode payload decryption
│       ├── manifest.rs              # receiver-local OperationDescriptor and opcode governance
│       ├── evidence.rs              # EvidenceAdapter trait, local_static, wallet_presentation crypto seam
│       ├── receipt.rs               # signed receipt/event types and reason/authenticator metadata
│       ├── ledger.rs                # local SQLite event/receipt/replay persistence and inspection
│       ├── schema.rs                # centralized runtime SQLite schema ontology
│       ├── ontology.rs              # shared prototype receiver/audience/reason constants
│       ├── runtime_mode.rs          # local_dev_plaintext / local_dev_tunnel / production_verified
│       ├── session.rs               # local in-memory session utility
│       └── bin/
│           ├── secs-gateway.rs      # canonical prototype gateway wrapper
│           └── secz.rs              # historical compatibility wrapper
└── docs/
    ├── README.md                    # docs index
    ├── implementation-status.md     # current status ledger
    ├── repository-schema.md         # this file
    ├── client-surfaces.md           # client-side/outgoing-call boundary
    ├── specs/
    │   ├── README.md
    │   └── 2026-06-01-secs-magik-objectives-spec.md
    ├── plans/
    │   ├── README.md
    │   ├── 2026-06-01-implementation-progress-checklist.md
    │   ├── 2026-06-01-secs-magik-implementation-issue-slices.md
    │   └── 2026-06-02-ready-for-prod-checklist.md
    └── announcement-thread.md       # public-language draft with prototype caveats
```

## Module ownership

| Module/file | Owns | Must not own |
|---|---|---|
| `core/src/lib.rs` | `ZenithPacket` v0, core opcode constants, exports. | Product policy, receiver-local manifest semantics, verifier state. |
| `core/src/packet_builder.rs` | Verifier-free `ZenithPacket` construction helper. | Capabilities, credential checks, evidence verification, authority decisions. |
| `core/src/zk.rs` | Low-level signing/proof helper primitives. | The full secS verifier pipeline or public claims that proof bytes are enough. |
| `client/src/main.rs` | CLI packet sending; current secC-like outgoing path. | Server-side verification, receiver-local operation authority. |
| `server/src/verifier.rs` | Typed verifier errors, prototype envelope check, signed context helpers. | Product policy, app login, settlement, arbitrary handler execution. |
| `server/src/ingress.rs` | Prototype TCP ingress and verifier/payload handoff. | Receiver-local manifest semantics or handler implementation details. |
| `server/src/gateway.rs` | Configurable router, legacy telemetry, receiver-local bounded handler routing, and handler lifecycle receipt/event emission. | Packet decode or payload decryption policy; durable distributed broker semantics; arbitrary shell authority. |
| `server/src/payload.rs` | Tunnel key parsing and runtime-mode payload decryption. | Opcode routing, manifest semantics, or receipt persistence. |
| `server/src/manifest.rs` | Receiver-local operation descriptors, handler IDs, evidence requirements, and opcode governance. | Client-only packet construction; global product policy; final global opcode ratification. |
| `server/src/evidence.rs` | `EvidenceAdapter` trait, `local_static` local-dev-test adapter, and cryptographic `wallet_presentation` proof-of-possession over the temporary secS challenge contract. | Mandatory external runtime dependencies, full Castalia Wallet wallet-core parity claims, trusted issuer/root policy, or production Dregg/Midnight/Cardano authority claims. |
| `server/src/receipt.rs` | In-memory signed receipt and event types: typed reject/verify/execute/forward receipts, decisions, authenticator kinds, stable event names, and Ed25519 receipt helpers. | Payload content logging and durable persistence by default. |
| `server/src/ledger.rs` | Local SQLite event/receipt/replay storage and redacted operator inspection using runtime SQL. | Compile-time SQLx macros unless offline cache is maintained; payload content persistence by default; public-chain anchoring. |
| `server/src/runtime_mode.rs` | Explicit local/dev/production mode selection. | Silent plaintext fallback. |
| `server/src/config.rs` | Typed gateway runtime config and readiness inputs. | Hidden production defaults or fixture-only smoke config masquerading as deployed production. |
| `server/src/identity.rs` | Verifier identity loading, signer key IDs, receipt/context signing, and local public-key registry checks. | Live federation discovery or complete trusted issuer/root policy. |
| `server/src/schema.rs` | Central runtime SQLite schema definitions and lightweight local ledger migrations. | Public-chain anchoring or remote retention. |
| `server/src/ontology.rs` | Shared prototype receiver/audience/reason constants. | Product authority or live trust registry semantics. |
| `server/src/bin/secs-gateway.rs` | Canonical prototype gateway command. | Reusable gateway logic. |
| `server/src/bin/secz.rs` | Compatibility wrapper for the historical command name. | Final verifier semantics or generic interface claims. |

## Opcode range schema

| Range | Governance | Where declared first | Rule |
|---:|---|---|---|
| `0x01`–`0x0A` | secS/core standardized | `core/src/lib.rs` constants plus `server/src/manifest.rs` descriptors | Very small cross-runtime baseline; current `0x01` and `0x02` are legacy examples. |
| `0x0B`–`0x3F` | Castalia-standard candidate | `server/src/manifest.rs` descriptors first, later promoted if ratified | Portable Castalia operation names/evidence expectations. Current `0x10`/`0x20`/`0x30` are candidates/dev bindings only. |
| `0x40`–`0xFF` | Operator-defined | Receiver manifest | Local/operator-specific handlers. |

## Docs schema

| Path | Purpose | Update rule |
|---|---|---|
| `README.md` | Root orientation map. | Keep current, shallow, searchable, boundary-safe, and status-explicit. |
| `docs/implementation-status.md` | Implementation status ledger. | Update whenever docs/code status changes; prevents future/planned work from being described as implemented. |
| `docs/repository-schema.md` | File-system/schema target for implementation agents. | Update before moving modules or adding new doc classes. |
| `docs/specs/` | Current architecture/specification docs. | Current source-of-truth specs only. |
| `docs/plans/` | Implementation plans/issue slices. | Reviewable plans; do not mix with historical audits. |
| `docs/announcement-thread.md` | External narrative draft. | Must not claim production-secure/ZK behavior before verifier proof exists. |
| `AGENTS.md` | Agent rules. | Keep aligned with current boundaries; stale rules are dangerous. |
| `CHANGELOG.md` | Commit reasoning. | Required when committing changes. |

## Migration notes from current repo

Current files that need boundary care:

- `server/src/bin/secz.rs` is now a thin compatibility wrapper. Prototype proof/TTL checks live in `server/src/verifier.rs`, payload handling in `server/src/payload.rs`, connection handling in `server/src/ingress.rs`, and telemetry/routing in `server/src/gateway.rs`.
- `README.md` previously described Dregg as the direct implementation path and Wallet as living inside secS-magik implementations. Current boundary: Dregg/Midnight/Cardano are optional evidence/anchor rails; WalletAuth and browser app sessions are separate from internal secS RPC.
- `docs/announcement-thread.md` previously used strong ZK/security language. It should remain a vision/draft with prototype caveats until signed contexts, receipts, evidence adapters, and verifier checks exist.
- Historical review files, if reintroduced under `docs/reviews/`, should remain audit evidence. Do not edit old findings into current guidance except by adding a short supersession note that points readers to `docs/implementation-status.md`.

## Verification checklist for docs realignment

```bash
git diff --check -- CHANGELOG.md README.md AGENTS.md docs/
cargo test --workspace
```

Docs content checks:

- [ ] README says local Hermes/secC/secZ are client-side/outgoing surfaces.
- [ ] README says secS-magik/secS is the verifier/RPC substrate.
- [ ] README does not call secZ the generic Castalia interface or verifier.
- [ ] README preserves `ZenithPacket` v0 and decimal opcode CLI rule.
- [ ] AGENTS.md names the corrected module boundaries.
- [ ] Announcement thread is caveated as a draft/target, not a current production claim.
- [ ] Specs/plans/status ledger are linked from README.
- [ ] Docs distinguish solid implemented, partial/prototype, planned next, future/optional, and out-of-scope surfaces.
- [ ] No secrets, real keys, tokens, DB files, or private operator paths are introduced.
