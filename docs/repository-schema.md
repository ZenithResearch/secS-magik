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
  source-of-truth specs, current plans, historical reviews, and public messaging drafts
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
│       ├── packet_builder.rs        # verifier-free packet construction helper, if needed
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
│       ├── main.rs                  # current secS prototype binary on port 9000
│       ├── verifier.rs              # typed verifier errors, prototype envelope check, signed context helpers
│       ├── ingress.rs               # prototype TCP ingress and verifier/payload handoff
│       ├── gateway.rs               # configurable router, telemetry schema, prototype bindings
│       ├── payload.rs               # tunnel key parsing and runtime-mode payload decryption
│       ├── manifest.rs              # receiver-local OperationDescriptor and opcode governance placeholder
│       ├── evidence.rs              # EvidenceAdapter placeholder; local_static adapter first later
│       ├── receipt.rs               # Receipt/decision placeholder
│       ├── ledger.rs                # SQLite event/receipt persistence placeholder
│       ├── runtime_mode.rs          # local_dev_plaintext / local_dev_tunnel / production_verified
│       ├── session.rs               # existing session store until superseded by verifier/session binding
│       └── bin/
│           ├── secs-gateway.rs      # canonical prototype gateway wrapper
│           └── secz.rs              # historical compatibility wrapper
└── docs/
    ├── README.md                    # docs index, once docs grow beyond a few files
    ├── repository-schema.md         # this file
    ├── specs/
    │   └── 2026-06-01-secs-magik-objectives-spec.md
    ├── plans/
    │   └── 2026-06-01-secs-magik-implementation-issue-slices.md
    ├── reviews/
    │   └── 2026-04-30-secs-daemon-code-review.md
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
| `server/src/gateway.rs` | Configurable router, telemetry schema, prototype machine-program bindings. | Packet verification or payload decryption policy. |
| `server/src/payload.rs` | Tunnel key parsing and runtime-mode payload decryption. | Opcode routing, manifest semantics, or receipt persistence. |
| `server/src/manifest.rs` | Placeholder home for receiver-local operation descriptors and opcode governance. | Client-only packet construction; global product policy. |
| `server/src/evidence.rs` | Placeholder home for evidence adapters. | Mandatory external runtime dependencies. |
| `server/src/receipt.rs` | Placeholder home for signed receipts and event object types. | Payload content logging by default. |
| `server/src/ledger.rs` | Placeholder home for SQLite event/receipt storage using runtime SQL. | Compile-time SQLx macros unless offline cache is maintained. |
| `server/src/runtime_mode.rs` | Explicit local/dev/production mode selection. | Silent plaintext fallback. |
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
| `docs/reviews/` | Code reviews and audits. | Historical evidence; do not rewrite as if current architecture. Add supersession notes if needed. |
| `docs/announcement-thread.md` | External narrative draft. | Must not claim production-secure/ZK behavior before verifier proof exists. |
| `AGENTS.md` | Agent rules. | Keep aligned with current boundaries; stale rules are dangerous. |
| `CHANGELOG.md` | Commit reasoning. | Required when committing changes. |

## Migration notes from current repo

Current files that need boundary care:

- `server/src/bin/secz.rs` is now a thin compatibility wrapper. Prototype proof/TTL checks live in `server/src/verifier.rs`, payload handling in `server/src/payload.rs`, connection handling in `server/src/ingress.rs`, and telemetry/routing in `server/src/gateway.rs`.
- `README.md` previously described Dregg as the direct implementation path and Wallet as living inside secS-magik implementations. Current boundary: Dregg/Midnight/Cardano are optional evidence/anchor rails; WalletAuth and browser app sessions are separate from internal secS RPC.
- `docs/announcement-thread.md` previously used strong ZK/security language. It should remain a vision/draft with prototype caveats until signed contexts, receipts, evidence adapters, and verifier checks exist.
- `docs/reviews/2026-04-30-secs-daemon-code-review.md`, if tracked, should remain historical audit evidence. Do not edit its findings into current guidance except by adding a short supersession note.

## Verification checklist for docs realignment

```bash
git diff --check -- README.md AGENTS.md docs/announcement-thread.md docs/repository-schema.md docs/specs/2026-06-01-secs-magik-objectives-spec.md
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
