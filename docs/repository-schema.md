# secS-magik repository schema

This document is the objective file-system schema for the next secS-magik implementation pass. It exists to keep the README, docs, and future code aligned with the corrected boundaries before verifier work begins.

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

Do not organize the repo as though secZ is the server-side verifier. secZ is a client-side / outgoing-call vocabulary surface in the corrected architecture. The existing `server/src/bin/secz.rs` file is a historical/prototype gateway binary and should either be renamed/refactored or clearly documented as a prototype compatibility surface when implementation begins.

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
│       ├── verifier.rs              # typed verifier pipeline and VerificationError
│       ├── context.rs               # VerifiedCallContext and SignedVerifiedCallContext if split from verifier.rs
│       ├── identity.rs              # key loading, signer key ids, signature verification helpers
│       ├── manifest.rs              # receiver-local OperationDescriptor and opcode range governance
│       ├── evidence.rs              # EvidenceAdapter trait and local_static adapter first
│       ├── receipt.rs               # Receipt, ReceiptKind, Decision, AuthenticatorKind
│       ├── ledger.rs                # SQLite event/receipt persistence with runtime SQL
│       ├── execution.rs             # MachineProgram trait, bounded execution broker, timeout/payload limits
│       ├── runtime_mode.rs          # local_dev_plaintext / local_dev_tunnel / production_verified
│       ├── session.rs               # existing session store until superseded by verifier/session binding
│       └── bin/
│           └── secz.rs              # historical/prototype gateway; keep only with compatibility caveat
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
| `server/src/verifier.rs` | Typed verifier pipeline and verifier decisions. | Product policy, app login, settlement, arbitrary handler execution. |
| `server/src/context.rs` | Signed `VerifiedCallContext` serialization/verification if split. | Raw private evidence by default. |
| `server/src/identity.rs` | Ed25519 signer/verifier key loading and key ids. | Hidden long-lived key generation or secret printing. |
| `server/src/manifest.rs` | Receiver-local operation descriptors and opcode range governance. | Client-only packet construction; global product policy. |
| `server/src/evidence.rs` | Evidence adapter trait and local_static first adapter. | Dregg/Midnight/Cardano mandatory runtime dependencies. |
| `server/src/receipt.rs` | Signed receipts and event object types. | Payload content logging by default. |
| `server/src/ledger.rs` | SQLite event/receipt storage using runtime SQL. | Compile-time SQLx macros unless offline cache is maintained. |
| `server/src/execution.rs` | Bounded handler execution after signed verified context. | Broad ambient shell authority. |
| `server/src/runtime_mode.rs` | Explicit local/dev/production mode selection. | Silent plaintext fallback. |
| `server/src/bin/secz.rs` | Current prototype gateway compatibility surface. | Final verifier semantics or generic Castalia interface claims. |

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

- `server/src/bin/secz.rs` currently performs prototype proof/TTL checks, decrypt/passthrough, SQLite telemetry, and handler routing. Under the corrected boundary, these are server-side verifier/execution prototype concerns, not proof that secZ owns verification.
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
