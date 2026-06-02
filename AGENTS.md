# secS-magik Agent Rules

These rules apply to this repository and all agent sessions within it.

## Project Overview

secS-magik is the Rust workspace for the secS permissioned RPC / verifier substrate in the Zenith and Castalia stack.

Corrected boundary:

- local Hermes secS tools/scripts/skills, secC, and secZ are client-side / outgoing-call surfaces that construct secS-compatible calls;
- secS-magik / secS is the verifier and permissioned RPC substrate;
- receiver-local manifests bind `u8` opcodes to operation descriptors and handlers after verification;
- Dregg, Midnight, and Cardano enter through evidence adapters or anchors, not as replacements for the secS verifier boundary;
- WalletAuth / browser app login is separate from internal secS RPC.

Do not describe secZ as the generic Castalia interface or as the verifier. The current `server/src/bin/secz.rs` file is a historical/prototype gateway binary and must be documented as such until it is refactored.

## Source-of-truth docs

Read these before implementation work:

- `README.md` — root orientation map and current boundary.
- `docs/implementation-status.md` — status ledger for solid/current, partial/prototype, planned, future, and out-of-scope surfaces.
- `docs/repository-schema.md` — objective file-system schema for the next implementation pass.
- `docs/specs/2026-06-01-secs-magik-objectives-spec.md` — current architecture/objectives spec.
- `docs/plans/2026-06-01-secs-magik-implementation-issue-slices.md` — issue-level implementation sequence, if present.

Historical reviews under `docs/reviews/` are evidence/provenance. Do not silently rewrite them as current architecture.

Status discipline: every docs/code claim should make clear whether a surface is solid/implemented, partial/prototype, planned next, future/optional, or out of scope. If unsure, mark it partial/prototype or planned, not implemented.

## Changelog

Maintain `CHANGELOG.md` in [Keep a Changelog](https://keepachangelog.com) format when committing changes.

After each commit, add an entry under `## [Unreleased]` using the format:

```markdown
- <what changed> — <why it was changed / what problem it solves>
```

Categories: `### Added` · `### Changed` · `### Fixed` · `### Removed`

The why is required. The diff shows what changed; the changelog records the reasoning that will not survive in the code.

Skip entries for whitespace-only commits, immediately reverted commits, and lock-file bumps with no behavioral intent change.

Never promote `[Unreleased]` to a version block without explicit instruction.

If `CHANGELOG.md` does not exist yet, create it:

```markdown
# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]
```

## Protocol Compatibility

### ZenithPacket v0

Preserve the v0 packet shape unless an explicit versioned migration is approved:

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

- Keep `opcode: u8`.
- Preserve bincode round-trip compatibility for v0.
- The CLI parses hub opcodes as decimal `u8`; use `16`, not `0x10`, unless hex parsing is explicitly added.
- Current prototype proof bytes are not real ZK verification. Label them `PrototypeProofEnvelope` until the typed verifier exists.
- `encrypted_payload` remains opaque to secS except for cryptographic/tunnel verification and handler handoff rules.

### Opcode governance

| Range | Governance | Rule |
|---:|---|---|
| `0x01`–`0x0A` | secS/core standardized | Very small cross-runtime baseline; current `0x01` and `0x02` are legacy examples. |
| `0x0B`–`0x3F` | Castalia-standard candidate | Portable Castalia operation names/evidence expectations after ratification. Current `0x10`/`0x20`/`0x30` are candidates/dev bindings only. |
| `0x40`–`0xFF` | Operator-defined | Receiver/operator local handlers declared by the manifest. |

## Target implementation modules

The next implementation pass should move toward this module ownership:

- `core/src/lib.rs` — `ZenithPacket` v0, constants, exports.
- `core/src/packet_builder.rs` — verifier-free packet construction helper.
- `server/src/verifier.rs` — typed verifier pipeline and `VerificationError`.
- `server/src/context.rs` — `VerifiedCallContext` / `SignedVerifiedCallContext`, if split from verifier.
- `server/src/identity.rs` — Ed25519 key loading, signer key IDs, signature verification helpers.
- `server/src/manifest.rs` — receiver-local `OperationDescriptor` and opcode range governance.
- `server/src/evidence.rs` — `EvidenceAdapter` trait; `local_static` first, then wallet presentation.
- `server/src/receipt.rs` — signed receipts, decisions, reason codes, authenticator kinds.
- `server/src/ledger.rs` — SQLite receipt/event persistence with runtime SQL.
- `server/src/execution.rs` — bounded handler execution after verified context.
- `server/src/runtime_mode.rs` — explicit `local_dev_plaintext`, `local_dev_tunnel`, `production_verified` modes.

## Development Guidelines

### Testing

Run the full workspace before reporting implementation work complete:

```bash
cargo test --workspace
cargo build --workspace
```

For core-only changes:

```bash
cargo test -p libsec-core --all-features
```

For docs-only changes:

```bash
git diff --check -- README.md AGENTS.md docs/
```

### SQLx

Use runtime SQL for telemetry/ledger tables unless the repo also commits and maintains a SQLx offline cache. Do not introduce compile-time SQL macros casually.

### Keys and secrets

Do not commit real tunnel keys, local telemetry databases, production packet captures, machine-specific secrets, bearer tokens, wallet secrets, or private operator config.

Tests may generate ephemeral keys. Docs must distinguish ephemeral test keys from operator identity keys.

### Signed contexts and receipts

Production-shaped verification should use portable public-key signatures, not shared-secret MACs as the main trust path.

- `VerifiedCallContext` should become signed and serialized.
- Receipts should include `authenticator_kind`, `signer_key_id`, and `signature`.
- Local/dev markers must be visibly non-authoritative.

### Runtime modes

Plaintext fallback must not be silent. Use explicit runtime modes:

- `local_dev_plaintext`
- `local_dev_tunnel`
- `production_verified`

Production-like mode should fail closed when required tunnel/MAC/session/evidence inputs are missing.

## Repository Structure

```text
secS-magik/
├── core/                  # verifier-free packet/core primitives
├── client/                # outgoing CLI / secC-like sender
├── server/                # secS verifier substrate and prototype binaries
├── docs/                  # specs, plans, reviews, external messaging drafts
├── README.md              # root orientation map
├── AGENTS.md              # agent/editor rules
└── Cargo.toml             # workspace definition
```

Current workspace members are `core`, `client`, and `server`.

Untracked local directories such as `hub/`, `ops/`, or `docs/reviews/` are not part of the Cargo workspace unless explicitly added and documented.

## Git Workflow

- Main branch: `main`
- Use focused branches or worktrees for agent changes.
- If the checkout is dirty with unrelated files, create a sibling worktree and apply only the intended changes there.
- Do not broad-stage local runtime artifacts, databases, logs, or untracked experimental directories.
