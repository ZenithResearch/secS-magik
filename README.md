# secS-magik

[![Rust CI](https://github.com/ZenithResearch/secS-magik/actions/workflows/ci.yml/badge.svg)](https://github.com/ZenithResearch/secS-magik/actions/workflows/ci.yml)
[![Documentation Pages](https://github.com/ZenithResearch/secS-magik/actions/workflows/pages.yml/badge.svg)](https://github.com/ZenithResearch/secS-magik/actions/workflows/pages.yml)

secS-magik is a Rust workspace for a receiver-controlled, permissioned machine-to-machine RPC and verifier substrate. A caller constructs a bounded packet, the receiver verifies the packet and authority context, a receiver-local manifest selects an exact operation, and a bounded local handler may run only after those checks succeed.

This repository is an active, production-shaped **local prototype**. It contains real protocol types, cryptography, verification and policy components, bounded execution, signed responses and receipts, SQLite persistence, local audit export/verification, native CLIs, and browser WASM. It does **not** contain evidence of an operator production deployment, a generic AI inference service, a durable conversation service, live federation consensus, or public-chain settlement.

## Start here

| Destination | Purpose |
|---|---|
| [Documentation site](https://zenithresearch.github.io/secS-magik/) | This README rendered as the project home, plus the tracked Markdown corpus. |
| [Rust API documentation](https://zenithresearch.github.io/secS-magik/api/) | Generated host-target API docs for the five workspace crates. |
| [WASM API documentation](https://zenithresearch.github.io/secS-magik/wasm-api/) | Generated wasm32 API docs for `libsec-core` and the permission panel. |
| [Browser permission panel](https://zenithresearch.github.io/secS-magik/panel/) | Existing no-network receiver-local policy authoring/evaluation UI. |
| [Current state](docs/current-state.md) | Short, date-stamped orientation derived from the implementation ledger. |
| [Implementation status](docs/implementation-status.md) | Evidence-level status ledger and the authority for implemented/partial/planned claims. |
| [Runtime reference](docs/reference/runtime.md) | Binaries, modes, configuration groups, operations, storage, and audit commands. |
| [WASM and Pages reference](docs/reference/wasm-and-pages.md) | WASM exports, browser boundary, local builds, and Pages layout. |

The root README is the canonical front door and operating map. The implementation ledger remains authoritative when a claim requires exact evidence or caveats.

## Status at a glance

| Surface | Current status | Exact boundary |
|---|---|---|
| Workspace | Solid / implemented | Five members: `libsec-core`, `client`, `server`, `secs-permissions`, and `panel`. |
| Packet compatibility | Solid / implemented | `ZenithPacket` v0 retains a `u8` opcode and its original bincode field order. The final `mac` field is reserved and unauthenticated. |
| Ingress | Solid local hardening; prototype transport | Bounded TCP reads, legacy Packet v0 plus versioned ingress envelopes, explicit payload modes, typed rejects, and concurrency limits. No TLS listener or deployed-service proof. |
| Caller and receiver identity | Solid local implementation | Ed25519 caller proofs, receiver signing identities, key identifiers, owner-private key-file checks, and receiver-held registries. Registry distribution/rotation remains operator-owned. |
| Verification and dispatch | Solid receiver-local implementation | Descriptor lookup, signed verified contexts, descriptor fingerprint rebinding checks, replay/session/expiry gates, permission checks, and handler routing. |
| Handler execution | Solid bounded local implementation | Native handlers and local-dev subprocess handlers with payload/output/time limits and lifecycle receipts. Not arbitrary shell authority. |
| Permission model | Solid / implemented | Shared receiver-local allow/deny records, exact or prefix resources, validity windows, revocation, deny-wins evaluation, CLI, and browser WASM panel. |
| Evidence adapters | Mixed | Local fixtures, wallet proof-of-possession over a temporary challenge contract, trusted issuer fixtures, and bounded Dregg-shaped/verifier seams exist. Live federation discovery/finality is not established. |
| Receipts and audit | Solid local/operator implementation | Signed receipt/event records, SQLite persistence, redacted inspection, versioned audit bundles/chains, local verification, and bounded external-anchor witnesses. Not blockchain immutability or public auditability. |
| Execution output transport | Solid core/server transport | Bounded, receiver-signed, request-correlated `ExecutionResponse` exists. The shipped client CLI does not yet have trusted response mappings for arbitrary non-legacy operations. |
| WASM | Solid bounded surfaces | Core tunnel encrypt/decrypt exports and a no-network permission-policy panel. No browser wallet product or remote administration plane. |
| `generate` / `chat` | Legacy examples only | Constants, client commands, and descriptors exist, but no inference backend, model routing, managed conversation store, or weave runtime is installed. |
| Production deployment | Not evidenced | `production_verified` fails closed on missing operator config, but repository tests and fixture smoke are not proof of a deployed production service. |

## What secS is—and is not

The intended ownership split is:

```text
user / local tool / service / agent harness
  -> client-side secS packet construction
  -> secS gateway and verifier
  -> receiver-local operation descriptor
  -> receiver-local bounded handler
  -> signed response + receipt/event evidence
```

- `client`, secC-like tools, local Hermes integrations, and future harness adapters are **callers**. They construct or carry requests; they do not decide receiver authority.
- `server` is the secS verifier and permissioned RPC substrate. It validates the receiver's conditions and produces typed signed handoff/audit objects.
- `ReceiverManifest` assigns local meaning to compact `u8` opcodes. An opcode alone never grants authority.
- Dregg, wallet, Midnight, Cardano, or other proof systems can enter through evidence adapters or anchors. They do not replace secS verification.
- Configured metadata-only routes can consult a trusted verification-key/circuit/public-input-schema registry and record `proof_metadata_bound`. That gate is not light-client or recursive proof verification: I18 light-client verification and I19 recursive proof-carrying state remain separate future boundaries.
- `server/src/bin/secz.rs` is a historical compatibility gateway and audit CLI surface, not the generic Castalia interface and not separate verifier ownership.
- Browser/app WalletAuth and product login UX are outside this internal RPC repository.

## Request lifecycle

The canonical prototype path is:

```text
1. caller identity + operation intent
2. ZenithPacket v0 or versioned IngressRequest envelope
3. bounded TCP read and frame decoding
4. caller proof, packet, payload-mode, and manifest checks
5. evidence / credential / capability / privacy policy evaluation
6. receiver-signed VerifiedCallContext
7. context signature + active-descriptor fingerprint revalidation
8. receiver-local replay, session, expiry, nullifier, and permission gates
9. bounded receiver-local handler execution
10. DecisionResponse or authenticated ExecutionResponse
11. signed receipt/event persistence and redacted operator/audit projections
```

Important ordering guarantees are covered by integration tests: verification failures and policy denials must not invoke handlers; descriptor mismatches fail before mutable route side effects; replay/nullifier reservations are receiver-local and bounded; output is bounded before it reaches signed response and receipt projections.

## Workspace inventory

The root `Cargo.toml` contains five members:

| Package | Kind | What is actually present |
|---|---|---|
| [`libsec-core`](core/README.md) | `rlib`, `cdylib`, `staticlib` | `ZenithPacket`, ingress frames, caller-proof encoding, decision/execution responses, packet builder, tunnel primitives, signature/Merkle helpers, and optional wasm32 exports. It is verifier-free. |
| [`client`](client/README.md) | Native binary | `generate`, `chat`, `hub`, and `identity` commands; caller-key lifecycle; packet signing; plaintext/static/session tunnel modes; bounded response decoding. |
| [`server`](server/README.md) | Library + three binaries | Config/readiness, ingress, verifier, evidence adapters, manifests, permission integration, replay/nullifier gates, handlers, receipts, SQLite ledger, audit export/verification, and gateway CLIs. |
| `secs-permissions` | Reusable library | Receiver-local permission records and fail-closed policy evaluation shared by the server, native policy CLI, and WASM panel. |
| [`panel`](panel/README.md) | `cdylib`, `rlib` | Four wasm-bindgen functions plus a static HTML/JavaScript policy panel that stores policy JSON in the browser. |

### Shipped binaries

| Command | Package | Status and purpose |
|---|---|---|
| `client` | `client` | Prototype outgoing packet CLI. `generate`/`chat` use the two legacy opcodes; `hub` parses decimal `u8` opcodes; `identity` prints a receiver-registry entry. |
| `secs-gateway` | `server` | Canonical configurable TCP gateway wrapper. Default mode is fail-closed `production_verified`; local use must explicitly select a dev mode. |
| `secz` | `server` | Historical compatibility name for a local gateway plus `audit verify` and `audit anchor verify` commands. |
| `secs-permctl` | `server` | Authors, revokes, lists, and evaluates receiver-local permission-policy JSON. |

### A client limitation worth knowing

The CLI exposes `hub <opcode> <payload>`, but its current trusted response mapping contains only opcodes `0x01` and `0x02`. For other opcodes it reports `response expectation is missing or invalid for this operation` before opening the TCP connection. Server-side non-legacy operations are exercised through library/integration-test paths; making arbitrary CLI response-key/schema mappings configurable is separate work.

That distinction matters when reading older shell examples that call `hub 16`: the parser and historical examples exist, but current client dispatch intentionally refuses operations without a pinned response contract.

## Wire and response contracts

### Packet v0 compatibility anchor

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

- The packet uses bincode and keeps `opcode: u8`.
- `proof` currently carries a versioned caller key reference plus Ed25519 signature over canonical envelope bytes on the client path. Prototype proof-envelope helpers remain elsewhere for bounded fixture paths.
- `encrypted_payload` can be plaintext only in explicit local-dev mode, statically tunneled in local-dev mode, or protected by a v2 X25519/HKDF session-derived key.
- `mac` is retained only for v0 byte-layout compatibility. Current clients write zeroes; the server never treats it as authentication.

### Ingress envelopes

- A bare bincode `ZenithPacket` remains a legacy-compatible ingress frame.
- `IngressRequestV1` adds bounded `evidence_refs` and `public_inputs`.
- `IngressRequestV2` adds the client ephemeral X25519 public key for session-derived tunnel keys.
- Evidence inputs are count- and size-bounded before verifier use.

### Responses

- `DecisionResponse` is the small accepted/rejected decision frame retained for legacy operations.
- `ExecutionResponse` is a versioned, receiver-signed frame with exact request-digest correlation, bounded output/schema fields, typed execution status/reasons, context/receipt references, and Ed25519 receiver authentication.
- Receipt schema v3 can carry a bounded redacted output projection. Raw payload and private evidence are excluded from ordinary receipt/operator/public-audit surfaces.

## Receiver-local operations

`ReceiverManifest::default_v0()` currently contains these descriptors:

| Opcode | Decimal | Operation | Target/status | Runtime binding |
|---:|---:|---|---|---|
| `0x01` | `1` | `legacy.generate` | Legacy core example | No generic inference handler is registered. |
| `0x02` | `2` | `legacy.chat` | Legacy core example | No generic chat or conversation handler is registered. |
| `0x10` | `16` | `candidate.dev.bash_echo` | Local-dev subprocess candidate | `bash` echo/cat binding in local-dev modes only. |
| `0x20` | `32` | `candidate.dev.json_validate` | Local-dev native candidate | Local Rust queue stub in local-dev modes only. |
| `0x30` | `48` | `candidate.dev.jq_identity` | Local-dev subprocess candidate | `jq .` binding in local-dev modes only. |
| `0x44` | `68` | `membership.provision` | Production-shaped receiver handler | Native handler is registered, but authority/evidence gates still fail closed. |
| `0x45` | `69` | `node.registration.v0` | Receiver handler with local-fixture authority mode | Native registration handler; not live federation authority. |

Additional demo descriptors, including the permissioned file-write and Dregg-shaped demo routes, are installed explicitly by tests/demos and are not part of the default manifest.

Canonical `0x44 membership.provision` remains protected by Issue #77's fail-closed descriptor-only runtime evidence guard: handler binding is not authority, and only the configured evidence adapter path can produce the evidence-backed signed context required to reach it.

Opcode governance:

| Range | Governance |
|---:|---|
| `0x01`–`0x0A` | Small secS/core-standardized range; current `0x01` and `0x02` remain legacy examples. |
| `0x0B`–`0x3F` | Castalia-standard candidate range; current entries are dev candidates, not ratified portable operations. |
| `0x40`–`0xFF` | Receiver/operator-defined range. Meaning comes from the receiver manifest and descriptor fingerprint. |

## Verification, authority, and privacy

The server library contains:

- caller proof-of-origin verification against receiver-held caller keys;
- receiver/verifier Ed25519 identity loading, deterministic key IDs, key status/validity checks, and signed context/receipt verification;
- descriptor-bound `VerifiedCallContext` with active-manifest authorization-fingerprint revalidation;
- receiver-local session, replay, expiry, scoped-nullifier, and permission enforcement;
- deny-by-default disclosure policies and JSON/string privacy scanners for receipt, operator, readiness, demo, and audit surfaces;
- evidence adapters for local static fixtures, wallet presentation proof-of-possession, signed federated credentials under receiver-held issuer metadata, bounded Dregg authority/snapshot material, and explicitly configured live-verifier seams;
- proof metadata/key registry gates for route-scoped configured proof expectations.

Evidence maturity is mixed. Tests exercise cryptographic and fail-closed properties, but fixtures, configured roots, in-process verifier seams, and local source-client contracts are not equivalent to live Castalia/Dregg finality, public network discovery, light-client verification, recursive proof-carrying state, Midnight proof settlement, or Cardano settlement.

The wallet adapter verifies a temporary minimal-equivalent secS challenge contract. It proves possession of the presented subject key under that contract; it is not full Castalia Wallet wallet-core parity and is not sufficient issuer/root authority by itself.

## Runtime modes

The gateway defaults to `production_verified` when no mode is provided.

| Mode | Behavior |
|---|---|
| `local_dev_plaintext` | Explicit local fixture mode; permits plaintext and local dev bindings. Defaults to `127.0.0.1:9001` and a local SQLite file unless overridden. |
| `local_dev_tunnel` | Explicit local fixture mode; requires static tunnel material and enables local dev bindings. |
| `production_verified` | Fail-closed mode requiring explicit bind, DB/ledger, receiver audience, verifier/tunnel keys, caller/trust/permission registries, limits, and adapter-specific readiness inputs. Dev/legacy descriptors cannot acquire production authority. |

See [the runtime reference](docs/reference/runtime.md) for the complete grouped environment-variable inventory and readiness boundaries.

## Local quick start

Requirements: a current Rust toolchain. Some local-dev handlers also require `bash` or `jq`; browser builds require `wasm-pack` and the `wasm32-unknown-unknown` target.

Build and test:

```bash
cargo build --workspace
cargo test --workspace
```

Start the canonical gateway in explicit plaintext local-dev mode:

```bash
SECS_RUNTIME_MODE=local_dev_plaintext cargo run -p server --bin secs-gateway
```

It listens on `127.0.0.1:9001` by default in local-dev modes. The client default is currently `127.0.0.1:9000`, so provide the server address:

```bash
cargo run -p client -- --server 127.0.0.1:9001 identity
cargo run -p client -- --server 127.0.0.1:9001 generate "hello"
cargo run -p client -- --server 127.0.0.1:9001 chat "hello"
```

The last two commands exercise legacy admission/decision surfaces. They do not call a model or return generated/chat content because no inference handlers are installed.

For a fixture-only production-shaped startup smoke:

```bash
./scripts/production-gateway-smoke.sh
```

That script creates temporary fixture material and local SQLite state. It is intentionally not production deployment proof.

## Permission policy tools

Native CLI example:

```bash
cargo run -p server --bin secs-permctl -- \
  --policy /tmp/secs-permissions.json \
  grant \
  --caller secS://caller-a \
  --opcode 0x50 \
  --operation demo.file.write \
  --resource file:///tmp/secs-demo/ \
  --prefix

cargo run -p server --bin secs-permctl -- \
  --policy /tmp/secs-permissions.json \
  evaluate \
  --caller secS://caller-a \
  --opcode 0x50 \
  --operation demo.file.write \
  --resource file:///tmp/secs-demo/demo.txt
```

The browser panel exposes the same shared model through `grant`, `revoke`, `evaluate`, and `list`. Policy stays in browser local storage; the panel has no server or network client and cannot change a running gateway by itself.

## Receipts, persistence, and audit

The server uses SQLx runtime queries against SQLite for:

- signed receipts;
- emitted lifecycle events;
- receiver-local replay reservations;
- scoped nullifier uses;
- audit publication status;
- legacy node telemetry.

Receipt/event pairs are written atomically on the covered paths. Operator inspection is schema-versioned and redacts payloads, credentials, raw private evidence, and raw signature material. Execution output is represented only under bounded output-projection rules.

The public-audit subsystem provides versioned bundle and chain formats, context-scoped range export, signer public-key material, deterministic entry/root hashes, local/no-op publisher semantics, and a standalone verifier that does not require SQLite database access. It also supports a bounded GitHub Gist anchor witness and local anchor-record verification.

```bash
cargo run -p server --bin secz -- audit verify <bundle.json>
cargo run -p server --bin secz -- audit anchor verify <bundle.json> <anchor.json>
```

These commands validate the repository's bundle/chain/anchor contracts. A Gist or local anchor record is not blockchain immutability, external consensus, production deployment proof, or proof that publication cannot be deleted.

## WASM and browser surfaces

Two wasm32 surfaces exist:

1. `libsec-core` with feature `uniffi` exports `wasm_encrypt` and `wasm_decrypt` for ChaCha20Poly1305 using caller-supplied key, nonce, plaintext/ciphertext, and associated data.
2. `panel` exports permission-policy `grant`, `revoke`, `evaluate`, and `list` functions and supplies a vanilla HTML/JavaScript UI in `panel/www`.

Build the panel locally:

```bash
rustup target add wasm32-unknown-unknown
wasm-pack build panel --target web --out-dir www/pkg --out-name panel
python3 -m http.server --directory panel/www 8000
```

Open `http://127.0.0.1:8000/`. See [WASM and Pages](docs/reference/wasm-and-pages.md) for export contracts, security boundaries, site generation, and published paths.

## Examples and scripts

| Path | What it demonstrates | Current caveat |
|---|---|---|
| `examples/hello-world.sh` | Historical local gateway/client round trip. | Uses non-legacy `hub 16`; current client refuses it without a trusted response mapping. |
| `examples/m12-demo.sh` | Caller authentication, expiry, replay, and receipt behavior. | Also uses `hub 16`; rely on focused integration tests until the CLI mapping is reconciled. |
| `examples/m12-tunnel-demo.sh` | Static local-dev tunnel and wrong-key rejection. | Same non-legacy client mapping caveat; v2 session tunnel behavior is covered by tests. |
| `examples/m13-permission-demo.sh` | Receiver-local permission CLI/model flow. | Demo authority only; no production filesystem authority. |
| `examples/m15-dregg-authority-demo.sh` | Bounded receiver-held Dregg-shaped resource-lock/attenuation checks. | Local fixtures and tests only; no live Dregg finality. |
| `scripts/production-gateway-smoke.sh` | Real gateway startup and malformed/oversized ingress rejects under full fixture config. | Fixture-only local smoke. |
| `scripts/tier-1-dregg-authority-snapshot-smoke.sh` | Snapshot fixture audit and focused positive/negative tests. | No network or federation finality. |
| `scripts/stress-identity-tests.sh` | Repeated identity-focused test execution. | Test stress helper, not load or deployment evidence. |

## Development and verification

CI enforces:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo audit
cargo check -p libsec-core --target wasm32-unknown-unknown --features uniffi
cargo check -p panel --target wasm32-unknown-unknown
```

The integration suite covers packet compatibility, caller authentication, context binding, ingress bounds, runtime readiness, permissions, replay/session/expiry, nullifiers, evidence tiers, wallet presentation, trusted issuer policy, Dregg-shaped verifier seams, node registration, handler negative matrices, receipts/ledger/audit formats, privacy redaction, and documentation overclaim guards.

Useful focused commands:

```bash
cargo test -p libsec-core --all-features
cargo test -p server --test runtime_config
cargo test -p server --test gateway_layout
cargo test -p server --test execution_output_transport
cargo test -p server --test public_audit_cli
cargo test -p server --test docs_overclaim_status_ledger
```

## Repository map

```text
secS-magik/
├── core/                 packet, ingress, response, tunnel, crypto, WASM primitives
├── client/               outgoing native CLI and caller identity/tunnel handling
├── server/               verifier, gateway, evidence, handlers, receipts, ledger, CLIs
├── permissions/          shared receiver-local permission model
├── panel/                wasm-bindgen permission wrapper + static browser UI
├── docs/
│   ├── current-state.md  concise derived orientation
│   ├── implementation-status.md  authoritative status ledger
│   ├── reference/        current runtime and WASM reference
│   ├── specs/            accepted/target contracts; check status before claiming runtime
│   ├── plans/            implementation sequencing and historical controls
│   ├── ideas/            non-authoritative design-gated proposals
│   └── ops/              runbook and deployment-evidence contracts
├── examples/             local scripts and fixture-oriented demonstrations
├── fixtures/             tracked public test/demo fixtures; never operator secrets
├── scripts/              smoke, stress, and documentation build helpers
└── .github/workflows/    Rust CI and documentation Pages automation
```

## Documentation authority and maintenance

| Question | Source |
|---|---|
| What is this repository and how do I use it? | This root README. |
| What is implemented, partial, planned, future, or out of scope? | [`docs/implementation-status.md`](docs/implementation-status.md). |
| What changed in top-level posture recently? | [`docs/current-state.md`](docs/current-state.md). |
| What architecture is targeted? | [`docs/specs/2026-06-01-secs-magik-objectives-spec.md`](docs/specs/2026-06-01-secs-magik-objectives-spec.md). |
| What is exploratory only? | [`docs/ideas/README.md`](docs/ideas/README.md). |
| What would count as production deployment evidence? | [`docs/ops/production-deployment-proof.md`](docs/ops/production-deployment-proof.md). |

Specs and plans describe contracts or intended sequences; they do not override the implementation ledger. Historical issue and PR references are provenance, not a substitute for current code inspection.

## Active architecture decisions

- [Issue #270](https://github.com/ZenithResearch/secS-magik/issues/270) proposes Matrix-owned conversation with secS restricted to exact authority-bearing machine operations. That decision is not implemented on `main` merely because a contract or draft exists.
- [Issue #274](https://github.com/ZenithResearch/secS-magik/issues/274) records an optional weave middleware idea around inference handlers. It remains design-gated; no weave storage, conversation continuity, loom UI, or inference middleware exists in runtime code.

## Explicit non-claims

The repository currently does not establish:

- a deployed production gateway or production secret-management system;
- a generic model inference server, agent harness, peer-chat runtime, or weave/loom service;
- live Castalia/Dregg discovery, consensus, capability authority, revocation finality, or recursive proof-carrying state;
- full Castalia Wallet wallet-core parity or browser WalletAuth product behavior;
- Midnight proof verification or Cardano settlement/authority;
- distributed/global/cross-Hub replay protection;
- public-chain immutability or public auditability from local SQLite, bundles, Gists, or Pages;
- arbitrary receiver shell, browser, filesystem, tool, model, provider, credential, or workspace selection by callers.

## Security

See [SECURITY.md](SECURITY.md). Never commit operator private keys, tunnel secrets, bearer tokens, production registries, live packet captures, private evidence, or local telemetry databases. Tracked fixtures and smoke scripts are intentionally public and must remain visibly non-authoritative.

## License

See [LICENSE](LICENSE).
