# server

`server/` is the secS gateway/verifier substrate crate for secS-magik.

Status: production-shaped local hardening is implemented for the current prototype gateway, including bounded ingress, explicit runtime config/readiness, receiver-local manifest routing, receiver-local permission policy readiness/loading for canonical gateway startup, signed context/receipt posture, local SQLite receipt/event persistence, redacted operator inspection, bounded handler execution, cryptographic wallet-presentation verification through an explicitly temporary minimal-equivalent secS challenge contract, Track E static trusted issuer/root policy on `main`, and Track I local production-shaped `membership.provision` E2E on `main` via PR #76 at `5e5bb71`. Issue #77 adds a fail-closed descriptor-only `production_verified` runtime guard for canonical `0x44` `membership.provision`; live runtime ingress now accepts a versioned request envelope carrying bounded evidence refs/public inputs for `membership.provision` and routes them through configured evidence adapters; handler binding is not authority; M15.2–M15.6 plus #159 provide bounded static Dregg policy-admission, fail-closed proof/finality blocker posture, and local operator-inspection while #144/M15.8 closes the bounded in-repo #73 finalizer while live proof/finality rails remain non-goals. First-prod authority is still bounded: full Castalia Wallet wallet-core parity/import, live Castalia/Dregg discovery, Midnight/Cardano authority, production deployment proof, and public auditability are not implemented here.

## Directory map

| Path | Responsibility |
|---|---|
| `Cargo.toml` | Server crate metadata and binary declarations. |
| `src/bin/secs-gateway.rs` | Canonical current configurable gateway wrapper. |
| `src/bin/secz.rs` | Historical command compatibility wrapper; not canonical verifier ownership. |
| `src/config.rs` | Typed runtime config and readiness inputs. |
| `src/runtime_mode.rs` | `local_dev_plaintext`, `local_dev_tunnel`, and `production_verified` modes. |
| `src/ingress.rs` | Bounded TCP ingress, packet decode, and verifier/payload handoff. |
| `src/gateway.rs` | Configurable router, legacy telemetry, receiver-local bounded handler routing, and handler lifecycle events. |
| `src/manifest.rs` | Receiver-local operation descriptors, handler IDs, evidence requirements, and opcode governance. |
| `src/verifier.rs` | Typed verifier errors, prototype envelope checks, and signed verified context helpers. |
| `src/evidence.rs` | `EvidenceAdapter`, `local_static`, cryptographic `wallet_presentation` verification over the temporary minimal-equivalent secS challenge contract, receiver-held `TrustedIssuerEntry` registry policy, and signed `membership_credential` / `provisioning_credential` verification. |
| `src/identity.rs` | Verifier identity loading, signer key IDs, context/receipt signing, and local public-key registry checks. |
| `src/receipt.rs` | Receipt/event types, decisions, reason codes, authenticator kinds, and signing helpers. |
| `src/ledger.rs` | Local SQLite event/receipt/replay persistence and redacted operator inspection. |
| `src/schema.rs` | Central runtime SQLite schema ontology. |
| `src/payload.rs` | Tunnel-key parsing and runtime-mode payload handling. |
| `src/session.rs` | Local in-memory session utility. |
| `src/ontology.rs` | Shared prototype receiver/audience/reason constants. |
| `tests/` | Integration and regression tests for ingress, gateway, ledger, receipt, identity, evidence, runtime config, and docs contracts. |

## Runtime modes

| Mode | Current use |
|---|---|
| `production_verified` | Default canonical gateway mode. Fails closed unless explicit `SECS_*` runtime, key, ledger, trust-registry, caller-registry, permission-policy, audience, tunnel X25519 secret, and limits are supplied. When `SECS_ALLOWED_EVIDENCE_ADAPTERS` includes `dregg_authority`, it also requires `SECS_DREGG_AUTHORITY_REGISTRY_PATH`. Fixture-only smoke must opt in with `SECS_FIXTURE_ONLY_SMOKE=1`. |
| `local_dev_plaintext` | Explicit local development mode. Allows plaintext local testing without silently looking like production. |
| `local_dev_tunnel` | Explicit local tunnel mode. Requires tunnel key material. |

Local development gateway:

```bash
SECS_RUNTIME_MODE=local_dev_plaintext cargo run -p server --bin secs-gateway
```

Historical compatibility wrapper:

```bash
SECS_RUNTIME_MODE=local_dev_plaintext cargo run -p server --bin secz
```

Fixture-only production-shaped smoke:

```bash
./scripts/production-gateway-smoke.sh
```

The smoke script uses temporary fixture key material and local SQLite state. It is not a production deployment.

## Important environment variables

Common gateway variables include:

- `SECS_RUNTIME_MODE`
- `SECZ_RUNTIME_MODE`
- `SECS_BIND_ADDR`
- `SECS_DB_URL`
- `SECS_LEDGER_PATH`
- `SECS_RECEIVER_AUDIENCE`
- `SECS_VERIFIER_KEY_PATH`
- `SECS_VERIFIER_KEY_ID`
- `SECS_TRUST_REGISTRY_PATH`
- `SECS_CALLER_REGISTRY_PATH`
- `SECS_PERMISSION_POLICY_PATH`
- `SECS_DREGG_AUTHORITY_REGISTRY_PATH` (required only when `SECS_ALLOWED_EVIDENCE_ADAPTERS` includes `dregg_authority`)
- `SECS_ALLOWED_EVIDENCE_ADAPTERS`
- `SECS_FIXTURE_ONLY_SMOKE`
- `SECS_MAX_WIRE_BYTES`
- `SECS_MAX_PAYLOAD_BYTES`
- `SECS_MAX_OUTPUT_BYTES`
- `SECS_HANDLER_TIMEOUT_MS`
- `SECS_INGRESS_READ_TIMEOUT_MS`
- `SECS_MAX_IN_FLIGHT_CONNECTIONS`
- `SECS_TUNNEL_KEY_HEX` (static local-dev tunnel key)
- `SECZ_TUNNEL_KEY_HEX` (legacy static local-dev tunnel key fallback)
- `SECS_TUNNEL_X25519_SECRET_HEX` (gateway-side 32-byte X25519 static secret for v2 session-derived tunnel keys; required in `production_verified`)
- `SECZ_TUNNEL_X25519_SECRET_HEX` (legacy fallback)
- Client-side v2 session-key packets use `SECS_TUNNEL_SERVER_X25519_PUBLIC_HEX` / `SECZ_TUNNEL_SERVER_X25519_PUBLIC_HEX`; do not publish the gateway secret.

Do not document real operator keys, bearer tokens, packet captures, production DB URLs, or private runtime config in this repository.

## Current opcode bindings

| Opcode | Decimal CLI value | Current meaning |
|---:|---:|---|
| `0x01` | `1` | `OPCODE_GENERATE`, legacy/core example. |
| `0x02` | `2` | `OPCODE_CHAT`, legacy/core example. |
| `0x10` | `16` | Bash echo-pipe prototype/dev binding. |
| `0x20` | `32` | Native Rust queue-stub prototype/dev binding. |
| `0x30` | `48` | `jq .` JSON formatter/parser prototype/dev binding. |
| `0x44` | `68` | `membership.provision` local production-shaped E2E descriptor. #77 fail-closes descriptor-only production runtime verification; live TCP evidence-ref/public-input support landed in #162; #160 implements bounded Dregg resource locks; #144/M15.8 reconciles the bounded #73 finalizer without claiming live proof/finality; handler binding is not authority and #144/M15.8 is the bounded finalizer. |

The client CLI accepts decimal values such as `16`, not `0x10`.

## Ledger and receipt posture

The current ledger is local/operator SQLite evidence:

- receipts and events persist with runtime SQL;
- receipt/event chains are inspectable by local operator helpers;
- default inspection redacts raw payload/private evidence and raw signature bytes;
- current claims are bounded to local operator evidence.

Do not describe this as public auditability, public anchoring, federation proof, or production settlement evidence.

## Wallet presentation verifier boundary

The current `wallet_presentation` adapter verifies signed presentation/challenge material cryptographically, but it does so with an explicitly temporary minimal-equivalent secS challenge contract in `server/src/evidence.rs`. That contract binds subject, audience, origin, operation, resource, nonce, issued/expires timestamps, signature suite, and a deterministic public-key fingerprint reference while Castalia Wallet wallet-core parity is pending. This is proof-of-possession for the claimed subject key in the presentation; it does not establish receiver trust, issuer/root/registry authority, or full wallet-core parity.

Packaging/client-surface boundary:

- Browser extension: owns user-facing wallet UX and should consume wallet semantics through a WASM binding; it is not shipped by `server/`.
- secZ/secC/local clients: may use native/client bindings or carry packet/evidence bytes; they construct or transport calls and presentations, but they are not verifier authority.
- secS/server: owns only the verifier subset and artifact-consumer boundary. It consumes signed presentation/challenge bytes and public verification material; it must not depend on UI session state, browser WalletAuth sessions, or extension runtime state.

This is not a full Castalia Wallet wallet-core import and not live Castalia Wallet parity. Track D alone is not trusted issuer/root/registry policy. Wallet proof-of-possession remains necessary where a descriptor requires it, but it is never sufficient issuer/root authority.

## Trusted issuer/root policy boundary

Track E is implemented on `main` as a static receiver-held fixture policy. `TrustedIssuerEntry` metadata in `server/src/evidence.rs` controls trusted issuer/root acceptance: issuer id, issuer key id, public key, status/validity, accepted evidence kinds, accepted audiences/operations/resources, `trust_root_ref`, and `registry_root_ref` must match the signed credential and descriptor-local policy.

The first-path federated credential verifier accepts signed `membership_credential` / `provisioning_credential` fixtures only when the credential signature verifies against receiver-held issuer metadata, the issuer/key/credential status is active in the fixture registry, subject/audience/operation/resource bindings match, and the receiver-local descriptor allows that evidence kind. `local_static`, plaintext/prototype evidence, wallet-only proof, embedded caller keys, and caller-supplied root refs reject as sufficient production authority.

This is a static fixture registry path only: no live Dregg consensus or Castalia registry discovery, no Midnight proof adapter, no Cardano settlement/finality proof, no production deployment proof, no public auditability, and no full Castalia Wallet wallet-core parity. Track I local production-shaped `membership.provision` E2E is implemented on `main`; #77 adds the descriptor-only production runtime fail-closed guard, but live TCP ingress wallet + issuer + Dregg authority evidence refs/public inputs landed in #162 through the versioned request envelope; #160 implements bounded Dregg resource locks; #144/M15.8 reconciles the bounded #73 finalizer without claiming live proof/finality; handler binding is not authority and #144/M15.8 is the bounded finalizer.

## Commands

```bash
cargo test -p server
cargo build -p server --bin secs-gateway
cargo test --workspace
cargo build --workspace
```

Useful focused tests:

```bash
cargo test -p server --test gateway_layout
cargo test -p server --test ledger
cargo test -p server --test receipt
cargo test -p server --test runtime_config
cargo test -p server wallet_presentation -- --nocapture
cargo test -p server wallet_challenge_contract -- --nocapture
cargo test -p server production_federated -- --nocapture
cargo test -p server trust trusted_issuer -- --nocapture
```

## Non-goals

`server/` does not own product policy, app/browser login UX, Dregg consensus, Midnight circuits, Cardano settlement/business logic, arbitrary shell authority, or Castalia membership semantics.

## Related docs

- [Root README](../README.md)
- [Implementation status](../docs/implementation-status.md)
- [Repository schema](../docs/repository-schema.md)
- [Ready-for-prod checklist](../docs/plans/2026-06-02-ready-for-prod-checklist.md)


## #169 trusted requested-authority attenuation boundary

#169 binds delegated attenuation / non-amplification to a verifier-derived trusted requested resource on the live evidence path: requested authority must not exceed held authority, and caller-declared `requested_resource` public inputs cannot satisfy the Dregg authority check by themselves. This is a no-widening check on Dregg authority admission, not Dregg-provisioned resource locks; #160 implements bounded Dregg-provisioned resource locks, and #144/M15.8 reconciles the bounded #73 finalizer reconciles #169/#160 without overclaim.


#160 implements bounded Dregg-provisioned resource locks: a Dregg authority token may bind an exact verifier-derived trusted requested resource as `resource_lock:verified`, reject mismatches as `resource_lock_violation`, and propagate the locked resource into the signed context for handler/policy use. This is separate from #169 trusted requested-authority attenuation, does not implement live Dregg revocation proof/BLS finality/rotated-replay proof verification, and #159 remains fail-closed blocker posture only. #144/M15.8 reconciles the bounded #73 finalizer.


#144/M15.8 reconciles the bounded #73 finalizer across #162 live ingress evidence refs/public inputs, #167 delegated attenuation / non-amplification, #169 trusted requested-authority attenuation, and #160 implements bounded Dregg-provisioned resource locks. The finalizer preserves `resource_lock:verified` acceptance, `resource_lock_violation` rejection, redaction-safe operator summaries, and signed-context propagation of the verified locked resource for handler/policy use. See `examples/m15-dregg-authority-demo.sh` for the bounded production-shaped demo/checklist. This is not deployment proof, not public auditability, not live Dregg revocation proof, not BLS threshold finality, not rotated-replay proof verification, not Midnight, and not Cardano.

Tunnel key lifecycle: `SECS_TUNNEL_X25519_SECRET_HEX` remains private gateway config. The derived public key identity is `tunnel:x25519:<sha256-prefix>` and may be shared with clients as `SECS_TUNNEL_SERVER_X25519_PUBLIC_ID`; optional `SECS_TUNNEL_NEXT_X25519_SECRET_HEX` declares a bounded next-key rotation posture. Receipts/log surfaces must expose only the redacted key id, never the secret bytes.

### Live Dregg verifier contract boundary (#177)

`dregg_authority` can now name live-required verifier modes in the receiver-held registry, but #177 is only the contract/fail-closed slice. The server exposes versioned live-Dregg evidence DTOs and trait seams, returns specific `missing_live_dregg_*_verifier` reason codes, and rejects production readiness when `SECS_DREGG_AUTHORITY_REGISTRY_PATH` requires a live verifier dependency that is not configured. Fixture status/root/finality material cannot satisfy those live modes.

Follow-up adapter issues own real verification:

- #178 — live revocation roots / attested-root non-membership verification.
- #179 — BLS threshold finality / QC verification.
- #180 — rotated replay/full-turn proof verification.

Do not describe #177 as live Dregg revocation/finality proof verification; it is the typed contract and fail-closed gate for those adapters.


### Live Dregg revocation roots (#178)

#178 installs the first real live-Dregg verifier adapter slice. `LiveDreggRevocationVerifierConfig` loads trusted federation/issuer/root/epoch windows from JSON, and `LiveDreggRevocationVerifier` verifies `LiveDreggProofKind::Revocation` envelopes by binding the receiver-held Dregg authority registry entry to a trusted root and an accepted non-membership proof reference. Production readiness for `live_revocation_verifier_required` registries now requires `SECS_DREGG_LIVE_REVOCATION_ROOTS_PATH`.

This remains bounded revocation-root/non-membership verification only. It does not implement BLS threshold finality (#179), rotated replay/full-turn proof verification (#180), Cardano settlement, Midnight proof verification, public auditability, or production deployment.


### Live Dregg BLS threshold finality (#179)

#179 installs the bounded BLS-threshold finality adapter slice. `LiveDreggBlsFinalityVerifierConfig` loads trusted federation committee/epoch windows from JSON, and `LiveDreggBlsFinalityVerifier` verifies `LiveDreggProofKind::BlsThresholdFinality` envelopes by binding receiver-held Dregg authority registry state to trusted committee config and accepted threshold-QC refs. Production readiness for `bls_threshold_required` registries now requires `SECS_DREGG_BLS_FINALITY_COMMITTEES_PATH`.

This remains bounded threshold-QC fixture verification at the adapter seam. It does not implement rotated replay/full-turn proof verification (#180), Cardano settlement, Midnight proof verification, public auditability, or production deployment.


### Live Dregg rotated replay/full-turn proof verification (#180)

#180 installs the bounded rotated replay verifier adapter. `LiveDreggRotatedReplayVerifierConfig` loads typed proof fixtures from JSON, and `LiveDreggRotatedReplayVerifier` verifies `LiveDreggProofKind::RotatedReplay` envelopes by binding federation/epoch/root, proof refs, resource hashes, turn hashes, old/new commitments, and nullifier sets. `RotatedReplayRequired` composes with the #179 BLS finality seam and can also compose with #178 live revocation through `LiveDreggCompositeVerifier`. Production readiness for rotated replay registries requires both `SECS_DREGG_BLS_FINALITY_COMMITTEES_PATH` and `SECS_DREGG_ROTATED_REPLAY_PROOFS_PATH`.

This remains bounded adapter-seam proof verification. It does not implement Cardano settlement, Midnight proof verification, public auditability, or production deployment.


### Public audit bundle contract (#181)

The server now exposes the `secs-public-audit-bundle-v1` contract for redacted local public-bundle export and verification. `Ledger::export_public_audit_bundle_for_context(...)` exports complete signed receipt chains with signer public-key refs, receipt signatures, redacted evidence summaries, and deterministic bundle root metadata. `PublicAuditBundle::verify_local_public_audit()` verifies the exported bundle without SQLite/private-key access.

This is local public-bundle verification, not external anchoring, public immutable publication, Cardano/Midnight settlement, or production deployment proof. External publication/anchoring remains a later #185-style rail.


### Receipt-chain audit export model (#182)

#182 strengthens `secs-public-audit-bundle-v1` with the versioned `secs-public-audit-chain-v1` root algorithm. Every exported receipt entry carries a `chain_index` and `previous_entry_hash_hex`, and the bundle chain metadata records a deterministic context-scoped range export (`chain_scope: context:<id>`). Context-scoped range export rejects missing endpoints and local bundle verification rejects reordered or broken hash-link chains. This is still local public-bundle verification, not external anchoring or immutable public publication.


### Audit publisher abstraction (#183) — audit publisher abstraction (#183)

#183 adds a local audit publisher abstraction and persisted `audit_publication_status` table for public audit bundles. Publication status is keyed by an `idempotency_key` over bundle version, chain algorithm version, chain scope, root hash, receipt count, and target kind. Target references are stored as `target_ref_digest_hex`, never raw target refs. The included local/no-op publisher proves status, retry, idempotency, and failure semantics without external anchoring claims. Publication verifies the local public audit bundle before recording success or failure, and publication failures do not rewrite receipt rows or bundle contents.
