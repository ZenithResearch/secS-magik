# server

`server/` is the secS gateway/verifier substrate crate for secS-magik.

Status: production-shaped local hardening is implemented for the current prototype gateway, including bounded ingress, explicit runtime config/readiness, receiver-local manifest routing, signed context/receipt posture, local SQLite receipt/event persistence, redacted operator inspection, bounded handler execution, cryptographic wallet-presentation verification through an explicitly temporary minimal-equivalent secS challenge contract, Track E static trusted issuer/root policy on `main`, and Track I local production-shaped `membership.provision` E2E on `main` via PR #76 at `5e5bb71`. Issue #77 adds a fail-closed descriptor-only `production_verified` runtime guard for canonical `0x44` `membership.provision`; live runtime ingress still does not verify wallet + issuer evidence and must not claim active `membership.provision` runtime authority until #78/#79-style follow-ups land. First-prod authority is still bounded: full Castalia Wallet wallet-core parity/import, live Castalia/Dregg discovery, Midnight/Cardano authority, production deployment proof, and public auditability are not implemented here.

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
| `production_verified` | Default canonical gateway mode. Fails closed unless explicit `SECS_*` runtime, key, ledger, trust-registry, audience, and limits are supplied. Fixture-only smoke must opt in with `SECS_FIXTURE_ONLY_SMOKE=1`. |
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
- `SECS_ALLOWED_EVIDENCE_ADAPTERS`
- `SECS_FIXTURE_ONLY_SMOKE`
- `SECS_MAX_WIRE_BYTES`
- `SECS_MAX_PAYLOAD_BYTES`
- `SECS_MAX_OUTPUT_BYTES`
- `SECS_HANDLER_TIMEOUT_MS`
- `SECS_INGRESS_READ_TIMEOUT_MS`
- `SECS_MAX_IN_FLIGHT_CONNECTIONS`
- `SECS_TUNNEL_KEY_HEX`
- `SECZ_TUNNEL_KEY_HEX`

Do not document real operator keys, bearer tokens, packet captures, production DB URLs, or private runtime config in this repository.

## Current opcode bindings

| Opcode | Decimal CLI value | Current meaning |
|---:|---:|---|
| `0x01` | `1` | `OPCODE_GENERATE`, legacy/core example. |
| `0x02` | `2` | `OPCODE_CHAT`, legacy/core example. |
| `0x10` | `16` | Bash echo-pipe prototype/dev binding. |
| `0x20` | `32` | Native Rust queue-stub prototype/dev binding. |
| `0x30` | `48` | `jq .` JSON formatter/parser prototype/dev binding. |
| `0x44` | `68` | `membership.provision` local production-shaped E2E descriptor. #77 fail-closes descriptor-only production runtime verification; evidence-aware live ingress/runtime authority remains tracked in #78/#79-style follow-ups. |

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

This is a static fixture registry path only: no live Dregg consensus or Castalia registry discovery, no Midnight proof adapter, no Cardano settlement/finality proof, no production deployment proof, no public auditability, and no full Castalia Wallet wallet-core parity. Track I local production-shaped `membership.provision` E2E is implemented on `main`; #77 adds the descriptor-only production runtime fail-closed guard, but live ingress/runtime wallet + issuer evidence verification remains tracked separately in #78/#79-style follow-ups.

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
