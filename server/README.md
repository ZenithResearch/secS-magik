# server

`server/` is the secS gateway/verifier substrate crate for secS-magik.

Status: production-shaped local hardening is implemented for the current prototype gateway, including bounded ingress, explicit runtime config/readiness, receiver-local manifest routing, signed context/receipt posture, local SQLite receipt/event persistence, redacted operator inspection, and bounded handler execution. First-prod authority is not complete: wallet cryptographic verification and trusted issuer/root policy remain separate Track D/E work.

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
| `src/evidence.rs` | `EvidenceAdapter`, `local_static`, and shape-only `wallet_presentation` shell. |
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

The client CLI accepts decimal values such as `16`, not `0x10`.

## Ledger and receipt posture

The current ledger is local/operator SQLite evidence:

- receipts and events persist with runtime SQL;
- receipt/event chains are inspectable by local operator helpers;
- default inspection redacts raw payload/private evidence and raw signature bytes;
- current claims are bounded to local operator evidence.

Do not describe this as public auditability, public anchoring, federation proof, or production settlement evidence.

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
```

## Non-goals

`server/` does not own product policy, app/browser login UX, Dregg consensus, Midnight circuits, Cardano settlement/business logic, arbitrary shell authority, or Castalia membership semantics.

## Related docs

- [Root README](../README.md)
- [Implementation status](../docs/implementation-status.md)
- [Repository schema](../docs/repository-schema.md)
- [Ready-for-prod checklist](../docs/plans/2026-06-02-ready-for-prod-checklist.md)
