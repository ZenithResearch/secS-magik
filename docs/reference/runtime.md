# Runtime and operations reference

Status: current reference for the code on `main`. The root [README](../../README.md) is the canonical entry point; [implementation-status.md](../implementation-status.md) owns evidence-level status.

## Executable surfaces

### `secs-gateway`

The canonical server entry point is a thin wrapper around `GatewayRuntimeConfig::from_env()` and `run_gateway_with_config()`.

```bash
SECS_RUNTIME_MODE=local_dev_plaintext cargo run -p server --bin secs-gateway
```

Without `SECS_RUNTIME_MODE` or the legacy `SECZ_RUNTIME_MODE`, the mode is `production_verified`; a bare command therefore fails until the required operator configuration is present. This is deliberate.

Local-dev defaults:

| Field | Default |
|---|---|
| bind | `127.0.0.1:9001` |
| SQLite URL | `sqlite:node_telemetry.db?mode=rwc` |
| receiver audience | `secS://receiver-a` prototype constant |
| allowed evidence adapters | `local_static` |
| max wire bytes | 2 MiB |
| max payload bytes | 1 MiB |
| max output bytes | 1 MiB |
| ingress read timeout | 10 seconds |
| max in-flight connections | 64 |

These are fixture defaults, not production recommendations.

### `secz`

With no audit subcommand, `secz` runs the historical compatibility gateway at `127.0.0.1:9001` using the local SQLite URL. It still consumes the runtime mode from the environment and should be started explicitly for local use:

```bash
SECS_RUNTIME_MODE=local_dev_plaintext cargo run -p server --bin secz
```

It also exposes standalone audit verification:

```bash
cargo run -p server --bin secz -- audit verify <bundle.json>
cargo run -p server --bin secz -- audit anchor verify <bundle.json> <anchor.json>
```

The audit commands verify public bundle/chain/anchor material and need no gateway process or SQLite access. They do not prove that a publication is immutable.

### `client`

```text
client [--server <host:port>] <generate|chat|hub|identity>
```

`--server` reads `SECS_URL` and otherwise defaults to `127.0.0.1:9000`. The local gateway defaults to port `9001`, so examples should set the address explicitly.

| Subcommand | Current behavior |
|---|---|
| `generate <prompt>` | Constructs opcode `0x01`, signs and sends it, then expects legacy `DecisionResponse`. No model handler is installed. |
| `chat <message>` | Constructs opcode `0x02`, signs and sends it, then expects legacy `DecisionResponse`. No chat/conversation handler is installed. |
| `hub <decimal-u8> <payload>` | Parses a decimal `u8`; current trusted response mapping only contains `0x01`/`0x02`, so other opcodes are refused before TCP dispatch. |
| `identity` | Loads/creates the configured caller key and prints a JSON receiver-registry entry. |

The client persists a stable owner-private key only when `SECS_CALLER_KEY_PATH` is supplied. Otherwise it creates an ephemeral key for the process.

### `secs-permctl`

`secs-permctl` edits and evaluates the JSON array consumed by the shared `secs-permissions` crate.

```text
secs-permctl [--policy <path>] list
secs-permctl [--policy <path>] grant --caller ... --opcode ... --operation ... --resource ...
secs-permctl [--policy <path>] revoke --caller ... --opcode ... --operation ... --resource ...
secs-permctl [--policy <path>] evaluate --caller ... --opcode ... --operation ... --resource ... [--now ...]
```

Unlike the client `hub` command, permission CLI opcodes accept decimal (`80`) or hex (`0x50`). Missing policy files load as an empty policy, which denies evaluation by default. Explicit deny records win over allows.

### `secs-devgraph-issue-create-v1`

This separate local binary invokes only the fixed DG-P producer. Its complete
argument surface is:

```text
secs-devgraph-issue-create-v1 \
  --request-file <owner-private-file> \
  --idempotency-key-file <owner-private-file> \
  --signed-projection-output <owner-private-file>
```

Receiver policy, service identity, public-key registry, producer manifest, and
replay database are loaded only from the canonical owner-controlled layout in
[the fixed-adapter reference](devgraph-issue-create-v1-cli.md). There are no
operation, audience, scope, policy, signer, key, database, route, handler, URL,
or transport flags. Success and denial summaries are bounded JSON and never
print the request, raw idempotency key, Wallet presentation/signature, service
key, or signed projection. The projection is written to the requested output
as canonical JSON plus one LF using an owner-private atomic create-only
publication. The path must be absent and cannot alias either caller input or
fixed manifest/key/policy/registry/replay state through direct, normalized,
symlinked-ancestor, or hard-link spellings. The entire canonical authority
subtree is excluded, including SQLite journal/WAL/shared-memory sidecars.
The validated canonical output directory is then held open and every output
operation is descriptor-relative, so a pathname swap after preflight cannot
redirect publication. The adapter reads its fail-closed clock immediately
before DG-P after authority loading and performs a second current-time DG-P
validation immediately before output. A newly crossed expiry produces no
output; the already-created replay reservation can remain until normal expiry
and pruning, without constituting a Devgraph Work mutation.

This is a local producer adapter, not a TCP/HTTP service, Devgraph Work
mutation, `EventReceipt`, deployment proof, Wallet vault reader, or hybrid/PQ
authorization path.

### `secs-devgraph-issue-create-v1-wallet`

This separate DG-E2 binary accepts the same three path flags, but its request
file is one raw Issue JSON object. It binds only `127.0.0.1:9045`, prints
`http://127.0.0.1:9045/`, and waits at most 300 seconds for the user to open the
page in Wallet-enabled Chrome. Only that valid GET generates the memory-only
session, nonce, and CSRF. The hardened page makes one direct, user-activated
call to the exact Wallet provider method and returns the signed presentation
through exact `/presentation`, or a stable text-free local cancellation through
exact `/cancel`, within the 60-second authority window. Wrong tokens do not
consume; valid-token malformed calls do; reloads, duplicates, and late calls
are gone. The listener closes before the existing typed producer opens
authority/replay state.

See [the Wallet-adapter reference](devgraph-issue-create-v1-wallet-cli.md) for
the exact GET/POST bindings and non-claims. The binary has no configurable
listener, generic browser RPC, Devgraph HTTP client, Wallet custody, temporary
presentation file, `.castaway` read, or hybrid/PQ v1 path.

## Runtime modes

| Value | Plaintext | Dev bindings | Key/config posture |
|---|---:|---:|---|
| `local_dev_plaintext` | Allowed | Enabled | Fixture/local settings may use defaults. |
| `local_dev_tunnel` | Rejected | Enabled | Static tunnel key is required for the current local-dev payload path. |
| `production_verified` | Rejected | Disabled | All required operator paths, limits, receiver identity, permission/trust/caller registries, and current X25519 secret must validate before serving. |

`production_verified` is production-shaped fail-closed configuration, not proof that a gateway has been deployed or operated safely.

## Gateway configuration

### Base runtime, storage, and identity

| Variable | Meaning |
|---|---|
| `SECS_RUNTIME_MODE` | One of the three exact runtime-mode strings. `SECZ_RUNTIME_MODE` is a legacy fallback. |
| `SECS_BIND_ADDR` | TCP listener address. Required in production mode. |
| `SECS_DB_URL` | SQLx SQLite URL. Required in production mode. |
| `SECS_LEDGER_PATH` | Filesystem path named by `SECS_DB_URL`; the two must agree in production mode. |
| `SECS_RECEIVER_AUDIENCE` | Receiver audience bound into verification. Required and non-prototype in production mode. |
| `SECS_VERIFIER_KEY_PATH` | Owner-private Ed25519 verifier signing-key file. Required in production mode. |
| `SECS_VERIFIER_KEY_ID` | Optional configured verifier identifier; otherwise derived from the public key. Unsafe/path-like identifiers reject. |
| `SECS_CALLER_REGISTRY_PATH` | Receiver-held caller public-key registry. Required in production mode. |
| `SECS_TRUST_REGISTRY_PATH` | Receiver-held issuer/root registry. Required in production mode. |
| `SECS_PERMISSION_POLICY_PATH` | Receiver-local permission JSON. Required in production mode. |
| `SECS_ALLOWED_EVIDENCE_ADAPTERS` | Comma-separated adapter allowlist; must be nonempty and known. Defaults to `local_static` only in local fixture posture. |
| `SECS_FIXTURE_ONLY_SMOKE` | Explicitly permits fixture-labelled production-shaped smoke inputs. It never upgrades them to production authority. |

### Bounded resource controls

| Variable | Bound |
|---|---|
| `SECS_MAX_WIRE_BYTES` | Maximum accepted ingress frame; hard maximum is the default 2 MiB wire cap. |
| `SECS_MAX_PAYLOAD_BYTES` | Maximum decrypted payload, no more than 1 MiB and no larger than the wire bound. |
| `SECS_MAX_OUTPUT_BYTES` | Maximum handler output, no more than 1 MiB. |
| `SECS_HANDLER_TIMEOUT_MS` | Handler deadline, bounded to 300,000 ms. |
| `SECS_INGRESS_READ_TIMEOUT_MS` | TCP ingress read deadline, bounded to 60,000 ms. |
| `SECS_MAX_IN_FLIGHT_CONNECTIONS` | Accepted-task concurrency cap, bounded to 4,096. |

All six variables must be explicitly present in production mode even when their values match local defaults.

### Tunnel configuration

Gateway variables:

| Variable | Meaning |
|---|---|
| `SECS_TUNNEL_KEY_HEX` | Static 32-byte hex key for `local_dev_tunnel`. `SECZ_TUNNEL_KEY_HEX` is a legacy fallback. |
| `SECS_TUNNEL_X25519_SECRET_HEX` | Current gateway X25519 secret for v2 session-derived keys; required in production mode. Legacy `SECZ_*` fallback exists. |
| `SECS_TUNNEL_NEXT_X25519_SECRET_HEX` | Optional next X25519 secret used to expose bounded current/next rotation metadata. Legacy `SECZ_*` fallback exists. |

Client variables:

| Variable | Meaning |
|---|---|
| `SECS_TUNNEL_SERVER_X25519_PUBLIC_HEX` | Selects v2 session-derived encryption using the gateway public key. |
| `SECS_TUNNEL_SERVER_X25519_PUBLIC_ID` | Optional pinned `tunnel:x25519:<digest>` identifier; mismatch fails closed. |
| `SECS_TUNNEL_KEY_HEX` | Selects the static local-dev tunnel path when no server public key is supplied. |

Every client tunnel variable also has a legacy `SECZ_*` fallback. Never publish the gateway X25519 secret.

### Evidence and proof configuration

| Variable | Current boundary |
|---|---|
| `SECS_DREGG_AUTHORITY_REGISTRY_PATH` | Required when the adapter allowlist includes `dregg_authority`; receiver-held bounded registry. |
| `SECS_DREGG_AUTHORITY_SNAPSHOT_PATH` | Required when the allowlist includes `dregg_authority_snapshot`; receiver-held snapshot fixture/config. |
| `SECS_PROOF_METADATA_CONFIG_PATH` | Route-scoped proof key/circuit/public-input metadata policy loaded during readiness. |
| `SECS_DREGG_LIVE_REVOCATION_ROOTS_PATH` | Configured trusted inputs for the in-process live revocation verifier seam. |
| `SECS_DREGG_BLS_FINALITY_COMMITTEES_PATH` | Configured trusted committee inputs for the in-process BLS finality seam. |
| `SECS_DREGG_ROTATED_REPLAY_PROOFS_PATH` | Configured trusted rotated-replay proof inputs. |

These paths are typed receiver-held inputs. Their presence does not establish live discovery, network consensus, light-client verification, or production finality.

The `dregg_live_source` adapter also requires:

- `SECS_DREGG_LIVE_SOURCE_URL` using HTTPS in production mode;
- `SECS_DREGG_LIVE_SOURCE_AUTH_TOKEN_PATH` pointing at owner-private auth material;
- `SECS_DREGG_LIVE_SOURCE_TIMEOUT_MS`;
- `SECS_DREGG_LIVE_SOURCE_RETRY_MAX`;
- `SECS_DREGG_LIVE_SOURCE_CACHE_TTL_SECONDS`;
- `SECS_DREGG_LIVE_SOURCE_STALE_MAX_SECONDS`.

The module currently owns request/response validation, auth-material loading, cache decisions, typed transport errors, and a transport trait. It does not ship a general live HTTP client that proves Castalia/Dregg authority.

## Client-only configuration

| Variable | Meaning |
|---|---|
| `SECS_URL` | Default gateway address for `client --server`. |
| `SECS_CALLER_KEY_PATH` | Stable Ed25519 caller key; created owner-private on first use. |
| `SECS_CALLER_KEY_ID` | Optional caller key-ID override. |
| `SECS_CLAIM_TTL` | Demo/test TTL override; invalid values fall back to 300 seconds. |
| `SECS_SAVE_PACKET_PATH` | Demo/test path for saving exact outbound wire bytes for replay tests. |

Saved packets and caller key files are sensitive local artifacts and must not be committed.

## Persistence schema

`server/src/schema.rs` centralizes the runtime SQLite table ontology:

| Table | Purpose |
|---|---|
| `receipts` | Signed verify/execute/reject records and bounded projections. |
| `events` | Emitted lifecycle events linked to contexts/receipts. |
| `replay_reservations` | Receiver-local `(session, opcode, nonce, scope)` replay claims. |
| `devgraph_authority_replay_reservations` | DG-P-only `(session_id, operation, nonce)` claims plus safe authority bindings for exact retry/conflict comparison. |
| `scoped_nullifier_uses` | Receiver-local scoped nullifier commitments. |
| `audit_publication_status` | Idempotent publication-attempt/result state. |
| `node_telemetry` | Legacy prototype telemetry. |

This schema is local operator state. The DG-P table is secS authority replay
state, not Devgraph Work storage or idempotency. None of these tables is a
distributed ledger or public chain.

## Audit formats and commands

Current public audit exports use bundle v2 and chain v2 while retaining v1 compatibility fixtures. Bundle entries contain redacted receipt data, signer public-key material, deterministic chain indices/hashes, and optional bounded output projections. The verifier checks schema/version, signatures, entry hashes, previous-entry links, root hash, and configured anchor digest/target bindings.

The external anchor record supports the bounded GitHub Gist target kind. It records a digest and publication witness, not the raw packet payload or private signing material. Deletion, account compromise, provider behavior, and lack of consensus remain outside the guarantee.

## Operational safety

- Never run the bare gateway expecting local defaults; explicit local-dev mode is required for local use.
- Never reuse tracked fixtures as operator keys or trust registries.
- Never expose `node_telemetry.db`, packet captures, auth-token files, caller/verifier secrets, or private evidence through Pages or source control.
- Treat a successful smoke script as local behavior evidence only.
- Treat a registered handler as code availability only; it is never authority without the full verified-context path.
