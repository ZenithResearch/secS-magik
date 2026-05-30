# secS-magik

secS-magik (formerly secS-daemon) is the repository providing the RPC layer for machine-to-machine capability communication in the Zenith / Castalia stack.

> **Current Direction (2026-05-29)**: This repository supplies the RPC/protocol surface. The interface remains as currently defined. Implementation of the RPC layer will go through **Dregg** (the generic capability layer). The **Wallet** (from the castalia-wallet repository) acts as the credential and ownership bridge inside secS-magik implementations.

## Current Architecture (2026-05-29)

- **Dregg** — Generic capability layer (proofs, revocation, authority, HubFS).
- **secS-magik (this repo)** — RPC layer. Interface unchanged; future implementation path is through Dregg.
- **Wallet** — Credential/ownership bridge. Lives inside secS-magik implementations. Used in **secZ** contexts. **secC** is the generic client.
- **secDaemon role** (from this repo) — Hub auth layer and gateway into hub sections. Ownership proven via address auth or (preferred) ZK proof of wallet ownership with Dregg.

The browser Castalia Wallet extension is the first place the wallet-as-bridge logic is being exercised.

See the full evolving model and planning surface:
https://github.com/bananawalnut/claude-hub/blob/main/capture/2026-05-29-castalia-wallet-rust-api-as-secZ-layer-for-secS-magik.md

---

## At a Glance

- What it does: receives `ZenithPacket` messages over TCP, parses the packet envelope, applies secZ proof-envelope and TTL checks on the execution sidecar path, decrypts payload bytes when configured, logs local telemetry, and routes bounded opcodes to configured machine programs.
- Who it is for: agents, local workers, homelab/cloud nodes, and Zenith-adjacent systems that need owned machine communication rails instead of broad bearer-token APIs.
- Primary stack: Rust workspace with `core`, `client`, and `server` crates; Tokio TCP; bincode packet serialization; optional ChaCha20Poly1305 tunnel decryption; SQLite telemetry through SQLx runtime queries.
- Current interfaces: `secS` on port `9000`, `secZ` on port `9001`, and the `client` CLI for sending packets.
- Start here: `core/` for packet types, `server/src/main.rs` for secS, `server/src/bin/secz.rs` for secZ, and `client/` for packet sending.

## Why This Exists

Agents need owned communication rails.

The current default asks machine systems to coordinate through infrastructure built for browser users: OAuth flows, REST APIs, webhooks, shared API keys, and centralized gateways. Those primitives are useful. They are not enough for peer machine execution.

secS-daemon changes the default shape.

- Proof envelopes move access away from bearer-secret-shaped APIs. On the secZ execution sidecar path, packets without the required proof-envelope and TTL fields are rejected before execution.
- Opcodes replace arbitrary authority. An agent does not receive a shell. It receives a bounded intent channel.
- Local manifests replace platform policy. The receiving machine decides what `0x20` means.
- `stdin` replaces framework lock-in. Rust can secure the transport while Python, Bash, Node, `jq`, or a local worker handles execution.
- SQLite telemetry replaces rented observability. The node records opcode and payload size locally, without a SaaS dependency.
- Peer nodes replace central gateways. A MacBook, Raspberry Pi, GPU instance, homelab server, or cloud box can all run the same rail.

That is the cybernetic benefit: machines coordinate through a nervous system they own.

## System Architecture

```text
                 ┌──────────────────────────────────────────────┐
                 │                  secC                        │
                 │        JIT proving client / packet sender     │
                 └──────────────────────┬───────────────────────┘
                                        │ ZenithPacket
                                        │ bincode over TCP
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                                secS                                     │
│                 open mathematical gatekeeper · port 9000                │
│                                                                         │
│  parse packet envelope  →  inspect proof fields  →  hand off bytes      │
│                                                                         │
│  no roles · no product policy · no hub dependency · no domain logic     │
└───────────────────────────────────────┬─────────────────────────────────┘
                                        │ same packet contract
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                                secZ                                     │
│                 configurable execution synapse · port 9001              │
│                                                                         │
│  decrypt payload  →  log telemetry  →  route opcode  →  execute binding │
│                                                                         │
│        0x10 → bash          0x20 → native Rust        0x30 → jq          │
└─────────────────────────────────────────────────────────────────────────┘
```

## secS vs secZ

These interfaces are separate on purpose.

| Interface | Port | Job | What it refuses |
|---|---:|---|---|
| `secS` | `9000` | Stable secure service interface. It handles canonical daemon traffic like `OPCODE_GENERATE = 0x01` and `OPCODE_CHAT = 0x02`. | Product policy, role logic, agent orchestration, payment logic. |
| `secZ` | `9001` | Extensible sidecar gateway. It validates the proof envelope, decrypts payload bytes when a tunnel key is configured, logs telemetry, and dispatches by `u8` opcode to a configured `MachineProgram`. | Hub dependencies, arbitrary shell access, hidden routing policy, payload parsing in the router. |

secS is the mathematical gate. secZ is the execution synapse.

## Repository Map

| Path | Responsibility | Start here |
|---|---|---|
| `README.md` | Root orientation map, architecture, protocol summary, and local run commands. | This file. |
| `Cargo.toml` | Rust workspace definition. | Workspace members are `core`, `client`, and `server`. |
| `Cargo.lock` | Locked Rust dependency graph. | Keep committed for reproducible builds. |
| `core/` | Shared packet, crypto-adjacent, proof, and FFI-capable core library. | `core/src/lib.rs`. |
| `client/` | CLI packet sender / secC-style client surface. | `client/src/main.rs`. |
| `server/` | secS and secZ daemon binaries plus routing/telemetry code. | `server/src/main.rs`, `server/src/bin/secz.rs`. |
| `examples/` | Example payloads or usage fixtures. | Use for local smoke examples if present. |
| `docs/` | Announcement and long-form docs. | `docs/announcement-thread.md`. |
| `AGENTS.md` | Agent workflow rules for editing the repo. | Read before modifying. |
| `LICENSE` | License terms. | Current license file. |
| `.github/` | GitHub workflows/config if present. | CI and repository automation. |

## Components

| Component | Location | Inputs | Outputs | Notes |
|---|---|---|---|---|
| Packet core | `core/` | Session ID, nonce, opcode, proof, TTL, encrypted payload, MAC | `ZenithPacket` and shared core types | Core should stay policy-free. |
| Client CLI | `client/` | Server address plus opcode/payload arguments | bincode-encoded packet over TCP | CLI opcodes are decimal `u8`; use `16`, not `0x10`. |
| secS daemon | `server/src/main.rs` | TCP packets on port `9000` | Canonical secure-service behavior | Mathematical gate; no product policy. |
| secZ daemon | `server/src/bin/secz.rs` | TCP packets on port `9001` | Routed machine-program execution | Configurable execution sidecar. |
| Router | `server/src/*` | Decrypted payload bytes and opcode | Bound `MachineProgram` execution | Meaning of opcodes remains local. |
| Telemetry | `server/src/*` | Opcode and payload size | Local SQLite `node_telemetry` rows | Runtime SQL only; no compile-time SQLx macros. |
| Machine programs | `server/src/*` | Decrypted payload bytes on `stdin` or Rust call | Local command/worker behavior | Bounded intent channel, not broad shell authority. |

## ZenithPacket Envelope

All client-to-daemon traffic is serialized with `bincode` as `libsec_core::ZenithPacket`:

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

Standard secS opcodes:

- `0x01` / decimal `1`: `OPCODE_GENERATE`
- `0x02` / decimal `2`: `OPCODE_CHAT`

secZ manifest opcodes currently bound:

- `0x10` / decimal `16`: Bash echo pipe. Prints `Bash received payload:` then streams payload bytes through `cat`.
- `0x20` / decimal `32`: Native Rust queue stub.
- `0x30` / decimal `48`: `jq .` JSON formatter/parser.

CLI rule:

- `client hub` parses opcode as decimal `u8`.
- Use `16`, not `0x10`, when calling the client.

## secZ Execution Pipeline

Inbound TCP traffic to `0.0.0.0:9001` follows a strict linear pipeline:

1. Ingestion: read raw bytes from `tokio::net::TcpStream`.
2. Deserialization: parse bytes with `bincode` into `ZenithPacket`.
3. Authentication envelope: reject packets with empty proof or zero `claim_ttl`.
4. Decryption:
   - If `SECZ_TUNNEL_KEY_HEX` is set, decrypt `encrypted_payload` with ChaCha20Poly1305 using that 32-byte hex key.
   - If `SECZ_TUNNEL_KEY_HEX` is absent, fall back to plaintext payload mode for local development and quick starts.
   - `SECS_TUNNEL_KEY_HEX` is accepted as a fallback environment variable.
5. Telemetry intercept: insert `opcode` and `payload_size` into local SQLite table `node_telemetry`.
6. Routing: dispatch decrypted bytes to the `ConfigurableRouter` registry.
7. Execution: invoke the bound `MachineProgram`.

## MachineProgram Extensibility Model

secZ delegates decrypted payloads using this async trait:

```rust
#[async_trait]
pub trait MachineProgram: Send + Sync {
    async fn execute(&self, payload: &[u8]);
}
```

Approved expansion paradigms:

- Subprocess forwarder: bind an opcode to a shell script, Python/Ruby/Node program, Unix tool such as `jq`, or local service CLI.
- Native Rust handler: implement `MachineProgram` directly when the binding needs in-process state or typed Rust behavior.
- Local queue bridge: bind an opcode to a narrow enqueue operation rather than handing agents broad machine authority.

Configuration as code is intentional. `server/src/bin/secz.rs::main()` is the deployment manifest. The manifest is the firewall.

## Running Locally

Build and test the workspace:

```bash
cargo test --workspace
cargo build --workspace
```

Run secS on the default secure-service interface:

```bash
cargo run -p server --bin server
```

Run secZ on the configurable execution sidecar interface:

```bash
cargo run -p server --bin secz
```

In another terminal, send a local secZ packet with a decimal opcode:

```bash
cargo run -p client -- \
  --server 127.0.0.1:9001 \
  hub 16 'hello from secC'
```

Use `16`, `32`, or `48` for the default secZ bindings. Do not pass `0x10` to the CLI unless the client has been changed to parse hex.

## Testing and Verification

Primary checks:

```bash
cargo test --workspace
cargo build --workspace
```

For README/path consistency:

```bash
for p in Cargo.toml core/ client/ server/ docs/ examples/; do test -e "$p" || echo "missing $p"; done
```

If you add telemetry code, verify it compiles without a pre-existing SQLite database. Do not use `sqlx::query!` or other compile-time SQL macros unless the repo also commits and maintains the required offline SQLx cache.

## Key Design Decisions

- secZ proof-envelope and TTL checks happen before payloads reach bound machine programs; secS currently parses and inspects packet fields without owning product policy.
- secS and secZ are separate because mathematical ingress and local execution policy should not share one responsibility boundary.
- Opcodes grant bounded intent channels; they do not grant broad shell authority.
- The receiving machine owns opcode meaning through a local manifest.
- Decrypted payload bytes are passed to local programs through simple interfaces such as `stdin` or native Rust handlers.
- Telemetry is local SQLite, not a SaaS dependency.
- Runtime SQL is required for telemetry so the workspace compiles without a prepared database.
- The daemon should not depend on Hub, product policy, roles, or centralized routing logic.

## Operational Boundaries

Do not use the “sex demon” pronunciation joke or framing for this repo. The project is `secS-daemon`, with `secS` and `secZ` interfaces.

This repo does not provide:

- general shell access for agents
- product authorization policy
- payment logic
- Hub orchestration logic
- centralized gateway requirements
- production security guarantees

Do not commit real tunnel keys, local telemetry databases, production packet captures, machine-specific secrets, or private operator config.

## License

See `LICENSE`.

## Repository Structure (Updated 2026-05-29)

- `server/` — The **sec** side (stable RPC / mathematical gatekeeper layer from the secS-magik protocol).
- `client/` — The **secC / secZ** side (treated as a unified client surface for now).
- `core/` — Shared packet/types. The credential/wallet bridge logic is primarily maintained in the separate **castalia-wallet** repository and imported into secS-magik implementations (client side) as needed.

Wallet placement: The Castalia Wallet acts as the credential and ownership bridge. It is imported into the secS-magik client side rather than duplicated in `core/`.

See the full direction in the vault planning surface.

