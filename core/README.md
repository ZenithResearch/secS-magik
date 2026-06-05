# core

`core/` is the verifier-free shared Rust crate for secS-magik packet and crypto primitives.

Status: implemented as shared primitives. It is not the server verifier, not product policy, and not an authority engine.

## Directory map

| Path | Responsibility |
|---|---|
| `Cargo.toml` | Crate metadata for `libsec-core`; optional UniFFI feature and library types. |
| `src/lib.rs` | `ZenithPacket` v0, `SessionHandshake`, opcode constants, and module exports. |
| `src/packet_builder.rs` | Verifier-free `ZenithPacket` construction helper. |
| `src/tunnel.rs` | ChaCha20Poly1305 tunnel helper functions and tests. |
| `src/zk.rs` | Ed25519 proof/signature helper primitives; not a full ZK verifier. |
| `src/ffi.rs` | UniFFI bindings behind the optional feature. |

## Boundary

`core` owns:

- the v0 packet shape;
- the current standardized opcode constants;
- packet construction helpers that do not validate authority;
- reusable tunnel/signature primitives.

`core` does not own:

- the production verifier pipeline;
- product policy;
- receiver-local manifests;
- replay/session/expiry enforcement;
- evidence/capability/credential validation;
- receipts, ledgers, or handler routing.

## Packet v0 compatibility

The v0 packet shape is the compatibility anchor:

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

- Preserve `opcode: u8` unless a versioned migration is explicitly approved.
- Preserve bincode round-trip compatibility for v0.
- Treat `src/zk.rs` as helper primitives, not proof that production ZK verification exists.
- `PacketBuilder` accepts caller-provided envelope fields; server-side authority checks happen in `server/`.

## Commands

```bash
cargo test -p libsec-core
cargo build -p libsec-core
cargo test -p libsec-core --features uniffi
```

For full repository confidence:

```bash
cargo test --workspace
cargo build --workspace
```

## Related docs

- [Root README](../README.md)
- [Client README](../client/README.md)
- [Server README](../server/README.md)
- [Implementation status](../docs/implementation-status.md)
