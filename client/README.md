# client

`client/` is the current secC-like outgoing packet sender for secS-magik.

Status: implemented as a prototype CLI client. It constructs and sends packets; it is not the verifier and does not decide receiver authority.

## Directory map

| Path | Responsibility |
|---|---|
| `Cargo.toml` | Client crate metadata and dependencies. |
| `src/main.rs` | CLI argument parsing, packet construction, TCP dispatch, and CLI tests. |

## Boundary

The client owns:

- CLI commands for `generate`, `chat`, and `hub` packets;
- outbound `ZenithPacket` construction;
- TCP send to a configured secS gateway.

The client does not own:

- authority verification;
- receiver-local manifest meaning;
- capability/credential/evidence validation;
- receipts or local ledger inspection;
- wallet cryptographic verification.

## Usage

Start a local development gateway in another terminal:

```bash
SECS_RUNTIME_MODE=local_dev_plaintext cargo run -p server --bin secs-gateway
```

Send a packet:

```bash
cargo run -p client -- --server 127.0.0.1:9001 generate "hello"
cargo run -p client -- --server 127.0.0.1:9001 chat "hello"
cargo run -p client -- --server 127.0.0.1:9001 hub 16 "hello from secC"
```

The server address can also come from `SECS_URL`:

```bash
SECS_URL=127.0.0.1:9001 cargo run -p client -- hub 16 "hello from secC"
```

## Opcode input rule

The `hub` command parses opcodes as decimal `u8` values.

Use:

- `16` for the current `0x10` prototype/dev binding;
- `32` for the current `0x20` prototype/dev binding;
- `48` for the current `0x30` prototype/dev binding.

Do not document `0x10` / `0x20` / `0x30` as accepted CLI input unless the parser is deliberately extended later.

## Current prototype defaults

The CLI currently builds prototype packets with local/default envelope fields suitable for local testing. That packet construction does not prove production wallet crypto, federated evidence, or public auditability.

## Commands

```bash
cargo test -p client
cargo build -p client
cargo test --workspace
```

## Related docs

- [Root README](../README.md)
- [Core README](../core/README.md)
- [Server README](../server/README.md)
- [Client surfaces](../docs/client-surfaces.md)
