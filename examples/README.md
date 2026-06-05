# examples

`examples/` contains local runnable demos for secS-magik prototype behavior.

## Current examples

| File | Purpose |
|---|---|
| `hello-world.sh` | Starts the historical `secz` compatibility gateway on `127.0.0.1:9001`, sends `Hello World` through decimal opcode `16`, and verifies the gateway log saw the payload. |

## Run

```bash
./examples/hello-world.sh
```

The script writes gateway output to `SECZ_HELLO_LOG` or `/tmp/secz-hello-world.log`.

## Manual equivalent

Terminal 1:

```bash
SECS_RUNTIME_MODE=local_dev_plaintext cargo run -p server --bin secz
```

Terminal 2:

```bash
SECS_URL=127.0.0.1:9001 cargo run -p client -- hub 16 "Hello World"
```

## Caveats

- This is a local/dev prototype example.
- `secz` is a compatibility wrapper, not canonical verifier ownership.
- Opcode `16` is the current decimal CLI value for a prototype/dev binding; do not use `0x10` as CLI input.
- This example does not prove production wallet crypto, federated evidence, public auditability, or deployment readiness.

## Troubleshooting

- If port `9001` is busy, stop the existing gateway before running the example.
- If Cargo binary selection is ambiguous, prefer `SECS_RUNTIME_MODE=local_dev_plaintext cargo run -p server --bin secz` and `cargo run -p client -- ...`.
- If the command hangs or fails, inspect the log at `SECZ_HELLO_LOG` or `/tmp/secz-hello-world.log`.
