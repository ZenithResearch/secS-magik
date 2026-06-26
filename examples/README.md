# examples

`examples/` contains local runnable demos for secS-magik prototype behavior.

## Current examples

| File | Purpose |
|---|---|
| `hello-world.sh` | Starts the historical `secz` compatibility gateway on `127.0.0.1:9001`, sends `Hello World` through decimal opcode `16`, and verifies the gateway log saw the payload. |
| `m12-demo.sh` | M12 end-to-end: authenticated caller accepted; forged proof / unknown caller / replay / expiry rejected with typed reasons; the caller receives the decision frame; an operator inspects the receipt chain. Local verifier behavior only. |
| `m13-permission-demo.sh` | M13 receiver-local permissions: authors a policy with `secs-permctl` (grant exact/prefix, deny-wins, validity window, revoke) and asserts the `ALLOW` / `DENY:<reason>` matrix. The same model the gateway enforces live (M13.3) and the browser panel drives (M13.4b). Receiver-local only. |

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


#144/M15.8 reconciles the bounded #73 finalizer across #162 live ingress evidence refs/public inputs, #167 delegated attenuation / non-amplification, #169 trusted requested-authority attenuation, and #160 implements bounded Dregg-provisioned resource locks. The finalizer preserves `resource_lock:verified` acceptance, `resource_lock_violation` rejection, redaction-safe operator summaries, and signed-context propagation of the verified locked resource for handler/policy use. See `examples/m15-dregg-authority-demo.sh` for the bounded production-shaped demo/checklist. This is not deployment proof, not public auditability, not live Dregg revocation proof, not BLS threshold finality, not rotated-replay proof verification, not Midnight, and not Cardano.

- `m12-tunnel-demo.sh` — local_dev_tunnel client/server round trip for #110 static local-dev client encryption: matching key accepts and wrong key rejects. #109 per-session key agreement is covered by core/client/server tests and the v2 ingress envelope, not claimed here as TLS/production transport security.

- `m12-tunnel-demo.sh` now pairs with #175 key-id semantics: v2/session clients can pin the gateway tunnel public-key id, and accepted v2 verify receipts include only the redacted `tunnel:x25519:<hash>` identifier.
