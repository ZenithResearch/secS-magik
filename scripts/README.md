# scripts

`scripts/` contains repository helper scripts for smoke checks and local verification.

## Current scripts

| Script | Purpose |
|---|---|
| `production-gateway-smoke.sh` | Builds the real `secs-gateway`, starts it with fixture-only `production_verified` env, sends malformed and oversized TCP input, and verifies the gateway rejects those frames without exiting. |
| `tier-1-dregg-authority-snapshot-smoke.sh` | Prints redaction-safe #72/#195 evidence for the David Lab Dregg-shaped authority snapshot, audits the fixture for secret/private-token markers, and runs the active/negative direct lookup and evidence-adapter authority snapshot tests. |

## production-gateway-smoke.sh

Run from the repository root:

```bash
./scripts/production-gateway-smoke.sh
```

Expected output includes:

```text
secS production-shaped local smoke (fixture-only, no real secrets)
smoke_ok: secs-gateway bound ... and rejected malformed/oversized TCP input with fixture-only production env
```

## What the script sets

The smoke creates temporary fixture files and exports local env vars including:

- `SECS_RUNTIME_MODE=production_verified`
- `SECS_FIXTURE_ONLY_SMOKE=1`
- `SECS_BIND_ADDR=127.0.0.1:0`
- `SECS_DB_URL=sqlite:$LEDGER_PATH?mode=rwc`
- `SECS_LEDGER_PATH`
- `SECS_RECEIVER_AUDIENCE`
- `SECS_VERIFIER_KEY_PATH`
- `SECS_VERIFIER_KEY_ID`
- `SECS_TRUST_REGISTRY_PATH`
- `SECS_MAX_WIRE_BYTES`
- `SECS_MAX_PAYLOAD_BYTES`
- `SECS_MAX_OUTPUT_BYTES`
- `SECS_HANDLER_TIMEOUT_MS`
- `SECS_INGRESS_READ_TIMEOUT_MS`
- `SECS_MAX_IN_FLIGHT_CONNECTIONS`
- `SECS_ALLOWED_EVIDENCE_ADAPTERS=local_static`

## Safety and side effects

- Builds `target/debug/secs-gateway`.
- Creates temporary files under `TMPDIR` or `/tmp`.
- Starts and kills a temporary gateway process.
- Uses fixture-only key material, not real operator secrets.

## Caveats

- This is a production-shaped local smoke, not a production deployment.
- It does not prove wallet-core cryptographic verification.
- It does not prove federated trusted issuer/root evidence.
- It does not make `local_static` production authority.
- It does not make the local SQLite ledger public auditability.


## tier-1-dregg-authority-snapshot-smoke.sh

Run from the repository root:

```bash
./scripts/tier-1-dregg-authority-snapshot-smoke.sh
```

Expected output includes:

```text
fixture_ok: secs-dregg-authority-snapshot-v1 did:example:david-lab castalia-demo:david-lab
resource_ok: resource://david-lab/demo-agent controller=did:example:david-lab status=active
redaction_ok: fixture contains no raw secret/private-token markers
smoke_ok: active snapshot accepts the controlled David Lab resource; stale, revoked, wrong namespace, wrong resource, missing source, and unknown issuer reject.
```

The script is deterministic and local. It does not start a gateway, contact a Dregg node, require external services, or prove production Castalia federation/finality/deployment/public-auditability.
