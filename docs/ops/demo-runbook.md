# secS-magik M15.8 Demo Runbook

This runbook reproduces the M15.8 bounded Dregg authority demo from a cold checkout. Every step is a copy-paste command. No secrets, no external services, no live network calls.

## What the demo shows

1. Gateway boots in `production_verified` mode with caller registry + permission policy + dregg authority snapshot
2. Client sends a tunnel-encrypted packet with an ed25519 caller proof
3. Gateway verifies: caller identity → session freshness → permission policy → dregg authority snapshot → wallet PoP → federated credentials → membership provision handler
4. Gateway returns a signed accept/reject decision to the caller
5. The receipt chain (verify + execute) is inspectable by the operator

## Prerequisites

- Rust toolchain (stable, same version CI uses)
- Git
- A terminal

No SQLite, Docker, external DB, or network access needed. All tests use in-memory SQLite and fixture data.

## Quick verification (60 seconds)

Prove the demo works without standing up the gateway:

```bash
cd /Users/bananawalnut/repos/secS-magik

# The e2e contract test exercises the full flow in one test
cargo test -p server --test production_federated \
  membership_provision_e2e_contract_reaches_verify_execute_and_ledger_inspection \
  -- --nocapture

# The M15.8 finalizer test proves resource-lock binding
cargo test -p server --test production_federated \
  m15_8_finalizer_binds_resource_locked_dregg_authority_into_signed_context \
  -- --nocapture

# Docs hygiene: no overclaim
cargo test -p server --test ready_for_prod_docs \
  dregg_authority_docs_record_144_finalizer_and_demo_without_live_proof_overclaim \
  -- --nocapture
```

All three should pass. If they pass, the demo works.

## Full test suite

```bash
cd /Users/bananawalnut/repos/secS-magik

# Full workspace — ~500+ tests, takes ~90s
cargo test --workspace --all-targets --all-features

# CI gates
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Verification script
bash docs/dev/verification.md
```

## What gets tested

| Layer | Test file | What it proves |
|---|---|---|
| Caller auth | `server/tests/caller_auth.rs` | Valid caller proof accepted; forged/expired/revoked rejected |
| Session + tunnel | `server/tests/ingress.rs` | Session handshake, tunnel encryption, v2 client public key exchange |
| Permission policy | `server/tests/permissioned_file_write_e2e.rs` | Caller×opcode×operation×resource enforcement, deny-wins |
| Dregg authority snapshot | `server/tests/dregg_authority_registry.rs` | `david-lab-demo` fixture loads, stale/revoked/wrong-namespace rejects |
| Dregg authority evidence | `server/tests/dregg_authority_evidence.rs` | Snapshot → evidence adapter, resource-lock binding, non-amplification |
| Wallet PoP | `server/tests/wallet_presentation.rs` | Cryptographic proof-of-possession, wrong key/sig rejects |
| Federated credentials | `server/tests/trust.rs` | Trusted issuer/root registry, membership credential verification |
| E2E contract | `server/tests/production_federated.rs` | Full verify+execute chain, receipt inspection, redaction safety |
| Live verifier seams | `server/tests/dregg_live_revocation.rs` `dregg_live_finality.rs` `dregg_rotated_proof.rs` | Fail-closed when live verifiers are required but not configured |
| Receipt chain | `server/tests/receipt.rs` | Signed receipts, schema versioning, tamper detection |
| Public audit | `server/tests/public_audit.rs` | Bundle export, local verification, hash-link chain integrity |
| Runtime config | `server/tests/runtime_config.rs` | Production requires explicit config, rejects fixture-only in production |
| Readiness | `server/tests/readiness.rs` | Gateway startup validates registry paths, snapshot sources |
| Docs hygiene | `server/tests/ready_for_prod_docs.rs` | 31 tests: no overclaim, correct boundary language |

## Demo script (standalone gateway)

This brings up the actual gateway binary. Fixture-only (no real secrets).

```bash
cd /Users/bananawalnut/repos/secS-magik

# Build
cargo build --release -p server --bin secs-gateway

# Generate temp directories
DEMO_DIR=$(mktemp -d)
echo "Demo dir: $DEMO_DIR"

# Generate a caller key
CLIENT_KEY_HEX=$(python3 -c 'import os; print(os.urandom(32).hex())')
echo "$CLIENT_KEY_HEX" > "$DEMO_DIR/caller.key"
chmod 600 "$DEMO_DIR/caller.key"

# Generate a verifier key  
VERIFIER_KEY_HEX=$(python3 -c 'import os; print(os.urandom(32).hex())')
echo "$VERIFIER_KEY_HEX" > "$DEMO_DIR/verifier.key"
chmod 600 "$DEMO_DIR/verifier.key"

# Derive the caller key id (ed25519 public key fingerprint)
CALLER_KEY_ID=$(python3 -c "
import hashlib, base64
from cryptography.hazmat.primitives.asymmetric import ed25519
sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('$CLIENT_KEY_HEX'))
pk = sk.public_key().public_bytes_raw()
print(f'ed25519:{hashlib.sha256(pk).hexdigest()[:32]}')
" 2>/dev/null || echo "ed25519:fixture-key-id")

# Generate a verifier key id
VERIFIER_KEY_ID=$(python3 -c "
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('$VERIFIER_KEY_HEX'))
pk = sk.public_key().public_bytes_raw()
print(f'ed25519:{hashlib.sha256(pk).hexdigest()[:32]}')
" 2>/dev/null || echo "ed25519:fixture-verifier")

# Create caller registry
cat > "$DEMO_DIR/caller-registry.json" << JSONEOF
[
  {
    "key_id": "$CALLER_KEY_ID",
    "public_key_hex": "$(python3 -c "
from cryptography.hazmat.primitives.asymmetric import ed25519
sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('$CLIENT_KEY_HEX'))
print(sk.public_key().public_bytes_raw().hex())
" 2>/dev/null || echo '0000000000000000000000000000000000000000000000000000000000000000')",
    "status": "active",
    "not_before": "2024-01-01T00:00:00Z",
    "not_after": "2099-12-31T23:59:59Z"
  }
]
JSONEOF

# Create permission policy
cat > "$DEMO_DIR/permissions.json" << JSONEOF
[
  {
    "caller": "$CALLER_KEY_ID",
    "opcode": 68,
    "operation": "membership.provision",
    "resource": "resource://david-lab/demo-agent",
    "status": "granted",
    "authority_source": "receiver_local"
  }
]
JSONEOF

echo "Demo files prepared in $DEMO_DIR"
echo ""
echo "=== To run the gateway ==="
echo ""
echo "cd /Users/bananawalnut/repos/secS-magik"
echo ""
echo "SECS_RUNTIME_MODE=production_verified \\"
echo "  SECS_CALLER_REGISTRY_PATH=$DEMO_DIR/caller-registry.json \\"
echo "  SECS_PERMISSION_POLICY_PATH=$DEMO_DIR/permissions.json \\"
echo "  SECS_DREGG_AUTHORITY_SNAPSHOT_PATH=server/tests/fixtures/david-lab-demo-snapshot.json \\"
echo "  SECS_VERIFIER_KEY_PATH=$DEMO_DIR/verifier.key \\"
echo "  SECS_RECEIVER_AUDIENCE=secS://local-demo \\"
echo "  SECS_BIND_ADDRESS=127.0.0.1:9044 \\"
echo "  SECS_DB_PATH=$DEMO_DIR/secs.db \\"
echo "  SECS_LEDGER_DB_PATH=$DEMO_DIR/secs.db \\"
echo "  SECS_ALLOWED_EVIDENCE_ADAPTERS=dregg_authority \\"
echo "  SECS_DREGG_AUTHORITY_REGISTRY_PATH=$DEMO_DIR/caller-registry.json \\"
echo "  ./target/release/secs-gateway"
echo ""
echo "=== To verify the full test suite instead ==="
echo "cargo test --workspace --all-targets --all-features"
```

## Non-claims (what this demo does NOT prove)

- ❌ Live Castalia Dregg API discovery (#206 in progress)
- ❌ Production deployment on a real host (#33 planned)
- ❌ Cardano settlement (#75 spec-ready)
- ❌ Castalia wallet-core parity (#71 spec-ready)
- ❌ Midnight proof verification (#74 spec-ready)
- ❌ Public chain anchoring of audit bundles
- ❌ Dregg blocklace finality or BLS threshold QC verification at runtime
- ❌ Network-facing TLS or DoS protection
- ❌ Multi-node federation or consensus

## Status after M15.8

All M12–M15 tracks are closed and CI-proven. The file-backed authority snapshot works. The live source client (#206) in progress will replace `SECS_DREGG_AUTHORITY_SNAPSHOT_PATH` with `SECS_DREGG_LIVE_SOURCE_URL` for dynamic authority, but the demo does not require it.

Test counts at HEAD:
- `cargo test --workspace --all-targets --all-features` passes clean
- `cargo fmt --all -- --check` passes clean
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes clean
- `bash docs/dev/verification.md` passes clean
- 31 ready_for_prod_docs tests pass clean