#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="${TMPDIR:-/tmp}/secs-magik-production-smoke-$$"
mkdir -p "$TMP_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT

KEY_PATH="$TMP_DIR/fixture-verifier.key"
TRUST_REGISTRY_PATH="$TMP_DIR/trust-registry.json"
LEDGER_PATH="$TMP_DIR/ledger.sqlite"

# Fixture-only Ed25519 secret bytes for local smoke. This is intentionally not a real operator key.
printf '0909090909090909090909090909090909090909090909090909090909090909' > "$KEY_PATH"
chmod 600 "$KEY_PATH"
printf '{"fixture_only":true,"trusted_verifiers":[]}' > "$TRUST_REGISTRY_PATH"

export SECS_RUNTIME_MODE=production_verified
export SECS_BIND_ADDR=127.0.0.1:0
export SECS_DB_URL="sqlite:$LEDGER_PATH?mode=rwc"
export SECS_RECEIVER_AUDIENCE=secS://local-smoke-receiver
export SECS_VERIFIER_KEY_PATH="$KEY_PATH"
export SECS_VERIFIER_KEY_ID=verifier:local-smoke-fixture
export SECS_TRUST_REGISTRY_PATH="$TRUST_REGISTRY_PATH"
export SECS_MAX_WIRE_BYTES=2097152
export SECS_MAX_PAYLOAD_BYTES=1048576
export SECS_HANDLER_TIMEOUT_MS=30000
export SECS_INGRESS_READ_TIMEOUT_MS=10000
export SECS_ALLOWED_EVIDENCE_ADAPTERS=local_static

cd "$ROOT"

echo "secS production-shaped local smoke (fixture-only, no real secrets)"
echo "receiver_audience=$SECS_RECEIVER_AUDIENCE"
echo "ledger_path=$LEDGER_PATH"
echo "trust_registry=fixture-only"

cargo test -p server --test runtime_config production_config_accepts_explicit_operator_runtime_fields -- --nocapture
cargo test -p server --test readiness readiness_reports_config_loaded_and_ledger_ready -- --nocapture
cargo test -p server --test ingress ingress_source_bounds_wire_reads_before_deserialization -- --nocapture

echo "smoke_ok: production-shaped config/readiness/ingress checks passed with fixture-only key material"
