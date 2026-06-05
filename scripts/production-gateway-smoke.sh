#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="${TMPDIR:-/tmp}/secs-magik-production-smoke-$$"
mkdir -p "$TMP_DIR"
GATEWAY_PID=""
cleanup() {
  if [[ -n "${GATEWAY_PID:-}" ]]; then
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

KEY_PATH="$TMP_DIR/fixture-verifier.key"
TRUST_REGISTRY_PATH="$TMP_DIR/trust-registry.json"
LEDGER_PATH="$TMP_DIR/ledger.sqlite"
LOG_PATH="$TMP_DIR/secs-gateway.log"

# Ephemeral fixture-only Ed25519 secret bytes for local smoke. This is intentionally not a real operator key.
python3 - <<'PY' > "$KEY_PATH"
import os
print(os.urandom(32).hex(), end='')
PY
chmod 600 "$KEY_PATH"
printf '{"fixture_only":true,"trusted_verifiers":[]}' > "$TRUST_REGISTRY_PATH"

export SECS_RUNTIME_MODE=production_verified
export SECS_FIXTURE_ONLY_SMOKE=1
export SECS_BIND_ADDR=127.0.0.1:0
export SECS_DB_URL="sqlite:$LEDGER_PATH?mode=rwc"
export SECS_LEDGER_PATH="$LEDGER_PATH"
export SECS_RECEIVER_AUDIENCE=secS://local-smoke-receiver
export SECS_VERIFIER_KEY_PATH="$KEY_PATH"
export SECS_VERIFIER_KEY_ID=verifier:local-smoke-fixture
export SECS_TRUST_REGISTRY_PATH="$TRUST_REGISTRY_PATH"
export SECS_MAX_WIRE_BYTES=2097152
export SECS_MAX_PAYLOAD_BYTES=1048576
export SECS_MAX_OUTPUT_BYTES=1048576
export SECS_HANDLER_TIMEOUT_MS=30000
export SECS_INGRESS_READ_TIMEOUT_MS=10000
export SECS_MAX_IN_FLIGHT_CONNECTIONS=64
export SECS_ALLOWED_EVIDENCE_ADAPTERS=local_static

cd "$ROOT"

echo "secS production-shaped local smoke (fixture-only, no real secrets)"
echo "receiver_audience=$SECS_RECEIVER_AUDIENCE"
echo "ledger_path=$LEDGER_PATH"
echo "trust_registry=fixture-only"

cargo build -p server --bin secs-gateway
"$ROOT/target/debug/secs-gateway" >"$LOG_PATH" 2>&1 &
GATEWAY_PID=$!

ADDR=""
for _ in $(seq 1 100); do
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    echo "secs-gateway exited before listening" >&2
    cat "$LOG_PATH" >&2 || true
    exit 1
  fi
  if grep -q 'listening on ' "$LOG_PATH"; then
    ADDR="$(python3 - "$LOG_PATH" <<'PY'
import re, sys
text=open(sys.argv[1]).read()
match=re.search(r'listening on ([^ ]+) ', text)
print(match.group(1) if match else '')
PY
)"
    [[ -n "$ADDR" ]] && break
  fi
  sleep 0.1
done

if [[ -z "$ADDR" ]]; then
  echo "secs-gateway did not report listener address" >&2
  cat "$LOG_PATH" >&2 || true
  exit 1
fi

python3 - "$ADDR" "$SECS_MAX_WIRE_BYTES" <<'PY'
import socket, sys
host, port = sys.argv[1].rsplit(':', 1)
port = int(port)
limit = int(sys.argv[2])
# malformed short input should be accepted at TCP layer and rejected before panic/exit.
with socket.create_connection((host, port), timeout=5) as sock:
    sock.sendall(b'not-a-bincode-packet')
# oversized input should be bounded and rejected before packet decode.
with socket.create_connection((host, port), timeout=5) as sock:
    sock.sendall(b'x' * (limit + 1))
PY

sleep 0.2
if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
  echo "secs-gateway exited after malformed/oversized input" >&2
  cat "$LOG_PATH" >&2 || true
  exit 1
fi

grep -q 'rejected malformed packet' "$LOG_PATH"
grep -q 'rejected oversized wire frame' "$LOG_PATH"

echo "smoke_ok: secs-gateway bound $ADDR and rejected malformed/oversized TCP input with fixture-only production env"
