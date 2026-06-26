#!/usr/bin/env bash
set -euo pipefail

# M12.4/#110 tunnel-mode client demo.
#
# Shows the real client calling a gateway in local_dev_tunnel mode with the
# same static local-dev tunnel key contract used by the server. This is not TLS,
# not production transport security, and not the #109 session-derived tunnel
# key path.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

step() { printf '\n=== %s ===\n' "$*"; }
assert_contains() {
  if ! grep -q "$2" <<<"$1"; then
    echo "ASSERTION FAILED: expected output to contain '$2'" >&2
    echo "$1" >&2
    exit 1
  fi
}

WORK_DIR="$(mktemp -d -t secs-m12-tunnel-demo)"
LOG_FILE="$WORK_DIR/gateway.log"
DB_FILE="$WORK_DIR/ledger.db"
REGISTRY_FILE="$WORK_DIR/caller-registry.json"
CALLER_KEY="$WORK_DIR/caller.key"
TUNNEL_KEY="0101010101010101010101010101010101010101010101010101010101010101"
WRONG_KEY="0909090909090909090909090909090909090909090909090909090909090909"

cargo build -p server -p client >/dev/null

step "0. Register the demo caller"
ENTRY_JSON="$(SECS_CALLER_KEY_PATH="$CALLER_KEY" cargo run -q -p client -- identity)"
python3 - "$ENTRY_JSON" >"$REGISTRY_FILE" <<'PY'
import json, sys
entry = json.loads(sys.argv[1])
print(json.dumps({"fixture_only": True, "callers": [entry]}, indent=2))
PY

step "1. Start local_dev_tunnel gateway"
SECS_RUNTIME_MODE=local_dev_tunnel \
  SECS_TUNNEL_KEY_HEX="$TUNNEL_KEY" \
  SECS_DB_URL="sqlite:${DB_FILE}?mode=rwc" \
  SECS_CALLER_REGISTRY_PATH="$REGISTRY_FILE" \
  cargo run -q -p server --bin secs-gateway >"$LOG_FILE" 2>&1 &
GATEWAY_PID=$!
trap 'kill "$GATEWAY_PID" >/dev/null 2>&1 || true; rm -rf "$WORK_DIR"' EXIT

for _ in {1..50}; do
  grep -q "listening on" "$LOG_FILE" 2>/dev/null && break
  kill -0 "$GATEWAY_PID" >/dev/null 2>&1 || { cat "$LOG_FILE"; exit 1; }
  sleep 0.1
done
grep -q "listening on" "$LOG_FILE" || { cat "$LOG_FILE"; exit 1; }

step "2. Matching client tunnel key -> ACCEPT"
ACCEPT_OUT="$(SECS_CALLER_KEY_PATH="$CALLER_KEY" SECS_TUNNEL_KEY_HEX="$TUNNEL_KEY" SECS_URL=127.0.0.1:9001 \
  cargo run -q -p client -- hub 16 "hello through local_dev_tunnel")"
echo "$ACCEPT_OUT"
assert_contains "$ACCEPT_OUT" "decision=accepted"
assert_contains "$ACCEPT_OUT" "receipt=receipt-execute-"

step "3. Wrong client tunnel key -> REJECT bad_mac"
if WRONG_OUT="$(SECS_CALLER_KEY_PATH="$CALLER_KEY" SECS_TUNNEL_KEY_HEX="$WRONG_KEY" SECS_URL=127.0.0.1:9001 \
  cargo run -q -p client -- hub 16 "wrong tunnel key")"; then
  echo "ASSERTION FAILED: wrong tunnel key must exit non-zero" >&2
  exit 1
fi
echo "$WRONG_OUT"
assert_contains "$WRONG_OUT" "decision=rejected reason=bad_mac"

step "Tunnel demo complete"
echo "client encrypt -> server decrypt -> accepted, and wrong-key reject demonstrated."
