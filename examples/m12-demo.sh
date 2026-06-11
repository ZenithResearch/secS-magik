#!/usr/bin/env bash
set -euo pipefail

# M12 demoable end-to-end secS milestone (#88).
#
# Shows, against the real gateway: an authenticated caller accepted; a forged
# proof and an unregistered caller rejected with typed reasons; replay and
# expiry rejected; the caller receiving the gateway's decision frame; and an
# operator inspecting the resulting receipt chain in the local ledger.
# Wallet + Dregg-shaped evidence verification is demonstrated at the adapter
# seam via its composition test (live evidence-aware ingress remains the
# #78/#79 follow-up rail and is intentionally NOT claimed here).
#
# Boundary (do not overclaim): this demo proves local verifier behavior only.
# It is not production deployment proof (#33), not public auditability (#37),
# not wallet-core parity (#71), not live registry discovery (#72), and not
# Dregg/Midnight/Cardano authority (#73/#74/#75). Caller proof-of-origin is
# necessary, never sufficient authority.
#
# Usage:
#   ./examples/m12-demo.sh

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

WORK_DIR="$(mktemp -d -t secs-m12-demo)"
LOG_FILE="$WORK_DIR/gateway.log"
DB_FILE="$WORK_DIR/ledger.db"
REGISTRY_FILE="$WORK_DIR/caller-registry.json"
CALLER_KEY="$WORK_DIR/caller.key"
IMPOSTOR_KEY="$WORK_DIR/impostor.key"
PACKET_FILE="$WORK_DIR/replay-packet.bin"

cargo build -p server -p client >/dev/null

step "0. Register the demo caller (receiver-held key registry)"
ENTRY_JSON="$(SECS_CALLER_KEY_PATH="$CALLER_KEY" cargo run -q -p client -- identity)"
CALLER_ID="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['key_id'])" "$ENTRY_JSON")"
python3 - "$ENTRY_JSON" >"$REGISTRY_FILE" <<'PY'
import json, sys
entry = json.loads(sys.argv[1])
print(json.dumps({"fixture_only": True, "callers": [entry]}, indent=2))
PY
echo "registered caller: $CALLER_ID"

step "1. Start the gateway with the caller registry"
SECS_RUNTIME_MODE=local_dev_plaintext \
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

step "2. Authenticated caller -> ACCEPT (caller sees the signed decision)"
ACCEPT_OUT="$(SECS_CALLER_KEY_PATH="$CALLER_KEY" SECS_URL=127.0.0.1:9001 \
  cargo run -q -p client -- hub 16 "hello from the registered caller")"
echo "$ACCEPT_OUT"
assert_contains "$ACCEPT_OUT" "decision=accepted"
assert_contains "$ACCEPT_OUT" "context=ctx-v1-"
assert_contains "$ACCEPT_OUT" "receipt=receipt-execute-"

step "3. Forged proof (impostor key under the registered id) -> REJECT"
if FORGED_OUT="$(SECS_CALLER_KEY_PATH="$IMPOSTOR_KEY" SECS_CALLER_KEY_ID="$CALLER_ID" \
  SECS_URL=127.0.0.1:9001 cargo run -q -p client -- hub 16 "forged")"; then
  echo "ASSERTION FAILED: forged caller must exit non-zero" >&2
  exit 1
fi
echo "$FORGED_OUT"
assert_contains "$FORGED_OUT" "decision=rejected reason=bad_caller_proof"

step "4. Unregistered caller -> REJECT (unknown key id)"
if UNKNOWN_OUT="$(SECS_CALLER_KEY_PATH="$IMPOSTOR_KEY" SECS_URL=127.0.0.1:9001 \
  cargo run -q -p client -- hub 16 "unknown caller")"; then
  echo "ASSERTION FAILED: unregistered caller must exit non-zero" >&2
  exit 1
fi
echo "$UNKNOWN_OUT"
assert_contains "$UNKNOWN_OUT" "decision=rejected reason=unknown_caller_key"

step "5. Replay (verbatim resend of an accepted packet) -> REJECT"
REPLAY_FIRST="$(SECS_CALLER_KEY_PATH="$CALLER_KEY" SECS_SAVE_PACKET_PATH="$PACKET_FILE" \
  SECS_URL=127.0.0.1:9001 cargo run -q -p client -- hub 16 "replay me")"
assert_contains "$REPLAY_FIRST" "decision=accepted"
REPLAY_OUT="$(python3 - "$PACKET_FILE" <<'PY'
import socket, sys
bytes_to_send = open(sys.argv[1], "rb").read()
sock = socket.create_connection(("127.0.0.1", 9001), timeout=5)
sock.sendall(bytes_to_send)
sock.shutdown(socket.SHUT_WR)
frame = b""
while True:
    chunk = sock.recv(4096)
    if not chunk:
        break
    frame += chunk
print(frame.decode("utf-8", errors="replace"))
PY
)"
echo "replay response frame contains: $(grep -o 'replay_detected' <<<"$REPLAY_OUT" | head -1)"
assert_contains "$REPLAY_OUT" "replay_detected"

step "6. Expired claim (TTL 0) -> REJECT"
if EXPIRED_OUT="$(SECS_CALLER_KEY_PATH="$CALLER_KEY" SECS_CLAIM_TTL=0 \
  SECS_URL=127.0.0.1:9001 cargo run -q -p client -- hub 16 "expired")"; then
  echo "ASSERTION FAILED: expired claim must exit non-zero" >&2
  exit 1
fi
echo "$EXPIRED_OUT"
assert_contains "$EXPIRED_OUT" "decision=rejected reason=expired_claim"

step "7. Wallet + Dregg-shaped evidence (adapter seam; shape+signature only)"
cargo test -q -p server --test production_federated \
  wallet_issuer_and_dregg_shaped_evidence_compose_through_composite_adapter 2>&1 | tail -3
echo "NOTE: evidence verification runs at the adapter seam; live evidence-aware"
echo "ingress remains the #78/#79 rail, and Dregg AUTHORITY remains #73."

step "8. Operator inspects the receipt chain"
if command -v sqlite3 >/dev/null 2>&1; then
  sqlite3 -header -column "$DB_FILE" \
    "SELECT receipt_id, kind, decision, reason FROM receipts ORDER BY rowid;"
else
  echo "(sqlite3 CLI not installed; receipts persisted in $DB_FILE)"
fi

step "M12 demo complete"
echo "authenticated accept, forged/unknown caller rejects, replay reject,"
echo "expiry reject, caller-visible decisions, and operator receipt inspection"
echo "all demonstrated against the live local gateway."
