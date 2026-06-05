#!/usr/bin/env bash
set -euo pipefail

# secZ Hello World quick start.
#
# This starts the local/dev secZ compatibility gateway on 127.0.0.1:9001, then sends
# "Hello World" through opcode 16 (0x10). The 0x10 manifest binding pipes
# the decrypted payload to:
#
#   bash -c "echo 'Bash received payload:'; cat"
#
# Usage:
#   ./examples/hello-world.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOG_FILE="${SECZ_HELLO_LOG:-/tmp/secz-hello-world.log}"
DB_FILE="${SECZ_HELLO_DB:-$(mktemp -t secz-hello-world.XXXXXX.db)}"
: > "$LOG_FILE"

SECS_RUNTIME_MODE=local_dev_plaintext SECS_DB_URL="sqlite:${DB_FILE}?mode=rwc" cargo run -p server --bin secz > "$LOG_FILE" 2>&1 &
SECZ_PID=$!
trap 'kill "$SECZ_PID" >/dev/null 2>&1 || true; rm -f "$DB_FILE"' EXIT

for _ in {1..50}; do
  if ! kill -0 "$SECZ_PID" >/dev/null 2>&1; then
    cat "$LOG_FILE"
    echo "secZ failed to start" >&2
    exit 1
  fi

  if grep -q "compatibility gateway listening" "$LOG_FILE" 2>/dev/null; then
    break
  fi

  sleep 0.1
done

if ! grep -q "compatibility gateway listening" "$LOG_FILE" 2>/dev/null; then
  cat "$LOG_FILE"
  echo "secZ did not become ready" >&2
  exit 1
fi

SECS_URL="127.0.0.1:9001" cargo run -p client -- hub 16 "Hello World"

sleep 0.5
cat "$LOG_FILE"

grep -q "invoking verified dev handler" "$LOG_FILE"
