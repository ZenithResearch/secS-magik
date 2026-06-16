#!/usr/bin/env bash
set -euo pipefail

# M13 receiver-local permission demo (#119/#121/#123/#125/#127).
#
# Proves the operator-facing permission flow end to end with secs-permctl:
# an operator grants a caller permission for a specific opcode/operation/
# resource, evaluates allowed and denied requests, sees deny-wins, revokes a
# grant, and watches each decision land as ALLOW or DENY:<typed-reason>.
#
# The same secs-permissions model demonstrated here is what the gateway
# enforces live before any handler side effect (proven by the M13.3 E2E
# suite, server/tests/permissioned_file_write_e2e.rs) and what the M13.4b
# browser panel drives.
#
# Boundary (do not overclaim): this demonstrates receiver-local policy
# authoring and evaluation only. It is not the live gateway TCP path, not
# production deployment proof (#33), not public auditability (#37), and not
# Dregg/Midnight/Cardano authority (#73/#74/#75). Every record is authored
# with authority_source = receiver_local.
#
# Usage:
#   ./examples/m13-permission-demo.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

step() { printf '\n=== %s ===\n' "$*"; }

WORK_DIR="$(mktemp -d -t secs-m13-demo)"
POLICY="$WORK_DIR/permissions.json"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

CALLER="secS://caller-a"
OPCODE="0x50"
OP="demo.file.write"
SANDBOX="file:///tmp/secs-demo/"
ALLOWED="file:///tmp/secs-demo/allowed.txt"
OTHER="file:///tmp/secs-demo/other.txt"

cargo build -q -p server --bin secs-permctl
PERMCTL=(./target/debug/secs-permctl --policy "$POLICY")

# Evaluate a request and assert the decision equals $1 (ALLOW or DENY:<reason>).
# secs-permctl exits non-zero on DENY, so capture output without tripping -e.
assert_decision() {
  local expected="$1"; shift
  local got
  got="$("${PERMCTL[@]}" evaluate "$@" || true)"
  if [[ "$got" != "$expected" ]]; then
    echo "ASSERTION FAILED: expected '$expected', got '$got'" >&2
    echo "  request: $*" >&2
    exit 1
  fi
  printf '  %-44s -> %s\n' "$*" "$got"
}

step "0. Empty policy fails closed (default deny)"
assert_decision "DENY:permission_no_matching_grant" \
  --caller "$CALLER" --opcode "$OPCODE" --operation "$OP" --resource "$ALLOWED" --now 1000

step "1. Grant caller-a a prefix scope over the sandbox"
"${PERMCTL[@]}" grant \
  --caller "$CALLER" --opcode "$OPCODE" --operation "$OP" \
  --resource "$SANDBOX" --prefix --not-before 0 --not-after 9999999999

step "2. Allowed: a resource under the granted prefix"
assert_decision "ALLOW" \
  --caller "$CALLER" --opcode "$OPCODE" --operation "$OP" --resource "$ALLOWED" --now 1000
assert_decision "ALLOW" \
  --caller "$CALLER" --opcode "$OPCODE" --operation "$OP" --resource "$OTHER" --now 1000

step "3. Denied: wrong caller and wrong operation (no matching grant)"
assert_decision "DENY:permission_no_matching_grant" \
  --caller "secS://intruder" --opcode "$OPCODE" --operation "$OP" --resource "$ALLOWED" --now 1000
assert_decision "DENY:permission_no_matching_grant" \
  --caller "$CALLER" --opcode "$OPCODE" --operation "demo.file.read" --resource "$ALLOWED" --now 1000

step "4. Deny wins: add an explicit deny for one exact resource"
"${PERMCTL[@]}" grant \
  --caller "$CALLER" --opcode "$OPCODE" --operation "$OP" \
  --resource "$OTHER" --deny --not-before 0 --not-after 9999999999
assert_decision "DENY:permission_explicit_deny" \
  --caller "$CALLER" --opcode "$OPCODE" --operation "$OP" --resource "$OTHER" --now 1000
# The prefix allow still applies to the other resource.
assert_decision "ALLOW" \
  --caller "$CALLER" --opcode "$OPCODE" --operation "$OP" --resource "$ALLOWED" --now 1000

step "5. Validity window: a request before/after the window is denied"
"${PERMCTL[@]}" grant \
  --caller "secS://timed" --opcode "$OPCODE" --operation "$OP" \
  --resource "$ALLOWED" --not-before 1000 --not-after 2000
assert_decision "DENY:permission_expired" \
  --caller "secS://timed" --opcode "$OPCODE" --operation "$OP" --resource "$ALLOWED" --now 5000
assert_decision "DENY:permission_not_yet_valid" \
  --caller "secS://timed" --opcode "$OPCODE" --operation "$OP" --resource "$ALLOWED" --now 500
assert_decision "ALLOW" \
  --caller "secS://timed" --opcode "$OPCODE" --operation "$OP" --resource "$ALLOWED" --now 1500

step "6. Revoke the prefix grant; caller-a is now denied"
"${PERMCTL[@]}" revoke \
  --caller "$CALLER" --opcode "$OPCODE" --operation "$OP" --resource "$SANDBOX"
assert_decision "DENY:permission_revoked" \
  --caller "$CALLER" --opcode "$OPCODE" --operation "$OP" --resource "$ALLOWED" --now 1000

step "7. Final policy"
"${PERMCTL[@]}" list

printf '\n=== M13 permission demo passed ===\n'
echo "Receiver-local policy only. The live gateway enforces this same model"
echo "before any handler side effect (M13.3 E2E). No Dregg authority (#73),"
echo "deployment proof (#33), or public auditability (#37) is claimed."
