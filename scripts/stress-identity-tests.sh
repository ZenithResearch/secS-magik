#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPEATS="${IDENTITY_STRESS_REPEATS:-20}"
TEST_THREADS=16

if [[ ! "$REPEATS" =~ ^[1-9][0-9]*$ ]]; then
  echo "IDENTITY_STRESS_REPEATS must be a positive integer" >&2
  exit 2
fi

cd "$ROOT"
echo "identity stress: repeats=$REPEATS test_threads=$TEST_THREADS (override repeats with IDENTITY_STRESS_REPEATS)"
for ((iteration = 1; iteration <= REPEATS; iteration++)); do
  echo "identity stress iteration $iteration/$REPEATS"
  cargo test -p server --test identity --all-features -- --test-threads "$TEST_THREADS"
done

echo "identity_stress_ok repeats=$REPEATS test_threads=$TEST_THREADS"
