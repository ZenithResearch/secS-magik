#!/usr/bin/env bash
set -euo pipefail

# M15.8 / #144 bounded Dregg authority finalizer smoke.
#
# This script is intentionally documentation-shaped: CI exercises the same
# contracts in Rust tests (`production_federated` and `ready_for_prod_docs`).
# Operators can use this file as the finalizer checklist for the bounded local
# secS verifier seam.

cat <<'EOF'
M15.8 bounded Dregg authority finalizer

This demo/checklist covers the bounded in-repo #73 finalizer composed by #144:

1. #162 live ingress evidence refs/public inputs reach the evidence-backed verifier path.
2. Wallet proof-of-possession and trusted issuer membership evidence remain required.
3. #167 delegated attenuation / non-amplification is preserved.
4. #169 trusted requested-authority attenuation derives requested_resource from trusted/decrypted payload material, not caller-declared public inputs.
5. #160 implements bounded Dregg-provisioned resource locks:
   - exact lock match emits resource_lock:verified;
   - mismatch rejects as resource_lock_violation;
   - the verified locked resource is carried in the signed context for handler/policy use.
6. Verify + execute receipts remain inspectable and redaction-safe.

Boundaries / non-claims:
- not deployment proof;
- not public auditability;
- not live Dregg revocation proof;
- not BLS threshold finality;
- not rotated-replay proof verification;
- not Midnight;
- not Cardano.

Local executable evidence:
  cargo test -p server --test production_federated m15_8_finalizer_binds_resource_locked_dregg_authority_into_signed_context -- --nocapture
  cargo test -p server --test production_federated membership_provision_e2e_contract_reaches_verify_execute_and_ledger_inspection -- --nocapture
  cargo test -p server --test ingress real_dregg_resource_lock -- --nocapture
  cargo test -p server --test ready_for_prod_docs dregg_authority_docs_record_144_finalizer_and_demo_without_live_proof_overclaim -- --nocapture
EOF
