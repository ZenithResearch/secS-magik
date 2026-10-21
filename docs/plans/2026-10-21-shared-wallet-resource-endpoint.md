# Shared Wallet resource endpoint integration

Status: reviewed release direction, 2026-10-21. This document adds no route, opcode,
credential, grant, listener or trust. Wallet public keys are sufficient operator
identities for the current DevGraph MVP; a portable admin credential is optional
follow-on work and must not block promotion of the tested key-authorized flow.

## Current implementation boundaries

- secS `tools/read-authority` issues/verifies holder-bound finite read credentials.
  `secs-devgraph-work-v2` issues exact-request credentials/projections under current
  native Work policy. secS never commits DevGraph objects.
- DevGraph's opt-in signed-read and guarded LAN compositions already put direct
  requests, operator review, credential enrollment, reads and scoped writes under
  one HTTPS origin. Operator keys come from receiver-held policy; every action
  still needs a bound Wallet proof and current policy.
- Transfer, browser and Zenith use that same resource origin. Transfer's native
  editor is a client, not a privileged path around server authorization.
- The normal installed private DevGraph factory is a separate composition. A git
  pull does not configure TLS, issuer pins, operator admission or the Wallet routes.
- The general secS gateway currently uses bounded TCP packet ingress. It is not
  an implemented HTTPS Wallet management server. Browser/app login remains outside
  this repository; a future HTTPS transport must call the same verifier boundary.

## Release sequence

Publish exact Wallet/secS candidate commits, align DevGraph's companion pins and
Zenith's native pin, then run their producer/consumer checks. Standalone read
authority includes the shared dated-validity helper; do not reinterpret read v1
as an unbounded credential or substitute tests of the root Cargo workspace.
Check the retained snapshot byte-for-byte against its pinned Wallet source.

After review and CI, build immutable source artifacts and prepare an explicit
HTTPS receiver deployment with rollback. Preserve existing key identities, grants,
request bytes and replay state. Keep challenge, credential, service-key and TLS
deadlines separate from Until-revoked standing grants. New trust or broader
authority requires exact operator authorization.

## Future generic administration

If portable admin credentials are added, secS owns their cryptographic verification
and issuer-mediated grant authorization. A verified admin may grant only within
its current receiver-held ceiling. No client gets the issuer signing key; no
holder-created child credential delegation is implied. DevGraph supplies typed
resource and operation adapters, current subtree resolution and transaction
receipts. Reject unsupported resource types rather than infer authority from ports.

Use a common advertised HTTPS service with versioned operations for all clients.
Any new admin credential and signed operation contract must be versioned and
reviewed across Wallet, verifier, receiver and stored records. Preserve existing
Packet v0, opcodes, read v1, request credentials, proofs and key-policy flows.

Required checks include ordinary-holder admin denial, exact receiver/resource
bindings, attempted ceiling expansion, current revocation, stale policy/replay
races, exact original-action status recovery, atomic mixed-grant decisions,
access-time subtree moves and legacy stored-record compatibility. Owner bootstrap
remains explicit; discovery, TLS trust and Wallet unlock do not make an owner.
Nostr/Matrix delivery and sync do not gate the direct-request MVP.
