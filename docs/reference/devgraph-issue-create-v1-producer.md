# `devgraph.issue.create.v1` authority producer reference

Status: DG-P implemented in secS; downstream consumers remain blocked by the
serialized cross-repository DAG.

Contract: [../specs/devgraph-issue-create-v1.md](../specs/devgraph-issue-create-v1.md)

## Boundary

`server::devgraph_authority` implements one producer for exactly
`devgraph.issue.create.v1`. It strictly decodes and canonicalizes one Issue
create request, verifies one Wallet Ed25519 presentation against one
receiver-held policy, emits one portable signed JSON authority projection, and
durably reserves `(session_id, operation, nonce)` before returning it.

It is not an ingress route, gateway descriptor, opcode, handler, generic Work
API, operation multiplexer, Devgraph client, Wallet method, CLI command, or
deployment. Devgraph still owns Work validation/mutation/idempotency/audit and
`EventReceipt`. `.castaway` remains only a vault and is not consulted by this
producer.

## Wallet presentation accepted by the producer

The strict presentation schema is
`devgraph.issue.create.wallet-presentation.v1`. Unknown and duplicate fields
reject. Its exact fields are:

```json
{
  "actor_public_key": "<base64url-no-pad 32-byte Ed25519 public key>",
  "actor_signature_suite": "Ed25519",
  "audience": "<exact receiver policy audience>",
  "expires_at": 0,
  "idempotency_key_digest_sha256": "<64 lowercase hex>",
  "issued_at": 0,
  "nonce": "<base64url-no-pad 12 bytes>",
  "operation": "devgraph.issue.create.v1",
  "request_digest_sha256": "<64 lowercase hex>",
  "resource": "Issue/<canonical-id>",
  "schema": "devgraph.issue.create.wallet-presentation.v1",
  "schema_version": 1,
  "session_id": "<base64url-no-pad 16 bytes>",
  "signature": "<base64url-no-pad 64-byte Ed25519 signature>"
}
```

The signature preimage is:

```text
UTF8("devgraph.issue.create.wallet-presentation.v1/signature\0") ||
RFC8785_JCS(presentation_without_signature)
```

The v1 actor identity is
`pubkey:sha256:<lowercase SHA-256 of the raw 32-byte public key>`. The
presentation binds the exact request and idempotency digests, audience,
operation, resource, session, nonce, issued-at, and expires-at accepted by
secS. `issued_at <= now < expires_at` and a maximum 60-second validity span are
enforced. Session identifiers decode to exactly 16 bytes; all-zero is valid.

This is compatible only with the Ed25519 half of Wallet's root identity.
Hybrid Ed25519 + ML-DSA-65 authorization requires a separately ratified v2
contract and cannot be appended to this format.

The producer rejects raw Wallet presentation JSON above 16,384 bytes before
parsing and checks exact no-pad base64url encoded lengths before allocation.
Wallet signatures use Ed25519 strict verification.

## Receiver-held policy

The fixed policy schema is `secs-devgraph-issue-create-policy.v1`. It contains
only `audience`, exact operation, safe policy ID, nonzero policy version,
schema, and bounded rules. Each rule binds actor ID, allow/deny effect,
validity window, active/revoked status, and exact or `Issue/`-bounded resource
matching. Active matching deny rules win; no active matching allow rule denies.
The caller cannot supply policy, scopes, verifier keys, routes, or handler
selection.

Raw receiver-policy JSON is capped at 262,144 bytes before parsing. Policy
versions and rule timestamps are at most `9007199254740991`.

The projection retains policy ID/version and the domain-separated SHA-256 of
the complete canonical policy. Policy rules and raw policy material are not
placed in projection telemetry.

## Signing, verification, and replay

The producer loads only an owner-private configured production Ed25519 secS
identity and requires a separately configured receiver-owned public-key
registry to trust the exact signing key at `now` before signing or replay
reservation. Its private signing method accepts only an opaque typed
`devgraph.issue.create.v1` projection preimage whose constructor is private to
the producer; there is no arbitrary-byte or suffix signing seam. Strict
Ed25519 verification uses the registry's duplicate, status, validity,
algorithm, public-key equality, signature, and exclusive `now < not_after`
checks.

Replay persistence uses the dedicated
`devgraph_authority_replay_reservations` table. Its unique key is exactly
`(session_id, operation, nonce)`; `replay_scope` is stored as the fixed
`session:operation:nonce` value under a database `CHECK`, is selected and
compared on retry, but does not widen the key. Exact retry requires
every safe authority binding that can affect projection bytes to match,
including request/idempotency, policy, Wallet-presentation, secS context, and
verifier-key bindings. Any variation is `ScopeConflict`. Prune/storage errors
and SQLite integer overflow fail closed. Rows expire at `expires_at <= now`.

## Portable consumer vectors

Cross-language consumers must use the byte-exact fixtures in
`server/tests/fixtures/devgraph_issue_create_v1/`:

- versioned `manifest.json`, with the expected clock, transport semantics, and
  raw SHA-256 digest for every other fixture;
- merged P4-O-DG-R1 `canonicalization-boundaries.json`, pinning the accepted
  IEEE-754 safe-integer bounds, control escapes, Unicode no-normalization, and
  array-order semantics;
- `request.json`, `canonical-request.json`, and the non-default
  Unicode/escaping/negative-priority pair;
- raw non-secret `idempotency-key.txt`;
- `wallet-presentation.json`;
- `receiver-policy.json` and `receiver-policy-binding.json`;
- `secs-public-key-registry.json`;
- `unsigned-projection.json`;
- `signed-projection.json`;
- `correlation-digest.txt`.

`server/tests/devgraph_authority_projection.rs` verifies these files directly,
including the exact signatures and correlation digest. It also covers strict
JSON/base64url handling, request/presentation/projection mutations, receiver
policy denial, verifier-key lifecycle, exact expiry, durable reopen retry and
conflict behavior, pre-DG-P schema upgrade/idempotence, storage failure,
IEEE-754-safe canonical integer bounds, no Unicode normalization, and
redaction. Canonical fixture files equal the canonical preimage bytes followed
by exactly one LF; tests compare full file bytes without trimming. Raw request,
Wallet presentation, policy, and projection JSON are capped before parsing at
131,072, 16,384, 262,144, and 16,384 bytes respectively.

## Safe outward data

Safe projection telemetry is limited to operation, actor ID, resource, session
ID, secS context ID, request/idempotency digests, policy ID/version/digest,
secS verifier key ID, and full-projection correlation digest. It excludes raw
idempotency key, Wallet public key/presentation/signature, secS signature,
title, description, reference arrays, policy rules, keys, URLs, headers, and
storage data.
