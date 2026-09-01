# `devgraph.issue.create.v1` exact-operation contract

Date: 2026-08-31
Status: P4-O-DG and P4-O-DG-R1 merged; DG-P producer merged through PR #284; DG-E1 fixed producer adapter merged through PR #285; DG-E2 fixed one-shot Wallet adapter implemented on its branch
Depends on: P4-R completed by PR #271 merge `5dfeb950da1d6baf80d98e0843684625c9af6f4f` and green post-merge Rust CI run `33448400000`
Repair: P4-O-DG-R1 / Issue #282, before DG-P

## Decision boundary

This document pins one exact authority-bearing operation:
`devgraph.issue.create.v1`. It creates exactly one canonical Devgraph `Issue`.
It is not a generic Work API, HTTP, RPC, tool, prompt, route, or handler
multiplexer.

P4-R's merge and post-merge `main` gate are complete, and PR #280 merged this
operator-ratified contract at `bfe1a453`. PR #283 then merged the
P4-O-DG-R1 safe-integer repair at `43d8904`, preserving its canonicalization
vectors before any producer or consumer shipped. DG-P now implements only the secS
producer described here: strict Issue request/Wallet presentation/policy
verification, one portable signed projection, and durable exact-operation
replay state. It does not assign an opcode, select an ABI, transport, socket,
route, endpoint, package, or deployment, and it does not implement a Wallet
method, Devgraph consumer/mutation, CLI, or end-to-end operation.

The exact producer presentation, policy, replay, and fixture formats are
registered in
[the DG-P reference](../reference/devgraph-issue-create-v1-producer.md).

## Ownership and authority boundaries

- The Castalia Wallet root Ed25519 keypair is the actor identity. The actor's
  private key remains in Wallet custody and never enters secS or Devgraph.
- `.castaway` is a protected vault. It is not the identity, signer, wallet,
  credential, trust root, authority projection, or gateway.
- secS verifies the actor proof, receiver policy, exact operation, resource,
  request, freshness, expiry, and replay bindings and emits a portable signed
  authority projection.
- Devgraph independently verifies the secS projection and alone owns canonical
  Work validation, mutation, idempotency, storage, audit, and `EventReceipt`.
- A Wallet proof of possession is necessary but not sufficient. Receiver-owned
  policy must explicitly authorize the actor for this exact operation and
  resource before secS emits an accepted authority projection.

No caller field can select or widen receiver policy, verifier keys, scopes,
handler identity, opcode, transport, URL, path, header, database, work kind, or
mutation method.

## Exact semantic operation

| Dimension | Contract |
|---|---|
| Operation ID | `devgraph.issue.create.v1` |
| Devgraph operation | `create_work_object` |
| Work kind | exactly `Issue` |
| Resource | exactly `Issue/<id>` where `<id>` is the validated request `id` |
| Authority category | Devgraph derives exactly `devgraph.write`; the caller does not supply scopes |
| Result | one Devgraph mutation result plus its canonical `EventReceipt`, or the exact duplicate result |
| Update precondition | none; `If-Match` is not part of create |

The `id` must match the Devgraph canonical ASCII identifier grammar
`^[a-z0-9](?:[a-z0-9-]{0,254}[a-z0-9])?$`. The resource comparison is
byte-for-byte and case-sensitive after constructing `Issue/` plus that exact
validated identifier. No path decoding, URL decoding, Unicode normalization,
aliasing, or pluralization occurs.

## Strict create request

The semantic request contains exactly these fields after defaults are
materialized:

```json
{
  "artifact_ids": [],
  "description": "",
  "external_link_ids": [],
  "id": "issue-example",
  "kind": "Issue",
  "priority": 0,
  "title": "Example issue"
}
```

Rules:

1. The raw request is at most 131,072 bytes before JSON parsing. Oversized
   whitespace and oversized strings reject before decoder allocation. Unknown
   or duplicate JSON object fields reject.
2. `kind` is present in the signed semantic request and is exactly `Issue`,
   even when a later transport represents kind outside its body.
3. `id` follows the canonical grammar above.
4. `title` is a non-empty JSON string.
5. `description` is a JSON string and defaults to the empty string.
6. `priority` is a JSON integer in the inclusive range
   `-9007199254740991..=9007199254740991` and defaults to zero. Floats,
   exponent notation, booleans, quoted integers, and values outside that range
   reject before canonicalization.
7. `artifact_ids` and `external_link_ids` are ordered arrays of identifiers
   using the same canonical grammar and default to empty arrays. Array order is
   significant for the digest.
8. The UTF-8 RFC 8785 JSON Canonicalization Scheme representation of the
   materialized object is at most 65,536 bytes.

The canonical request digest is:

```text
request_digest_sha256 = lowercase_hex(
  SHA-256(
    UTF8("devgraph.issue.create.request.v1\0") ||
    RFC8785_JCS(materialized_create_request)
  )
)
```

The digest is exactly 64 lowercase hexadecimal characters. It binds the
complete semantic request, including `kind`, and not raw transport bytes.

## RFC 8785 safe-integer and string profile

P4-O-DG-R1 defines the numeric interoperability profile for every RFC 8785
canonical JSON value governed by this v1 contract:

```text
MAX_SAFE_INTEGER = 9007199254740991  // 2^53 - 1
MIN_SAFE_INTEGER = -9007199254740991 // -(2^53 - 1)
```

- `priority` is within `MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER`.
- Every other canonicalized integer is non-negative and within
  `0..=MAX_SAFE_INTEGER`. This applies to integers in the materialized request,
  Wallet proof or presentation, receiver-policy input or decision, unsigned
  authority projection, and full signed authority projection.
- Narrower field rules remain in force: `schema_version` is exactly `1`,
  `receiver_policy_version` identifies the exact receiver-owned decision,
  `issued_at < expires_at`, and the validity window is at most 60 seconds.
- A decoder may use a wider native integer internally, but it must reject an
  out-of-range number before canonicalization, digesting, signing, policy use,
  replay reservation, forwarding, mutation, or receipt creation. Numeric
  strings, booleans, floats, and exponent notation do not become integers.

RFC 8785 delegates JSON number serialization to ECMAScript's number
serialization model, whose interoperable number domain is IEEE-754 binary64.
Beyond `2^53 - 1`, adjacent integers are not all exactly representable, so
Rust, JavaScript, and Python producers or consumers could otherwise round or
emit divergent canonical bytes for the same intended value. This repair
narrows an unimplemented contract; it changes no stored or deployed format.
Any future wider integer domain requires a separately versioned representation
rather than reinterpretation of v1.

The repair preserves numeric JSON field types, every field name, schema and
version identifier, domain separator, digest construction, operation/resource
semantic, and Ed25519-only v1 boundary. It adds neither a runtime nor a
hybrid/PQ claim.

RFC 8785 does not normalize JSON strings. Decoded Unicode code points are
preserved, required control characters use their canonical JSON escapes, and
object-property sorting does not reorder arrays. Therefore precomposed and
decomposed Unicode spellings remain byte-distinct, and the order of
`artifact_ids` and `external_link_ids` remains digest-significant.

The committed vectors at
`server/tests/fixtures/devgraph_issue_create_v1/canonicalization-boundaries.json`
pin the accepted lower and upper priority bounds, one-step-outside denials, the
maximum non-negative canonical integer, control escaping, Unicode
no-normalization, array order, exact canonical UTF-8 JSON, and request digests.
The fixture file is a manifest, not a signing preimage. For each accepted
request vector, implementations decode `materialized_request`, independently
apply RFC 8785, compare the resulting bytes with `canonical_json_utf8`, and
hash only the contract's domain separator plus those canonical request bytes.

## Idempotency binding

The caller creates one idempotency key containing 16 through 128 ASCII
characters from `[A-Za-z0-9._~-]`. The raw key may be carried only by the
eventual fixed adapter and Devgraph idempotency seam; it is never persisted,
logged, placed in receipts, or copied into the authority projection.

```text
idempotency_key_digest_sha256 = lowercase_hex(
  SHA-256(UTF8(exact_idempotency_key))
)
```

secS binds the digest into the signed authority projection. Devgraph recomputes
it from the exact received idempotency key before authorization and mutation.
A mismatch rejects before any work, replay, outbox, audit, or receipt side
effect. Reuse is valid only as a retry of the same operation, `Issue` resource,
and canonical request digest. A matching retry returns the existing Devgraph
receipt and performs no second mutation. Reuse for any other scope is an
idempotency conflict.

## Actor and Wallet proof

Version 1 uses the Wallet root's Ed25519 public key and signature only:

```text
actor_id = "pubkey:sha256:" || lowercase_hex(SHA-256(raw_32_byte_ed25519_public_key))
actor_signature_suite = "Ed25519"
```

The Wallet-signed proof must bind the exact audience, operation, resource,
request digest, idempotency-key digest, session ID, nonce, issued-at, and
expires-at values that secS accepts. secS records a digest of that verified
presentation in the portable projection; the raw Wallet signature and private
material do not cross into Devgraph receipts.

The raw Wallet presentation is at most 16,384 bytes before JSON parsing.
Base64url values are length-checked before decoding: public keys are exactly 43
encoded characters, sessions 22, nonces 16, and Ed25519 signatures 86. secS
uses strict Ed25519 verification, including rejection of weak/small-order
encodings.

This is compatible with the Ed25519 half of Wallet's one-root Dregg hybrid
identity. It is not hybrid or post-quantum authorization: it does not bind or
verify ML-DSA-65 public material or a second signature. Requiring both Ed25519
and ML-DSA-65 is a new `devgraph.issue.create.v2` contract and cannot be inferred
from, appended to, or relabeled as v1.

## Receiver-held policy input

The fixed receiver policy uses schema
`secs-devgraph-issue-create-policy.v1`. Raw receiver-policy JSON is at most
262,144 bytes before parsing. It binds the exact audience and operation, a safe
nonzero policy ID/version, and at most 256 bounded deny-wins rules. Every policy
version and rule timestamp is a non-negative integer no greater than
`9007199254740991`. The policy is receiver-owned; callers cannot supply or
widen it.

## Portable secS authority projection

The cross-language projection is strict UTF-8 JSON, not Rust `bincode`. It has
exactly these fields; unknown or duplicate fields reject:

```json
{
  "actor_id": "pubkey:sha256:<64 lowercase hex>",
  "actor_signature_suite": "Ed25519",
  "audience": "<exact receiver-configured Devgraph audience>",
  "expires_at": 0,
  "idempotency_key_digest_sha256": "<64 lowercase hex>",
  "issued_at": 0,
  "nonce": "<base64url-no-pad 12 bytes>",
  "operation": "devgraph.issue.create.v1",
  "receiver_policy_digest_sha256": "<64 lowercase hex>",
  "receiver_policy_id": "<receiver-owned identifier>",
  "receiver_policy_version": 1,
  "replay_scope": "session:operation:nonce",
  "request_digest_sha256": "<64 lowercase hex>",
  "resource": "Issue/issue-example",
  "schema": "secs-devgraph-authority.v1",
  "schema_version": 1,
  "secs_context_id": "<secS-generated context identifier>",
  "secs_verifier_key_id": "<receiver-trusted key identifier>",
  "secs_verifier_signature": "<base64url-no-pad 64-byte Ed25519 signature>",
  "secs_verifier_signature_suite": "Ed25519",
  "session_id": "<base64url-no-pad 16 bytes>",
  "wallet_presentation_digest_sha256": "<64 lowercase hex>"
}
```

The unsigned projection contains every field above except
`secs_verifier_signature`. Its signature preimage is:

```text
UTF8("secs-devgraph-authority.v1/signature\0") ||
RFC8785_JCS(unsigned_projection)
```

The full signed projection correlation digest is:

```text
secs_authority_projection_digest_sha256 = lowercase_hex(
  SHA-256(
    UTF8("secs-devgraph-authority.v1/projection\0") ||
    RFC8785_JCS(full_signed_projection)
  )
)
```

The raw projection is at most 16,384 bytes before JSON parsing.
All projection integer fields are non-negative JSON integers within
`0..=9007199254740991`, subject to the narrower field rules above. Values
outside that range reject before canonicalization or signature verification.
All digests are 32-byte SHA-256 values encoded as 64 lowercase hexadecimal
characters. `session_id`, `nonce`, and the verifier signature use unpadded RFC
4648 base64url and decode to exactly 16, 12, and 64 bytes.

The audience is the exact non-empty receiver-configured Devgraph audience and
is compared byte-for-byte. Neither Wallet nor another caller chooses it. The
receiver policy ID, version, and digest identify the exact receiver-owned
policy decision used by secS. Devgraph trusts only configured production
authority keys; a key included only inside the projection is not a trust root.

### V1 canonical-integer compatibility erratum

The pre-runtime DG-P implementation narrows the earlier prose that described
`priority` as arbitrary `i64` and projection numbers as arbitrary `u64`.
RFC 8785 interoperates through the IEEE-754 exact-integer range, so every
canonicalized integer in v1 is restricted to the bounds above. This is a
fail-closed compatibility erratum made before any DG-V consumer, route, or Work
mutation shipped; it does not widen the ratified operation. UTF-8 strings are
not Unicode-normalized, JSON escaping is canonicalized, and array order remains
significant. The cross-language fixtures pin both bounds and these semantics.

## Freshness, expiry, and replay

- `issued_at < expires_at`.
- `expires_at - issued_at` is at most 60 seconds.
- Verification accepts only when `issued_at <= now < expires_at`.
- Exact boundary rule: `now >= expires_at` rejects as expired before any
  Devgraph operation or receipt side effect.
- A future-issued projection (`now < issued_at`) rejects as not yet valid.
- secS reserves `(session_id, operation, nonce)` under
  `session:operation:nonce` before forwarding to any downstream handler.
- Duplicate replay with a different idempotency scope rejects. An exact
  duplicate retry can only recover the already persisted Devgraph receipt.
- Clock-read failure rejects; it never becomes an infinite or saturated
  validity window.

## Devgraph verification and operation handoff

Before canonical Work mutation, Devgraph must:

1. Strictly decode the projection and reject malformed/unknown fields.
2. Resolve `secs_verifier_key_id` only through its receiver-owned trust
   registry; verify key algorithm, production-authority status, lifecycle, and
   Ed25519 signature over the exact portable preimage.
3. Compare the exact audience, schema, operation, resource, actor suite,
   receiver-policy binding, replay scope, and validity window.
4. Reconstruct and validate the strict create request, resource, canonical
   request digest, and idempotency-key digest.
5. Derive exactly `devgraph.write` from the receiver-owned mapping for
   `devgraph.issue.create.v1`; ignore and reject caller-supplied scopes.
6. Preserve actor, session, secS context, policy, verifier key, authority
   projection digest, request digest, and idempotency digest as safe authority
   telemetry.
7. Invoke Devgraph's canonical create service. secS never owns Work lifecycle,
   repository, ontology, storage, or `EventReceipt` semantics.

The semantic handoff is not an authorization to expose a caller-selected HTTP
route. A later adapter may choose a fixed receiver-local transport, but the
caller cannot supply a URL, origin, path, method, header name/value, redirect,
proxy, handler ID, opcode, database query, or storage credential.

## Result and receipt correlation

Success means Devgraph atomically persists the `Issue`, its canonical
`EventReceipt`, and the emitted-event relationship. Verification acceptance or
a secS verify receipt alone is not Work success.

The Devgraph receipt/audit projection for this operation must retain at least:

- `operation = devgraph.issue.create.v1`;
- `subject_label = Issue` and exact `subject_id`;
- actor ID, session ID, and secS context ID;
- Devgraph correlation ID and receipt ID;
- request digest and idempotency-key digest;
- receiver policy ID/version/digest;
- secS verifier key ID and authority projection digest;
- duplicate status and persisted receipt status.

The raw idempotency key, raw Wallet presentation/signature, raw secS verifier
signature, request title/description, private evidence, keys, headers, URLs,
and storage data do not enter receipt or log projections.

The secS execution result binds the exact request digest and the bounded
Devgraph mutation-result bytes. Its execution receipt persists only the output
schema, byte count, and domain-separated digest and thereby correlates to the
Devgraph receipt ID without copying raw Work content. If required Devgraph or
secS receipt persistence fails, no successful execution response exists.

## Fail-closed matrix

Every case below rejects before Devgraph mutation and successful receipt:

- missing, malformed, unknown-field, duplicate-field, unsigned, wrong-suite,
  wrong-key, invalid-signature, untrusted-key, revoked-key, expired-key, or
  not-yet-valid-key projection;
- wrong schema/version, audience, operation, resource, kind, actor, receiver
  policy, replay scope, request digest, idempotency digest, session, or nonce;
- future issued-at, zero/inverted/overlong validity, `now >= expires_at`, or
  clock failure;
- any canonicalized integer outside its P4-O-DG-R1 safe-integer domain;
- missing Wallet possession proof or actor not authorized by receiver policy;
- malformed/oversized create request, unknown fields, invalid identifier,
  empty title, invalid priority, or invalid reference identifiers;
- caller-selected scope, handler, opcode, route, URL, path, method, header,
  redirect, proxy, database operation, Work kind, or mutation;
- reuse of one idempotency key outside the exact operation/resource/request
  scope;
- secS replay reservation, Devgraph atomic mutation/receipt, or secS receipt
  persistence failure.

All denials produce bounded redaction-safe reasons. They do not echo raw
credentials, signatures, idempotency keys, request content, policy material,
headers, or storage details.

## Explicit non-ratifications and stop conditions

- No generic Work API or machine-operation multiplexer is ratified.
- No read, list, update, patch, transition, archive, relationship, blocker,
  proposal accept/convert, export, admin, tool, or skill operation is ratified.
- No arbitrary route, URL, path, method, header, handler, opcode, database
  query, or storage access is ratified.
- No reusable bearer token, OAuth flow, trusted-localhost exception,
  `LocalDevVerifier` production path, direct Neo4j access, or auth bypass is
  ratified.
- `.castaway` grants no identity or authority and cannot sign this operation.
- No ML-DSA-65, hybrid/PQ authorization, Dregg finality, public auditability,
  cloud deployment, or production-readiness claim is made.
- DG-P implements a fixed producer module, narrow production Ed25519
  signer/verifier seam, and dedicated replay ledger only. No API route, CLI
  command, Wallet method, manifest descriptor, handler, Devgraph consumer,
  receipt schema, transport, or deployment is implemented by DG-P. The later
  DG-E1 adapter invokes only this exact producer from owner-private files; it
  does not change the DG-P library boundary or add a route/handler/Work mutation.

Stop and return to contract review if implementation needs a generic operation,
accepts caller-selected receiver controls, treats secS verification as Work
success, bypasses Devgraph's canonical service/outbox, weakens exact digest or
expiry bindings, treats `.castaway` as authority, or adds PQ claims to v1.
