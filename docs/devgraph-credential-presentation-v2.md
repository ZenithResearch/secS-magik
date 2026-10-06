# Credential-bound Devgraph authority v2

Status: implemented review candidate. This is an additive, explicitly configured
file adapter, not an installed service or production qualification. The existing
Work/Arena v1 request canonical bytes, v1 projection decoder, v1 replay records,
Packet v0 and operation policy remain intact.

## Ownership and consent

Devgraph constructs Work/Arena requests, disclosures and execution transport.
Wallet verifies the generic attached credential and approves every use, without
operation lists, route admission or Devgraph adapters. secS issues an attestation
under its current receiver-held Work policy and verifies the resulting holder
presentation before producing a v2 authority projection. The receiver must
independently rederive request bindings and check current policy and resource
versions under its mutation lock. A credential, membership proof or read bearer
alone never permits a mutation.

The preflight credential does not reserve a mutation or replay entry. Its maximum
lifetime is 120 seconds, shortened by grants or approaching deny rules. The holder
presentation has a fresh nonce after consent and lasts at most 60 seconds, never
past the credential. Unknown callers, schemas, signatures and changed policy
bindings fail closed. No Dregg token or capability support is claimed.

The typed request adapter now admits the three `workflow.*` operations in Work v1,
and canonical Work v2 operations including `progress.set`, independent `restore`,
and `proposal.reject`. All six Todo types are covered; base Todo deliberately has
no subtype workflow. `status` remains v1-only, and v1 never acquires v2 progress
semantics. Unsupported kind/operation pairs fail before credential issuance.
Decision, ReviewPacket, Handoff and ExternalLink references participate in the
complete resource inventory. Parentage matches the canonical public contract.

This adds parser support, not grants. Existing grants and renewal scopes remain
unchanged: an exact v1 operation never authorizes its v2 name. Adding workflow or
progress authority requires an explicit reviewed policy selection. Devgraph still
owns stage legality, completion evidence, proposal disposition, versions and atomic
mutation/receipt checks; secS cannot infer those from a signature.

## Generic contract and application bindings

`castalia.request-credential.v1` claims bind issuer/key, holder public key,
audience, browser-origin or terminal-caller identity, request/disclosure/policy
digests, issuer nonce and validity. Its fixed signature domain is
`castalia.request-credential.v1/signature\0`.

`castalia.credential-presentation.v2` binds those values, the digest of the entire
signed credential, and a fresh holder nonce and validity. Its fixed signature
domain is `castalia.credential-presentation.v2/signature\0`. Generic keys,
signatures and digests use lowercase hexadecimal. `request_bytes_base64` uses
standard padded base64. Canonical JSON uses sorted keys, compact UTF-8 and safe
integers; duplicate keys, unknown fields and malformed encodings are rejected.

The opaque request bytes are `devgraph.credential-request.v2\0` followed by
canonical JSON with exactly `schema`, `request` and
`idempotency_key_digest_sha256`. `request` is the existing typed canonical
Work/Arena value. The projection retains its request-schema-specific digest
(v1 or v2) separately from this wrapper's digest. The legacy idempotency hash is
preserved.

The deterministic disclosure title is `Devgraph request`. The first four
statements describe the operation, sorted resources, expected version (`new`
when null), and idempotency digest. Following statements contain the complete
canonical request in scalar-safe chunks of at most 480 UTF-8 bytes, prefixed
`Request part N: `. At most 140 chunks are allowed. No request is truncated.
Control and bidirectional formatting characters in rendered statements are
rejected. Generic limits are 131072 request bytes, 262144 envelope bytes and 144
statements of 512 UTF-8 bytes each.

The projection is `secs-devgraph-work-authority.v2`, version 2, signed under
`secs-devgraph-work-authority.v2/signature\0`. It replaces the v1 Wallet digest
field with `credential_presentation_digest_sha256` and adds
`credential_request_digest_sha256`, `credential_digest_sha256` and
`disclosure_digest_sha256`. It keeps independently derived actor, operation,
resources, idempotency and current policy bindings. Authority signatures retain
the existing base64url transport. `session_id` is the full issuer nonce and
`nonce` is the full holder nonce, each 32 lowercase hex characters. The replay
scope is `credential:operation:nonce`.

## Explicit local adapter

The new binary is `secs-devgraph-work-v2`. It reads the existing owner-private
`authority/devgraph.work.v1` generation and additionally requires the separate
owner-private `authority/credential-presentation-v2.json` file:

```json
{
  "schema": "secs-devgraph-credential-config.v2",
  "schema_version": 2,
  "issuer": "secs://devgraph-work",
  "callers": [{"kind": "terminal", "id": "devgraph-review"}]
}
```

This example is not installed automatically. Operators must explicitly configure
and pin the matching issuer, audience, key and allowed callers in Wallet and
Devgraph. A web request cannot choose its own trust configuration. The separate
config survives v1 policy-generation renewal; a changed policy still invalidates
old credentials. No authority root, key path or endpoint selector is accepted by
the CLI. No live configuration or real grant is created by this change.

```text
secs-devgraph-work-v2 issue-credential \
  --request-file /absolute/private/preflight.json \
  --idempotency-key-file /absolute/private/idempotency.txt \
  --presentation-request-output /absolute/private/new-wallet-request.json

secs-devgraph-work-v2 authorize \
  --request-file /absolute/private/approved-request.json \
  --idempotency-key-file /absolute/private/idempotency.txt \
  --signed-projection-output /absolute/private/new-projection.json
```

Preflight input has exactly `schema: secs-devgraph-credential-input.v2`,
`schema_version: 2`, `request`, `holder_public_key` and `caller`. Authorization
input has exactly `schema: secs-devgraph-work-producer-input.v2`,
`schema_version: 2`, `request`, `credential`, `disclosure` and `presentation`.
Files use the existing owner-private, bounded, symlink/hardlink/ACL checked
helpers. Outputs are create-only and cannot enter the authority data root.

V2 adds `devgraph_authority_v2_replay` to the existing SQLite database only when
used. Full nonces and exact signed projection bytes are retained; identical
retries return the same projection while changed bindings conflict. V1 tables
and rows are not reinterpreted. After a lost response, reconcile using the same
request and operation before any new mutation. Projection success is not graph
mutation success.

Operator recovery requires the existing authority snapshot **and** a separately
preserved private v2 caller configuration. SQLite snapshots include the additive
v2 table. Restoring expired authority is not renewal. No backup command silently
activates v2.

## Evidence and remaining gates

Synthetic fixed-key fixtures cover every existing Work/Arena request, exact
signature reproduction, policy changes, caller denial, expiry, altered bindings,
and duplicate/conflicting replay. The fixture seeds are public test inputs,
never deployment identities. `server/tests/fixtures/credential-v2/` records the
cross-language bundle and provenance. The original 23 vectors are unchanged;
`progress-signed-vectors.json` adds 48 workflow/Todo vectors consumed independently
by Devgraph's Python receiver and Rust native SDK. Request corpora come from public
Devgraph commit `3454db330ec4a1b42352367652b2a0ceb5a066c4`; the parser is independently
implemented here, with no public Devgraph source dependency.

Run locked workspace tests/build, the focused v1/v2 tests and documentation
assembly before review. A passing source test does not establish loaded-Chrome
consent, the interactive terminal ceremony, real issuer configuration or an
installed native host. Those require the coordinated Wallet/Devgraph candidate
and separate isolated acceptance. The legacy path remains available during
migration; there is no automatic fallback from v2 to v1.

Independent Wallet interoperability can be checked without importing its source
fixture into this repository:

```text
SECS_TEST_WALLET_GENERIC_FIXTURE=/absolute/path/to/credential-presentation-v2.json cargo test --locked -p server --test devgraph_work_v2 optional_independent_wallet_fixture
```

The optional test compares both exact signing transcripts and verifies both
signatures. Absence of that environment variable is not interoperability evidence;
record an explicit execution in review evidence.
