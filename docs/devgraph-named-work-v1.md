# Named Devgraph Work authority v1

This branch implements a separate native `secs-devgraph-work-v1` producer for
eleven closed operations: create, patch, status, archive, accept, convert,
parent.set, dependency.add/remove, and blocker.add/remove. The existing Issue
v1 projection, Wallet ceremony, Packet v0, and opcodes remain unchanged. This
producer does not execute Devgraph mutations or enter the generic Packet router.

The input schema is `secs-devgraph-work-producer-input.v1`, version 1, containing
a `devgraph.work-request.v1` request and a
`devgraph.work.wallet-presentation.v1` signed presentation. Request parsing is
independent of Wallet and Devgraph and reproduces the shared canonical vectors.
Every request-derived resource requires a current grant for its exact
`devgraph.work.<operation>.v1` operation. Reparenting binds both parents;
conversion binds the Proposal, destination Issue, and acceptance Decision.

Policy schema `secs-devgraph-work-policy.v1` contains audience, policy_id,
policy_version, rules, schema, and schema_version. Rules contain actor_id,
effect (`allow`/`deny`), status (`active`/`revoked`), not_before/not_after,
operation, resource, and resource_match (`exact`/`prefix`). The actor is the
SHA-256 identity of the Wallet Ed25519 public key. Resources are `Kind/id`;
allowed kinds are the five Work kinds plus Decision provenance. Denies win,
all affected resources need allows, and expiry is capped by grant expiry and
approaching deny rules. Policy files and request/projection JSON have closed
fields, duplicate-key and safe-integer checks, and byte/depth limits.

The projection schema is `secs-devgraph-work-authority.v1`. It uses the separate
signature domain `secs-devgraph-work-authority.v1/signature\0`, exact canonical
request hash, idempotency hash, resources array, verified actor/session/nonce,
receiver policy ID/version/digest, and pinned service verifier identity. Maximum
lifetime is 60 seconds. The projection has no generic scope or bearer authority.
The production registry must trust the service key at issuance time.

```text
secs-devgraph-work-v1 \
  --request-file /absolute/private/producer-input.json \
  --idempotency-key-file /absolute/private/idempotency.txt \
  --signed-projection-output /absolute/private/new-projection.json
```

The fixed bundle is beneath the account home returned by the OS:
`Library/Application Support/Zenith/secS/authority/devgraph.work.v1/`.
It contains receiver-policy.json, secs-public-key-registry.json, verifier.key,
replay.sqlite3, and producer-manifest.json. The manifest schema is
`secs-devgraph-work-producer-manifest.v1`, version 1, with audience,
receiver_policy_digest_sha256, replay_schema (`secs-devgraph-work-replay.v1`),
secs_public_key_registry_sha256 (raw-file SHA-256), and secs_verifier_key_id.
No data-root, policy, audience, URL, or key selector is accepted on the CLI.

Input, authority, replay, and output files are owner-private and checked through
held descriptors with symlink, ACL, ownership, and mount checks. Output is
create-only, cannot live inside the service data root, and is written only
after replay reservation. Retrying after a lost output must use the same input
and idempotency key with a new output path. The producer rechecks expiry before
publishing. Wallet private signing material is never read by secS.

The existing durable replay table is reused with separate operation names.
Named Work encodes the sorted resource array as canonical JSON in its `resource`
text column; historical Issue v1 entries keep their original string. Neither
Packet serialization nor the replay table's schema changes. A changed binding
for the same session/operation/nonce fails closed; identical retries can reopen
the same private database and produce the same projection.

Devgraph must independently pin the corresponding policy binding and service
public registry. Its HTTP receiver verifies the projection and performs one
canonical transaction with a receipt. secS success proves projection issuance,
not downstream mutation or external event delivery.

Tests cover every shared operation, all-resource grant denials, deny precedence,
expiry capping, replay conflicts, native file roundtrips, output aliases, and
cross-language signed projections. The optional ignored test
`native_wallet_to_secs_workflow` accepts an explicitly built Wallet binary and
synthetic workflow through `DEVGRAPH_TEST_WALLET_BINARY` and
`DEVGRAPH_TEST_WORKFLOW`; its optional public output is selected by
`DEVGRAPH_TEST_NATIVE_WORK_OUTPUT`. These are test-only inputs and do not
exist in the production CLI. Installed acceptance still requires the actual
operator identity and current grants. No production grant is created here.

## Owner-local authority administration

The separate `admin` command is an explicit operator surface. It never loads a
Wallet actor seed, changes Packet/opcode semantics, or executes graph mutations.
The invocation above keeps its original three required file arguments; it cannot
select another authority root, operation family, shell or receiver URL.

```text
secs-devgraph-work-v1 admin status
secs-devgraph-work-v1 admin provision --policy-file /absolute/private/policy.json
secs-devgraph-work-v1 admin provision --policy-file /absolute/private/next-policy.json --expected-policy-digest SHA256
secs-devgraph-work-v1 admin provision --policy-file /absolute/private/next-policy.json --expected-policy-digest SHA256 --rotate-verifier
secs-devgraph-work-v1 admin snapshot --output-directory /absolute/private/empty-directory
secs-devgraph-work-v1 admin verify-snapshot --input-directory /absolute/private/snapshot
```

Provisioning validates the closed existing Work policy and creates its own random
Ed25519 verifier key in secS custody. The key is stored as private hex bytes, never
returned to the caller. Initial creation requires policy version 1 and no prior
bundle. Renewal/rotation require the exact current policy digest, unchanged
policy ID, and exactly the next version. They preserve replay rows and reject
stale plans, version rollback and duplicate application. Rotation generates a new
secS verifier identity; renewal keeps the existing identity. The public verifier
registry ends with the latest policy grant window; renewal is explicit.

A stable owner-private `.devgraph-work.lock` lives in `secS/authority/`, outside
the active generation. Issuance and status acquire a shared lock; provision and
snapshot acquire an exclusive lock. Busy calls fail immediately. Provisioning
stages all five validated files, snapshots the SQLite replay database consistently,
then atomically publishes or exchanges the complete active directory. Exchanged
previous generations remain under private `.work-generation-*` names as recovery
evidence; issuance never selects them. Do not restore an old generation as a way
to renew authority. Devgraph controls receiver activation separately and installs
matching pins last; mismatched producer/receiver generations deny writes. For
revocation, Devgraph removes receiver admission before installing revoked rules,
so queued requests must recheck the current receiver binding after obtaining the
mutation lock. Transactions already authorized before revocation can finish;
revocation does not cancel or drain those transactions. Emergency revocation
requires owner control of receiver storage, never the actor key or saved signer
profile. A missing producer does not prevent removing receiver admission.

Snapshot destinations must already exist, be owner-private and empty, and live
outside the secS root. Native secS copies its own key and public metadata, uses a
SQLite-consistent `VACUUM INTO` snapshot, verifies database integrity and required
replay schema, and returns bounded public metadata. `verify-snapshot` checks the
same files and key/public agreement without activating authority. Expired/revoked
snapshots remain valid recovery material: `current_authority_valid=false` prohibits
a current authority claim, but does not prevent preserving identity and history.
Both commands return `secs-devgraph-work-admin.v1` JSON with policy/key/registry
bindings and per-file SHA-256/size metadata. No raw key or SQLite contents appear
in stdout. Copies retain raw private-file custody; they are not encrypted vaults.

The native private-file validator also permits a narrowly proven macOS mounted
root owned by root:wheel with mode 0775 when the calling user is outside wheel,
filesystem ownership is enforced, and the held directory matches the actual mount
root. Every private destination leaf and key file still requires current-user
ownership and private permissions. Ordinary group-writable ancestors remain
rejected.

Source tests cover native provisioning, shared/exclusive lock conflict, malformed
and mismatched key state, stale renewal, replay-preserving rotation, private
snapshot verification including expired authority, and create-only outputs. A
successful operator deployment and actual-identity Work acceptance require
separate Devgraph evidence; source tests do not establish those outcomes.


## Arena request extension

Implemented source: the fixed native named-operation binary also accepts the
closed `devgraph.arena-request.v1` schema. Arena is a separate type; its
`create`, `patch`, and `archive` operations name an Arena subject, and
`member.set` names an Initiative or Task subject. Exact Arena references carry
`kind`, `id`, and `expected_version`. Every affected Arena and Work resource is
included in the signed inventory. Old Work requests retain their bytes and
`devgraph.work-request.v1\0` digest domain; Arena requests use
`devgraph.arena-request.v1\0`. Presentation/projection signature domains remain
unchanged because operation and request digest bind the new domain explicitly.

Work `parent.set` may include `previous_arena` when an assigned standalone Task
receives a parent. That Arena is an additional required permission resource.
The Devgraph receiver performs the atomic edge removal and version checks;
the native signer/verifier does not inspect or write the graph. Arena operations
require explicit `devgraph.arena.*.v1` rules. Existing Work rules confer no Arena
operation permission. Membership itself conveys no permission or Work status.

Positive and negative vectors live under `tests/fixtures/arena-v1` beside the
native request parser tests. Native signing, all-resource policy denial, replay,
and cross-language proof tests cover the extension. Live Gallery activation
requires compatible Devgraph runtime/migration and explicit local grant setup;
source tests do not establish deployment. The canonical runtime contract is
https://github.com/ZenithResearch/devgraph/blob/main/ontology/arena-runtime.md.
