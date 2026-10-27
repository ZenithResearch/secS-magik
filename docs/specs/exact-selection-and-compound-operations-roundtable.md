# Exact selection and compound-operation roundtable

Status: **options and recommended direction**, not an implemented v2 contract.
This review changes no runtime, signed scope, existing grant or application UI.
Three independent reviews examined selectors/attenuation, mutation enforcement
and the administrator experience.

## Separate identity, placement and authorization

A resource identity is `(canonical service, namespaced kind, immutable ID)`.
UUIDs are a useful ID encoding, not a scope rule. Existing stable provider IDs
remain valid; there is no reason to rename existing DevGraph objects or grants.
The same ID in another service or kind is a different object. IDs must not be
reused for a newly created replacement object after deletion.

An object's current path describes placement. A permission can deliberately
follow its identity through a rename/move, follow a live hierarchy instead, or
require both the exact identity and continued membership in that hierarchy.
Names and breadcrumbs help the user select objects, but do not establish identity
or authority. Moving an object never changes the identity tuple by itself.

Current DevGraph already has exact Work/Arena ID selectors. Generic secS v1 has
only All and Paths; Paths compares node-vector prefixes, not exact equality.
Even a path ending in a UUID may later have children. The missing piece is a
portable selector algebra, not UUID generation.

## Alternatives

| Option | Benefit | Limitation / decision |
|---|---|---|
| Infer exactness from a current leaf/full path | No new field | Reject: future children and relocation make it ambiguous; changes old signed meaning. |
| Versioned Paths with explicit self/subtree match | Small conceptual extension; clear per-root intent | Viable when permission should be tied to placement. A full path still changes on relocation. Cannot add the field to closed v1 bytes. |
| Provider-owned exact-ID constraints | Existing compatibility route, including DevGraph's exact selectors | Retain as a bridge. Current generic derivation requires opaque constraints to be equal, so changing the ID array is not a generic attenuation operation. |
| Versioned Objects plus explicit Descendants | Identity and containment are separate; works for flat providers and hierarchies | Recommended shared direction; requires coordinated secS/Core/provider/client decoder and narrowing rules. |

A node reference can remain `{kind, id}`. Service binding already exists in the
signed grant; avoid duplicating a second unverified service identity inside every
selector. If imported references contain a service field, it must match the
verified grant/service binding. URLs stay outside resource identity.

## Recommended selector vocabulary

- **Objects:** a bounded exact set; no descendants. Exact(A, B) can narrow to
  Exact(A). An exact instance never becomes All or a descendant scope.
- **Descendants:** selected anchors, a supported named relation, allowed target
  kinds, and explicit include-self behavior. Membership is resolved from current
  provider state, with defined ambiguity/cycle/depth behavior.
- **All:** matching instances of explicitly authorized kinds in this service.
  Later instances match; new kinds, operations or relaxed conditions do not.
- **Guarded Objects:** an exact set intersected with the parent's existing
  hierarchy boundary. This is required when a hierarchy grant narrows to objects.
  It is a bounded typed form, not an arbitrary user expression language.

Conceptual future selector, not a supported current wire value:

```json
{
  "mode": "objects",
  "refs": [{"kind": "devgraph:Task", "id": "task-123"}],
  "within": {
    "relation": "devgraph:work-containment.v1",
    "roots": [{"kind": "devgraph:Project", "id": "project-a"}]
  }
}
```

The example means “this Task, while inside Project A.” Omitting the within guard
would mean “this Task wherever it goes,” which the parent grant might not allow.
The relation/resolver must be installed and supported; a descriptor cannot add
new execution semantics.

### Do not launder a hierarchy restriction during narrowing

A Wallet cannot prove current ancestry from an ID alone. Therefore it must not
turn Descendants(Project A) into an unguarded Objects(Task X) just because X was
inside A at issuance. Retain the ancestor guard and recheck it on each call, or
reject that derivation until a shared verifier can establish the subset.

All-to-Objects narrowing is valid only with the same service/type, operation,
validity and unchanged restrictions. Generic constraints currently attenuate by
exact equality. Any new typed narrowing must be implemented and tested in secS
and Wallet Core together; the client cannot assert that a new condition is safer.
Keep unknown v2 selectors closed for older readers and retain all v1 signed bytes,
backups and prefix interpretation.

## Exact IDs do not eliminate compound authorization

Moving an object can change its source membership, destination membership,
inherited visibility, ownership or quota. Knowing exactly which object is moving
does not authorize those effects. An installed operation contract should resolve
all affected targets and evaluate the complete plan.

| Named target/effect | Example required permission |
|---|---|
| Subject object | Relocate this Task/Asset |
| Actual source container | Detach this member |
| Requested destination | Attach this member |
| Additional declared effects | Ownership, descendants, ACL or quota changes where applicable |

Detach is not general delete permission; attach is not unrestricted create.
The user sees one **Move** operation, with **From** and **To** scope rows.
Permission names and effect requirements remain provider-defined, versioned and
explicit; these are proposed generic roles, not new active DevGraph operations.

Prefer a complete paired rule, such as **Move Tasks from Project A into Project
B**. Two rules A-to-B and C-to-D must not create A-to-D by unioning their source
and destination sets. Nor should independent write access in A and B silently
become cross-boundary transfer authority. Keep current conservative before/after
semantics; a future explicit transfer capability can authorize selected pairs.

### Receiver plan, not several client approval requests

1. Bind the signed command to subject, requested destination, expected versions
   and original idempotency key. The receiver resolves the actual source and all
   required related resources; supplied ancestry/source claims are not trusted.
2. Load current authority and a consistent resource snapshot. Validate operation,
   exact/descendant selectors, all named target roles and permitted move pair.
3. Under the mutation boundary, recheck relevant object/container versions,
   membership and authorization. Mutate atomically, then enforce declared
   postconditions before committing receipt/audit state.
4. A stale source/destination, denied effect, ambiguous hierarchy or changed
   policy causes no partial move. Unknown results recover the original command
   with its original idempotency key; never send another move with a fresh key.

These checks can run in one server-side batch and transaction; they need not add
network round trips or multiple Wallet password prompts. Optimize by reusing
resolved ancestry within that transaction, not by omitting required checks or
caching an allow decision indefinitely. A separate authorization service is not
made transactionally consistent merely by batching calls: it needs an explicit
revision/fencing/consistency contract with the mutation boundary. Cross-service
moves require their own coordination protocol and are outside this local design.

## What DevGraph already does

The reviewed named Work request inventory includes child and old/new parent IDs.
The mutation validates the actual previous parent and versions. ResourceScopeGuard
selects pre-state candidate grants per affected resource; ScopedMutation requires
that one of those same candidates also covers that resource afterward. Thus an
A-only grant and a separate B-only grant cannot launder a move out of A.

The named mutation adapter repeats verification inside the storage transaction,
checks before mutation, and rolls back on a failed postcheck. Neo4j's named
mutation boundary uses a guard lock. Current tests cover reparenting, membership
moves, paths, rollback and current-policy checks. This is evidence for those
examined paths, not a full audit of every operation, descendant side effect or
externally executed job.

Implementation references:

- DevGraph `src/devgraph/work_requests.py`, `src/devgraph/named_work.py`.
- DevGraph `src/devgraph/auth/write_scope.py`, `src/devgraph/auth/secs_work.py`.
- DevGraph `tests/auth/test_write_scope.py`, `tests/auth/test_resource_paths.py`.
- secS `crates/secs-grant-contract/src/lib.rs`, Scope/permissions_within.
- Transfer `Sources/ZenithTransfer/NativeGrantSelection.swift`, exactResources.

The reusable mapping should name installed operation/resolver versions, target
roles and cardinality, permitted kinds, compound permission requirements and
pre/post effects. Its current read/write/admin effect label is only a display
classification; it is not a complete effect-plan contract.

## Qualification before implementation rollout

- Exact ID never includes later children; a UUID-shaped path remains a prefix.
- Rename keeps identity; relocation changes only explicitly hierarchy-bound scope.
- Same ID in another service/type and deleted/reused identities are denied.
- Hierarchy-derived exact credentials retain their ancestry guard after a move.
- Source-only, destination-only, forged/omitted source and incorrect pair denied.
- A-to-B plus C-to-D never yields A-to-D; reverse movement is separately decided.
- Concurrent reparenting, stale parent versions, policy/revocation change and
  unsupported relations are rejected under a defined consistency boundary.
- Subtree/ACL/quota effects require declared authorization; partial effects roll
  back, and original-result recovery cannot execute the move twice.
- Existing fixed-ID grants, prefix scopes, signed records and backups remain exact.

Next bounded step: define the new proposal revision and narrowing/effect vectors,
then implement the shared verifier and receiver plan before exposing selectors
in the generic editor. No existing grant needs conversion just to add a new model.

Primary reference: [Cedar compound authorization](https://docs.cedarpolicy.com/bestpractices/bp-compound-auth.html)
explicitly describes source, destination and optional object checks for a move.
It supports the design vocabulary; it is not a claim that Cedar is installed or
that these proposed contracts already interoperate with it.

## Ontology alignment

See the [pinned domain-vocabulary crosswalk](../contracts/authorization-ontology-alignment/v1/README.md). It distinguishes existing canonical terms, related draft concepts and missing candidates without changing signed semantics.
