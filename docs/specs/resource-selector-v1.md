# Resource selector primitive v1

Status: **implemented additive Rust library**, not a signed grant migration or
installed provider/editor capability. Authorized continuation of the resource
selection roundtable and domain-vocabulary alignment.

Implementation: `crates/secs-grant-contract/src/resource_selector.rs`. Wallet
Core consumes the same pinned source and exposes public selection review and
structural narrowing, with no custody operation or new signing API. The existing
`secs.holder-grant.v1`/credential/presentation formats, Scope::All/Paths,
constraints, fixed-ID grants, backup decoders and Packet v0 are unchanged.

## Closed envelope

The new independent schema name is `secs.resource-selector.v1`. It is unsigned,
not a grant or proof, and **cannot be inserted into existing v1 permissions**.
It carries a canonical service, explicit target kinds and one selection:

- All: current/future objects of those kinds in that verified service.
- Objects: a bounded exact kind/ID set, optionally guarded by a hierarchy.
- Descendants: explicit relation, root references and include-self behavior.

Objects use stable opaque IDs; UUID generation is unnecessary. IDs must never be
recycled. Names, paths, URLs, application profiles and organizational seats do
not establish identity or authority. Root kinds can differ from target kinds.
No prefix-to-object conversion exists. A selector is not an ontology class or a
replacement for the domain definitions in the shared crosswalk.

Limits: 16 kinds, 128 exact references, 16 hierarchy roots, existing 256-byte
printable ASCII identifiers, and the shared 128-KiB duplicate-key-rejecting JSON
parser. Empty/duplicate sets, unknown schemas/modes/fields and foreign services
fail closed. The new All form explicitly rejects unsupported extra fields.

## Narrowing without trusting a client's graph

Validate both selectors first. Canonical service stays equal and target kinds
can only narrow. All may narrow to any supported selection. An exact set may
only narrow its references and add a hierarchy restriction. A hierarchy-derived
exact set must retain the parent's guard: same relation, same/subset explicit
anchors, no include-self expansion. Descendant anchors may only be selected
from the parent's explicit roots; an offline client cannot prove that a new
anchor lies inside them. Unsupported implications are rejected conservatively.

The same rule applies to Objects-within-guard. This prevents selecting a Task
inside Project A and then dropping the Project A condition as the Task moves.
Structural narrowing alone proves no current ancestry or active grant status.
Operation, constraints, holder, lifetime and delegation rules remain separate
and must not be widened when a future signed integration uses this primitive.

## Authoritative evaluation and compound effects

`ResourceSnapshot` is implemented only by a provider-owned consistent snapshot.
The expected service comes from verified provider context. The evaluator checks
existence, selected kind/ID, installed relation support and current strict
descendancy. Missing/deleted resources do not match. Unsupported relations and
resolver errors (cycles/ambiguity/staleness) return an error; never convert errors
into an allow result. A caller-supplied graph cannot satisfy this trust boundary.

This resource-only gate is not a complete authorization decision. Providers must
check verified grants/current policy, operation/conditions, revocation and replay.
For moves, subject/actual-source/destination/descendant effects must be checked
as one paired rule within the transaction, including postconditions. Independent
checks in this library do not create a move capability. Those compound-operation
contracts and provider execution adapters remain the next implementation slice.

## Compatibility and rollout

No existing record is rewritten, and no app or production service is changed.
New Rust public APIs do not imply browser/native feature negotiation. A separately
versioned permission/grant integration, provider adapter and generic editor must
be coordinated before these selectors become issuable credentials. Older readers
continue rejecting unsupported modes rather than interpreting them as Paths.
Onward delegation remains disabled.

Tests cover Work and unrelated media identifiers, hierarchy guard preservation
after moves, foreign service/type rejection, future instances, bounds/closed
JSON, unsupported relations, conservative narrowing and an exhaustive small-model
subset check. Shared media vectors are in
`crates/secs-grant-contract/tests/fixtures/resource-selectors.json`.

Vocabulary/source review: [domain crosswalk](../contracts/authorization-ontology-alignment/v1/README.md).
