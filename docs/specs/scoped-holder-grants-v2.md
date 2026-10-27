# Scoped holder grants v2

Status: candidate source integration. No installed application, live policy or
existing grant is migrated by these changes. V1 remains a supported closed reader.

`scoped_grants` adds `secs.holder-grant.v2`, `secs.holder-credential.v2` and
`secs.holder-presentation.v2`. Each has its own signature domain. Claims retain
issuer/key/canonical-service, holder/installation, validity, revision and bounded
credential lifetime. Onward delegation remains rejected. A v2 permission has
operation, resource, exact-equality constraints and a nonempty list of named
resource roles. Each role contains a `secs.resource-selector.v1` selector.

Deriving a child requires every complete child permission to narrow one complete
parent permission. Operation, resource, role set and constraints stay bound;
selectors may narrow but cannot drop inherited hierarchy guards. Selecting roles
from different parent permissions is never a valid proof of attenuation. Existing
v1 signed bytes are not converted, renamed or interpreted as exact objects.

The installed provider, not a signed client claim, defines the operation effect
contract. Its complete roles/cardinalities/kinds are checked before dispatch.
`provider_snapshot` is a bounded process bridge for provider-owned witnesses; it
is not a credential or a client proof of ancestry. The helper executable exposes
`issue_v2`, `verify_v2`, `check_selector`, and `check_effect` to a trusted provider
process. Passing these helpers alone proves neither current registry status nor
permission to execute a handler.

Wallet Core uses a dual reader inside the existing encrypted store. V1 and v2
records retain their serialized shapes, backup ownership and user consent gates.
Native JSON custody commands and Chrome's existing save/use/present flow dispatch
to the corresponding version. A version mismatch fails; a v2 failure never retries
as v1. Older clients must refuse unsupported v2 metadata.

DevGraph's candidate integration retains original application constraints and
intersects them with the signed selector against current graph state. Policy and
revocation are fenced through result capture. List filtering precedes disclosure;
exact IDs are not path prefixes. Its existing signed Work/Arena write transport
retains native admission and adds one-complete-rule pre/post resource checks under
the mutation transaction and current policy lock. A source is resolved from graph
state. The same original source, destination, affected subtree and chosen rule
are retained for the postcheck; denial rolls back mutation and receipt/audit.

The v2 holder issuance adapter currently issues **read** grants. Work/Arena writes
still use the existing signed presentation/projection path with the new paired
receiver guard. It does not claim that a saved holder grant can mint a Work write
credential or that Transfer has a generic role-specific scope editor. These are
separate remaining integration gates, not a transparent fallback.

Before coordinated rollout: qualify the exact native/WASM builds, compatibility
and encrypted restore, old fixed-ID grants, new resources, hierarchy changes,
source/destination pairing, replay/revocation, and both direct and routed access.
Live code/policy changes and app replacement require separate review.
