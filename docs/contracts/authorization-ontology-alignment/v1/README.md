# Shared authorization vocabulary alignment

Status: **review crosswalk**, not an ontology release, wire contract or authority.

`crosswalk.json` aligns the resource-authorization design with canonical DevGraph
v0.10.0 and the review-only shared domain draft discussed in the ontology
hosting-readiness review. The same bytes are consumed by the Zenith site
`src/content/authorization-ontology-alignment.json`. Source revisions and draft
digests are embedded; no application records or machine configuration are copied.

Use domain modules; treat applications as implementations/contributors. Reuse
canonical Work/Seat/preset terms. Keep ResourceInstance (capacity resources),
ScopeRef (namespace), directory identity, membership and authority separate.
A ServiceInstance is a deployment, not a canonical service identity. Canonical
CONTAINS maps to runtime HAS_CHILD; CONTAINS_WORK remains Arena membership.

Missing authorization vocabulary is marked candidate rather than silently
adding classes or OWL equivalence. secS owns verification and signed grant
semantics; Wallet Core owns holder storage/derivation and signing boundaries;
provider adapters resolve actual objects, placement and mutation effects. An
ontology record, schema validation or website display grants no permission.

The exact-selector and compound-operation proposals remain unchanged: stable
object references, explicit descendant guards, and transactional paired
source/destination checks. Current signatures and fixed-ID grants are preserved.

To promote this review: agree domain ownership and term definitions, publish a
versioned canonical vocabulary, then separately coordinate runtime contracts and
consumer compatibility. Do not modify immutable DevGraph releases or the shared
draft manifest in place. Website deployment is separate from this source review.
