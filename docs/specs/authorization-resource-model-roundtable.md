# Authorization resource model and service onboarding roundtable

Status: **design recommendation and implementation plan**. This review changes
no deployed UI, grant, owner policy, signer, signed envelope or runtime adapter.
The signed current/future Arena implementation remains the compatibility input.
Three independent reviews considered authorization semantics, scope UX and the
second-service onboarding boundary. All recommended the same primary choices.

## Decision: Selected / All

Use the provider's resource labels: **Selected Arenas** and **All Arenas**.
“All Arenas” selects the live collection in the named canonical service and
includes subsequently created matching Arena instances. Helper text says
“Includes Arenas added later.” The final approval review retains that meaning.
Do not put the entire temporal explanation in the option name.

Inside Selected, offer **Select all currently listed** where a complete,
authorized enumeration and the fixed-selection capacity permit it. This creates
an explicit fixed set. It is a convenience action, not a third fundamental
scope mode. If a catalog is paginated or filtered, say **Select these N** rather
than implying the whole graph has been enumerated. Never treat an empty selection
as All. Disable the bulk action if it cannot fit a supported contract.

Existing fixed-ID grants display **Selected Arenas · N**, including grants whose
IDs happen to equal every Arena currently present. They must not be reclassified
as All, widened, re-signed or rewritten. For a user who needs an issuance-time
snapshot, Selected already supplies that behavior; a third top-level radio would
obscure rather than clarify its fixed-set semantics.

“All” applies to resource instances within the explicit permission. It does not
mean all services, all resource types, all operations, all related objects or
administration. New operations/types and changed operation semantics never join
an old grant through a label, wildcard preset or ontology update.

## What the code provides, and what it does not

- Generic secS signed permissions already carry operation, resource, All/Paths
  scope and opaque constraints. Derivation must match one parent rule; it cannot
  union read-A/write-B into read/write-A/B. Wallet Core stores, backs up and
  derives these records without Arena-specific signer cases.
- DevGraph's v8 member draft has explicit dynamic Arena coverage; v6 fixed-ID
  grants stay fixed. The adapter compiles both to the existing generic envelopes.
  The opaque constraints still apply: an old permission with Scope::All and a
  fixed arena_ids condition is not the dynamic All Arenas selection.
- Transfer still renders and compiles DevGraph-specific controls and versions.
  The authorization profile, shared provider SDK and generated editor are planned
  contracts, not installed generic service onboarding.
- The fixture schema/validator checks vocabulary, references and supported
  constraint-profile IDs. It does not verify a running receiver, handler,
  signature, ancestry, revocation or replay behavior.

This work should extract the missing shared layers, not add another signing
protocol or force every provider to inherit the DevGraph Work hierarchy.

## Authorization metamodel

| Concept | Identity and purpose | Examples |
|---|---|---|
| Provider authority | Trusted issuer/key lifecycle | A provider's registered signing authority |
| Canonical service | Stable authority namespace across access points | One DevGraph; one media-library instance |
| Access point | A verified route to that service, never separate grant authority | Local secS RPC, HTTPS, Tailnet |
| Resource type | Namespaced type with immutable authorization semantics | devgraph:Arena, devgraph:Project, media:Project, media:Asset |
| Resource instance | Canonical service + type + immutable ID | A particular Arena, asset or render job |
| Resource relation | Named provider-authoritative relation | contains-work, collection-membership, job-input |
| Operation | Stable versioned action and defined resource effects | Read Arena, move asset, start render job |
| Resource selector | Exact objects, live type collection, or supported descendants | Selected IDs; All Assets; assets below a collection |
| Permission rule | Operation(s) paired with selector and restrictions | Read in A; rename in B |
| Grant / credential / presentation | Provider approval / bounded holder use / exact-call proof | Existing secS and Wallet Core contracts |
| Preset / Seat association | Editable configuration recipe / organizational classification | Viewer, Project Manager; neither creates authority alone |

The small common ontology describes these concepts and their relationships.
Each service maps its domain ontology into it. The domain ontology and the
resource containment graph are separate: an Asset being conceptually a Resource,
or two products both having a Project, does not establish access inheritance.
Cross-service type links support discovery and presentation only unless a future
explicit authorization contract says otherwise.

DevGraph may describe Arena containment and Work parent/child relationships.
A media service may describe Project -> Collection -> Asset, alongside RenderJob
-> input Asset relations. A flat key/value service can have no containment at all.
The reusable editor must not fabricate Arena or Project containers for it.

## Scope and operation semantics the mapping must declare

1. **Exact versus descendants.** An exact resource selector includes only the
   named instance; a descendant selector explicitly declares its relation,
   included target types, whether the anchor itself matches, and relocation
   behavior. A path prefix is not an exact record even if it is a leaf today.
   Generic secS Paths currently has 16 roots and 32 nodes/root. Larger exact sets
   require a reviewed bounded representation, not an unlimited UI promise.
2. **Authoritative hierarchy.** The receiver resolves containment; the caller
   cannot assert it. Current DevGraph ambiguity checks remain closed. A general
   DAG needs a declared multiple-parent rule, cycle/depth limits and an installed
   evaluator; v1 tree/prefix support must reject unsupported relations.
3. **Container metadata versus contents.** Viewing Arena/Collection metadata
   does not imply reading its Work/Assets. The target type and selected actions
   make this distinction; do not create an Arena-specific special grant.
4. **Creation.** Authorize the operation on its destination collection/service,
   with the new type and requested fields constrained by the handler. A child
   need not already exist or have an ID. This is a planned reusable adapter
   capability; do not relabel DevGraph's current hierarchy-creation limitation
   as implemented. Reading All never confers Create.
5. **Several affected resources.** A move checks the source and destination;
   a render-job submission checks its project/destination, each input asset and
   the execution operation. Resolve all required targets authoritatively and
   recheck them inside the mutation boundary. A single target label is not proof
   that a multi-object operation is authorized.
6. **Bounded extensibility.** Pin semantic versions and the approved profile
   digest. UI grouping such as Read/Change/Execute/Administration is descriptive;
   the exact operation IDs establish authority. Unknown selectors, conditions,
   effects or resolver contracts prevent approval and execution. Onward
   delegation remains disabled.

Any selector/effect additions belong in a new proposal revision with explicit
consumer support, not silently appended to the closed v1 descriptor or signed
claims. Existing fixed-ID and path grants continue through their old adapter.

## Generic editor experience

Keep the service and recipient above an editor of independent rules. Each rule
chooses target types, scope (Selected / All), optional supported descendants,
operations, restrictions and duration. The resource types and action groups
come from the profile. Changing a preset fills a draft; it never changes a grant.

Example DevGraph rules:

- Arena records -> All Arenas -> List, View.
- Work types Initiative/Project/Issue/Task -> within Zenith Arena, including
  descendants -> List, View.
- Tasks -> within one Project -> Edit, Change progress.

Example media-service rules, rendered by the same editor:

- Collection records -> Selected Collections: Client A -> View.
- Assets -> below Client A's collections -> List, View.
- Assets -> below Editing collection -> Rename.
- Render jobs -> below one Project -> View, Cancel.

Read and write rules retain their own scopes. Selection is a positive allow set;
no unchecked child may masquerade as an exclusion under a selected ancestor.
Exclude/deny semantics require a separately supported evaluator and review.

## What belongs in a small mapping file

A portable profile supplies namespaced type IDs; singular/plural labels;
supported scope/relationship semantics; stable operation IDs and labels; target
applicability and affected-resource resolver contracts; constraint profiles;
display groups; optional presets; semantic versions and a digest.

A separate, reviewed **installed receiver binding** supplies operation-to-handler
and resolver IDs, transaction boundaries, current grant/revision/revocation
checks, idempotency and atomic replay consumption. The public profile cannot
supply executable code, install handlers, trust an issuer, or authorize itself.

An existing framework plugin may supply these bindings for a supported framework.
A Cedar adapter or OpenFGA relationship resolver would be an installed integration,
not a claim that a common JSON description is equivalent to either engine's full
policy language. The useful common request vocabulary is principal, action,
resource and context; relationship semantics remain explicitly modeled.

Primary references checked during the review:

- [Cedar authorization request](https://docs.cedarpolicy.com/auth/authorization.html)
  describes principal/action/resource/context.
- [Cedar schema and namespaces](https://docs.cedarpolicy.com/schema/schema.html)
  separates resource types, action applicability and schema validation.
- [OpenFGA parent-child modeling](https://openfga.dev/docs/modeling/parent-child)
  requires the relation and its permission propagation to be defined; containment
  alone does not confer access.

These references inform the vocabulary. They do not establish interoperability,
certification, procurement eligibility or compatibility already implemented here.

## Twenty-minute benchmark and delivery gate

The target is **configure a service in 20 minutes once the standard receiver SDK
or framework adapter is installed and its handlers are already implemented**.
Securing an arbitrary unintegrated application by dropping in JSON is not a
credible claim. Shared infrastructure needs to make the fast path real first.

The `media-library.example.json` fixture supplies five types and 20 operations,
including creation, moves and job execution. Its Project label overlaps with
DevGraph while its Collection/Asset/RenderJob vocabulary does not. The current
v1 descriptor can validate its vocabulary, but cannot yet encode all semantics
above. It is deliberately a design stress fixture, not a passing runtime demo.

The timed trial starts with a trusted, running service, an admitted owner and the
shared SDK. Suggested budget: 3 minutes identify types/relations; 5 minutes map
20 existing operations to installed bindings; 4 minutes validate the profile and
catalog; 4 minutes run the prebuilt conformance checks; 4 minutes use Transfer to
review/issue a narrowly scoped test grant and prove both permitted and denied
calls. Record actual time; a written estimate does not pass the benchmark.

Release gates:

1. One shared profile loader, selection compiler/editor and provider lifecycle
   SDK serve DevGraph and the real second service. No new Core service cases,
   copied credential screens or service-specific branches in the generic editor.
2. The second service is configured by its mapping/binding and adapter tests;
   it uses the same owner/request/review/approve/status/revoke/recover lifecycle.
3. All includes later matching instances; fixed Selected stays fixed. New types,
   operations and relaxed conditions never widen old grants.
4. Read-A/write-B, movement out of scope, destination-scoped creation, multi-target
   effects and ambiguous/unsupported relations pass positive and negative tests.
5. Wrong service/issuer, profile drift, replay across access points, expiration,
   revocation, lock/relaunch recovery and onward delegation fail closed.
6. Existing DevGraph stored/signed fixtures, fixed grants, backups and credential
   derivation keep their exact compatibility; installed qualification follows.

Implement in order: refine the versioned profile and selectors; extract the
provider lifecycle SDK; render the profile-driven editor; migrate DevGraph via
its compatibility adapter; then run the real timed second-service trial. The
existing generic signing model is retained throughout.
