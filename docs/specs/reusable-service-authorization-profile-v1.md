# Reusable service authorization profile

Status: **proposed implementation contract**, not a deployed feature. This
specification adds no authority and changes no existing signed bytes. The
examples and descriptor schema are review fixtures. Runtime implementation and
consumer migration are the next bounded issue, not something these files enable.

## Outcome

Connecting another service should mean supplying a description of its permissions
and resources, implementing a small receiver adapter, and passing the shared
conformance suite. It should not require another Wallet, signer, grant format,
credential database, administration screen or network-specific authority domain.

The first acceptance gate is the same editor and grant machinery configuring
both DevGraph and an unrelated album/asset service. DevGraph-specific code is not
the reusable interface. There must be no `if service == DevGraph` branch in the
shared editor, Wallet storage or signer.

## Existing foundation and actual gap

The implemented `crates/secs-grant-contract/src/lib.rs` already supplies:

- `IssuerPin`: issuer, key ID, public key and canonical service identity;
- provider-signed `secs.holder-grant.v1` permissions with operation, resource,
  scope and constraints;
- `secs.holder-credential.v1` and `secs.holder-presentation.v1`;
- equal-or-narrower same-holder derivation, explicit installation binding,
  finite credentials, and rejection of onward delegation;
- issuer-signed access-point bindings, separate from grant authority.

It deliberately does not establish current grant status, revocation, replay
consumption or graph ancestry. Receivers must enforce those checks. Constraints
currently attenuate by **exact equality**, not arbitrary expression evaluation.

DevGraph still owns a product-specific selection compiler, durable grant/status
integration and catalog. Transfer still parses DevGraph draft versions and
contains Work/Arena UI logic. The missing reusable layer is service onboarding,
administration and selection, not another signing protocol.

## Canonical model and ownership

| Concept | Meaning | Owner |
|---|---|---|
| Wallet identity | Public key with proof of possession | Wallet Core and signer |
| Provider authority | Trusted issuer and key lifecycle | Provider registry |
| Canonical service | Stable authority target across access points | Provider/service registration |
| Access point | Local RPC, HTTPS, LAN, Tailnet or Funnel route | Transport and verified route binding |
| Authorization profile | Versioned operation/resource vocabulary and editor hints | secS contract; supplied by service |
| Resource catalog | Authorized current object names and canonical paths | Service adapter |
| Grant | Provider-approved permission set for a holder | Shared grant service and provider |
| Credential | Finite equal-or-narrower use of that grant | Holder Wallet Core |
| Presentation | Proof bound to the exact call and freshness data | Holder signer; secS verifies |
| Preset | Editable recipe compiled into exact permissions | Administrator/service configuration |
| Seat type | Organizational classification associated with a recipe | Organization ontology; never authority alone |

Authentication proves the caller identity. Authorization determines what that
identity may do. Discovery, a reachable socket, a URL, a Seat association and a
pretty permission label establish neither.

Wallet Core owns custody, signing, grant verification, derivation and encrypted
Wallet backup/storage. The app owns its connections and network configuration.
Transfer renders the shared editor and invokes administration; it does not
become a provider or place application configuration inside the Wallet backup.

## Declarative profile

The proposed closed descriptor is in
`../contracts/service-authorization-profile/v1/descriptor.schema.json`.
DevGraph and album-service fixtures sit beside it. It describes:

1. Stable versioned operation IDs and readable labels/descriptions.
2. Resource types, allowed node kinds and a supported scope selector.
3. Required constraint-profile IDs, interpreted only by installed adapters.
4. Optional permission recipes; recipients, scope and duration are selected
   separately and compiled into the exact review.
5. Supported existing grant/credential/presentation contracts.

The descriptor is reusable across instances. An authenticated instance
registration separately binds its issuer pin, canonical service ID and profile
digest. The public profile cannot introduce a trusted issuer, grant access,
select an executable handler or download code. Private catalogs require the
appropriate authorization; profiles need not reveal actual Arena or album names.

Only built-in supported selectors are rendered. Start with `path_prefix.v1`,
using the existing `Scope::All` / `Scope::Paths` representation. Paths are
prefixes: a currently leaf object may acquire descendants later. Exact record
selection requires an explicitly supported adapter constraint or a separately
versioned selector; it must never be inferred from current leaf status.
Unsupported selectors or constraints are
shown as unsupported and cannot be approved. No arbitrary JavaScript, expression
language, shell command or service-provided native view is part of onboarding.

The shared validator checks unique identifiers, operation/resource references,
recipe references, supported selectors, size limits and constraint profiles;
JSON Schema alone is insufficient for those semantic checks.

## Thin receiver adapter

The proposed shared SDK supplies request/inbox/review/decision/status handling,
the grant registry, revocation/revision checks, idempotency, replay consumption,
recovery and receipt contracts. These are extraction work, not implemented claims.
An adapter supplies only:

- `describe`: the profile and its supported semantic versions;
- `authorize_admin`: the registered owner's or administrator's current authority;
- `catalog` / `resolve`: permitted objects and authoritative current paths;
- `compile_selection`: a deterministic mapping to existing typed permissions;
- `execute_verified`: the exact installed operation handler and its transaction.

The application must not assert its own ancestry. The adapter resolves it from
authoritative state. Moved-out objects lose access on subsequent requests.
Related objects and list results must be filtered through the same verifier.
Mutations recheck authority and resource versions inside their mutation boundary.
Transport middleware cannot authorize a handler by itself.

Existing receiver-local `OperationDescriptor` and opcode governance remain in
force. A profile operation ID maps to a reviewed local descriptor/handler;
metadata never installs that mapping. ZenithPacket v0 is unchanged.

## One configuration and usage flow

1. Discover/select an access point and verify its canonical service binding.
2. Authenticate the Wallet and check the registered owner/admin role.
3. Load a verified profile and authorized resource catalog.
4. Pick a request/recipient, optional preset, permissions, scope and duration.
5. Compile the exact selection; bind the profile digest and compiled permissions
   into the Wallet review, using the existing signed action-details boundary.
6. Approve and issue an ordinary provider-signed grant; record a durable result.
7. The recipient saves that grant in Wallet and derives an equal/narrower finite
   credential. Each call still passes current-status and replay enforcement.

All access points for one provider/service use the same authority and current
grant registry. A shared database alone is not sufficient: replay consumption and
revision checks must be coordinated and atomic at that authority boundary.
Locality does not bypass signatures. LAN, Tailnet and Funnel do not alter grants.

Owner pairing is distinct from issuing a member credential. First-owner pairing
requires an explicit OS-protected setup claim or approval by an existing owner;
being the first remote caller or merely being on the same machine is insufficient.
The owner gets the defined administration role, not a self-credential picker.
Legacy owner-policy conversion is a compatibility migration, not an Arena switch.

An `admin` display classification is not issuer authority. The administration
controller independently checks the registered owner/admin role; an ordinary
member grant must not bootstrap that role or authorize issuing grants to others.
Delegated access administration needs a separate explicitly bounded contract.

## Compatibility and safe boundaries

- Preserve existing v1 signed grant, credential and presentation bytes. They are
  closed contracts; do not append profile fields to their claims in place.
- Pin profiles in instance registration and exact selection reviews. Operation
  IDs retain immutable semantics for existing grants. Semantic changes require
  a new operation/model version and explicit migration or fail-closed refusal.
- Add profile/catalog support before migrating DevGraph consumers. Old grants
  remain readable and verified through their existing adapter until retired.
- Metadata edits never widen an issued credential. Renaming a label does not
  rename an operation; a new resource kind does not enter an explicit member set.
- Keep opaque constraints identical during holder derivation. A future typed
  narrowing algebra requires its own shared verifier and negative vectors.
- Presets and Seat types are configuration, never implicit grants. Updating a
  recipe does not rewrite existing grants.
- Keep onward delegation disabled. Cross-holder delegation is a future distinct
  versioned contract, not a UI flag or an interpretation of attenuation.

## Delivery slices and benchmarks

1. **Contract and fixtures:** agree the profile, adapter ports and compatibility
   rules; validate two unrelated services and rejection cases.
2. **Shared provider SDK:** extract current grant lifecycle and conformance tests
   from the product adapter without changing existing wire contracts.
3. **Shared client/editor:** render profiles and scopes through the same model in
   Transfer, iOS and Chrome; keep signing/verification in Wallet Core/secS.
4. **DevGraph adapter:** migrate Work and Arena together, including old grants,
   owner setup, uncertain decisions, revocation and service aliases.
5. **Second-service gate:** integrate the album/asset fixture through a real
   adapter. Zero new Wallet Core service cases, zero copied credential screens,
   and the same positive/negative test corpus are release requirements.

Track clean-machine onboarding time and the number of service-specific files
changed. Target a service descriptor, a thin adapter and tests; do not promise an
arbitrary service can be secured by dropping in JSON alone. The user benchmark
is select service, authenticate, choose recipient/permissions/resources, review,
approve. Network settings and policy-format migrations must not become repeated
per-resource setup tasks.

Negative gates include wrong service/issuer, unknown operation/constraint,
profile drift, expanded scope, escaped path ancestry, replay across access
points, expired/revoked/superseded grants, duplicate decisions, partial writes,
lock/relaunch recovery and cross-holder delegation. Installed native and remote
qualification remain necessary after source/schema tests pass.

## Independent rule editing compatibility (2026-10-27)

Implemented in the existing `secs-grant-contract` holder verifier: each child
permission must fit one parent permission with the same operation, resource and
exact opaque constraints, and an equal or narrower path scope. Read-A/write-B
must never become read/write-A/B. The independent-action conformance test covers
equal and narrower derivation, both crossed-scope attacks, relaxed conditions
and onward delegation rejection. No signature domain or wire field changes.

Transfer's DevGraph adapter now compiles independently selected rules to the
existing provider draft arrays. DevGraph owns exact Arena IDs, touched-resource
requirements and current hierarchy evaluation. Creation, proposals and provenance
are not implicitly attached to a hierarchy. These adapter semantics do not make
the proposed descriptor a runtime authority source; the generic profile SDK and
a second provider remain planned. Wallet Core retains the same native revision
and verifies stored and derived rules through the same secS contract.


## Live collections and future resources

The existing reusable-grant `Scope::All` denotes a live resource set within one
signed permission and its exact opaque provider constraints, not an issuance-time
inventory. A provider may use that to cover current and future objects of a
collection. Generic secS does not interpret provider-owned collection predicates.
Same-holder `All` → `All` stays equal; `All` → specific path roots narrows; a
fixed/path scope cannot widen to `All`. Opaque constraints remain byte-equivalent,
current assignment and revocation remain receiver checks, and onward delegation
remains disabled. Conformance tests use provider-neutral collection/item names;
DevGraph maps its explicit Arena selector without changing signed v1 envelopes.


## Scope and second-service roundtable

The [scope/resource metamodel review](authorization-resource-model-roundtable.md)
recommends Selected / All as the primary labels, fixed snapshots as selection
conveniences, an explicit distinction between object identity and containment,
and a timed 20-operation second-service benchmark. It records remaining generic
SDK/editor work and does not change deployed authority or signed contracts.

## Ontology alignment

See the [pinned domain-vocabulary crosswalk](../contracts/authorization-ontology-alignment/v1/README.md). It distinguishes existing canonical terms, related draft concepts and missing candidates without changing signed semantics.
