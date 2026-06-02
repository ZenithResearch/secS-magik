# secS-magik ready-for-prod checklist

This is the repo-local control surface for turning secS-magik from the current prototype verifier/RPC substrate into the first production-shaped implementation train.

Source captures:

- Claude Hub capture: `/Users/bananawalnut/claude-hub/capture/2026-06-02-secs-magik-track-a-ready-for-prod-slices.md`
- Parent work surface: `/Users/bananawalnut/claude-hub/capture/2026-06-02-secs-magik-ready-for-prod-work-surface.md`

Status: A0 production definition locked; A1 repo status reconciled; A2 rail taxonomy and non-goals complete; A3 identity/key lifecycle gate complete; A4 wallet-core integration gate complete; A5 federated evidence model gate complete; A6 production policy matrix complete. Later slices should expand this file phase-by-phase without weakening the production target or re-opening completed issue-train work.

## A0 — Production target

First-prod readiness requires all three Track A rails:

1. Local single-node production-shaped deployment.
2. Castalia Wallet-backed app/user auth.
3. Cross-Hub/federated evidence.

secS-magik is ready for first prod only when one Hub can run a production-shaped secS verifier service that:

- rejects insecure/local-dev authority in production mode;
- verifies wallet-core-defined presentations for app/user subjects;
- evaluates federated evidence from another Hub/Castalia-style authority through the narrowed A5 first path — signed membership/provisioning credentials, receiver-held trusted issuer/root metadata, and status checks — while preserving future Dregg anchor/root seams behind A9;
- signs and persists operator-visible receipts/contexts;
- executes only bounded descriptor-authorized handlers;
- proves a membership-provisioning flow end-to-end without relying on hand-wavy future rails.

## A0 — Required rails

| Rail | Required for first prod? | Meaning | First proof |
|---|---:|---|---|
| Local single-node production-shaped deployment | Yes | One Hub/secS instance can run with production config, explicit keys, fail-closed runtime mode, bounded handlers, redacted ledger, and documented smoke commands. | Local production-mode smoke with signed context, receipt chain, and no local-dev evidence satisfying authority. |
| Castalia Wallet-backed app/user auth | Yes | Browser/app user presents wallet-core-defined challenge/signature evidence; secS verifies the same canonical wallet-core semantics used by the extension/secZ/secC. | Wallet presentation cryptographic happy path plus wrong signature/key/subject/audience/origin/replay/expiry rejects. |
| Cross-Hub/federated evidence | Yes | Hub A can evaluate evidence produced/signed/anchored/revoked/vouched for by Hub B, Castalia, or Dregg-shaped authority while still applying Hub A local manifest policy. | Fixture federation evidence adapter or policy path that accepts a trusted issuer/root and rejects untrusted/revoked/stale evidence. |

## A0 — Not enough for prod

Local smoke readiness alone is not enough for first prod.

The current implemented surfaces prove important substrate behavior, but they do not by themselves satisfy the production target:

- `local_static` evidence is a deterministic local/dev/test scaffold. It must not satisfy production authority.
- `wallet_presentation` is currently a typed fail-closed shell. It does not yet prove production wallet crypto.
- The local SQLite receipt/event ledger is local audit evidence. It is not public auditability or cross-Hub federation by itself.
- Dregg, Midnight, and Cardano are not current runtime dependencies in this repo. They enter only through future adapter/evidence/anchor semantics unless explicitly promoted by a later slice.
- Matrix room/message federation is not the cross-Hub/federated evidence rail.
- Browser WalletAuth/session UX is not owned by secS-magik, except for the wallet presentation evidence that secS must verify.

## A0 — Language discipline

Use these phrases until code proves stronger claims:

- local production-shaped deployment;
- wallet-core-defined presentation;
- typed fail-closed wallet shell;
- cross-Hub/federated evidence rail;
- fixture trusted issuer/root;
- generic trust/root ref seam with Dregg as future subtype;
- production-mode reject path;
- receiver-local manifest policy.

Avoid these phrases for current code:

- production-secure wallet auth;
- fully federated Dregg authority;
- fully ZK-verified proof;
- public auditability;
- Cardano-backed membership provisioning;
- Matrix federation as the authority rail.

## A0 — Stop condition

A0 stops here: the production definition is explicit, all three rails are required, and local smoke readiness is explicitly insufficient.

A0 stopped here: the production definition became explicit, all three rails became required, and local smoke readiness became explicitly insufficient. A1 has since reconciled the current repo checkpoint below.

## A1 — Current checkpoint and completed slices

A1 reconciles the repo status ledger against the completed implementation train through Issue 4.2 and the A0 ready-for-prod definition. This section is a checkpoint, not a new production claim.

Current branch context:

- Phase branch: `phase/track-a-ready-for-prod`
- A0 issue-boundary commit: `a7b556f docs: lock ready-for-prod production target`
- A1 scope: docs/status reconciliation only; no runtime code changes.
- Adjacent untracked dirs still out of scope unless explicitly promoted: `docs/reviews/`, `hub/`, `ops/`.

Completed / solid enough to build on:

| Surface | Current status | What future slices may assume | What future slices must not claim |
|---|---|---|---|
| `ZenithPacket` v0 and decimal `u8` opcode parsing | Solid / implemented | Packet shape and current CLI decimal parsing are regression-covered compatibility constraints. | Do not change packet shape or silently add hex opcode parsing as part of ready-for-prod work. |
| Runtime modes and payload handling | Solid / implemented for current gateway | Plaintext is explicit local-dev only; default production-shaped mode fails closed without required tunnel/evidence. | Do not claim the whole service is production-secure only because plaintext fallback is no longer silent. |
| Receiver-local manifest descriptors | Solid / implemented as descriptor layer | Operation descriptors and reserved opcode range governance exist in `server/src/manifest.rs`. | Do not claim final Castalia-standard opcode assignments are ratified. |
| Signed `VerifiedCallContext` and receipts | Solid / implemented locally | Current code can sign/verify local Ed25519 contexts/receipts and persist receipt metadata. | Do not claim production identity discovery, key rotation, or public auditability yet. |
| Receipt/event ledger | Solid / implemented as local SQLite ledger | Verify/reject/execute records can be persisted without raw payload content by default. | Do not claim public audit proof or cross-Hub receipt trust from local SQLite alone. |
| `EvidenceAdapter` and `local_static` | Solid / implemented as local-dev-test seam | Descriptor evidence requirements can flow through an adapter into signed contexts/receipts. | `local_static` cannot satisfy production authority. |
| `wallet_presentation` adapter shell | Partial / prototype | Shape validation and fail-closed status handling exist for wallet-presentation evidence. | Do not claim production wallet cryptographic verification. |
| Verified-context handler routing | Partial / prototype | Handlers now consume `VerifiedCallContext` and emit execution receipts through bounded local routing. | Do not claim final durable/general execution broker semantics. |

Remaining first-prod gaps carried forward into A2–A9:

- production identity/key lifecycle and public-key discovery;
- wallet-core-backed cryptographic verification path;
- cross-Hub/federated evidence object model, trusted issuer/root representation, and revocation/staleness semantics;
- production policy matrix proving `local_static`/dev evidence cannot satisfy production descriptors;
- first membership-provisioning E2E operation and failure matrix;
- phase/branch/PR checklist where phases are PR boundaries and issues are commit boundaries.

A1 stop condition is satisfied when `docs/implementation-status.md` and this checklist agree on the current solid/partial/planned surfaces and preserve caveats for wallet crypto, identity lifecycle, bounded broker, runtime hardening, and federated evidence.

## A2 — Rail taxonomy and non-goals

A2 turns the A0 production target into working ownership boundaries. These boundaries decide what belongs in secS-magik before later slices become implementation issues.

### A2 — Required rails

| Rail | Owned by secS-magik? | Required for first prod? | Scope in this repo | First-prod proof target |
|---|---:|---:|---|---|
| Local production-shaped secS service | Yes | Yes | Runtime mode enforcement, explicit operator/verifier config, bounded handler routing, signed contexts/receipts, redacted local ledger, and documented smoke commands. | Production-mode local smoke rejects local/dev evidence and produces signed verify/execute receipts. |
| Wallet-core-backed user/app auth evidence | Partly | Yes | secS verifies or consumes canonical Castalia Wallet evidence for a descriptor. Wallet UI/session UX stays outside this repo. | Wallet presentation happy path plus wrong signature/key/subject/audience/origin/replay/expiry rejects. |
| Cross-Hub/federated evidence evaluation | Yes at verifier/evidence boundary | Yes | Typed evidence adapter/model for trusted issuer/root, remote receipt/capability/credential/revocation/root evidence, and receiver-local policy enforcement. | Fixture trusted issuer/root accepts valid evidence and rejects untrusted, revoked, stale, malformed, wrong-audience, or wrong-operation evidence. |
| Signed receipt/context identity | Yes | Yes | Signer identity, key id, signed `VerifiedCallContext`, signed receipts, and local/operator-visible provenance. | Tamper, wrong key, expired context, and untrusted/revoked issuer checks are named and later tested. |
| Descriptor-bound bounded execution | Yes | Yes | Receiver-local manifest policy binds opcode/operation/evidence to bounded handler execution after verification. | Handlers run only from verified context; oversized payload, unavailable handler, and descriptor mismatch fail closed. |
| Redacted local ledger and operator inspection | Yes | Yes | Local SQLite receipt/event persistence with payload redaction by default and inspectable decision chain. | Verify/reject/execute receipts are inspectable without storing raw payload/evidence by default. |
| End-to-end membership-provisioning proof | Yes for secS verifier/runbook path | Yes | A fixture operation proves machine-to-machine membership provisioning through wallet + federated evidence + bounded handler + receipts. | `membership.provision`, `gallery.member.provision`, or `hub.member.provision` runbook/test proves more than packet echo. |

### A2 — Deferred / future rails

| Rail | Status | First-prod posture | Promotion trigger |
|---|---|---|---|
| Dregg consensus / live root service | Future or explicitly promoted by A5/A9 | Not a blanket runtime dependency. May be represented by fixture trusted roots, Dregg-shaped root refs, or static registry semantics until promoted. | Promote only if first-prod federation requires live Dregg-backed roots/revocation rather than fixture trusted issuers/roots. |
| Midnight/private-statement proof adapter | Future unless A7 chooses private statement/public-input membership proof | Not required for generic membership provisioning. | Promote only if first-prod needs private statement verification rather than public wallet/federated evidence. |
| Cardano settlement/capital evidence | Future for settlement/capital operations | Not required for generic membership provisioning. | Promote only if the selected first operation involves settlement, capital, or on-chain business evidence. |
| Public chain anchoring of receipts | Future external proof rail | Current SQLite ledger remains local/operator audit only. | Promote when public audit proof is a first-prod requirement, not merely a nice-to-have. |
| Castalia Wallet product UI/session flow | Outside this repo | secS only consumes/verifies wallet evidence. | Implement in Castalia Wallet / app surfaces; secS participates through verifier contract only. |

### A2 — Non-goals for secS-magik

secS-magik does not own:

- Gallery product policy;
- ordinary browser app session UX beyond wallet presentation evidence;
- Matrix room/message federation;
- Dregg consensus implementation inside secS-magik;
- Midnight circuit authoring inside secS-magik;
- Cardano settlement/business logic;
- auction/business logic;
- broad shell access;
- centralized Hub orchestration;
- Castalia membership semantics as product authority.

### A2 — Language discipline

Use these phrases:

- `local production-shaped secS service` for the local deployment target;
- `wallet-core-backed evidence` or `wallet-core-defined presentation` for app/user auth evidence;
- `cross-Hub/federated evidence evaluation` for the receiver-side verifier rail;
- `fixture trusted issuer/root` for first local federation proofs that do not yet run live Dregg;
- `trust_root_ref` / `registry_root_ref` for future-compatible root semantics, with Dregg as a future subtype only;
- `receiver-local manifest policy` for the final local authorization decision;
- `local SQLite receipt/event ledger` for current audit storage.

Avoid these phrases unless a later issue implements and verifies them:

- `production-secure wallet auth`;
- `fully federated Dregg authority`;
- `fully ZK-verified proof`;
- `public auditability`;
- `Cardano-backed membership provisioning`;
- `Matrix federation` as the authority rail;
- `WalletAuth is part of secS-magik`.

A2 acceptance is met when future implementers can tell what belongs in secS-magik versus Castalia Wallet, Dregg, Matrix, Gallery, Hub app policy, Midnight, and Cardano without reopening A0.

## A3 — Identity/key lifecycle decision gate

A3 fixes the first production-shaped signer/key posture for later implementation issues. This is a checklist decision gate, not an implementation claim: current code can sign local Ed25519 contexts/receipts, but production key loading, discovery, rotation, and revocation still need implementation.

### A3 — First signer/key model

First implementation posture: **single `node_verifier_key` for the first production-shaped secS service**, with an explicit future split between verifier-signing and runtime/node identity keys once there is a second concrete consumer that needs separation.

Rationale:

- A single verifier key keeps the first local production-shaped deployment understandable and testable.
- Signed `VerifiedCallContext` and receipts need one stable operator-visible signer before federated evidence expands.
- Splitting verifier/runtime keys too early increases config, rotation, and discovery surface before A5 defines federated evidence consumers.
- The naming must still avoid painting the repo into a corner: use `node_verifier_key`, not generic `node_key`, so future split keys can be introduced without redefining current semantics.

### A3 — Key loading and config path

First-prod implementation should load the verifier signing key from explicit operator config, not from implicit dev defaults.

Required config fields for later implementation issues:

| Field | Meaning | First-prod rule |
|---|---|---|
| `SECS_VERIFIER_KEY_PATH` or config-file equivalent | Path/handle for the private verifier signing key. | Required in `production_verified`; test fixtures may generate ephemeral keys. |
| `SECS_VERIFIER_KEY_ID` or derived key id | Stable public identifier for receipts and signed contexts. | Must be present or derivable from public key fingerprint. |
| `SECS_TRUST_REGISTRY_PATH` or config-file equivalent | Local/static trusted public-key registry for first local/federated fixture proofs. | Required before cross-Hub/federated evidence accepts non-local issuer evidence. |
| `SECS_RUNTIME_MODE` | Runtime posture. | `production_verified` must fail closed if signing key or required trust registry material is missing. |

Secrets rule: docs/tests may use ephemeral generated keys or fixture public keys, but real operator private keys, tokens, packet captures, and machine-specific config must not be committed.

### A3 — Key id format

First implementation should use a deterministic, portable key id:

```text
ed25519:<base64url-or-hex-public-key-fingerprint>
```

Rules:

- The key id identifies the public verification key, not a local filename.
- The key id appears in signed `VerifiedCallContext` and signed receipts.
- The signature covers the context/receipt payload, while the key id lets verifiers look up the public key.
- If later Castalia/Dregg registry identifiers become canonical, this key id can become the local key fingerprint inside a richer issuer/root namespace instead of being discarded.

### A3 — Public-key discovery path

First implementation posture: **local/static trust registry first, Castalia/Dregg discovery later unless A5/A9 promotes live federation**.

| Discovery source | First-prod role | Notes |
|---|---|---|
| Local config for own verifier public key | Required | Lets the service verify its own signed contexts/receipts and expose operator-visible signer metadata. |
| Static trusted issuer/root registry | Required for first fixture federation | Can model trusted Hub/Castalia/Dregg-shaped roots without running live Dregg consensus. |
| Castalia registry | Future / optional until promoted | Expected durable ecosystem discovery path, but not required for the first local fixture proof unless explicitly promoted by A5/A9. |
| Dregg root/ref | Future / optional until promoted | May become the revocation/root freshness source; first pass can carry Dregg-shaped root refs as data. |

### A3 — Minimum revocation and rotation posture

First implementation should model revocation/rotation at the registry semantics layer even if it uses local fixtures:

- registry entries include `key_id`, public key, issuer/root id, `status`, `not_before`, `not_after`, and optional `revoked_at` / `replaced_by`;
- accepted statuses are explicit: `active`, `revoked`, `expired`, `unknown`;
- `production_verified` rejects unknown, revoked, expired, not-yet-valid, or wrong-issuer keys;
- rotation means a new key id can be active while the old key id is rejected after `revoked_at` / expiry;
- local/dev/test keys are labeled `local_dev` or fixture-only and cannot satisfy production issuer authority.

### A3 — Test matrix for later implementation issues

Later code issues that implement A3 must name and pass tests for:

| Case | Expected result |
|---|---|
| valid context/receipt signed by active configured key | accept |
| tampered context or receipt payload | reject |
| signature from wrong key id | reject |
| unknown key id | reject |
| revoked key id | reject |
| expired key id / outside validity window | reject |
| not-yet-valid key id | reject |
| local/dev/test key used for production authority | reject |
| trusted static issuer/root fixture with active key | accept only for descriptors that permit that issuer/root |
| trusted key for wrong audience/operation/subject | reject |

A3 acceptance is met when later implementers can open this checklist and know the first signer model, key loading/config expectation, key id format, public-key discovery path, revocation/rotation posture, and the tests that must prevent local/dev keys from becoming production authority.

## A4 — Wallet-core integration decision gate

A4 fixes how secS-magik should use Castalia Wallet semantics before wallet-presentation verification becomes implementation work. This is a decision gate, not a claim that production wallet crypto is already implemented.

### A4 — Locked integration path

First target: **direct minimal wallet-core verifier API/crate dependency**.

secS-magik should verify wallet presentations by calling a minimal verifier surface owned by the shared Castalia Wallet Rust core semantics layer. The verifier API should validate raw/canonical wallet evidence rather than making secS trust an independently produced artifact by default.

Fallback path if dependency shape blocks the first implementation: **wallet-core-defined verified artifact**, but only if the artifact is signed or otherwise traceable to wallet-core semantics and still binds challenge, subject, audience, origin, replay nonce, expiry, public key, and operation/descriptor context. This fallback must be recorded as an explicit follow-up issue rather than silently duplicating logic in secS-magik.

Rejected path: **duplicate secS wallet verifier logic**. secS-magik must not invent a second challenge/signature verification contract that can drift from the browser extension, secZ/secC, or wallet-core semantics.

### A4 — Ownership boundary

| Surface | Owner | A4 rule |
|---|---|---|
| Castalia Wallet Rust core verifier semantics | Castalia Wallet / shared wallet-core crate | Owns canonical challenge/signature validation, presentation schema, replay/expiry checks, and public-key binding semantics. |
| secS `wallet_presentation` evidence adapter | secS-magik | Calls the wallet-core verifier API or validates a wallet-core-defined signed/traceable artifact; converts result into typed evidence result and receipts. |
| Browser extension / WASM wallet UX | Castalia Wallet | Produces user-facing presentation flow; not owned by secS-magik. |
| secZ/secC/local clients | Client surfaces | May construct requests or presentations using wallet-core bindings, but do not become verifier authority. |
| Product session / WalletAuth UX | App/Gallery/Hub surfaces | Out of scope for secS-magik except as evidence inputs to descriptors. |

### A4 — Expected verifier API contract

Later implementation issues should target a narrow API shape like:

```text
verify_wallet_presentation(input) -> WalletPresentationVerification
```

Minimum input fields:

- `subject_id`;
- `audience` / receiver Hub or secS service id;
- `origin` / app origin where applicable;
- `operation` / descriptor operation name;
- `challenge`;
- `signature`;
- `public_key` or wallet-controlled verification key reference;
- `replay_nonce`;
- `issued_at` / `not_before`;
- `expires_at`;
- optional evidence refs / issuer refs needed by A5.

Minimum result fields:

- `accepted: bool`;
- `subject_id`;
- `wallet_key_id` / public-key fingerprint;
- `presentation_id` or hash;
- `reason_code` for rejects;
- `evidence_summary_hash` for receipts;
- `verified_at`;
- `schema_version`.

### A4 — Affected repo paths / crates

Expected secS-magik paths for later implementation issues:

| Path | Expected role |
|---|---|
| `server/src/evidence.rs` | Extend `wallet_presentation` adapter from shape-only fail-closed shell into wallet-core-backed verification call. |
| `server/tests/wallet_presentation.rs` | Add cryptographic happy-path and reject tests. |
| `server/src/receipt.rs` | Ensure wallet verification result summaries enter signed receipts without raw private evidence by default. |
| `server/src/verifier.rs` | Ensure accepted wallet evidence can contribute to signed `VerifiedCallContext`. |
| `docs/plans/2026-06-02-ready-for-prod-checklist.md` | Preserve this decision and issue-level acceptance criteria. |

Expected adjacent/shared crate surface:

| Surface | Expected role |
|---|---|
| Castalia Wallet Rust core verifier crate/API | Canonical wallet presentation verification. Exact repo/path to be supplied by the wallet-core implementation slice. |
| WASM/browser bindings | Consumer of the same semantics, not a parallel verifier contract. |
| Native/secZ/secC bindings | Consumer of the same semantics for local/client construction paths. |

### A4 — Test and acceptance matrix for implementation issues

Later code issues must name and pass tests for:

| Case | Expected result |
|---|---|
| valid wallet-core presentation for expected subject/audience/origin/operation | accept |
| invalid signature | reject with typed reason |
| wrong public key / key id mismatch | reject with typed reason |
| wrong subject | reject with typed reason |
| wrong audience / receiver | reject with typed reason |
| wrong origin | reject with typed reason |
| wrong operation / descriptor mismatch | reject with typed reason |
| replayed nonce / presentation id | reject with typed reason |
| expired or not-yet-valid presentation | reject with typed reason |
| malformed presentation shape | reject with typed reason |
| wallet-core verifier unavailable or feature-disabled | fail closed, not local_static fallback |
| accepted presentation receipt | signed receipt includes summary/hash/key id without raw private evidence by default |

### A4 — Packaging implications

The shared verifier semantics must be usable from both browser/WASM and native/server contexts without semantic drift:

- keep verifier logic in a core Rust surface with feature flags if needed;
- isolate browser-only APIs from the minimal verifier core;
- avoid Node/browser global assumptions in secS server builds;
- ensure secS can compile/test without bundling extension UI code;
- keep schema/version constants shared or explicitly mirrored with compatibility tests.

A4 acceptance is met because the checklist selects the direct minimal wallet-core verifier API as the first target, records the artifact fallback boundary, rejects duplicated secS semantics, names affected secS paths/shared crate surfaces, and lists signature/audience/origin/replay/expiry tests plus browser/WASM/native packaging constraints.

## A5 — Federated evidence model decision gate

A5 reimplements the cross-Hub/federated evidence rail after the candidate evidence-kind review. The key correction is that not every candidate is a peer-level verifier input. A5 now separates primary authorization evidence, supporting status/freshness evidence, and trust/root reference metadata, then narrows the first implementation path to the smallest honest production-shaped proof.

This remains a checklist/design gate, not an implementation claim. It permits fixture first-prod evidence without pretending Dregg consensus, live Castalia registry discovery, Merkle inclusion proofs, capability algebra, or public audit anchoring already exist.

### A5 — Core definitions

| Term | Definition | First-prod posture |
|---|---|---|
| Subject Hub | The Hub/secS service receiving and deciding the call, e.g. Gallery Hub. | Applies receiver-local manifest policy last. |
| Issuer / authority | The Hub, Castalia authority, static fixture issuer, or future Dregg/Castalia root that issued evidence. | Must map to a trusted issuer/root entry and active verification key. |
| Primary authorization evidence | Caller-supplied evidence that may directly satisfy a descriptor requirement. | First path is `membership_credential` / `provisioning_credential`. |
| Supporting status/freshness evidence | Evidence or registry state used to evaluate a primary authorization object. | First path uses `registry_status` / `revocation_status`, not cryptographic proof claims. |
| Trust/root reference metadata | Verifier-held registry/root configuration or future root refs. | `TrustedIssuerEntry` and `trust_root_ref` constrain authority; callers do not bring their own trust root. |
| Receiver-local manifest policy | The receiving Hub's operation descriptor and evidence requirements. | Federated evidence may satisfy requirements, but never bypasses local policy. |

### A5 — Reimplemented evidence classes

| Class | Evidence / metadata | Role | First implementation posture |
|---|---|---|---|
| Primary authorization evidence | `membership_credential` / `provisioning_credential` | Proves subject membership/role or provisioning authority issued by a trusted issuer. | Implement first. Derived from the earlier broad `issuer_credential`; must bind subject, audience, operation/scope, expiry, revocation/status ref, signer key id, and signature. |
| Primary authorization evidence | `remote_verification_attestation` | A trusted Hub/authority attests that it verified evidence under a named policy/descriptor. | Keep as second-path evidence. Replaces the over-broad first-pass use of `remote_signed_receipt`; do not accept vague execution receipts as authority. |
| Primary authorization evidence | `scoped_delegation_credential` | Simpler bounded delegation/provisioning grant without full capability algebra. | Allowed as an intermediate form if A7 needs delegated machine-to-machine provisioning before Dregg capabilities exist. |
| Future primary authorization evidence | `capability_caveat` | Full delegated/scoped capability with caveats, discharge, attenuation, revocation, and path validation. | Defer unless A9 promotes Dregg/capability machinery. Do not fake capability algebra with string checks. |
| Supporting status/freshness evidence | `registry_status` / `revocation_status` | Status lookup for issuer/key/credential/root: active, revoked, expired, unknown, not-yet-valid. | Implement first through static trust registry fields. Reserve `revocation_proof` for real proof-backed systems. |
| Supporting status/freshness evidence | `membership_root_ref` | Reference to a membership state root or roster commitment. | Reference only unless paired with `membership_inclusion_proof`; a root alone is not authorization evidence. |
| Future supporting evidence | `membership_inclusion_proof` | Root + subject witness/path proving inclusion in a committed membership set. | Future unless A7/A9 require root-backed membership proof. |
| Trust/root reference metadata | `TrustedIssuerEntry` | Verifier-held trusted issuer/root metadata: keys, status, scopes, evidence kinds, operations, audiences. | Required first. This is configuration/registry metadata, not caller-supplied evidence. |
| Trust/root reference metadata | `trust_root_ref` / `registry_root_ref` | Generic future-compatible root reference; Dregg may become one subtype. | Use instead of first-pass `dregg_root_ref` to avoid implying live Dregg. |
| Future trust/root subtype | `dregg_anchor_ref` | Dregg-specific root/finality/revocation anchor. | Future subtype only if A9 promotes live Dregg or Dregg-backed roots/revocation. |

### A5 — Candidate evidence kind decisions

| Original candidate | Decision | Reason |
|---|---|---|
| `remote_signed_receipt` | Reframed as second-path `remote_verification_attestation`. | A receipt can launder weak upstream policy unless it explicitly attests verified policy, subject, audience, operation, descriptor hash, expiry, replay scope, and issuer. |
| `capability_caveat` | Deferred. | Strong long-term Dregg-aligned shape, but too easy to fake without caveat language, discharge, attenuation, revocation, and path validation. |
| `issuer_credential` | Narrowed to first-path `membership_credential` / `provisioning_credential`. | Best first membership-provisioning proof; easier to fixture honestly; still must bind audience, operation/scope, expiry, and revocation/status. |
| `revocation_proof` | Demoted to first-path `revocation_status` / `registry_status`; proof reserved for future. | Static fixture status is not cryptographic proof of non-revocation. Calling it proof would overclaim. |
| `membership_root` | Demoted to `membership_root_ref` unless paired with `membership_inclusion_proof`. | A root alone proves nothing without witness/path, freshness rule, and publisher governance. |
| `dregg_root_ref` | Generalized to `trust_root_ref` / `registry_root_ref`; Dregg becomes future subtype. | Avoids implying live Dregg integration while preserving Dregg-compatible shape. |

### A5 — First implementation path

First implementation should prove cross-Hub/federated membership authority with the narrowest honest path:

1. Configure a static `TrustedIssuerEntry` for a fixture Hub/Castalia-style issuer/root.
2. Verify a signed `membership_credential` or `provisioning_credential` for the subject and operation.
3. Check `registry_status` / `revocation_status` from the static trust registry rather than claiming cryptographic revocation proof.
4. Bind subject, audience, operation/scope, issuer/root id, validity window, replay id/nonce, signer key id, schema version, and evidence summary hash.
5. Apply receiver-local manifest policy after evidence validation.
6. Emit accepted/rejected evidence summary into `VerifiedCallContext` and signed receipts without storing raw private evidence by default.
7. Carry `remote_verification_attestation`, `capability_caveat`, `membership_root_ref`, `membership_inclusion_proof`, and Dregg anchor refs as future-compatible classes, not first implementation blockers.

### A5 — Trusted issuer/root representation

First implementation should use a local/static trust registry shaped like future Castalia/Dregg discovery but not claiming live federation.

Minimum registry entry:

```text
TrustedIssuerEntry
  issuer_id
  issuer_kind                  # hub | castalia_registry | registry_root | fixture
  trusted_root_ref             # generic trust/root reference, not necessarily Dregg
  public_keys[]                # key_id, algorithm, public_key, status, not_before, not_after, revoked_at, replaced_by
  accepted_evidence_kinds[]    # e.g. membership_credential, provisioning_credential, remote_verification_attestation
  accepted_operations[]
  audience_scope[]
  root_status                  # active | revoked | expired | unknown
  registry_version
```

Rules:

- Production descriptors may accept federated evidence only from configured active issuers/roots.
- A trusted issuer/root does not bypass receiver-local manifest policy.
- Fixture issuers/roots must be labeled fixture/static and cannot be described as live Dregg or live Castalia registry federation.
- A revoked, expired, unknown, wrong-operation, or wrong-audience issuer/root rejects with typed reason and receipt.
- Caller-supplied embedded keys or root refs are evidence data only; they must chain to receiver-held trusted issuer/root metadata.

### A5 — Public-key discovery path

| Discovery source | A5 role | Acceptance boundary |
|---|---|---|
| Static trust registry | First implementation path | Provides trusted issuer/root id, public keys, validity/status, accepted evidence kinds, accepted operations, and audience scope. |
| Castalia registry | Future/promoted path | May replace or feed the static registry when live registry discovery is required. |
| Generic `trust_root_ref` / `registry_root_ref` | Future-compatible reference path | Lets the model preserve root semantics without forcing Dregg into first implementation. |
| Dregg anchor/root | Future/promoted subtype | May provide root freshness, revocation, and capability path validation only if A9 promotes live Dregg. |
| Embedded evidence key | Allowed only as evidence data | Must still chain to configured trusted issuer/root; an embedded key alone is not authority. |

### A5 — Expiry, replay, and audience semantics

All federated evidence that can satisfy production descriptors must bind:

- `subject_id` — who/what the evidence is about;
- `audience` — receiving Hub/secS service or accepted audience scope;
- `operation` / `scope` — descriptor operation it may satisfy;
- `issuer_id` / `trusted_root_ref` — who issued or anchored it;
- `issued_at` / `not_before` / `expires_at` — validity window;
- `replay_scope` / `nonce` / evidence id — replay boundary;
- `signer_key_id` — public key lookup id;
- evidence hash / schema version — compatibility and receipt summarization.

Rules:

- Wrong audience rejects even if signature is valid.
- Wrong operation/scope rejects even if issuer is trusted.
- Expired or not-yet-valid evidence rejects.
- Replayed evidence id/nonce rejects when a replay store is available; until implemented, replay-store work remains a production blocker.
- Evidence summaries/hashes may enter receipts; raw private evidence must not be stored by default.

### A5 — Typed failure reasons

Later code issues must use typed reject reasons and emit reject receipts for at least:

| Failure reason | Meaning |
|---|---|
| `untrusted_issuer` | Issuer/root id is absent or not configured as trusted. |
| `revoked_issuer` | Issuer/root/key is revoked. |
| `expired_issuer` | Issuer/root/key is outside validity window. |
| `unsupported_evidence_kind` | Descriptor or registry does not accept that evidence kind. |
| `malformed_federated_evidence` | Evidence cannot parse or misses required fields. |
| `invalid_evidence_signature` | Signature/proof does not verify against discovered public key. |
| `wrong_audience` | Evidence targets another receiver/audience. |
| `wrong_operation` | Evidence does not bind to the requested descriptor operation. |
| `wrong_subject` | Evidence subject does not match request/descriptor requirements. |
| `revoked_evidence` | Credential, attestation, capability, or referenced root/status is revoked. |
| `expired_evidence` | Evidence is expired or not yet valid. |
| `stale_root` | Root/ref freshness is too old for descriptor policy. |
| `replay_detected` | Evidence id/nonce/replay scope has already been consumed. |
| `local_policy_reject` | Evidence is valid but receiver-local manifest policy still rejects it. |

### A5 — Test matrix for later implementation issues

| Case | Expected result |
|---|---|
| trusted fixture issuer + valid `membership_credential` / `provisioning_credential` | accept if receiver-local manifest permits evidence kind and operation/scope |
| untrusted issuer/root | reject `untrusted_issuer` |
| revoked issuer/root/key | reject `revoked_issuer` or `revoked_evidence` |
| expired issuer/root/key/evidence | reject `expired_issuer` or `expired_evidence` |
| malformed credential/attestation | reject `malformed_federated_evidence` |
| invalid evidence signature | reject `invalid_evidence_signature` |
| wrong audience | reject `wrong_audience` |
| wrong operation/scope | reject `wrong_operation` |
| wrong subject | reject `wrong_subject` |
| unsupported evidence kind for descriptor | reject `unsupported_evidence_kind` |
| valid evidence but receiver-local policy mismatch | reject `local_policy_reject` |
| replayed evidence id/nonce | reject `replay_detected` once replay store is implemented; until then, carry as production blocker |
| caller supplies embedded key/root without configured trust chain | reject `untrusted_issuer` |
| `membership_root_ref` without inclusion proof when descriptor requires membership proof | reject `unsupported_evidence_kind` or `malformed_federated_evidence` |
| Dregg root/ref supplied while Dregg is not promoted by A9 | treat only as `trust_root_ref` data; do not claim live Dregg validation |

A5 acceptance is met because this reimplemented model defines evidence object classes, trusted issuer/root representation, public-key discovery, remote attestation / credential / status / root-reference shapes, expiry/replay semantics, typed failure reasons, and a fixture first-prod path. It also incorporates the pros/cons review by narrowing first implementation to membership/provisioning credential plus static trusted issuer registry and status checks, without pretending Dregg consensus is implemented or bypassing receiver-local policy.

## A5 downstream development impact checkpoint

This checkpoint captures the consequences of the A5 reimplementation for later development. Future implementation agents should treat this as a constraint, not as historical commentary.

Downstream rules:

- A6 production policy rows should be written around `membership_credential` / `provisioning_credential`, `TrustedIssuerEntry`, and `registry_status` / `revocation_status` as the first federated evidence path.
- A7 first E2E should prove wallet presentation plus membership/provisioning credential evidence through receiver-local manifest policy, bounded handler execution, and receipts.
- A8 issue decomposition should derive phase/issue boundaries from the narrowed first path; do not create first-path issues for demoted candidate kinds unless A9 promotes them.
- A9 is the only place to promote live Dregg anchors, capability algebra, cryptographic revocation proofs, or membership inclusion proofs into first-prod scope.

Forbidden first-path assumptions:

- Do not accept vague remote execution receipts as authorization evidence; use `remote_verification_attestation` only as a second-path attestation with explicit verified-policy bindings.
- Do not fake `capability_caveat` semantics with string checks.
- Do not call static `revocation_status` a cryptographic `revocation_proof`.
- Do not treat `membership_root_ref` as membership proof without `membership_inclusion_proof`.
- Do not call generic `trust_root_ref` / `registry_root_ref` live Dregg validation.


## A6 — Production policy matrix

A6 converts the A0/A2/A5 boundaries into an implementable production policy matrix. This is still a checklist/design gate, not a claim that every runtime test is already implemented. Later code issues must preserve these rows as acceptance tests or named test cases before claiming production authority.

### A6 — Policy principle

Production authority is determined by the combination of runtime mode, receiver-local descriptor policy, and validated evidence. No adapter output bypasses the receiver's manifest policy, and no local/dev/static evidence may satisfy a production descriptor.

Rules:

- `local_static`, plaintext, and fixture-only local evidence are allowed only for local/dev descriptors in local/dev runtime modes.
- `production_verified` must fail closed if the descriptor requires wallet or federated evidence and the supplied adapter evidence is local/dev/static, missing, malformed, stale, revoked, or not bound to the requested subject/audience/operation.
- Wallet-presentation acceptance requires wallet-core-backed cryptographic verification. The current shape-only shell must remain fail-closed for production acceptance.
- Federated evidence acceptance uses A5's narrowed first path: `membership_credential` / `provisioning_credential`, receiver-held `TrustedIssuerEntry`, and `registry_status` / `revocation_status`.
- Valid evidence may satisfy descriptor evidence requirements, but receiver-local manifest policy still makes the final local authorization decision.

### A6 — Runtime × descriptor evidence × adapter evidence matrix

| Runtime mode | Descriptor evidence requirement | Adapter / evidence supplied | Expected result | Required future test target |
|---|---|---|---|---|
| `local_dev_plaintext` or `local_dev_tunnel` | dev-marked descriptor / local test operation | plaintext tunnel or `local_static` fixture | Accept only for dev-marked descriptors; emit visibly local/dev receipt context. | `local_dev_descriptor_accepts_local_static_fixture` |
| `local_dev_plaintext` or `local_dev_tunnel` | production descriptor | plaintext tunnel or `local_static` fixture | Reject; local/dev runtime cannot satisfy production authority. | `local_dev_runtime_rejects_production_descriptor` |
| `production_verified` | any production descriptor | missing evidence / plaintext-only packet | Reject before handler execution with typed missing/unsupported evidence reason. | `production_verified_missing_evidence_rejects_before_handler` |
| `production_verified` | wallet presentation | `local_static` | Reject; local static evidence is disallowed for wallet-auth production descriptors. | `production_wallet_descriptor_rejects_local_static` |
| `production_verified` | wallet presentation | current shape-only `wallet_presentation` shell with unsupported crypto status | Reject/fail closed until wallet-core cryptographic verification exists. | `production_wallet_shape_only_shell_fails_closed` |
| `production_verified` | wallet presentation | wallet-core cryptographic presentation with valid signature, subject, audience, origin, operation, replay nonce, and expiry | Accept only if descriptor permits wallet evidence and receiver-local policy passes. | `production_wallet_core_presentation_accepts_when_policy_matches` |
| `production_verified` | wallet presentation | wrong signature/key/subject/audience/origin/operation/replay/expiry | Reject with typed reason; emit reject receipt without handler execution. | `production_wallet_presentation_reject_matrix` |
| `production_verified` | federated evidence | untrusted `membership_credential` / `provisioning_credential` issuer or caller-supplied embedded key/root | Reject `untrusted_issuer`; embedded keys/roots do not create authority. | `production_federated_untrusted_issuer_rejects` |
| `production_verified` | federated evidence | trusted issuer but revoked, expired, unknown, not-yet-valid, or stale issuer/key/credential status | Reject `revoked_issuer`, `expired_issuer`, `revoked_evidence`, `expired_evidence`, or stale/status-specific reason. | `production_federated_status_reject_matrix` |
| `production_verified` | federated evidence | trusted active issuer + valid credential but wrong audience, subject, operation/scope, or unsupported evidence kind for descriptor | Reject `wrong_audience`, `wrong_subject`, `wrong_operation`, or `unsupported_evidence_kind`. | `production_federated_binding_reject_matrix` |
| `production_verified` | federated evidence | trusted active issuer + fresh non-revoked `membership_credential` / `provisioning_credential`, but receiver-local manifest policy mismatch | Reject `local_policy_reject`; valid foreign evidence never bypasses local policy. | `production_federated_valid_evidence_local_policy_rejects` |
| `production_verified` | federated evidence | trusted active issuer + fresh non-revoked operation-bound `membership_credential` / `provisioning_credential` + descriptor permits evidence + receiver-local policy passes | Accept; emit evidence summary into signed context/receipts without raw private evidence by default. | `production_federated_membership_credential_accepts_when_policy_matches` |
| `production_verified` | membership proof | `membership_root_ref` without `membership_inclusion_proof` when descriptor requires proof of membership | Reject as unsupported/malformed for that descriptor; root refs alone are not authorization evidence. | `production_membership_root_ref_without_inclusion_proof_rejects` |
| `production_verified` | Dregg-backed root/revocation/capability evidence | `dregg_anchor_ref` / Dregg-shaped root data while A9 has not promoted live Dregg | Treat only as generic `trust_root_ref` / `registry_root_ref` data; do not claim live Dregg validation or use it as first-path authority. | `production_dregg_ref_without_promotion_is_not_live_validation` |

### A6 — Test naming and implementation guidance

The test targets above are future code test names or semantic test descriptions. They should be implemented as focused tests in the later issue that touches the corresponding verifier/evidence/descriptor path, likely across:

- `server/tests/evidence.rs` or future production evidence tests for adapter policy;
- `server/tests/wallet_presentation.rs` for wallet-core-backed acceptance/rejects;
- future federated evidence tests once A5 objects are implemented;
- ingress/router tests proving rejects happen before handler execution and receipts are emitted.

Do not overfit future tests to exact prose from this checklist. The contract to preserve is the semantic matrix: runtime mode + descriptor requirement + validated evidence + receiver-local policy determines accept/reject.

### A6 — Acceptance

A6 acceptance is met because this checklist now names a runtime mode × descriptor evidence × adapter/evidence matrix, every row has a concrete future test target, `local_static` is explicitly local/dev/test-only, wallet shape-only evidence fails closed in production, federated rows use the narrowed A5 first-path objects, and forbidden first-path claims are bounded so demoted Dregg/capability/proof/root candidates cannot satisfy production authority without A9 promotion.

## Slice acceptance criteria

These criteria travel with the A0–A9 slices. A later phase/issue is not complete until its row is satisfied without weakening the A0 production definition.

| Slice | Acceptance criteria | Verification / evidence | Must not claim |
|---|---|---|---|
| A0 — Lock Track A production definition | The checklist names all three first-prod rails as required: local production-shaped deployment, Castalia Wallet-backed app/user auth, and cross-Hub/federated evidence. Local smoke readiness is explicitly insufficient. | `rg "local single-node|Wallet-backed|cross-Hub|federated evidence|not enough" docs/plans/2026-06-02-ready-for-prod-checklist.md` | Do not treat cross-Hub/federated evidence as optional; do not treat wallet crypto as future-only if first-prod includes app/user auth; do not make Dregg/Midnight/Cardano blanket runtime dependencies. |
| A1 — Repo status reconciliation | `docs/implementation-status.md` and this checklist agree on current solid, partial/prototype, planned, future, and out-of-scope surfaces through Issue 4.2 and A0/A1. | `rg "wallet_presentation|local_static|federated|Dregg|planned|production" docs/implementation-status.md`; `rg "A1|completed|partial|planned|wallet-core|federated|phase/branch/PR" docs/plans/2026-06-02-ready-for-prod-checklist.md` | Do not describe future rails as implemented; do not erase partial/prototype caveats for wallet crypto, identity lifecycle, bounded broker, runtime hardening, or federated evidence. |
| A2 — Rail taxonomy and non-goals | Required rails, deferred/future rails, secS-magik non-goals, and language discipline are explicit enough that implementers can distinguish secS-magik work from Castalia Wallet, Dregg, Matrix, Gallery, Hub app policy, Midnight, and Cardano. | `rg "Required rails|Non-goals|Matrix|Dregg consensus|Wallet|Language discipline" docs/plans/2026-06-02-ready-for-prod-checklist.md` | Do not let app/browser session UX, Matrix federation, Dregg consensus, Midnight circuits, Cardano settlement, or product policy become implicit secS-magik scope. |
| A3 — Identity/key lifecycle decision gate | The checklist identifies the first signer/key model, key loading/config path, key id format, public-key discovery path, and minimum revocation/rotation posture for first prod. | Checklist includes tests or future issue rows for tamper, wrong key, expired context, revoked/untrusted issuer, and local/dev non-authoritative keys. | Do not claim production identity discovery or key rotation until implemented; do not let local/dev/test keys appear authoritative. |
| A4 — Wallet-core integration decision gate | The checklist selects or explicitly carries the wallet-core integration path: direct minimal verifier API or wallet-core-defined verified artifact. The rejected option is duplicated secS wallet verifier semantics. | Checklist records the chosen path, tradeoffs, affected files/crates, tests for signature/audience/origin/replay/expiry, and browser/WASM/native packaging implications. | Do not invent independent secS wallet verification semantics; do not trust an unsigned/untraceable artifact producer as equivalent to verifying raw wallet evidence. |
| A5 — Federated evidence model decision gate | The checklist defines layered evidence classes, trusted issuer/root representation, public-key discovery, remote attestation / membership credential / status / root-reference shapes, expiry/replay semantics, and typed failure reasons. | Checklist names the fixture first-prod path using `membership_credential` / `provisioning_credential` plus static `TrustedIssuerEntry` and tests for untrusted issuer, revoked/expired status, malformed evidence, wrong audience, wrong operation, wrong subject, replay, and embedded-key/root trust-chain failures. | Do not pretend Dregg consensus, capability algebra, membership-root inclusion proofs, or cryptographic revocation proofs are implemented by fixture evidence; do not let federated evidence bypass receiver-local manifest policy. |
| A6 — Production policy matrix | The checklist contains a runtime mode × descriptor evidence × adapter evidence matrix proving local/dev/static evidence cannot satisfy production descriptors and that every accept/reject row has a test target. Federated rows must use the narrowed A5 first-path objects: `membership_credential` / `provisioning_credential`, `TrustedIssuerEntry`, and registry/revocation status. | `rg "production_verified|local_static|wallet presentation|membership_credential|provisioning_credential|TrustedIssuerEntry|revocation_status|untrusted issuer|revoked|stale" docs/plans/2026-06-02-ready-for-prod-checklist.md` plus future tests named per row. | Do not let `local_static`, plaintext, dev descriptors, vague remote receipts, caller-supplied roots, or demoted Dregg refs satisfy production authority. |
| A7 — First membership-provisioning E2E shape | The first E2E operation is selected (`membership.provision`, `gallery.member.provision`, or `hub.member.provision`) and includes happy path, failure matrix, receipt/ledger inspection, and local fixture constraints. It should combine wallet presentation with narrowed A5 membership/provisioning credential evidence. | Checklist/runbook names the operation, descriptor, evidence inputs, handler behavior, inspectable receipts, and failures for missing wallet evidence, wrong audience/origin, invalid signature, replay/expiry, untrusted/revoked membership/provisioning credential or issuer/key status, descriptor mismatch, handler unavailable, oversized payload, and redaction leak checks. | Do not make the E2E a packet echo; do not require real secrets; do not hide that fixtures are fake but semantically production-shaped; do not make live Dregg, capability algebra, cryptographic revocation proof, or membership inclusion proof first-E2E blockers unless A9 promotes them. |
| A8 — Convert Tracks A–I into issue-ready repo checklist | Tracks A–I are grouped into coherent implementation phases. Each phase has branch name, PR title/scope, issue/commit sequence, verification gate, and merge/stop condition. Each issue/commit has objective, files, commands, acceptance criteria, stop condition, and what it must not claim. | Checklist contains a phase/branch/PR plan preserving the repo pattern: phases are branch/PR boundaries and issues inside phases are commit boundaries, with A6/A7 downstream issues derived from A5's narrowed first implementation path. | Do not produce one branch/PR per issue unless that issue is promoted into a full phase; do not omit cross-Hub/federated evidence from first-prod requirements; do not build downstream issues around demoted A5 candidates as first-path requirements. |
| A9 — Defer or promote Tracks J–L intentionally | Dregg, Midnight, and Cardano are either explicitly first-prod dependencies with concrete evidence/adapter requirements, or explicitly deferred/future/adapter-scoped with rationale. Dregg defaults to future subtype of `trust_root_ref` / `registry_root_ref` unless promoted. | Checklist names whether Dregg is live dependency or static fixture/generic trust-root seam, whether Midnight/private statement work is required, and whether Cardano settlement/capital evidence is in scope. | Do not silently smuggle Dregg/Midnight/Cardano into the first implementation sequence; do not erase future adapter seams when deferring them; do not call static status or root refs Dregg validation. |

## Future expansion placeholders

Later slices should expand this checklist in place:

- A1 — repo status reconciliation — complete;
- A2 — rail taxonomy and non-goals — complete;
- A3 — identity/key lifecycle decision gate — complete;
- A4 — wallet-core integration decision gate — complete;
- A5 — federated evidence model decision gate — complete;
- A6 — production policy matrix — complete;
- A7 — first membership-provisioning E2E shape;
- A8 — issue-ready phase/branch/PR checklist for Tracks A–I;
- A9 — Dregg/Midnight/Cardano defer-or-promote decision.

A8 must preserve the repo workflow pattern: phases are branch/PR boundaries, and issues inside each phase are commit boundaries.
