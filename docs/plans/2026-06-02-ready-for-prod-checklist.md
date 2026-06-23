# secS-magik ready-for-prod checklist

This is the repo-local control surface for turning secS-magik from the current prototype verifier/RPC substrate into the first production-shaped implementation train.

Source captures:

- Claude Hub capture: `/Users/bananawalnut/claude-hub/capture/2026-06-02-secs-magik-track-a-ready-for-prod-slices.md`
- Parent work surface: `/Users/bananawalnut/claude-hub/capture/2026-06-02-secs-magik-ready-for-prod-work-surface.md`

Status: Track A is complete through A9 as a docs/control-surface phase. Track D is complete through D4 on `phase/track-d-wallet-core-crypto`: wallet presentation verification is cryptographic through an explicitly temporary minimal-equivalent secS challenge contract, not a full Castalia Wallet wallet-core import/parity. Track E is merged on `main` via PR #69 at `baee35b` with post-merge main Rust CI run 27050361282 passed, adding static receiver-held trusted issuer/root policy, signed membership/provisioning credential verification, policy-matrix tests, and safe evidence summaries. Track I `membership.provision` E2E (#70) is complete for local production-shaped E2E via PR #76 at `5e5bb71`; Issue #77 adds a fail-closed descriptor-only `production_verified` runtime evidence guard for canonical `0x44` `membership.provision`. Live runtime ingress still does not verify wallet + issuer evidence and live TCP ingress still has no evidence refs/public inputs for `membership.provision`; handler binding is not authority until #141/#144 wire-path work lands, and #73 Dregg authority remains future. A0 production definition locked; A1 repo status reconciled; A2 rail taxonomy and non-goals complete; A3 identity/key lifecycle gate complete; A4 wallet-core integration gate complete; A5 federated evidence model complete; A6 production policy matrix complete; A7 first membership-provisioning E2E shape complete; A8 issue-ready phase/branch/PR checklist complete; A9 future-rail defer/promote decision complete. Dregg, Midnight, and Cardano are deferred from first-prod implementation unless a later issue explicitly promotes them.

## Current merge status after Track E

Track E trusted issuer/root policy is complete on `main`: PR #69 merged at `baee35be4c2ed5ec6c626540b52b86516ee7debd`, post-merge main Rust CI run 27050361282 passed, and issues #35/#63 closed. Track I `membership.provision` E2E (#70) is complete for local production-shaped E2E on `main` via PR #76 at `5e5bb71` with post-merge CI run 27071532041. Issue #77 adds a fail-closed runtime guard for descriptor-only production verification of canonical `0x44` `membership.provision`; it does not make live ingress evidence-aware. Non-covered PR #69/#76 claims remain explicitly tracked by #71 (wallet-core parity), #72 (live Castalia registry discovery), #73 (future Dregg authority), #74 (Midnight), #75 (Cardano), #33 (deployment proof), #37 (public auditability), and #141/#144 live TCP evidence-ref/public-input follow-ups.

## A0 — Production target

First-prod readiness requires all three Track A rails:

1. Local single-node production-shaped deployment.
2. Castalia Wallet-backed app/user auth.
3. Cross-Hub/federated evidence.

secS-magik is ready for first prod only when one Hub can run a production-shaped secS verifier service that:

- rejects insecure/local-dev authority in production mode;
- verifies temporary minimal-equivalent secS wallet presentations for app/user subjects until wallet-core parity is reconciled;
- evaluates federated evidence from another Hub/Castalia-style authority through the narrowed A5 first path — signed membership/provisioning credentials, receiver-held trusted issuer/root metadata, and status checks — while preserving future Dregg anchor/root seams behind A9;
- signs and persists operator-visible receipts/contexts;
- executes only bounded descriptor-authorized handlers;
- proves a membership-provisioning flow end-to-end without relying on hand-wavy future rails.

## A0 — Required rails

| Rail | Required for first prod? | Meaning | First proof |
|---|---:|---|---|
| Local single-node production-shaped deployment | Yes | One Hub/secS instance can run with production config, explicit keys, fail-closed runtime mode, bounded handlers, redacted ledger, and documented smoke commands. | Local production-mode smoke with signed context, receipt chain, and no local-dev evidence satisfying authority. |
| Castalia Wallet-backed app/user auth | Yes | Browser/app user presents signed challenge evidence through the temporary minimal-equivalent secS wallet-presentation contract; full wallet-core parity remains future reconciliation. | Wallet presentation cryptographic happy path plus wrong signature/key/subject/audience/origin/replay/expiry rejects. |
| Cross-Hub/federated evidence | Yes | Hub A can evaluate evidence produced/signed/anchored/revoked/vouched for by Hub B, Castalia, or Dregg-shaped authority while still applying Hub A local manifest policy. | Fixture federation evidence adapter or policy path that accepts a trusted issuer/root and rejects untrusted/revoked/stale evidence. |

## A0 — Not enough for prod

Local smoke readiness alone is not enough for first prod.

The current implemented surfaces prove important substrate behavior, but they do not by themselves satisfy the production target:

- `local_static` evidence is a deterministic local/dev/test scaffold. It must not satisfy production authority.
- `wallet_presentation` now verifies signed presentation/challenge material cryptographically through the explicitly temporary minimal-equivalent secS challenge contract. It does not prove full Castalia Wallet wallet-core parity, production deployment, or trusted issuer/root policy.
- The local SQLite receipt/event ledger is local audit evidence. It is not public auditability or cross-Hub federation by itself.
- Dregg, Midnight, and Cardano are not current runtime dependencies in this repo. They enter only through future adapter/evidence/anchor semantics unless explicitly promoted by a later slice.
- Matrix room/message federation is not the cross-Hub/federated evidence rail.
- Browser WalletAuth/session UX is not owned by secS-magik, except for the wallet presentation evidence that secS must verify.

## A0 — Language discipline

Use these phrases until code proves stronger claims:

- local production-shaped deployment;
- temporary minimal-equivalent secS wallet presentation until wallet-core parity is reconciled;
- typed fail-closed wallet shell;
- cross-Hub/federated evidence rail;
- static fixture trusted issuer/root policy;
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
| `wallet_presentation` adapter | Solid / implemented as temporary minimal-equivalent secS contract | Cryptographic signature verification, challenge field binding, and fail-closed reject handling exist for wallet-presentation evidence. | Do not claim full Castalia Wallet wallet-core import/parity, production deployment, or trusted issuer/root policy. |
| Verified-context handler routing | Solid / implemented as receiver-local bounded routing after Track F | Handlers consume `VerifiedCallContext`, select by descriptor `handler_id`, enforce local limits, and emit execution receipts for bounded outcomes. | Do not claim durable/distributed broker semantics or broad shell authority. |

Remaining first-prod gaps carried forward into A2–A9:

- production identity/key lifecycle and public-key discovery;
- temporary minimal-equivalent secS wallet cryptographic verification path, with full wallet-core parity still to reconcile before any full wallet-core claim;
- cross-Hub/federated evidence object model, trusted issuer/root representation, and revocation/staleness semantics;
- production policy matrix proving `local_static`/dev evidence cannot satisfy production descriptors;
- first membership-provisioning E2E operation and failure matrix (implemented on main through Track I / PR #76; follow-up runtime/live-ingress gaps are tracked separately);
- phase/branch/PR checklist where phases are PR boundaries and issues are commit boundaries.

A1 stop condition is satisfied when `docs/implementation-status.md` and this checklist agree on the current solid/partial/planned surfaces and preserve caveats for wallet crypto, identity lifecycle, bounded broker, runtime hardening, and federated evidence.

## A2 — Rail taxonomy and non-goals

A2 turns the A0 production target into working ownership boundaries. These boundaries decide what belongs in secS-magik before later slices become implementation issues.

### A2 — Required rails

| Rail | Owned by secS-magik? | Required for first prod? | Scope in this repo | First-prod proof target |
|---|---:|---:|---|---|
| Local production-shaped secS service | Yes | Yes | Runtime mode enforcement, explicit operator/verifier config, bounded handler routing, signed contexts/receipts, redacted local ledger, and documented smoke commands. | Production-mode local smoke rejects local/dev evidence and produces signed verify/execute receipts. |
| Wallet-core-backed user/app auth evidence | Partly | Yes | secS currently verifies a temporary minimal-equivalent secS wallet-presentation contract for a descriptor; canonical Castalia Wallet wallet-core evidence remains future reconciliation. Wallet UI/session UX stays outside this repo. | Wallet presentation happy path plus wrong signature/key/subject/audience/origin/replay/expiry rejects. |
| Cross-Hub/federated evidence evaluation | Yes at verifier/evidence boundary | Yes | Typed evidence adapter/model for trusted issuer/root, remote receipt/capability/credential/revocation/root evidence, and receiver-local policy enforcement. | Fixture trusted issuer/root accepts valid evidence and rejects untrusted, revoked, stale, malformed, wrong-audience, or wrong-operation evidence. |
| Signed receipt/context identity | Yes | Yes | Signer identity, key id, signed `VerifiedCallContext`, signed receipts, and local/operator-visible provenance. | Tamper, wrong key, expired context, and untrusted/revoked issuer checks are named and later tested. |
| Descriptor-bound bounded execution | Yes | Yes | Receiver-local manifest policy binds opcode/operation/evidence to bounded handler execution after verification. | Handlers run only from verified context; oversized payload, unavailable handler, and descriptor mismatch fail closed. |
| Redacted local ledger and operator inspection | Yes | Yes | Local SQLite receipt/event persistence with payload redaction by default and inspectable decision chain. | Verify/reject/execute receipts are inspectable without storing raw payload/evidence by default. |
| End-to-end membership-provisioning proof | Yes for secS verifier/runbook path | Yes | A fixture operation proves machine-to-machine membership provisioning through wallet + federated evidence + bounded handler + receipts. | `membership.provision`, `gallery.member.provision`, or `hub.member.provision` runbook/test proves more than packet echo; #84 pins that fixture smoke/log output or verifier-only acceptance without an accepted execute receipt is non-success. |

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
- `temporary minimal-equivalent secS wallet presentation` for current app/user auth evidence, or `wallet-core-backed evidence` / `wallet-core-defined presentation` after wallet-core parity is reconciled;
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
| `server/src/evidence.rs` | Current implementation extends `wallet_presentation` from shape-only fail-closed shell into cryptographic verification over the temporary minimal-equivalent secS contract; later work should replace/reconcile it with wallet-core parity. |
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
- Wallet-presentation acceptance now requires cryptographic verification over the temporary minimal-equivalent secS challenge contract. Shape-only evidence and `ShapeValidatedSignatureUnsupported` remain fail-closed; full wallet-core parity remains future reconciliation work.
- Federated evidence acceptance uses A5's narrowed first path: `membership_credential` / `provisioning_credential`, receiver-held `TrustedIssuerEntry`, and `registry_status` / `revocation_status`.
- Valid evidence may satisfy descriptor evidence requirements, but receiver-local manifest policy still makes the final local authorization decision.

### A6 — Runtime × descriptor evidence × adapter evidence matrix

| Runtime mode | Descriptor evidence requirement | Adapter / evidence supplied | Expected result | Required future test target |
|---|---|---|---|---|
| `local_dev_plaintext` or `local_dev_tunnel` | dev-marked descriptor / local test operation | plaintext tunnel or `local_static` fixture | Accept only for dev-marked descriptors; emit visibly local/dev receipt context. | `local_dev_descriptor_accepts_local_static_fixture` |
| `local_dev_plaintext` or `local_dev_tunnel` | production descriptor | plaintext tunnel or `local_static` fixture | Reject; local/dev runtime cannot satisfy production authority. | `local_dev_runtime_rejects_production_descriptor` |
| `production_verified` | any production descriptor | missing evidence / plaintext-only packet | Reject before handler execution with typed missing/unsupported evidence reason. | `production_verified_missing_evidence_rejects_before_handler` |
| `production_verified` | wallet presentation | `local_static` | Reject; local static evidence is disallowed for wallet-auth production descriptors. | `production_wallet_descriptor_rejects_local_static` |
| `production_verified` | wallet presentation | shape-only `wallet_presentation` evidence with `ShapeValidatedSignatureUnsupported` / unsupported crypto status | Reject/fail closed; shape-only evidence cannot satisfy wallet authority. | `production_wallet_shape_only_shell_fails_closed` |
| `production_verified` | wallet presentation | temporary minimal-equivalent secS cryptographic presentation with valid signature, subject, audience, origin, operation, resource, replay nonce, public key ref/id, and expiry | Accept only if descriptor permits wallet evidence and receiver-local policy passes; do not call this full wallet-core parity. | `production_wallet_core_presentation_accepts_when_policy_matches` |
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
- `server/tests/wallet_presentation.rs` for temporary minimal-equivalent secS wallet acceptance/rejects;
- future federated evidence tests once A5 objects are implemented;
- ingress/router tests proving rejects happen before handler execution and receipts are emitted.

Do not overfit future tests to exact prose from this checklist. The contract to preserve is the semantic matrix: runtime mode + descriptor requirement + validated evidence + receiver-local policy determines accept/reject.

### A6 — Acceptance

A6 acceptance is met because this checklist now names a runtime mode × descriptor evidence × adapter/evidence matrix, every row has a concrete future test target, `local_static` is explicitly local/dev/test-only, wallet shape-only evidence fails closed in production, cryptographic wallet presentation is bounded to the temporary minimal-equivalent secS contract until wallet-core parity is reconciled, federated rows use the narrowed A5 first-path objects, and forbidden first-path claims are bounded so demoted Dregg/capability/proof/root candidates cannot satisfy production authority without A9 promotion.

## A7 — First membership-provisioning E2E shape

A7 selects the first end-to-end production-shaped flow that later implementation issues must prove. This is still a checklist/design gate, not a claim that the E2E code already exists.

### A7 — Selected first operation

Selected operation: **`membership.provision`**.

Reason: `membership.provision` is generic enough to prove the secS verifier substrate without embedding Gallery product policy, but specific enough to demonstrate real machine-to-machine membership provisioning instead of packet echo. Product-specific aliases such as `gallery.member.provision` may be fixture descriptors later, but the first canonical operation should be generic unless A8 promotes a product-specific phase.

Descriptor intent:

```text
operation: membership.provision
runtime_mode: production_verified
evidence_required:
  - wallet_presentation
  - membership_credential OR provisioning_credential
handler: fixture_membership_provisioner
receipt_chain:
  - verify receipt
  - execution receipt
  - ledger inspection/export row
```

### A7 — Local fixture contract

The first E2E must run locally without real secrets while remaining semantically production-shaped.

Fixture rules:

- Wallet evidence uses generated/ephemeral fixture keys and wallet-core-shaped challenge/presentation bytes; no real wallet private keys are committed.
- Federated evidence uses a static `TrustedIssuerEntry` plus signed fixture `membership_credential` / `provisioning_credential`; no live Castalia/Dregg registry is required.
- Registry/status evidence is fixture `registry_status` / `revocation_status`; do not call it cryptographic revocation proof.
- The handler is a bounded fixture membership provisioner that records a local membership/provisioning result or fixture state transition. It is not a broad shell command and not product membership policy.
- Receipts and ledger rows include evidence summary hashes / ids, signer key ids, decisions, and reason codes without storing raw private evidence or payload contents by default.

### A7 — Happy path flow

1. A client-side surface constructs a `ZenithPacket` v0 for `membership.provision` using the verifier-free packet builder.
2. The request carries a wallet-core-shaped presentation for the caller subject, audience, origin, operation, replay nonce, issued/not-before/expires window, and signature material.
3. The request carries narrowed A5 federated evidence: a signed `membership_credential` or `provisioning_credential`, plus references that chain to receiver-held `TrustedIssuerEntry` and status metadata.
4. secS runs in `production_verified` mode and maps the opcode/operation to the receiver-local `membership.provision` descriptor.
5. The verifier checks wallet presentation semantics and A5 federated evidence, including subject, audience, operation/scope, issuer/root trust, validity window, replay id/nonce, signer key id, and registry/revocation status.
6. The receiver-local manifest policy confirms that this descriptor accepts the supplied wallet + membership/provisioning evidence.
7. The verifier emits a signed `VerifiedCallContext` containing redacted evidence summaries.
8. The descriptor-bound fixture handler provisions local membership state from the verified context only.
9. The ledger stores verify + execute receipts and an operator-inspectable decision chain.

### A7 — Failure matrix and future test targets

| Case | Expected result | Required future test target |
|---|---|---|
| missing wallet presentation | reject before handler execution with typed missing-wallet evidence reason and reject receipt | `membership_provision_missing_wallet_presentation_rejects` |
| wallet presentation shape-only / unsupported crypto | reject/fail closed; only cryptographic presentation over the temporary minimal-equivalent secS contract can satisfy the current wallet verifier | `membership_provision_wallet_shape_only_fails_closed` |
| invalid wallet signature or wrong key | reject before handler execution | `membership_provision_invalid_wallet_signature_rejects` |
| wrong wallet subject | reject; subject must match descriptor/request/evidence binding | `membership_provision_wrong_wallet_subject_rejects` |
| wrong audience or origin | reject with typed audience/origin reason | `membership_provision_wrong_audience_or_origin_rejects` |
| wrong operation in wallet challenge | reject; wallet evidence must bind `membership.provision` | `membership_provision_wallet_wrong_operation_rejects` |
| expired or not-yet-valid wallet challenge | reject before handler execution | `membership_provision_expired_wallet_challenge_rejects` |
| replayed wallet challenge or evidence nonce | reject once replay store is implemented; until then replay-store work remains a production blocker | `membership_provision_replayed_nonce_rejects` |
| missing membership/provisioning credential | reject; wallet evidence alone is insufficient for this E2E descriptor | `membership_provision_missing_federated_credential_rejects` |
| untrusted issuer / embedded key without trust chain | reject `untrusted_issuer` | `membership_provision_untrusted_issuer_rejects` |
| revoked, expired, unknown, not-yet-valid, or stale issuer/key/credential status | reject with typed issuer/evidence status reason | `membership_provision_revoked_or_stale_credential_rejects` |
| wrong credential subject | reject `wrong_subject` | `membership_provision_wrong_credential_subject_rejects` |
| wrong credential audience | reject `wrong_audience` | `membership_provision_wrong_credential_audience_rejects` |
| wrong credential operation/scope | reject `wrong_operation` | `membership_provision_wrong_credential_scope_rejects` |
| descriptor does not accept supplied evidence kind | reject `unsupported_evidence_kind` | `membership_provision_descriptor_rejects_unsupported_evidence_kind` |
| valid wallet + valid credential but receiver-local manifest policy mismatch | reject `local_policy_reject` | `membership_provision_local_policy_rejects_valid_foreign_evidence` |
| handler unavailable | reject/fail execution with execution receipt; verifier acceptance does not imply execution success | `membership_provision_handler_unavailable_emits_execution_receipt` |
| oversized payload or output | reject/fail execution through bounded broker limits | `membership_provision_oversized_payload_rejects` |
| payload/log redaction leak | test proves raw private evidence/payload is not stored in receipts/ledger by default | `membership_provision_receipts_redact_private_evidence` |
| happy path with generated fixtures | accepts, provisions local fixture membership state, signs verified context, emits verify + execute receipts, and supports operator ledger inspection | `membership_provision_fixture_happy_path_emits_receipt_chain` |

### A7 — Runbook outline for later implementation

Later code issues should produce a runnable local command or integration test with this shape:

```bash
SECS_RUNTIME_MODE=production_verified SECS_VERIFIER_KEY_PATH=fixtures/keys/node-verifier.ed25519 SECS_TRUST_REGISTRY_PATH=fixtures/trust/membership-issuers.json cargo test -p server membership_provision_fixture_happy_path -- --nocapture
```

Expected observable outputs:

- verified context signer key id;
- accepted wallet evidence summary hash/id;
- accepted membership/provisioning credential summary hash/id;
- handler result showing local fixture membership provisioned;
- verify receipt id and execution receipt id;
- ledger query/export row with no raw private evidence/payload contents.

### A7 — Acceptance

A7 acceptance is met because the checklist selects `membership.provision` as the first canonical E2E operation, defines the local fixture contract, names the happy path, names the failure matrix with future test targets, requires wallet presentation plus narrowed A5 membership/provisioning credential evidence, preserves local/no-real-secret execution, and makes the success condition membership provisioning with receipt/ledger inspection rather than packet echo.


## A8 — Issue-ready phase/branch/PR checklist for Tracks A–I

A8 converts the remaining Tracks A–I production-readiness work into repo-executable phases. This section is a planning/acceptance gate, not a claim that the implementation phases are already complete.

Boundary rule:

- Phases are branch and pull-request boundaries.
- Issues inside each phase are commit boundaries.
- Do not create one branch or PR per issue unless that issue is explicitly promoted into a whole phase.
- Every issue should follow TDD where it changes runtime behavior: write/verify the failing test first, implement the minimal change, then run the targeted gate and the phase gate.
- Docs-only design gates must name future tests and run docs hygiene; they must not claim runtime behavior is implemented.
- The first production implementation path must preserve A5/A6/A7: wallet presentation plus `membership_credential` / `provisioning_credential`, receiver-held `TrustedIssuerEntry`, `registry_status` / `revocation_status`, receiver-local manifest policy, bounded execution, receipts, and ledger inspection.

### A8 — Phase map

| Phase / tracks | Branch | PR title / scope | Issue / commit sequence | Phase verification gate | Merge / stop condition |
|---|---|---|---|---|---|
| Track A — production-readiness reconciliation | `phase/track-a-ready-for-prod` | `docs: define secS ready-for-prod implementation train` | A0 through A9, one commit per slice | `git diff --check -- CHANGELOG.md README.md AGENTS.md docs/` plus targeted `rg` checks for A0–A9 acceptance terms | Merge only after A9 explicitly defers or promotes Dregg/Midnight/Cardano and the checklist no longer contains unresolved Track A decisions. |
| Track B — production identity and key lifecycle | `phase/track-b-identity-key-lifecycle` | `feat(server): add production verifier identity lifecycle` | B1 key config/loading; B2 key id/public registry; B3 signed-context/receipt production posture; B4 rotation/revocation tests/docs | `cargo test -p server identity receipt verifier -- --nocapture`; `cargo test --workspace`; `cargo build --workspace`; `cargo fmt --all -- --check`; strict Clippy if available | Stop when operator-visible key path, key ids, signatures, wrong-key/tamper tests, local/dev non-authoritative labels, and B4 unknown/revoked/expired/not-yet-valid own-verifier lifecycle checks are complete without hidden long-lived key generation. |
| Track C — replay, session, and expiry enforcement | `phase/track-c-replay-session-expiry` | `feat(server): enforce replay session and expiry policy` | C1 replay store interface; C2 descriptor TTL/session/audience binding; C3 reject receipts for replay/expiry/session failures; C4 docs/status acceptance; review-fix commits may extend test coverage without widening the runtime scope | `cargo test -p server --test ledger replay -- --nocapture`; `cargo test -p server --test gateway_layout replay -- --nocapture`; `cargo test -p server --test verifier_context -- --nocapture`; workspace tests/build/fmt/Clippy | Stop when production packets cannot execute twice within the configured receiver-local replay store/scope, stale/overlong claims reject before handlers, receipt reasons are stable, and pre-verification/signature failures do not consume replay slots. |
| Track D — wallet cryptographic verification / shared wallet core | `phase/track-d-wallet-core-crypto` | `feat(server): verify wallet presentations cryptographically` | Complete through D4: D0 baseline; D1 temporary minimal-equivalent secS challenge contract; D2 secS verifier integration; D3 wallet reject matrix; D4 client/browser/native packaging notes | `cargo test -p server wallet_presentation -- --nocapture`; `cargo test -p server wallet_challenge_contract -- --nocapture`; `cargo test -p server --test ready_for_prod_docs -- --nocapture`; docs `rg`; `cargo fmt --all -- --check`; `git diff --check` | Complete when `wallet_presentation` has a successful cryptographic path and wrong signature/key/subject/audience/origin/operation/resource/replay/expiry/future-issued/malformed/missing evidence reject over the temporary contract, with docs explicitly saying this is not a full wallet-core import/parity. |
| Track E — production evidence policy and first federated evidence path | `phase/track-e-production-evidence-policy` | `feat(server): enforce production evidence policy and trusted issuer credentials` | Complete locally through E11: E1 typed evidence kinds/production policy; E2 shared fixtures; E3 trusted issuer registry seam; E4 signed membership/provisioning verifier; E5 reject matrix; E6 wallet+issuer composition; E7 descriptor-local gates; E8 fixture registry loader; E9 A6 policy matrix; E10 summary/reason safety; E11 docs/status sync; E12 phase gate/PR remains pending | `cargo test -p server policy_matrix -- --nocapture`; `cargo test -p server evidence_summary_redacts_private_material -- --nocapture`; docs `rg`; `git diff --check`; E12 still needs broader workspace/fmt/Clippy/PR CI gate | Stop when `local_static` cannot satisfy production descriptors and trusted active membership/provisioning credentials can satisfy only permitted operations after receiver-local policy. Locally true after E1–E10; not merged until PR/main CI pass. |
| Track F — bounded execution broker | `phase/track-f-bounded-execution-broker` | `feat(server): execute verified operations through bounded handlers` | F1 descriptor-bound handler registry; F2 timeout/payload/output limits; F3 execution receipts for all outcomes; F4 gate dev subprocess path; review hardening for streaming output cap, process-group timeout cleanup, signed-context descriptor revalidation, and max in-flight connection cap | `cargo test -p server --test gateway_layout -- --nocapture`; `cargo test -p server`; workspace tests/build/fmt/Clippy | Stop when no broad shell authority is reachable by default, handler selection is descriptor-bound, subprocess output and runtime tasks are bounded, and every routed success/failure emits an execution receipt. |
| Track G — ingress/service runtime hardening | `phase/track-g-service-runtime-hardening` | `feat(server): harden production service runtime and smokes` | G1 canonical production binary/config; G2 startup fail-fast checks; G3 health/readiness or CLI checks; G4 local production smoke script; review hardening for config-bound runtime mode, explicit production bind/DB/ledger/limits, trust registry readiness, fixture-only smoke gating, and live binary smoke | `cargo test --workspace`; `cargo build --workspace`; `scripts/production-gateway-smoke.sh`; `git diff --check` | Stop when an operator can run a documented local `production_verified` fixture smoke without insecure default config, local/dev authority, or secret/payload leaks. |
| Track H — receipt/event ledger production posture | `phase/track-h-ledger-operator-inspection` | `feat(server): add operator receipt inspection and redaction posture` | H1 receipt query/export; H2 retention/redaction policy; H3 receipt schema/versioning; H4 receipt-chain integration tests | `cargo test -p server ledger receipt -- --nocapture`; workspace tests/build/fmt/Clippy | Stop when operators can inspect accepted/rejected/executed decisions and receipts remain local/redacted/versioned without claiming public anchoring. |
| Track I — first production-shaped membership-provisioning E2E | `phase/track-i-membership-provision-e2e` | `feat(server): prove membership.provision production-shaped e2e` | I1 fixture client packet/evidence builder; I2 happy-path E2E; I3 A7 failure matrix; I4 runbook and operator expected-output docs | `SECS_RUNTIME_MODE=production_verified SECS_VERIFIER_KEY_PATH=fixtures/keys/node-verifier.ed25519 SECS_TRUST_REGISTRY_PATH=fixtures/trust/membership-issuers.json cargo test -p server membership_provision -- --nocapture`; workspace tests/build/fmt/Clippy | Stop when `membership.provision` proves real local fixture membership provisioning with signed verify + execute receipts and ledger inspection, not packet echo. |

### A8 — Track A issue/commit sequence

Track A is the current checklist branch. It remains docs/design work until A9 is complete.

| Issue / commit | Objective | Files | Commands | Acceptance criteria | Stop condition | Must not claim |
|---|---|---|---|---|---|---|
| A0 — Lock production definition | Encode that first-prod requires local production-shaped deployment, wallet-backed app/user auth, and cross-Hub/federated evidence. | `docs/plans/2026-06-02-ready-for-prod-checklist.md`, `CHANGELOG.md` | `rg "local single-node|Wallet-backed|cross-Hub|federated evidence|not enough" docs/plans/2026-06-02-ready-for-prod-checklist.md`; `git diff --check -- CHANGELOG.md docs/` | All three rails are required and local smoke alone is insufficient. | Commit only this scope. | Do not narrow first-prod to local smoke only. |
| A1 — Reconcile repo status | Align status ledger and checklist through Issue 4.2. | `docs/implementation-status.md`, checklist, `CHANGELOG.md` | `rg "wallet_presentation|local_static|federated|Dregg|planned|production" docs/implementation-status.md docs/plans/2026-06-02-ready-for-prod-checklist.md` | Solid/partial/planned/future surfaces are not contradictory. | Stop before new runtime claims. | Do not mark wallet crypto/federation/runtime hardening implemented. |
| A2 — Rail taxonomy and non-goals | Separate secS-magik work from Wallet, Dregg, Matrix, Gallery, Hub app policy, Midnight, and Cardano. | checklist, `CHANGELOG.md` | `rg "Required rails|Non-goals|Matrix|Dregg consensus|Wallet|Language discipline" docs/plans/2026-06-02-ready-for-prod-checklist.md` | Required/deferred/non-goal rails are readable by future agents. | Stop after taxonomy. | Do not smuggle product policy or external rails into secS scope. |
| A3 — Identity/key lifecycle gate | Select first signer/key posture and future tests. | checklist, `CHANGELOG.md` | `rg "node_verifier_key|Ed25519|signer_key_id|authenticator_kind|revoked|wrong key|rotation" docs/plans/2026-06-02-ready-for-prod-checklist.md` | First key model, config path, key id, discovery path, revocation/rotation posture, and tests are explicit. | Stop before coding identity. | Do not claim production key rotation/discovery exists. |
| A4 — Wallet-core integration gate | Select direct minimal wallet-core verifier API first and bound fallback artifact path; Track D later used a temporary minimal-equivalent secS contract because inspected wallet-core parity was incomplete. | checklist, `CHANGELOG.md` | `rg "direct minimal Castalia Wallet Rust core verifier API|signed/traceable artifact|duplicate secS wallet verifier|WASM|native|temporary minimal-equivalent" docs/plans/2026-06-02-ready-for-prod-checklist.md` | secS does not claim full wallet-core parity; packaging implications are named. | Stop before adding dependencies. | Do not treat shape-only wallet shell as production auth or the temporary contract as full wallet-core integration. |
| A5 — Federated evidence model gate | Define first federated objects, trusted issuer/root registry, status, expiry/replay, and typed failures. | checklist, `CHANGELOG.md` | `rg "membership_credential|provisioning_credential|TrustedIssuerEntry|registry_status|revocation_status|untrusted_issuer|wrong_audience|wrong_operation|wrong_subject" docs/plans/2026-06-02-ready-for-prod-checklist.md` | First path uses credentials + static trust registry/status; demoted candidates are future. | Stop before policy matrix. | Do not call static status Dregg validation or cryptographic revocation proof. |
| A6 — Production policy matrix | Convert A0/A2/A5 into accept/reject rows with future test targets. | checklist, `CHANGELOG.md` | `rg "production_verified|local_static|wallet presentation|membership_credential|provisioning_credential|TrustedIssuerEntry|revocation_status|future test target" docs/plans/2026-06-02-ready-for-prod-checklist.md` | Every row has a future test target; local/dev evidence cannot satisfy production. | Stop after matrix. | Do not let local_static/plaintext/caller roots satisfy production authority. |
| A7 — First E2E shape | Select `membership.provision`, fixture contract, happy path, failure matrix, and runbook outline. | checklist, `CHANGELOG.md` | `rg "membership.provision|fixture_membership_provisioner|membership_provision_.*rejects|receipt|ledger|packet echo" docs/plans/2026-06-02-ready-for-prod-checklist.md` | The E2E proves fixture provisioning plus receipts/ledger, not packet echo. | Stop after E2E contract. | Do not require real secrets or live Dregg/Midnight/Cardano. |
| A8 — Issue-ready phase checklist | Group Tracks A–I into phases with branch, PR, issue/commit sequence, gates, stop conditions, and forbidden claims. | checklist, `CHANGELOG.md`, capture surface | `rg "phase/track-b-identity-key-lifecycle|phase/track-i-membership-provision-e2e|phases are branch|issues are commit|membership_credential|TrustedIssuerEntry" docs/plans/2026-06-02-ready-for-prod-checklist.md`; `git diff --check -- CHANGELOG.md README.md AGENTS.md docs/` | An agent can pick the first future issue without rediscovering context; A5/A6/A7 downstream work is preserved. | Commit only docs/status/capture surfaces for A8. | Do not create one branch/PR per issue or build around demoted A5 candidates. |
| A9 — Future rail decision | Defer or promote Dregg, Midnight, and Cardano explicitly. | checklist, `CHANGELOG.md`, capture surface | `rg "Dregg|Midnight|Cardano|deferred|promoted|trust_root_ref|registry_root_ref" docs/plans/2026-06-02-ready-for-prod-checklist.md` | J–L cannot enter implementation silently. | Merge Track A only after this row is complete. | Do not call fixture roots live Dregg validation. |

### A8 — Track B issue/commit details: production identity and key lifecycle

| Issue / commit | Objective | Files | TDD / verification commands | Acceptance criteria | Stop condition | Must not claim |
|---|---|---|---|---|---|---|
| B1 — Explicit node/verifier key config | Add operator-visible key loading for the first `node_verifier_key` posture. | `server/src/identity.rs`, `server/src/verifier.rs`, `server/src/receipt.rs`, `server/src/lib.rs`, docs/config docs | RED: tests for missing production key path and hidden generation rejection. GREEN: `cargo test -p server identity_key_config -- --nocapture` | Production mode loads keys only from explicit env/file config; tests may generate ephemeral keys. | Stop after config/load behavior and docs. | Do not generate hidden long-lived production keys. |
| B2 — Deterministic key id and public registry seam | Define key id format and receiver-held public key lookup/registry seam. | `server/src/identity.rs`, possible `server/src/trust.rs`, `docs/implementation-status.md` | RED/GREEN targeted key id + wrong-key lookup tests; workspace gate | Contexts/receipts include deterministic `signer_key_id`; wrong/untrusted key rejects. | Stop before rotation state if not in this commit. | Do not claim live federation registry discovery. |
| B3 — Signed context/receipt production posture | Ensure signed contexts and receipts use the configured key path in production and local/dev markers stay visibly non-authoritative. | `server/src/verifier.rs`, `server/src/receipt.rs`, tests | RED/GREEN tamper, wrong key, expired context, local-dev marker tests | `authenticator_kind`, `signer_key_id`, and signatures are present and verified. | Stop when existing tests and new production-key tests pass. | Do not call local_dev_untrusted public proof. |
| B4 — Rotation/revocation test posture | Add first revocation/rotation seam or explicit TODO-backed registry contract if implementation waits for Track E. | `server/src/identity.rs`, checklist/status docs | RED/GREEN revoked key rejects if seam is implemented; otherwise docs hygiene + future test target checks | Revoked/untrusted/expired key cases are represented by code or explicitly carried as production blockers. | Stop when Track E dependency is clear. | Do not pretend rotation/revocation is production-complete unless real state exists. |

#### B1 completion checkpoint

B1 is implemented on `phase/track-b-identity-key-lifecycle` as the issue-boundary runtime slice for explicit node/verifier key config.

Implementation evidence:

- `server/src/identity.rs` defines `VerifierIdentityConfig`, `NodeVerifierIdentity`, typed `IdentityConfigError` values, `load_node_verifier_identity`, and the explicit `explicit_test_fixture_identity` helper.
- `production_verified` without a verifier key path fails before serving or signing with `MissingVerifierKeyPath`.
- Missing/inaccessible key files fail as `KeyFileInaccessible`; malformed key material fails as `MalformedVerifierKey`.
- Valid operator key files load into a signer identity that exposes `signer_key_id`, public key bytes, and context/receipt signing helpers.
- Local/dev generated identities are represented only by the explicit test fixture helper and are stamped `LocalDevUntrusted`.

Verification evidence:

```bash
cargo test -p server identity_key_config -- --nocapture
cargo test -p server verifier -- --nocapture
cargo test -p server receipt -- --nocapture
```

B1 remains bounded: no public-key registry discovery, deterministic key-id scheme, rotation, revocation, Dregg/Castalia registry lookup, wallet-core crypto, Midnight, or Cardano semantics are implemented or claimed by this issue.

#### B2 completion checkpoint

B2 is implemented on `phase/track-b-identity-key-lifecycle` as the issue-boundary runtime slice for deterministic verifier key ids and the first local public-key lookup seam.

Implementation evidence:

- `server/src/identity.rs` defines `derive_ed25519_key_id`, `PublicVerifierKey`, and `PublicVerifierKeyRegistry`.
- Default production identity loading derives `signer_key_id` as `ed25519:<sha256-public-key-fingerprint>` when no safe explicit key-id override is configured.
- Explicit key-id overrides reject empty values, local path-shaped values, and 64+-char hex secret-shaped values as `UnsafeVerifierKeyId`.
- Signed contexts and signed receipts inherit the identity signer id.
- `PublicVerifierKeyRegistry` verifies signed contexts and receipts by declared key id and rejects unknown key ids or signatures that only verify under a different key.

Verification evidence:

```bash
cargo test -p server identity_key_id -- --nocapture
cargo test -p server wrong_key -- --nocapture
cargo test -p server verifier_context -- --nocapture
cargo test -p server receipt -- --nocapture
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check -- CHANGELOG.md README.md AGENTS.md docs/ server/
```

B2 remains bounded: no live federation registry discovery, trusted issuer policy, key status, key revocation, key rotation, Dregg/Castalia registry lookup, wallet-core crypto, Midnight, or Cardano semantics are implemented or claimed by this issue.

#### B3 completion checkpoint

B3 is implemented on `phase/track-b-identity-key-lifecycle` as the issue-boundary runtime slice for configured signed-context and signed-receipt production posture.

Implementation evidence:

- `server/src/verifier.rs` exposes `verify_manifest_operation_and_sign_with_identity`, so manifest-derived signed contexts can be signed by the loaded `NodeVerifierIdentity` rather than raw signer constants.
- `server/src/ingress.rs` loads `SECS_VERIFIER_KEY_PATH` / `SECS_VERIFIER_KEY_ID` through `VerifierIdentityConfig::from_env()` when `production_verified` is active and fails before serving if the production identity cannot load.
- `server/src/gateway.rs` carries a `NodeVerifierIdentity`, verifies signed contexts against its local own-verifier key registry before emitting verify/execute receipts or invoking handlers, and signs receipts through that configured identity.
- `ConfigurableRouter::with_identity` supports production-shaped receipt signing with the loaded identity, while default/local fixture routers use `explicit_test_fixture_identity` and stamp receipts as `local_dev_untrusted`.
- Existing context/receipt tamper, wrong-key, wrong-audience, and expired-context tests remain green.

Verification evidence:

```bash
cargo test -p server verifier_signs_manifest_context_with_loaded_production_identity -- --nocapture
cargo test -p server gateway_router -- --nocapture
cargo test -p server verifier_context -- --nocapture
cargo test -p server receipt -- --nocapture
cargo test -p server identity -- --nocapture
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check -- CHANGELOG.md README.md AGENTS.md docs/ server/
```

B3 remains bounded: no production key rotation/revocation, trusted issuer/root registry policy, live federation discovery, wallet-core crypto, Dregg/Castalia registry lookup, Midnight, Cardano, or public receipt/audit anchoring is implemented or claimed by this issue.

#### B4 completion checkpoint

B4 is implemented on `phase/track-b-identity-key-lifecycle` as the issue-boundary runtime slice for the first own-verifier key rotation/revocation posture.

Implementation evidence:

- `server/src/identity.rs` extends `PublicVerifierKey` entries with `status`, `not_before`, `not_after`, `revoked_at`, `replaced_by`, and `production_authority` fields.
- `VerificationKeyStatus` explicitly represents `active`, `revoked`, `expired`, `unknown`, and `not_yet_valid` status states.
- `PublicVerifierKeyRegistry::verify_signed_context` and `verify_receipt_at` reject unknown key ids, duplicate key ids, revoked keys including effective `revoked_at` metadata, expired keys, unknown-status keys, and keys outside their validity windows before trusting signatures.
- Receipt verification evaluates key validity at the receipt's signing timestamp, so historical receipts signed while the verifier key was valid can still verify after later key expiry while receipts signed after expiry reject.
- `PublicVerifierKey::active` is fail-closed for production authority by default; `NodeVerifierIdentity::public_verifier_key` marks only configured non-local verifier identities as production authority, and `verify_production_signed_context` / `verify_production_receipt_at` reject local/dev/test fixture keys, non-`ed25519_node_and_verifier` authenticator kinds, and non-`ed25519` key metadata even when their signatures verify.
- Production identity loading rejects symlink and group/world-readable verifier key files, and the public `NodeVerifierIdentity` API no longer exposes raw secret key bytes.
- Rotation metadata is intentionally non-transitive: `replaced_by` documents a successor key id but does not automatically trust that replacement unless it is separately configured and active in the registry.

Verification evidence:

```bash
cargo test -p server identity_key_status -- --nocapture
cargo test -p server revoked_key_rejects -- --nocapture
cargo test -p server expired_key_rejects -- --nocapture
cargo test -p server --test identity -- --nocapture
cargo test -p server verifier_context -- --nocapture
cargo test -p server receipt -- --nocapture
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

B4 remains bounded: this is an own configured verifier-key lifecycle seam, not a complete production trusted issuer/root registry. Static `TrustedIssuerEntry` policy, federated credential status checks, live Castalia/Dregg discovery, cryptographic revocation proof, wallet-core crypto, Midnight, Cardano, and operator rotation runbooks remain future Track E or later work unless explicitly promoted.

### A8 — Track C issue/commit details: replay, session, and expiry enforcement

| Issue / commit | Objective | Files | TDD / verification commands | Acceptance criteria | Stop condition | Must not claim |
|---|---|---|---|---|---|---|
| C1 — Replay store interface | Add replay/nonce store trait with in-memory and local test implementation. | `server/src/session.rs`, possible `server/src/replay.rs`, `server/src/verifier.rs` | RED duplicate nonce executes; GREEN `cargo test -p server replay_store -- --nocapture` | Duplicate replay scope can be detected deterministically. | Stop before descriptor policy changes. | Do not claim distributed/global replay protection. |
| C2 — Descriptor TTL/session/audience binding | Bind TTL/replay scope to subject, session, audience, operation, and descriptor max TTL. | `server/src/manifest.rs`, `server/src/verifier.rs`, tests | RED wrong audience/session/overlong TTL cases; targeted tests | Expired or over-long claims reject before handler execution. | Stop after typed verifier rejects. | Do not rely on packet TTL alone as full credential expiry. |
| C3 — Reject receipts for replay/expiry/session failures | Persist typed reject receipts for replay, expiry, wrong session/audience. | `server/src/ingress.rs`, `server/src/receipt.rs`, `server/src/ledger.rs`, tests | RED receipt absent on replay reject; GREEN targeted ledger/receipt tests | Reject reasons are receipt-backed and inspectable. | Stop when handler is not called on reject. | Do not expose raw payload/evidence in receipts. |
| C4 — Docs/status acceptance | Record implemented Track C behavior and bounded claims after C1–C3. | `docs/implementation-status.md`, checklist, maybe README/changelog/docs-contract tests | RED/GREEN docs-contract status tests; `git diff --check`; targeted replay tests | Track C status names receiver-local/local durable replay/session/expiry enforcement, stable reject reasons, and non-consumption of replay slots on pre-verification/signature failure. | Stop after docs match implemented behavior. | Do not claim distributed/global/cross-Hub/cluster-wide replay, wallet crypto, trusted issuer/root registry, Dregg/Midnight/Cardano rails, ingress DoS hardening, bounded subprocess containment, or public auditability. |

#### Track C completion checkpoint

Track C was completed on fresh branch `phase/track-c-replay-session-expiry-v2` as a receiver-local bounded-claim implementation. It implements receiver-local/local durable replay/session/expiry enforcement only within the configured receiver-local replay store/scope.

Implementation evidence:

- Duplicate `(session_id, opcode, nonce, replay_scope)` verified contexts reserve atomically in local SQLite, including concurrent identical routes, and duplicate reservations reject with `replay_detected` before telemetry or handler execution.
- Runtime DDL now lives in `server/src/schema.rs` as a named schema ontology for `events`, `receipts`, `replay_reservations`, and `node_telemetry`; ledger/gateway initialization applies those named table definitions instead of embedding `CREATE TABLE` DDL inline.
- Prototype receiver constants now live in `server/src/ontology.rs` for the default receiver audience, prototype local subject, local test audience/origin, local prototype signer id, unverified prototype operation label, and replay reservation reason strings.
- Descriptor max TTL overclaims reject with `claim_ttl_exceeds_descriptor_max` before signed context issuance.
- All-zero session IDs reject with `invalid_session` before signed context issuance.
- Expired, wrong-audience, and invalid-signature signed contexts emit signed reject receipts/events before replay reservation and before handler execution.
- Pre-verification/signature failures emit signed reject receipts/events where the router has identity context, preserve stable reason codes, avoid raw payload content, and do not consume replay slots.

Verification evidence:

```bash
cargo test -p server --test ledger replay -- --nocapture
cargo test -p server --test gateway_layout replay -- --nocapture
cargo test -p server --test gateway_layout gateway_router_concurrent_identical_replay_executes_once -- --nocapture
cargo test -p server --test schema -- --nocapture
cargo test -p server --test verifier_context -- --nocapture
cargo test -p server --test ready_for_prod_docs -- --nocapture
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check -- README.md CHANGELOG.md docs/ server/
```

Boundary assessment: C1–C4 are the planned Track C runtime/docs slices. The additional C5/C6 review-fix commits did not widen Track C into Track F/G/H/E; they repaired audit consistency for Track C reject paths and added explicit concurrent replay coverage required by issue #23. C7 updated the repo/capture/PR boundary assessment, and C8 moved inline DDL plus repeated receiver constants into central schema/ontology modules without changing the Track C runtime boundary. C2/C3 are broader than issue #23 alone, but they are inside the planned Track C phase boundary from the A8 phase map.

Centralization follow-ups for later tracks:

- Move runtime receiver audience from prototype constant toward operator configuration when Track G production service runtime hardening lands.
- Consider a typed reason-code module or enum for gateway-only execution/replay reasons (`payload_too_large`, `handler_timeout`, `handler_unavailable`, handler subprocess errors) before Track F/H expand handler/ledger surfaces.
- Replace remaining test-local repeated audience/subject/origin fixtures with shared fixture helpers if those tests start driving production policy in Tracks D/E/I; until then they are test data, not runtime authority.

C4 remains bounded: Track C is not distributed/global/cross-Hub/cluster-wide replay protection, does not complete production wallet crypto, trusted issuer/root registry, Dregg/Midnight/Cardano rails, ingress DoS hardening, bounded subprocess side-effect containment, or ledger public auditability, and must not be described as “production packets cannot execute twice” unless qualified as within the configured receiver-local replay store/scope.

### A8 — Track D issue/commit details: wallet cryptographic verification / shared wallet core

Track D branch: `phase/track-d-wallet-core-crypto`.
Primary issue: #34, phase issue: #62.

Hardened start-of-phase finding (2026-06-05): the inspected Castalia Wallet Rust core at `/Users/bananawalnut/repos/castalia-wallet/crates/castalia-wallet-core` exposes `verify_presentation`, `verify_signature`, and `canonical_challenge_bytes`, but its current challenge bytes bind `audience`, `domain`, `expiresAt`, `issuedAt`, `nonce`, `operation`, `origin`, and `version` only. They do not yet bind secS-required `subject`, `resource` / payload schema, or `public_key_ref` as first-class challenge fields. Therefore Track D must either (a) land an upstream wallet-core change before importing it, or (b) implement an explicitly temporary secS minimal-equivalent challenge contract/wrapper that binds the full secS list. If (b), docs and code must name it temporary and must not claim full Castalia Wallet integration.

| Issue / commit | Objective | Files | TDD / verification commands | Acceptance criteria | Stop condition | Must not claim |
|---|---|---|---|---|---|---|
| D0 — Branch/spec baseline and shared fixture helpers | Start from clean `main`, record the wallet-core inspection finding, create shared D/E/I fixture constants/helpers, and add RED baseline tests for crypto-required wallet evidence. | `server/tests/wallet_presentation.rs`, `server/tests/evidence.rs`, docs/status/checklist/capture | `cargo test -p server wallet_presentation -- --nocapture`; initial RED tests may be ignored only with a named blocker before D1 | Branch is clean; Track D spec and issue surfaces reflect the wallet-core binding gap; literals for subject/audience/origin/operation/resource/timestamps/nonces start moving into shared helpers before new matrix tests proliferate. | Stop before implementation if wallet-core binding ambiguity is not resolved. | Do not begin D1 from scattered literals or an unrecorded wallet-core assumption. |
| D1 — Wallet-core challenge/signature contract | Import wallet-core only if it binds the full secS challenge, otherwise implement and document a temporary minimal-equivalent secS challenge contract. | `Cargo.toml`, `server/src/evidence.rs`, wallet integration docs | RED compile/test against desired wallet-core verifier API or RED minimal-contract challenge tests; `cargo test -p server wallet_challenge_contract -- --nocapture` | Challenge bytes bind subject, audience, origin, operation, resource, nonce, issued/expires, signature suite, and public key ref/id; exact byte layout/order is tested and documented. | Stop before positive evidence acceptance. | Do not duplicate wallet semantics independently in secS without marking the contract temporary/minimal. |
| D2 — Cryptographic wallet presentation verification | Replace unsupported shell acceptance with a positive cryptographic verification path over the D1 contract. | `server/src/evidence.rs`, `server/tests/wallet_presentation.rs` | RED valid fixture rejected; GREEN `cargo test -p server wallet_presentation valid_fixture_verifies_cryptographically -- --nocapture` | Valid fixture presentation verifies cryptographically and emits safe evidence summary. Shape-only unsupported status remains fail-closed unless crypto passes. | Stop when positive path is crypto-backed and secret-safe. | Do not commit real wallet private keys; do not leak raw private keys/signatures in summaries/logs/receipts. |
| D3 — Wallet reject matrix | Add exhaustive wrong signature/key/subject/audience/origin/operation/resource/replay/expiry/future-issued/malformed/missing-evidence tests. | wallet tests, verifier/evidence code | `cargo test -p server wallet_presentation -- --nocapture`; targeted reason-code checks | Each failure rejects distinctly enough for debugging/policy; changing any contextual challenge field invalidates the signature or maps to the right typed reject; shared fixture helpers are used exclusively. | Stop before federated credentials. | Do not treat browser WalletAuth HTTP session as secS wallet presentation; do not bypass crypto with shape-only status. |
| D4 — Packaging and client-surface notes + phase close | Document native/WASM/browser/secC/secZ packaging boundary and update status/changelog/checklist/capture surfaces. | `docs/client-surfaces.md`, README/status docs, `CHANGELOG.md`, capture surfaces | docs `rg`, `git diff --check`, full workspace gate and PR CI | Browser extension = WASM binding, secZ/secC = native/client binding, secS = verifier subset/artifact consumer; status surfaces name whether this is wallet-core import or temporary minimal equivalent. | Stop when docs are consumer-oriented and post-merge main CI passes. | Do not make packaging notes into runtime implementation claims; do not claim production deployment/public auditability/Dregg authority. |

#### D1 completion checkpoint

D1 defines an explicitly temporary secS wallet challenge contract in `server/src/evidence.rs` because the hardened start-of-phase wallet-core finding showed current wallet-core challenge bytes do not bind every secS-required field. The contract is minimal-equivalent pending Castalia Wallet wallet-core parity and must be replaced or reconciled before secS claims full wallet-core integration. Its canonical byte contract binds subject, audience, origin, operation, resource, nonce, issued/expires timestamps, signature suite, and public key ref/id with exact layout/order covered by `server/tests/wallet_challenge_contract.rs`. D1 does not wire adapter success, does not add a wallet-core dependency, and does not make `wallet_presentation` cryptographic acceptance production-ready.

#### Track D completion checkpoint

Track D is complete through D4 as a bounded wallet-presentation verifier slice. The implemented verifier is cryptographic for signed presentation/challenge evidence over the explicitly temporary minimal-equivalent secS challenge contract in `server/src/evidence.rs`; it is not a full Castalia Wallet wallet-core import and must be replaced or reconciled when wallet-core challenge parity binds the secS-required fields directly.

Implementation evidence:

- D1 canonical challenge bytes bind subject, audience, origin, operation, resource, nonce, issued/expires timestamps, signature suite, and public key ref/id with exact order covered by `server/tests/wallet_challenge_contract.rs`.
- D2 accepts the valid no-real-secret fixture cryptographically and emits safe public evidence summary fields without `ShapeValidatedSignatureUnsupported`.
- D3 rejects wrong signature, wrong key, wrong subject, wrong audience, wrong origin, wrong operation, wrong resource, changed replay nonce, expired challenge, future-issued challenge, malformed bytes, unsupported signature suite, missing evidence, and unknown evidence refs with typed fail-closed results.
- D4 documents the packaging/client-surface boundary: browser extension = WASM binding, secZ/secC/local clients = native/client binding or packet/evidence carrier, and secS = verifier subset/artifact consumer.

Verifier-consumer boundary:

- secS consumes signed presentation/challenge bytes plus public verification material.
- secS does not consume UI session state, app cookies, extension runtime state, or browser WalletAuth sessions as verifier authority.
- secZ/secC/local clients may construct or transport presentation evidence, but they do not decide authority.

Verification evidence:

```bash
cargo test -p server wallet_presentation -- --nocapture
cargo test -p server wallet_challenge_contract -- --nocapture
cargo test -p server --test ready_for_prod_docs -- --nocapture
rg "wallet|temporary minimal|verifier subset|ShapeValidatedSignatureUnsupported" docs/ README.md server/README.md --files-with-matches
cargo fmt --all -- --check
git diff --check README.md CHANGELOG.md docs/ server/
```

Track D remains bounded: it does not claim production deployment, public auditability, live Castalia Wallet parity, full wallet-core integration, Dregg/Midnight/Cardano authority, trusted issuer/root policy, or the first production-shaped `membership.provision` E2E.

### A8 — Track E issue/commit details: production evidence policy and first federated evidence path

| Issue / commit | Objective | Files | TDD / verification commands | Acceptance criteria | Stop condition | Must not claim |
|---|---|---|---|---|---|---|
| E1 — Descriptor runtime evidence policy | Add production/dev evidence policy fields or equivalent verifier config. | `server/src/manifest.rs`, `server/src/evidence.rs`, `server/src/verifier.rs`, tests | RED production descriptor accepts `local_static`; GREEN policy reject tests | `local_static` and plaintext cannot satisfy production descriptors. | Complete locally as `704a17b` with typed evidence kinds and production-policy baseline rejects. | Do not weaken local/dev fixtures; keep them local/dev only. |
| E2 — Trusted issuer registry objects | Implement static `TrustedIssuerEntry` and key/status lookup for fixture first path. | `server/src/evidence.rs` or `server/src/trust.rs`, fixtures/tests | RED untrusted embedded key accepted; GREEN trusted/untrusted issuer tests | Receiver-held issuer/root metadata controls trust; embedded keys are evidence data only. | Complete locally across `0d2ec62` shared trust fixtures and `4c391aa` registry seam. | Do not call static registry live Castalia/Dregg discovery. |
| E3 — Membership/provisioning credential verifier | Verify signed fixture `membership_credential` / `provisioning_credential` with subject/audience/operation/status binding. | evidence/trust modules, tests/fixtures | RED valid credential unsupported; GREEN `cargo test -p server production_federated -- --nocapture` | Trusted active credential can satisfy permitted descriptor; wrong subject/audience/operation/status rejects. | Complete locally as `9f9b8a9`; reject matrix, wallet composition, descriptor-local gates, registry loader, A6 matrix, and summary safety followed in E5–E10. | Do not use remote receipts or capability caveats as first-path authority. |
| E4 — A6 production policy matrix tests | Turn A6 rows into semantic tests. | `server/tests/evidence.rs`, `server/tests/wallet_presentation.rs`, possible production policy tests | Run named A6 future targets where implemented plus workspace gate | The matrix is executable for local/dev, wallet, and federated first-path rows. | Complete locally as `7ab1bf4` after E5 `ddb4b0c`, E6 `dc5f0ba`, E7 `f1ecdc3`, E8 `f2d6a36`, and before E10 `f18adde`; E12 phase gate still pending. | Do not overfit to prose; preserve semantic accept/reject contract. |

#### Track E local completion checkpoint through E11

Track E is implemented locally on `phase/track-e-production-evidence-policy` through E11. E1–E10 are committed and tested locally: `704a17b` typed evidence kinds and production-policy baseline rejects; `0d2ec62` shared Track E trust fixtures; `4c391aa` trusted issuer registry seam; `9f9b8a9` signed membership/provisioning verifier; `ddb4b0c` credential reject matrix; `dc5f0ba` wallet + issuer composition; `f1ecdc3` descriptor-local gates; `f2d6a36` fixture registry loader; `7ab1bf4` A6 policy matrix tests; and `f18adde` evidence summary safety, reason codes, and operator-inspection distinction.

Implementation evidence:

- `server/src/evidence.rs` defines `TrustedIssuerEntry`, `TrustedIssuerRegistry`, typed `membership_credential` / `provisioning_credential` evidence kinds, static registry loading, credential verification, status/root/ref checks, safe evidence summaries, and typed failure reason surfaces.
- `server/tests/support/trust_fixtures.rs` and `server/tests/support/wallet_fixtures.rs` provide shared no-real-secret D/E/I fixture values for issuer/root/credential and wallet subject/audience/origin/resource data.
- `server/tests/trust.rs` covers registry/loader and trusted-issuer fail-closed behavior.
- `server/tests/production_federated.rs` covers valid and rejected membership/provisioning credentials, wallet+issuer composition, descriptor-local policy, A6 policy-matrix rows, redaction safety, and reason-code/operator-inspection distinctions.

Track E changed authority semantics by making production evidence acceptance receiver-held and layered: wallet proof-of-possession may be necessary where a descriptor requires it, but it is never sufficient issuer/root authority; caller-supplied keys/root refs are evidence data only; static `TrustedIssuerEntry` metadata and descriptor-local policy decide whether signed membership/provisioning credentials can satisfy production descriptors.

Remaining blockers after E11:

- Track E E12 is complete on `main` through PR #69 and docs sync.
- Track I local production-shaped `membership.provision` E2E is complete on `main` through PR #76 at `5e5bb71` with post-merge CI run 27071532041; #77 and #84 are closed guard/negative-proof slices, and remaining runtime/live-ingress hardening follow-ups are #78-#83.
- Full Castalia Wallet wallet-core parity/replacement of the temporary challenge contract remains future reconciliation.
- Live Castalia/Dregg discovery, Midnight proof verification, Cardano settlement/finality proof, production deployment proof, and public auditability remain unimplemented and must not be claimed.

### A8 — Track F issue/commit details: bounded execution broker

| Issue / commit | Objective | Files | TDD / verification commands | Acceptance criteria | Stop condition | Must not claim |
|---|---|---|---|---|---|---|
| F1 — Descriptor-bound handler registry | Route handlers by descriptor `handler_id` from verified context. | `server/src/gateway.rs`, `server/src/ingress.rs`, possible `server/src/execution.rs` | RED unknown handler still executes/falls through; GREEN handler registry tests | Handler selection is descriptor-bound and unknown handler rejects. | Stop before limits. | Do not leave broad ambient shell execution as default. |
| F2 — Execution limits | Add timeout, payload-size, and output-size limits. | execution/gateway/manifest modules, tests | RED oversized payload/output or timeout succeeds; GREEN limit tests | Oversized/timeout cases fail with typed execution receipt. | Stop after limits are enforced. | Do not log raw payload/output by default. |
| F3 — Execution receipts for all outcomes | Ensure success, unavailable, failure, timeout, oversized all emit execution receipts/events. | `server/src/receipt.rs`, `server/src/ledger.rs`, ingress/execution tests | RED missing receipt for failure; GREEN targeted tests | Every handler outcome is receipt-backed. | Stop when ledger inspection proves chain. | Do not claim verifier acceptance implies execution success. |
| F4 — Gate or remove subprocess prototype path | Contain arbitrary subprocess/native demo behavior behind explicit allowlisted descriptors or remove it from production binary. | `server/src/bin/secz.rs`, `server/src/gateway.rs`, docs | Search for subprocess paths + tests proving production disallows unallowlisted shell | Production path cannot reach arbitrary shell commands by default. | Stop before runtime hardening. | Do not break compatibility binary silently without docs. |

#### Track F completion checkpoint

Track F is complete as a receiver-local bounded execution broker: handler selection is bound to descriptor `handler_id` from the signed `VerifiedCallContext`; unknown or missing handlers reject with execution receipts instead of falling through by opcode; payload size, output size, and timeout limits reject with stable execution reasons; success, handler-decline, unavailable, timeout, oversized-payload, and oversized-output paths all emit signed execution receipts; and production runtime bindings do not register dev subprocess handlers by default. This does **not** claim durable distributed execution, broad shell authority, production wallet/federated evidence policy, Dregg/Midnight/Cardano authority, or public auditability.

### A8 — Track G issue/commit details: ingress/service runtime hardening

| Issue / commit | Objective | Files | TDD / verification commands | Acceptance criteria | Stop condition | Must not claim |
|---|---|---|---|---|---|---|
| G1 — Canonical production binary and config | Define the production service entrypoint and typed config. | `server/src/bin/secs-gateway.rs`, config module/docs | RED missing config starts production; GREEN config validation tests | Production mode requires explicit key, ledger, trust registry, limits, and runtime mode config. | Complete: `secs-gateway` reads typed env config and no longer inherits fixture receiver audience in production. | Do not treat compatibility `secz` binary as canonical without refactor. |
| G2 — Startup fail-fast checks | Validate required production config before serving. | gateway/runtime/config modules, tests | RED bad config binds socket; GREEN startup validation tests | Missing production config fails before service accepts traffic. | Complete: missing receiver/key/trust registry and fixture receiver audience fail in config construction before bind. | Do not silently fall back to local dev. |
| G3 — Health/readiness or CLI checks | Add operator-visible health/readiness surface appropriate to the binary. | service binary/docs/tests | Targeted tests or smoke command | Operator can tell config-loaded, ledger-ready, and trust registry-ready states. | Complete: readiness reports config-loaded, ledger-ready, and trust-registry ready/fixture-only; missing ledger schema is not ready. | Do not report ready while critical dependencies are missing. |
| G4 — Local production smoke script | Add no-real-secret fixture smoke command/runbook. | `scripts/`, `fixtures/`, docs | Run script locally plus workspace gate | Smoke runs in `production_verified` with fixture keys/registry and no real secrets. | Complete: `scripts/production-gateway-smoke.sh` runs fixture-only production-shaped config/readiness/ingress checks and cleans temp files. | Do not call smoke success production deployment. |

#### Track G completion checkpoint

Track G is complete as local ingress/service runtime hardening: gateway wire reads are bounded before bincode deserialization, malformed under-limit packets remain malformed, empty streams exit quietly, oversized wire frames reject before decode/decrypt/verification, slow incomplete reads time out, production gateway config requires explicit non-fixture receiver audience/key/trust-registry/limits, readiness distinguishes config/ledger/trust states, and the smoke script runs with temporary fixture-only key material. The targeted audit follow-up has since added explicit logical `proof` / `encrypted_payload` length prechecks before bincode packet decode. This does **not** claim full DoS resistance because connection/task concurrency is still bounded only by the configured local cap and broader production traffic controls remain outside this repo, and it does **not** claim production deployment, wallet crypto, trusted issuer/root policy, Dregg/Midnight/Cardano authority, or public auditability.

#### Targeted audit hardening completion checkpoint

The targeted audit authority/entrypoint/decode hardening slice is complete for issues #53, #54, and #55: `production_verified` rejects legacy `0x01`/`0x02` descriptors that rely only on `prototype-proof-envelope`, the old implicit `server` binary / `run_node` direct opcode-dispatch path has been retired in favor of explicit `secs-gateway` / `secz` binaries, and ingress rejects huge declared `proof` or `encrypted_payload` lengths before bincode can deserialize attacker-controlled `Vec` fields. Verification lives in `server/tests/targeted_audit_hardening.rs` and `server/tests/ingress.rs`. This still does **not** implement wallet cryptographic verification, trusted issuer/root production policy, deployment proof, public auditability, or complete ingress reject audit visibility.

### A8 — Track H issue/commit details: receipt/event ledger production posture

| Issue / commit | Objective | Files | TDD / verification commands | Acceptance criteria | Stop condition | Must not claim |
|---|---|---|---|---|---|---|
| H1 — Receipt query/export | Add CLI/API or testable function for operator receipt/decision-chain inspection. | `server/src/ledger.rs`, service/CLI docs/tests | RED cannot inspect known receipt chain; GREEN ledger export tests | Operator can inspect accept/reject/execute chain by context/receipt id. | Stop before retention policy. | Do not expose private payload/evidence. |
| H2 — Redaction/retention policy | Document and enforce redaction defaults and retention/versioning notes. | `docs/implementation-status.md`, `server/src/ledger.rs`, tests | Redaction leak tests + docs hygiene | Raw private evidence/payload is absent by default; schema/version is explicit. | Stop after tests and docs agree. | Do not claim public auditability. |
| H3 — Receipt schema/versioning | Make receipt schema/version posture explicit for operator inspection and future migrations. | `server/src/receipt.rs`, `server/src/ledger.rs`, docs/status | Schema/version docs hygiene plus targeted receipt/ledger tests | Receipt schema/version is explicit enough for future exports/migrations. | Stop before chain integration tests. | Do not claim public anchoring or Dregg chain semantics. |
| H4 — Receipt-chain integration tests | Verify request lifecycle writes reject/verify/execute receipts as expected. | ingress/ledger/receipt tests | `cargo test -p server receipt_chain ledger -- --nocapture` | Full local chain is inspectable and reason-coded. | Stop before E2E phase. | Do not anchor to Dregg/public chain unless A9 promotes. |

#### Track H completion checkpoint

Track H is implemented on `phase/track-h-ledger-operator-inspection` as a local receipt/event ledger posture slice.

Implementation evidence:

- `server/src/receipt.rs` defines `RECEIPT_SCHEMA_VERSION = 1`; persisted receipts now carry `schema_version` and optional `context_id` so verified-context receipt chains can be inspected and later migrated/exported.
- `server/src/schema.rs` centralizes the versioned `receipts` columns and applies lightweight column additions for existing local SQLite ledgers.
- `server/src/ledger.rs` exposes `inspect_receipt_by_id` and `inspect_receipt_chain_by_context_id`, returning `OperatorReceiptInspection` rows with export schema version, receipt schema version, reason codes, operation/handler metadata, redacted packet/session/nonce hex identifiers, signer metadata, signature presence/length, and signature SHA-256 digest only.
- `server/tests/ledger.rs`, `server/tests/receipt.rs`, and `server/tests/gateway_layout.rs` cover redacted inspection, explicit schema/version posture, and an inspectable verify/execute/replay-reject lifecycle chain.

Boundaries preserved:

- Exports are local/operator inspection aids, not public auditability.
- Raw payloads, private evidence, and raw signature bytes are absent from the default inspection surface.
- Retention is local SQLite database retention until operator rotation/deletion; there is no public anchoring, Dregg chain semantics, or remote retention claim.

### A8 — Track I issue/commit details: end-to-end production-mode flow

| Issue / commit | Objective | Files | TDD / verification commands | Acceptance criteria | Stop condition | Must not claim |
|---|---|---|---|---|---|---|
| I1 — Fixture client packet/evidence builder | Build a local no-real-secret `membership.provision` fixture call using the packet builder, wallet fixture, and trusted issuer fixture. | `fixtures/`, `server/tests/`, possible `core/src/packet_builder.rs` tests | RED fixture cannot construct expected packet/evidence; GREEN fixture builder tests | Fixture includes generated wallet keys, static `TrustedIssuerEntry`, signed membership/provisioning credential, and fixture status. | Stop before executing handler. | Do not commit real keys or live registry data. |
| I2 — Happy-path membership provisioning E2E | Execute through production mode, manifest, wallet, federated evidence, handler, receipts, ledger. | integration tests, execution/evidence/ledger modules | `SECS_RUNTIME_MODE=production_verified SECS_VERIFIER_KEY_PATH=fixtures/keys/node-verifier.ed25519 SECS_TRUST_REGISTRY_PATH=fixtures/trust/membership-issuers.json cargo test -p server membership_provision_fixture_happy_path -- --nocapture` | Local fixture membership state is provisioned; signed verified context, verify receipt, execution receipt, and ledger row exist. | Stop before broad failure matrix. | Do not count packet echo or verifier-only accept as success. |
| I3 — A7 failure matrix | Implement failure tests named in A7 for missing/wrong/replayed/expired wallet and federated evidence, descriptor mismatch, handler unavailable, oversized payload, redaction leaks. | integration tests plus modules touched by failures | `cargo test -p server membership_provision -- --nocapture`; workspace gate | Every A7 failure either has a passing test or is explicitly carried as a named blocker with reason. | Stop after matrix is green. | Do not hide replay-store gaps. |
| I4 — Runbook and expected outputs | Document exact local command, fixture setup, expected receipts, and ledger inspection. | `docs/runbooks/` or `docs/plans/`, README pointer, status docs | `rg "membership.provision|verify receipt|execution receipt|ledger inspection|no real secrets" docs/`; `git diff --check` | Operator can run the flow locally and know what success/failure looks like. | Stop when docs match the actual test command. | Do not describe fixture evidence as live Dregg/Castalia/Cardano authority. |

### A8 — Remaining future issues to pick

Track B, Track C, Track D, Track E, Track F, Track G, Track H, and Track I local production-shaped E2E now have completion checkpoints in this checklist. Remaining first-prod path blockers are separate follow-up rails: deployment proof (#33), public auditability (#37), wallet-core parity (#71), live registry discovery (#72), Dregg/Midnight/Cardano rails (#73-#75), and remaining post-merge review hardening #78-#83 (#77/#84 are closed). Pick the next issue from the earliest incomplete dependency in that E/I chain unless a later decision explicitly changes the first-prod authority model.

### A8 — Acceptance

A8 acceptance is met because this checklist now groups Tracks A–I into coherent implementation phases, gives every phase a branch name, PR title/scope, issue/commit sequence, verification gate, and merge/stop condition, and gives every issue/commit an objective, files, commands, acceptance criteria, stop condition, and forbidden claims. The plan preserves the repo pattern that phases are branch/PR boundaries and issues are commit boundaries, includes cross-Hub/federated evidence as a first-prod requirement through A5's narrowed `membership_credential` / `provisioning_credential` + `TrustedIssuerEntry` path, and keeps demoted A5 candidates out of first-path issue requirements unless A9 promotes them.


## A9 — Future rail defer/promote decision for Tracks J–L

A9 closes Track A by deciding whether Dregg, Midnight, and Cardano are first-prod dependencies or future adapter seams. This is a decision gate, not runtime implementation.

A9 decision: **defer Tracks J–L from the first implementation sequence**.

Rationale:

- A7 selected `membership.provision` as the first production-shaped E2E operation, and that operation can be proven with wallet presentation plus A5's narrowed federated evidence path.
- A5/A6 already provide a concrete first federation path: `membership_credential` / `provisioning_credential`, receiver-held `TrustedIssuerEntry`, `registry_status` / `revocation_status`, and generic `trust_root_ref` / `registry_root_ref` metadata.
- Promoting live Dregg, Midnight, or Cardano now would widen first-prod from machine-to-machine membership provisioning into consensus, private-statement proof design, or settlement/capital semantics before the verifier/runtime/bounded-execution rails are stable.
- Deferral preserves future adapter seams without letting them become hidden blockers for Tracks B–I.

### A9 — Decision matrix

| Track / rail | First-prod decision | First implementation representation | Promotion trigger | Required pre-promotion artifact | Must not claim while deferred |
|---|---|---|---|---|---|
| Track J — Dregg authority rail beyond the M12.3 shape seam | Deferred; not a live first-prod dependency. | Generic `trust_root_ref` / `registry_root_ref` plus static fixture `TrustedIssuerEntry` and fixture `registry_status` / `revocation_status`. M12.3 adds a Dregg-shaped receipt/capability-reference shape + author-signature adapter seam only; semantic authority remains deferred. | Promote only if first-prod membership provisioning requires live Dregg-backed roots, revocation/freshness, capability path validation, or remote verification attestations beyond the static trusted-issuer fixture path. | A design spec naming Dregg authority boundary, root discovery, freshness/revocation model, capability object/caveat semantics, receipt/attestation schema, failure reasons, and tests for stale/revoked/wrong-root/wrong-operation cases. | Do not call generic `trust_root_ref` / `registry_root_ref`, fixture roots, fixture status, static issuer entries, or M12.3 shape/signature verification live Dregg validation. Do not make capability algebra a first-path requirement. |
| Track K — Midnight / generic ZK proof adapter | Deferred; not required for generic `membership.provision`. | No proof adapter in first path. Prototype proof envelope checks remain prototype-only; wallet and federated credentials carry first-prod authority. | Promote only if a selected first-prod operation requires a private statement whose public inputs, circuit/proof format, subject/audience/operation binding, expiry, and replay semantics are defined. | A private-statement/public-input spec, circuit/proof dependency boundary, verifier API, fixture proof model, and wrong-statement/wrong-public-input/expired/replayed proof tests. | Do not treat proof-shaped bytes, current prototype proof envelope, or generic ZK language as meaningful Midnight/private-statement verification. |
| Track L — Cardano / settlement evidence | Deferred; not required for generic membership provisioning. | No Cardano evidence in first path. Receipts remain local/operator ledger evidence, not settlement or chain anchoring. | Promote only if the selected operation involves settlement, capital, auction/business evidence, token ownership, or on-chain finality as part of authorization or receipt proof. | A settlement/capital evidence spec naming transaction/finality schema, latency expectations, business operation linkage, verifier inputs, replay/finality failure reasons, and tests for wrong asset/wrong transaction/not-final/stale settlement cases. | Do not describe `membership.provision` fixture success, local SQLite receipts, or static credentials as Cardano-backed membership provisioning or public-chain proof. |

### A9 — Resulting first implementation path

Tracks B–I were the first implementation sequence selected from A8; later completion checkpoints in this checklist annotate tracks as they land:

1. Track B — production identity and key lifecycle.
2. Track C — replay, session, and expiry enforcement.
3. Track D — wallet cryptographic verification / shared wallet core.
4. Track E — production evidence policy and static trusted-issuer membership/provisioning credentials.
5. Track F — bounded execution broker.
6. Track G — ingress/service runtime hardening.
7. Track H — receipt/event ledger production posture.
8. Track I — first production-shaped `membership.provision` E2E.

First-prod federation means: a receiver can evaluate another Hub/Castalia-style authority's signed membership/provisioning credential through receiver-held trusted issuer/root metadata and status checks, then still apply receiver-local manifest policy. It does **not** mean live Dregg consensus, Midnight proofs, Cardano settlement, public anchoring, or Matrix federation.

### A9 — Future adapter seams preserved

Deferral does not delete future rails. It preserves them as explicit seams:

- Dregg may later become a subtype of `trust_root_ref` / `registry_root_ref` or a source for `remote_verification_attestation`, root freshness, revocation, and capability path validation.
- Midnight may later become a proof adapter after statement meaning and public inputs are specified.
- Cardano may later become a settlement/capital evidence adapter for operations that actually need on-chain facts.
- Public anchoring of local receipts may later be added as an export/anchor rail, but current receipt/event ledger work remains local/operator audit evidence.

### A9 — Acceptance

A9 acceptance is met because Dregg, Midnight, and Cardano are explicitly deferred from first-prod implementation, each deferred rail has a rationale, a preserved adapter seam, a concrete promotion trigger, a required pre-promotion artifact, and forbidden claims. Dregg defaults to the generic `trust_root_ref` / `registry_root_ref` seam plus static `TrustedIssuerEntry` / fixture status path, Midnight requires a future private-statement/public-input spec before implementation, and Cardano is limited to future settlement/capital evidence rather than generic membership provisioning.

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
- A7 — first membership-provisioning E2E shape — complete;
- A8 — issue-ready phase/branch/PR checklist for Tracks A–I — complete;
- A9 — Dregg/Midnight/Cardano defer-or-promote decision — complete.

Track A is now complete through A9. Preserve the repo workflow pattern going forward: phases are branch/PR boundaries, and issues inside each phase are commit boundaries.
## 2026-06-05 Track H PR readiness and documentation navigation

- Track H #61 is implemented through PR #65 / commit 7742ce9: H1 collision-resistant receipt IDs, #57 replay reservation pruning, H2 atomic receipt/event persistence, folded #51/#52 audit visibility, and H4 redaction/schema/docs/status sweep are complete. The full local gate passed on PR #65 before this documentation navigation pass. Remaining action is approval to merge PR #65, then watch post-merge main CI and close folded issues.
- Documentation navigation now follows a README-as-map pattern: the root README links to child READMEs for `core/`, `client/`, `server/`, `docs/`, `docs/specs/`, `docs/plans/`, `examples/`, and `scripts/`, and stale historical-plan language is explicitly caveated.
