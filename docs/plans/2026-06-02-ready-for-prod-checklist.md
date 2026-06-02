# secS-magik ready-for-prod checklist

This is the repo-local control surface for turning secS-magik from the current prototype verifier/RPC substrate into the first production-shaped implementation train.

Source captures:

- Claude Hub capture: `/Users/bananawalnut/claude-hub/capture/2026-06-02-secs-magik-track-a-ready-for-prod-slices.md`
- Parent work surface: `/Users/bananawalnut/claude-hub/capture/2026-06-02-secs-magik-ready-for-prod-work-surface.md`

Status: A0 production definition locked; A1 repo status reconciled; A2 rail taxonomy and non-goals complete; A3 identity/key lifecycle gate complete. Later slices should expand this file phase-by-phase without weakening the production target or re-opening completed issue-train work.

## A0 — Production target

First-prod readiness requires all three Track A rails:

1. Local single-node production-shaped deployment.
2. Castalia Wallet-backed app/user auth.
3. Cross-Hub/federated evidence.

secS-magik is ready for first prod only when one Hub can run a production-shaped secS verifier service that:

- rejects insecure/local-dev authority in production mode;
- verifies wallet-core-defined presentations for app/user subjects;
- evaluates federated evidence produced, signed, anchored, revoked, or vouched for by another Hub, Castalia authority, or Dregg-shaped root/ref seam while still applying the receiver's local manifest policy;
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
- Dregg-shaped root/ref seam;
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
- `Dregg-shaped root/ref seam` for future-compatible root semantics;
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

## Slice acceptance criteria

These criteria travel with the A0–A9 slices. A later phase/issue is not complete until its row is satisfied without weakening the A0 production definition.

| Slice | Acceptance criteria | Verification / evidence | Must not claim |
|---|---|---|---|
| A0 — Lock Track A production definition | The checklist names all three first-prod rails as required: local production-shaped deployment, Castalia Wallet-backed app/user auth, and cross-Hub/federated evidence. Local smoke readiness is explicitly insufficient. | `rg "local single-node|Wallet-backed|cross-Hub|federated evidence|not enough" docs/plans/2026-06-02-ready-for-prod-checklist.md` | Do not treat cross-Hub/federated evidence as optional; do not treat wallet crypto as future-only if first-prod includes app/user auth; do not make Dregg/Midnight/Cardano blanket runtime dependencies. |
| A1 — Repo status reconciliation | `docs/implementation-status.md` and this checklist agree on current solid, partial/prototype, planned, future, and out-of-scope surfaces through Issue 4.2 and A0/A1. | `rg "wallet_presentation|local_static|federated|Dregg|planned|production" docs/implementation-status.md`; `rg "A1|completed|partial|planned|wallet-core|federated|phase/branch/PR" docs/plans/2026-06-02-ready-for-prod-checklist.md` | Do not describe future rails as implemented; do not erase partial/prototype caveats for wallet crypto, identity lifecycle, bounded broker, runtime hardening, or federated evidence. |
| A2 — Rail taxonomy and non-goals | Required rails, deferred/future rails, secS-magik non-goals, and language discipline are explicit enough that implementers can distinguish secS-magik work from Castalia Wallet, Dregg, Matrix, Gallery, Hub app policy, Midnight, and Cardano. | `rg "Required rails|Non-goals|Matrix|Dregg consensus|Wallet|Language discipline" docs/plans/2026-06-02-ready-for-prod-checklist.md` | Do not let app/browser session UX, Matrix federation, Dregg consensus, Midnight circuits, Cardano settlement, or product policy become implicit secS-magik scope. |
| A3 — Identity/key lifecycle decision gate | The checklist identifies the first signer/key model, key loading/config path, key id format, public-key discovery path, and minimum revocation/rotation posture for first prod. | Checklist includes tests or future issue rows for tamper, wrong key, expired context, revoked/untrusted issuer, and local/dev non-authoritative keys. | Do not claim production identity discovery or key rotation until implemented; do not let local/dev/test keys appear authoritative. |
| A4 — Wallet-core integration decision gate | The checklist selects or explicitly carries the wallet-core integration path: direct minimal verifier API or wallet-core-defined verified artifact. The rejected option is duplicated secS wallet verifier semantics. | Checklist records the chosen path, tradeoffs, affected files/crates, tests for signature/audience/origin/replay/expiry, and browser/WASM/native packaging implications. | Do not invent independent secS wallet verification semantics; do not trust an unsigned/untraceable artifact producer as equivalent to verifying raw wallet evidence. |
| A5 — Federated evidence model decision gate | The checklist defines evidence objects, trusted issuer/root representation, public-key discovery, remote receipt/capability/credential/revocation/root shapes, expiry/replay semantics, and typed failure reasons. | Checklist names at least one fixture first-prod evidence path and tests for untrusted issuer, revoked/stale evidence, malformed evidence, wrong audience, wrong operation, and wrong subject. | Do not pretend Dregg consensus is implemented by fixture evidence; do not let federated evidence bypass receiver-local manifest policy. |
| A6 — Production policy matrix | The checklist contains a runtime mode × descriptor evidence × adapter evidence matrix proving local/dev/static evidence cannot satisfy production descriptors and that every accept/reject row has a test target. | `rg "production_verified|local_static|wallet presentation|federated evidence|untrusted issuer|revoked|stale" docs/plans/2026-06-02-ready-for-prod-checklist.md` plus future tests named per row. | Do not let `local_static`, plaintext, or dev descriptors satisfy production authority. |
| A7 — First membership-provisioning E2E shape | The first E2E operation is selected (`membership.provision`, `gallery.member.provision`, or `hub.member.provision`) and includes happy path, failure matrix, receipt/ledger inspection, and local fixture constraints. | Checklist/runbook names the operation, descriptor, evidence inputs, handler behavior, inspectable receipts, and failures for missing wallet evidence, wrong audience/origin, invalid signature, replay/expiry, untrusted/revoked federated evidence, descriptor mismatch, handler unavailable, oversized payload, and redaction leak checks. | Do not make the E2E a packet echo; do not require real secrets; do not hide that fixtures are fake but semantically production-shaped. |
| A8 — Convert Tracks A–I into issue-ready repo checklist | Tracks A–I are grouped into coherent implementation phases. Each phase has branch name, PR title/scope, issue/commit sequence, verification gate, and merge/stop condition. Each issue/commit has objective, files, commands, acceptance criteria, stop condition, and what it must not claim. | Checklist contains a phase/branch/PR plan preserving the repo pattern: phases are branch/PR boundaries and issues inside phases are commit boundaries. | Do not produce one branch/PR per issue unless that issue is promoted into a full phase; do not omit cross-Hub/federated evidence from first-prod requirements. |
| A9 — Defer or promote Tracks J–L intentionally | Dregg, Midnight, and Cardano are either explicitly first-prod dependencies with concrete evidence/adapter requirements, or explicitly deferred/future/adapter-scoped with rationale. | Checklist names whether Dregg is live dependency or fixture/root-ref seam, whether Midnight/private statement work is required, and whether Cardano settlement/capital evidence is in scope. | Do not silently smuggle Dregg/Midnight/Cardano into the first implementation sequence; do not erase future adapter seams when deferring them. |

## Future expansion placeholders

Later slices should expand this checklist in place:

- A1 — repo status reconciliation — complete;
- A2 — rail taxonomy and non-goals — complete;
- A3 — identity/key lifecycle decision gate — complete;
- A4 — wallet-core integration decision gate;
- A5 — federated evidence model decision gate;
- A6 — production policy matrix;
- A7 — first membership-provisioning E2E shape;
- A8 — issue-ready phase/branch/PR checklist for Tracks A–I;
- A9 — Dregg/Midnight/Cardano defer-or-promote decision.

A8 must preserve the repo workflow pattern: phases are branch/PR boundaries, and issues inside each phase are commit boundaries.
