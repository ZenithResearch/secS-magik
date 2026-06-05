---
description: Instruction-level implementation surface for the secS-magik objectives spec, expanding the minimal slices into concrete issue-ready checkpoints with repo paths, scope boundaries, acceptance criteria, and verification commands.
type: capture
created: 2026-06-01
date: 2026-06-01
tags: [capture, implementation-plan, issues, secS-magik, secS, verifier, manifests, receipts, evidence, Rust]
arena: [Zenith]
domain: [planning, projects, architecture]
axes: [analytical]
status: review implementation surface
source: [[2026-06-01-secs-magik-objectives-spec]]
repo: /Users/bananawalnut/repos/secS-magik @ 8523167 historical import baseline; see ../implementation-status.md for current status
---

# secS-magik implementation issue slices

Repo-local copy imported from Claude Hub capture on 2026-06-01. This is a historical issue-slice plan; many early slices have since landed. For current implemented/partial/planned status, see `../implementation-status.md`.

## Summary

This capture expands the current [[2026-06-01-secs-magik-objectives-spec]] into implementation-ready issue slices. The goal is not to rewrite the architecture; the objective is to make the next repository work easy to assign, review, and stop at clean boundaries.

The implementation posture is compatibility-first:

- preserve `ZenithPacket` v0 exactly;
- preserve `u8` opcode dispatch;
- preserve current CLI decimal opcode behavior;
- move trust decisions out of ad hoc boolean/prototype checks and into typed verifier results;
- keep local Hermes/secC/secZ as client-side ways to call secS, not verifiers;
- keep receiver-local manifests sovereign over opcode meaning;
- produce receipts and local events before claiming real auditability.

## Current repo baseline

Historical baseline inspected at import time: `/Users/bananawalnut/repos/secS-magik` at `8523167` on `main`. This is not the current HEAD/status snapshot.

Observed relevant files:

- `Cargo.toml` — workspace with `core`, `client`, and `server` members.
- `core/src/lib.rs` — defines `ZenithPacket`, `SessionHandshake`, `OPCODE_GENERATE`, `OPCODE_CHAT`, and packet serialization tests.
- `core/src/tunnel.rs` — tunnel crypto helpers used by the server gateway.
- `core/src/zk.rs` — current ZK/proof-adjacent core surface.
- Historical note: at the import baseline, `server/src/lib.rs`, `server/src/main.rs`, and `server/src/bin/secz.rs` still carried direct TCP/prototype gateway responsibilities. Current HEAD has retired `server/src/main.rs`, moved reusable ingress/gateway/payload logic into library modules, and keeps `server/src/bin/secz.rs` as a compatibility wrapper. See `../implementation-status.md`.
- `client/src/main.rs` — client sender surface.
- `hub/src/dispatcher.rs`, `hub/src/lib.rs` — untracked adjacent hub surface; do not depend on it in the first implementation sequence unless deliberately promoted into the workspace.

Dirty/untracked baseline:

- `docs/reviews/`
- `hub/`
- `ops/`

Implementation issues should either avoid these paths or explicitly declare if they are brought under version control. Do not let untracked adjacent work become accidental scope.

## Review decisions to lock before coding

These decisions are now locked for the first coding pass unless the user explicitly reopens them. The point of this gate is to prevent implementation agents from silently choosing incompatible trust, opcode, context, or evidence semantics while coding.

Locked decisions:

1. `OperationDescriptor` starts server-side in `server/src/manifest.rs`.
2. Opcode ranges are reserved by governance tier: core standardized first, then Castalia standardized, then operator-defined.
3. `VerifiedCallContext` is serializable and signed, not merely process-internal.
4. Receipts should be signed by a portable node/verifier identity path, with local/dev placeholders only allowed for local tests and clearly non-authoritative.
5. `0x01` and `0x02` remain legacy secS examples in the core standardized range.
6. `local_static` is the first evidence adapter, followed by wallet presentation, with Midnight / ZK proof / Dregg-style receipt adapters after the adapter contract stabilizes.

### Decision 1 — Where should `OperationDescriptor` live first, and how are opcode ranges governed?

Locked v0 decision: `OperationDescriptor` lives in `server/src/manifest.rs` first. The receiver server owns the concrete local manifest because dispatch meaning is receiver-local. The shared standard is not “every receiver must use every opcode the same way forever”; the shared standard is a reserved-range policy plus descriptor semantics.

Purpose:

`OperationDescriptor` is the object that says what a bare local opcode means on this receiver. It binds an opcode like `0x20` to an operation such as `queue.enqueue`, points to a handler, and declares the required evidence/capabilities before that handler can run.

The key correction from review: opcodes should not be a total free-for-all. They should have reserved tiers:

| Range | Governance | Meaning | v0 posture |
|---:|---|---|---|
| `0x01`–`0x0A` | secS/core standardized | Very small cross-runtime baseline operations and legacy examples. | Preserve `0x01` and `0x02`; reserve the rest. |
| `0x0B`–`0x3F` | Castalia standardized | Castalia ecosystem operations whose names/evidence expectations should be portable across compliant receivers. | Reserve for future Castalia standardization; current `0x10`, `0x20`, `0x30` may be dev/prototype candidates, not final public assignments unless ratified. |
| `0x40`–`0xFF` | Operator-defined | Receiver/operator local operations. Meaning is declared by that receiver’s manifest. | Safe place for local/custom handlers once the manifest exists. |

This preserves both ideas:

- there is a standardized opcode space for interoperability;
- the server/receiver still owns the actual manifest and handler binding.

Tradeoffs:

| Option | Upside | Downside | Locked choice |
|---|---|---|---|
| `server/src/manifest.rs` first with reserved ranges | Keeps implementation honest: server owns concrete dispatch, but docs reserve shared opcode bands. Avoids freezing unstable descriptor structs into `core` while still preventing chaos. | Clients cannot yet import a shared descriptor type; docs/tests must enforce ranges until promotion. | Yes. |
| `core/src/manifest.rs` immediately | Clients/secC/secZ can share descriptor structs immediately. | Risks turning every descriptor field into a premature wire/API contract and pretending all opcode meanings are globally fixed. | No for v0. |
| Separate `manifest` crate | Clean long-term contract if many binaries need manifest logic. | Too much structure before one server implementation proves the descriptor shape. | Later only. |

Coding instructions:

- Implement `server/src/manifest.rs` first.
- Add constants or docs for `CORE_STANDARD_RANGE`, `CASTALIA_STANDARD_RANGE`, and `OPERATOR_DEFINED_RANGE`.
- Treat `0x10`, `0x20`, and `0x30` as current dev/prototype descriptors inside the Castalia-standard candidate range, not as permanently ratified public semantics.
- Do not require local Hermes/secC/secZ clients to import descriptor structs just to construct packets in v0.

Acceptance for this decision:

- [ ] v0 docs state that opcode meaning is receiver-local within reserved governance ranges.
- [ ] The manifest marks `0x01`/`0x02` as core standardized legacy examples.
- [ ] The manifest marks `0x10`/`0x20`/`0x30` as Castalia-standard candidates or dev bindings, not final public commitments.
- [ ] Operator-defined examples, if added, use `0x40+`.
- [ ] Any later promotion of descriptors to `core` is treated as a compatibility decision, not a casual refactor.

### Decision 2 — Should `VerifiedCallContext` serialize in v0?

Locked v0 decision: use a signed serialized `VerifiedCallContext` contract. It may still be generated process-internally first, but the target implementation is a signed context object with explicit signer, audience, expiry, schema version, redaction rules, and replay semantics.

Purpose:

`VerifiedCallContext` is the verifier’s handoff object. It is what handlers and adjacent runtimes receive after secS has decoded the packet, checked proof/TTL/runtime mode, looked up the operation descriptor, and accepted required evidence. If it remains purely internal, it is safe but weak as an interoperability primitive. Since the intended architecture includes machine-to-machine calls, local Hermes/secC/secZ clients, receipts, and eventual cross-runtime verification, the context should become a signed handoff object rather than an invisible in-process struct.

Required v0 shape:

```text
SignedVerifiedCallContext
  schema_version
  context_id
  packet_hash
  session_id
  nonce
  opcode
  operation
  subject
  target / audience
  evidence_summary_hashes, not raw evidence blobs by default
  capability_result summary
  credential_result summary
  issued_at
  expires_at
  replay_scope
  signer_key_id
  signature
```

Rules:

- Sign the context over canonical serialized bytes.
- Include `schema_version` from the first implementation.
- Include `audience`/target so a context accepted for one receiver cannot be replayed as authority somewhere else.
- Include `expires_at` and replay scope.
- Include hashes/summaries of evidence by default, not raw private evidence.
- Handlers may receive the deserialized struct, but the struct must be able to round-trip through the signed serialization format.

Tradeoffs:

| Option | Upside | Downside | Locked choice |
|---|---|---|---|
| Process-internal only | Safest and easiest to change. | Does not produce the portable handoff object the architecture wants. | No. |
| Serialize behind feature flag | Useful halfway step. | Still punts signing/audience/replay decisions. | Only acceptable as an intermediate commit, not final v0. |
| Signed serialized context | Strong handoff object for handlers, adjacent runtimes, debugging, and eventual federation. | Requires key identity, canonical serialization, expiry, replay, redaction, and compatibility decisions immediately. | Yes. |

Coding instructions:

- Add `VerifiedCallContext` and `SignedVerifiedCallContext` in `server/src/verifier.rs` or a `server/src/context.rs` module.
- Use canonical bincode/serde serialization initially if the repo already uses bincode, but isolate serialization behind functions so canonicalization can be tightened later.
- Add signature using the selected local verifier/node key path from Decision 3.
- Tests must prove a signed context verifies, tampered bytes fail, wrong audience fails, and expired context fails.

Acceptance for this decision:

- [ ] `VerifiedCallContext` has a signed serialized representation in v0.
- [ ] Signature covers packet hash, subject, operation, audience, expiry, and evidence summary.
- [ ] The context includes schema version and signer key id.
- [ ] Tests reject tampered, expired, wrong-audience, or wrong-signer contexts.
- [ ] Raw private evidence is not serialized by default; summaries/hashes are used unless a later adapter explicitly requires otherwise.

### Decision 3 — How should receipts and signed contexts be authenticated first?

Locked v0 decision: build toward node/verifier identity signing, not local-only placeholders. Local/dev authenticators are allowed only for unit tests and local demos and must be visibly non-authoritative. The first production-shaped implementation should use an Ed25519-style signing key with a portable public key id, because the repo already depends on `ed25519-dalek` and because signatures produce portable verification outcomes without shared secrets.

The important distinction:

- Shared-secret MACs prove “someone with the same secret made this,” but the verifier must already possess the secret. That is not portable across independent operators without secret distribution.
- Public-key signatures prove “the holder of this private key made this,” and anyone with the public key / key id can verify. That is portable across logs, receipts, handlers, and future federation.
- Chain/proof anchoring proves more than local authorship, but only after there is something stable to anchor.

Outcome-strength table:

| Authenticator | Secret/key portability | What a verifier can prove | Strong outcome | Weakness / cost | Use in v0 |
|---|---|---|---|---|---|
| Plain local string marker | No secret; no cryptographic portability. | Nothing cryptographic; only that the code stamped a label. | Useful only to avoid pretending dev receipts are real. | Zero trust value. | Tests/demos only, stamped `local_dev_untrusted`. |
| Local MAC with configured shared secret | Secret is not portable unless copied to every verifier; copying increases compromise blast radius. | A party with the same secret produced or accepted the receipt/context. | Tamper evidence inside one deployment. | Poor federation story; hard rotation; all holders can forge. | Optional local integration mode only, not public proof. |
| Node identity Ed25519 signature | Public key is portable; private key stays on node/operator. | This node signed this receipt/context. | Strong audit attribution across logs and other Hubs if key id is trusted. | Requires node key lifecycle: generation, storage, rotation, revocation, registry. | Primary v0 production-shaped path if node identity is the trust anchor. |
| secS verifier Ed25519 signature | Public key is portable; private key stays with verifier component. | This verifier instance signed this verification decision. | Stronger component-level provenance: separates verifier decision from broader node runtime. | Requires deciding whether verifier key is distinct from node key; execution receipts may need node/runtime signature too. | Preferred if verifier decisions need to be independently attributable. |
| Node signs execution receipts, verifier signs verification contexts | Public keys are portable; private keys remain scoped by role. | Verifier attests verification; node/runtime attests execution. | Best semantic separation and audit clarity. | More moving parts and key ids; slightly more implementation work. | Recommended target if scope allows. |
| Dregg receipt / federation root | Portable through federation trust root. | Receipt/capability status according to Dregg/federation state. | Revocation/capability graph can become externally checkable. | Dregg dependency and federation semantics must be stable. | Later adapter/anchor, not first v0. |
| Midnight proof | Portable proof artifact, depending on verifier and public inputs. | A statement was proven without revealing private inputs. | Privacy-preserving public proof rail. | Requires circuit/public-input design; not the general receipt-auth solution. | Later evidence adapter. |
| Cardano anchoring/settlement | Portable public-chain evidence. | Timestamped/settled public fact. | Strong public persistence and settlement linkage. | Too slow/heavy for every machine-call receipt; domain-specific. | Later for capital/settlement operations. |

Locked recommendation:

- Sign `VerifiedCallContext` with the secS verifier key if the implementation can keep verifier identity distinct.
- Sign execution receipts with the node/runtime key if execution occurs outside the verifier boundary.
- If that split is too large for the first coding pass, use one node/verifier Ed25519 key pair but name the compromise explicitly as `node_verifier_key` and keep the API capable of splitting it later.
- Do not use shared-secret MACs as the main portable path.

Coding instructions:

- Add `signer_key_id` and `signature` fields to signed contexts and receipts.
- Add `authenticator_kind` with values such as `local_dev_untrusted`, `local_mac`, `ed25519_node`, `ed25519_verifier`, `ed25519_node_and_verifier`, `external_anchor`.
- Load dev keys from explicit env/file path only; do not generate hidden long-lived keys without telling the operator where they live.
- Tests may generate ephemeral keys, but docs must distinguish ephemeral test keys from operator identity keys.

Acceptance for this decision:

- [ ] Portable v0 verification uses public-key signatures, not shared-secret MACs.
- [ ] Receipts and signed contexts include `authenticator_kind`, `signer_key_id`, and `signature`.
- [ ] Tests prove signature verification, tamper rejection, wrong-key rejection, and expired-context rejection.
- [ ] Local/dev markers cannot be described as production authority or public proof.
- [ ] Docs include key lifecycle TODOs: generation, storage, rotation, revocation, and registry/public-key discovery.

### Decision 4 — What happens to `0x01` and `0x02`?

Locked v0 decision: `0x01` and `0x02` stay legacy secS examples in the core standardized opcode range; Castalia-ish local operations use the Castalia-standard candidate range for now.

Purpose:

This preserves the existing prototype contract while the verifier/manifest/receipt layers are extracted. It also avoids confusing old examples with the newer Castalia operation vocabulary.

Acceptance for this decision:

- [ ] Regression tests preserve existing `OPCODE_GENERATE = 0x01` and `OPCODE_CHAT = 0x02` behavior.
- [ ] Manifest docs label them as core standardized legacy examples.
- [ ] Current `0x10`/`0x20`/`0x30` dev bindings are labeled Castalia-standard candidates or dev bindings, not final global semantics.

### Decision 5 — Which evidence adapter comes first?

Locked v0 decision: implement `local_static` first. It is not the message we ultimately offer to the outside world; it is the scaffolding adapter that proves the verifier/evidence/descriptor/receipt plumbing works. After that, implement `wallet_presentation`, then Midnight/ZK proof or Dregg-style receipt adapters once the adapter contract stops moving.

Purpose:

Evidence adapters are the seam where secS learns how to ask “what authority supports this call?” without hard-coding Dregg, Midnight, Cardano, wallet signatures, or local allowlists into the verifier itself. `local_static` is chosen first because it gives deterministic, dependency-free tests for the seam. It answers: can a descriptor require evidence, can the verifier request it, can an adapter answer, can the decision become a signed context/receipt, and can missing/insufficient evidence fail closed?

This is not ecstatic/final status. It is working-now status. The stronger public message comes from the next adapters, but those adapters are safer once the local seam is already proven.

Why not start with the public-facing adapters?

| Adapter first | What it proves | Why not first | Why still important |
|---|---|---|---|
| `local_static` | The adapter interface, descriptor requirement flow, fail-closed behavior, receipt/context integration, deterministic tests. | It is not public trust and must be marked local/dev/test. | It makes the rest implementable without conflating interface bugs with cryptographic/proof bugs. |
| `wallet_presentation` | A real user/wallet subject can satisfy a challenge for a target audience/origin. | Forces challenge format, signature suite, subject id, origin/audience, replay, and wallet UX decisions at the same time as the adapter trait. | It should be second because it is the first real auth rail for app/user integration. |
| `midnight_proof` / generic ZK proof | A private statement can satisfy public verifier inputs without exposing private data. | Requires circuit/public input design; otherwise the adapter only verifies “some proof-shaped bytes,” not a meaningful authority claim. | It becomes the privacy/proof rail after the adapter request/result contract is stable. |
| Dregg-style/federation receipt | Capability, revocation, or federation state can support a call. | Pulls in federation semantics, root discovery, revocation propagation, and Dregg runtime questions before secS verifier is proven. | It becomes important when Castalia needs cross-Hub capability and revocation semantics. |
| Cardano settlement evidence | Settlement/capital facts can support money operations. | Too domain-specific and heavy for generic RPC verification. | Important later for capital/auction/settlement operations. |

Concrete reason for `local_static` first:

- It lets the team implement and test fail-closed verifier behavior immediately.
- It lets every later adapter reuse the same `EvidenceRequest`, `EvidenceResult`, reason codes, and receipt/context integration.
- It prevents a wallet/Midnight/Dregg bug from being misdiagnosed as a verifier architecture bug.
- It keeps Dregg/Midnight optional instead of accidentally making them mandatory runtime dependencies.
- It gives local Hermes/secC/secZ a working call path now while the stronger proof rails are being designed.

Coding instructions:

- Implement `local_static` with explicit labels: `local_static`, `local_dev`, `test_only`, or equivalent.
- `local_static` may satisfy deterministic fixtures/allowlists, but its receipts/contexts must not claim public proof.
- The adapter trait must include enough structure for wallet and proof adapters later: subject, audience, operation, resource, evidence refs, public inputs, and reason codes.
- Add explicit failure cases: missing evidence, wrong subject, wrong audience, insufficient evidence, revoked/denied if represented.

Acceptance for this decision:

- [ ] `local_static` proves the adapter trait, request, result, descriptor requirement flow, and signed receipt/context integration.
- [ ] `local_static` is labeled local/dev/test, not production authority.
- [ ] `wallet_presentation` is next and must define challenge, subject, audience, origin, signature/ref fields, and replay semantics before implementation.
- [ ] Midnight/ZK proof adapter is not attempted until public inputs and statement meaning are defined.
- [ ] Dregg/federation receipt adapter is not attempted until capability/revocation/root semantics are defined.
- [ ] Dregg, Midnight, and Cardano remain optional adapters, not mandatory verifier runtime dependencies.

### Decision-gate acceptance

- [ ] The implementer records these locked decisions in repo docs before code changes, or records different user-approved decisions.
- [ ] Any changed decision is reflected in the issue list below before execution.
- [ ] No code issue starts while a decision materially changes file placement, serialization, receipt auth, opcode mapping, or adapter order.
- [ ] Local/dev-only constructs are visibly stamped and cannot be mistaken for public proof, production authority, or final federation semantics.
- [ ] Signed contexts and signed receipts have explicit key identity, expiry, audience, and replay semantics.

## Phase 0 — repo-facing specification and guardrails

### Issue 0.0 — Add the current spec to repo docs

Objective: Put the current architecture source inside the repo without changing runtime behavior.

Files:

- Create: `docs/specs/2026-06-01-secs-magik-objectives-spec.md`
- Modify: `README.md` only if it already has a docs/index section suitable for a one-line pointer.

Instructions:

1. Copy the content of the vault capture `capture/2026-06-01-secs-magik-objectives-spec.md` into `docs/specs/2026-06-01-secs-magik-objectives-spec.md`.
2. Add a short repo-local heading at top if needed: “This document is imported from Claude Hub capture and is the current implementation source of truth.”
3. Do not edit Rust code in this issue.
4. If `README.md` has an orientation/docs section, add exactly one pointer to the spec. If it does not, skip README changes rather than restructuring it.

Acceptance criteria:

- [ ] `docs/specs/2026-06-01-secs-magik-objectives-spec.md` exists and contains the role split: local Hermes/secC/secZ are client-side surfaces; secS-magik/secS is verifier/RPC substrate.
- [ ] The spec preserves `ZenithPacket` v0 and `u8` opcode dispatch language.
- [ ] No runtime source files changed.
- [ ] `cargo test --workspace` still passes.

Verification:

```bash
cargo test --workspace
rg "local Hermes|secC|secZ|verifier/RPC substrate|ZenithPacket|u8" docs/specs/2026-06-01-secs-magik-objectives-spec.md
```

Stop condition:

Commit only docs/specs plus optional README pointer. Do not combine with type work.

### Issue 0.1 — Align codebase layout with the current secS direction

Objective: Refactor the repository structure so the codebase matches the corrected boundary before more verifier behavior accumulates in legacy/prototype locations.

Files:

- Modify: `server/src/lib.rs`
- Move/refactor as needed: `server/src/bin/secz.rs`
- Possibly create: `server/src/ingress.rs`, `server/src/gateway.rs`, `server/src/runtime.rs`, `server/src/manifest.rs`, `server/src/receipt.rs`, `server/src/evidence.rs`
- Possibly modify: `docs/repository-schema.md`, `docs/implementation-status.md`, `README.md`

Instructions:

1. Inventory current modules and binaries against `docs/repository-schema.md`.
2. Identify names that still imply the wrong ownership boundary, especially the historical `server/src/bin/secz.rs` server-side gateway name.
3. Move reusable verifier/gateway/runtime code out of binaries into library modules before adding new behavior.
4. Keep binary compatibility where practical by leaving thin wrapper binaries or clearly documented aliases if a current command still needs to work.
5. Update docs to describe the new paths as an orientation map, not as agent guidance.
6. Do not change packet serialization or opcode semantics in this issue.

Acceptance criteria:

- [ ] Verifier, ingress/gateway, runtime execution, manifest, receipt, and evidence responsibilities have clear module homes or explicit TODO placeholders.
- [ ] The historical secZ-named server binary is either renamed, wrapped, or documented as a compatibility shim rather than the canonical verifier location.
- [ ] Public README stays product-neutral and reader-oriented.
- [ ] `docs/repository-schema.md` matches the actual code layout after the refactor.
- [ ] `cargo test --workspace` passes.

Verification:

```bash
cargo test --workspace
rg "server/src/bin/secz.rs|manifest|receipt|evidence|runtime_mode|verifier" README.md docs/repository-schema.md docs/implementation-status.md server/src
```

Stop condition:

Stop after structural refactor and docs alignment. Do not introduce new verification semantics beyond preserving existing behavior.

### Issue 0.2 — Add regression tests for preserved packet and opcode behavior

Objective: Freeze the behaviors that must not break before extraction begins.

Files:

- Modify: `core/src/lib.rs`
- Modify: `server/src/bin/secz.rs`
- Possibly modify: `client/src/main.rs` if CLI decimal opcode parsing currently lives there.

Instructions:

1. Add or confirm a `ZenithPacket` v0 round-trip test that includes non-empty proof, TTL, payload, MAC, and opcode.
2. Add a test that `u8::MAX` opcode round-trips without widening the field.
3. Add or confirm tests that empty proof and zero TTL still serialize but will be verifier failures later.
4. Add CLI/client test coverage for decimal opcode use if there is testable parsing logic. If no testable parsing function exists, create a small parser function and test decimal `16` as valid while documenting that `0x10` is not accepted unless support is deliberately added later.
5. Add a gateway/router test that unknown opcodes do not execute mapped handlers.

Acceptance criteria:

- [ ] `ZenithPacket` struct fields and field types are unchanged.
- [ ] Tests prove packet round-trip for normal and boundary opcode values.
- [ ] Tests distinguish serialization validity from verifier acceptance for empty proof / zero TTL.
- [ ] Decimal opcode behavior is either tested directly or a TODO is documented with exact file/function gap.
- [ ] Unknown opcode does not execute a handler.
- [ ] `cargo test --workspace` passes.

Verification:

```bash
cargo test --workspace zenith_packet -- --nocapture
cargo test --workspace opcode -- --nocapture
cargo test --workspace
```

Stop condition:

Stop after regression tests. Do not introduce verifier module in this issue.

## Phase 1 — typed verifier extraction

### Issue 1.1 — Introduce typed verification results and signed context types without changing routing yet

Objective: Define the verifier result types, error vocabulary, and signed `VerifiedCallContext` contract that later code will return and persist.

Files:

- Create: `server/src/verifier.rs`
- Possibly create: `server/src/context.rs`
- Possibly create: `server/src/identity.rs`
- Modify: `server/src/lib.rs`

Instructions:

1. Add `pub mod verifier;` in `server/src/lib.rs`. If context/signing code is split, also add `pub mod context;` and/or `pub mod identity;`.
2. Create `VerificationError` with at least these v0 variants:
   - `MalformedPacket`
   - `ExpiredClaim`
   - `MissingPrototypeProofEnvelope`
   - `BadPrototypeProofEnvelope`
   - `MissingTunnelKey`
   - `BadMac`
   - `UnknownOperation`
   - `HandlerUnavailable`
   - `WrongAudience`
   - `InvalidSignature`
   - `InternalError`
3. Create `VerificationDecision` or `VerificationResult` that can represent `Verified(VerifiedCallContext)` or `Rejected(VerificationError)`.
4. Create `VerifiedCallContext` with v0 fields: `schema_version`, `context_id`, `packet_hash`, `session_id`, `nonce`, `opcode`, `operation`, `subject`, `target/audience`, `evidence_summary`, `capability_result`, `credential_result`, `issued_at`, `expires_at`, and `replay_scope`.
5. Create `SignedVerifiedCallContext` with `context`, `signer_key_id`, `authenticator_kind`, and `signature`.
6. Add helper functions to sign and verify context bytes with an Ed25519-style key path. Tests may use ephemeral keys.
7. Add unit tests for error display/debug stability, one successful context construction, valid signature verification, tampered-context rejection, wrong-key rejection, wrong-audience rejection, and expired-context rejection.
8. Do not route live packets through this module yet.

Acceptance criteria:

- [ ] `server::verifier` compiles as a separate module.
- [ ] `VerificationError` is typed; no boolean-only verifier API is introduced.
- [ ] `VerifiedCallContext` has a signed serialized representation in v0.
- [ ] Signed context includes `schema_version`, `audience`, `expires_at`, `signer_key_id`, `authenticator_kind`, and `signature`.
- [ ] Tests reject tampered, expired, wrong-audience, and wrong-key contexts.
- [ ] Existing server/client behavior is unchanged.
- [ ] `cargo test --workspace` passes.

Verification:

```bash
cargo test -p server verifier -- --nocapture
cargo test --workspace
```

Stop condition:

Commit after typed verifier/context/signing types and tests compile. Do not move `validate_zk_proof` yet.

### Issue 1.2 — Extract prototype proof and TTL checks into `Verifier`

Objective: Replace ad hoc proof/TTL boolean checks with typed verifier failures while honestly naming the current weakness.

Files:

- Modify: `server/src/verifier.rs`
- Modify: `server/src/bin/secz.rs`

Instructions:

1. Add a `Verifier` struct or stateless `verify_prototype_packet` function in `server/src/verifier.rs`.
2. Move the current logic `!packet.proof.is_empty() && packet.claim_ttl > 0` behind a function named around `PrototypeProofEnvelope`.
3. Return `MissingPrototypeProofEnvelope` for empty proof.
4. Return `ExpiredClaim` or `BadPrototypeProofEnvelope` for zero TTL, depending on the accepted naming.
5. Update `server/src/bin/secz.rs` to call the verifier instead of local `validate_zk_proof`.
6. Keep the same runtime rejection behavior for invalid proof/TTL, but make the reason typed in code and log output.
7. Preserve tests equivalent to `validate_zk_proof_accepts_non_empty_proof_and_positive_ttl`, `validate_zk_proof_rejects_empty_proof`, and `validate_zk_proof_rejects_zero_ttl`, now against `Verifier`.

Acceptance criteria:

- [ ] `server/src/bin/secz.rs` no longer owns the proof/TTL trust rule.
- [ ] The prototype proof check is explicitly named as prototype, not real ZK verification.
- [ ] Empty proof returns a typed verifier error.
- [ ] Zero TTL returns a typed verifier error.
- [ ] Existing valid packets still reach the router.
- [ ] `cargo test --workspace` passes.

Verification:

```bash
rg "fn validate_zk_proof|!packet\.proof\.is_empty\(\) && packet\.claim_ttl > 0" server/src
cargo test -p server verifier -- --nocapture
cargo test -p server --bin secz proof -- --nocapture
cargo test --workspace
```

Stop condition:

Stop when the old boolean helper is gone or reduced to a private wrapper that delegates to typed verifier output.

### Issue 1.3 — Make runtime mode explicit for plaintext fallback

Objective: Replace silent plaintext fallback with explicit `local_dev_plaintext`, `local_dev_tunnel`, or `production_verified` mode.

Files:

- Modify: `server/src/verifier.rs`
- Modify: `server/src/bin/secz.rs`
- Possibly create: `server/src/runtime_mode.rs`

Instructions:

1. Add `RuntimeMode` enum:
   - `LocalDevPlaintext`
   - `LocalDevTunnel`
   - `ProductionVerified`
2. Add env parsing for a single explicit variable such as `SECS_RUNTIME_MODE` or `SECZ_RUNTIME_MODE`; document whichever is chosen.
3. In `LocalDevPlaintext`, allow payload passthrough but stamp logs/receipts later as insecure.
4. In `LocalDevTunnel`, require tunnel key and reject undecryptable payloads.
5. In `ProductionVerified`, fail closed if tunnel/MAC/session/evidence requirements are missing.
6. Update tests so plaintext fallback only happens when explicit local-dev plaintext mode is active.

Acceptance criteria:

- [ ] Plaintext fallback cannot happen silently by merely omitting tunnel keys.
- [ ] Local dev plaintext mode has an explicit env/config path and visible log label.
- [ ] Tunnel mode still decrypts valid ciphertext and rejects wrong keys.
- [ ] Production mode fails closed for missing required crypto/evidence inputs.
- [ ] Existing local tests are updated to choose the intended mode.
- [ ] `cargo test --workspace` passes.

Verification:

```bash
cargo test -p server runtime_mode -- --nocapture
cargo test -p server --bin secz decrypt -- --nocapture
cargo test --workspace
```

Stop condition:

Do not add receipts in this issue; only mode and verifier/decrypt behavior.

## Phase 2 — receiver-local manifest

### Issue 2.1 — Define operation descriptors and manifest lookup

Objective: Replace implicit opcode maps with receiver-local operation descriptors.

Files:

- Create: `server/src/manifest.rs`
- Modify: `server/src/lib.rs`
- Modify: `server/src/bin/secz.rs`

Instructions:

1. Add `pub mod manifest;` to `server/src/lib.rs`.
2. Define `OperationDescriptor` with v0 fields:
   - `opcode: u8`
   - `name: String` or a small `OperationName` newtype
   - `payload_schema: Option<String>`
   - `target_kind: TargetKind`
   - `required_credentials: Vec<String>`
   - `required_capabilities: Vec<String>`
   - `accepted_evidence: Vec<String>`
   - `replay_scope: ReplayScope`
   - `max_ttl_seconds: u64`
   - `handler_id: String`
   - `dev_binding: bool`
3. Add a `ReceiverManifest` struct that maps opcode to descriptor.
4. Add constants/helpers documenting the reserved ranges:
   - core standardized: `0x01`–`0x0A`;
   - Castalia-standard candidate: `0x0B`–`0x3F`;
   - operator-defined: `0x40`–`0xFF`.
5. Seed descriptors for `0x01`, `0x02`, `0x10`, `0x20`, and `0x30`.
6. Mark `0x01`/`0x02` as core standardized legacy examples.
7. Mark `0x10` Bash echo and `0x30` `jq .` as dev bindings in the Castalia-standard candidate range, not final global semantics.
8. Add tests for lookup success, unknown opcode failure, dev-binding flags, and range classification.

Acceptance criteria:

- [ ] Manifest lookup is receiver-local and keyed by `u8` opcode.
- [ ] Descriptors include semantic operation names above local opcodes.
- [ ] `0x01`, `0x02`, `0x10`, `0x20`, and `0x30` are represented.
- [ ] `0x01`/`0x02` are labeled core standardized legacy examples.
- [ ] `0x10`/`0x20`/`0x30` are labeled Castalia-standard candidates/dev bindings until ratified.
- [ ] Operator-defined range begins at `0x40`.
- [ ] Dev bindings are visibly marked.
- [ ] Unknown opcode produces a typed manifest/verifier error path.
- [ ] `cargo test --workspace` passes.

Verification:

```bash
cargo test -p server manifest -- --nocapture
cargo test --workspace
```

Stop condition:

Stop after descriptors exist and are tested. Do not rewrite execution broker semantics yet.

### Issue 2.2 — Route descriptor lookup through verification before execution

Objective: Make manifest meaning part of the verification path before handler execution.

Files:

- Modify: `server/src/verifier.rs`
- Modify: `server/src/manifest.rs`
- Modify: `server/src/bin/secz.rs`

Instructions:

1. Pass a `ReceiverManifest` reference into verifier or gateway verification flow.
2. On packet receipt, decode packet, verify prototype proof/TTL/runtime mode, then lookup operation descriptor.
3. Populate `VerifiedCallContext.operation`, `handler_id`, and range/governance metadata from descriptor.
4. Sign the verified context before handler execution if Issue 1.1 signing support exists; otherwise pass the unsigned struct only as an intermediate commit with a TODO to sign before the phase is complete.
5. Only route to a handler after `VerifiedCallContext` exists.
6. Reject unknown opcode before handler lookup.
7. Keep `ConfigurableRouter` handler map for now, but align handler key/id with descriptor.

Acceptance criteria:

- [ ] Handler execution is downstream of typed verification plus descriptor lookup.
- [ ] Unknown opcode returns/reports typed rejection and does not execute a handler.
- [ ] Known mapped opcode still executes its handler in local dev mode.
- [ ] `VerifiedCallContext` includes operation name, handler id, audience, expiry, and signer metadata once signed.
- [ ] Known mapped operation can produce a signed context before handler execution.
- [ ] `cargo test --workspace` passes.

Verification:

```bash
cargo test -p server verifier -- --nocapture
cargo test -p server --bin secz router -- --nocapture
cargo test --workspace
```

Stop condition:

Do not introduce durable receipt tables yet; this issue should only connect verifier, manifest, and routing.

## Phase 3 — receipts and local event ledger

### Issue 3.1 — Define receipt and event types

Objective: Add typed receipt/event objects before changing SQLite persistence.

Files:

- Create: `server/src/receipt.rs`
- Modify: `server/src/lib.rs`
- Modify: `server/src/verifier.rs` if it needs shared `Decision` or `ReasonCode` types.

Instructions:

1. Add `pub mod receipt;` to `server/src/lib.rs`.
2. Define `ReceiptKind`: `Reject`, `Verify`, `Execute`, `Forward`.
3. Define `Decision`: `Accepted`, `Rejected`.
4. Define `Receipt` with v0 fields from the spec where currently available:
   - `receipt_id`
   - `kind`
   - `packet_hash`
   - `session_id`
   - `nonce`
   - `opcode`
   - `operation`
   - `decision`
   - `reason`
   - `handler_id`
   - `timestamp`
   - `authenticator_kind`
   - `signer_key_id`
   - `signature`
5. Define `AuthenticatorKind` with at least `LocalDevUntrusted`, `LocalMac`, `Ed25519Node`, `Ed25519Verifier`, `Ed25519NodeAndVerifier`, and `ExternalAnchor`.
6. Define event names: `packet_received`, `packet_rejected`, `packet_verified`, `operation_described`, `operation_routed`, `handler_started`, `handler_succeeded`, `handler_failed`, `receipt_emitted`.
7. Add tests for creating reject, verify, and execution receipts without payload contents.
8. Add tests for signing/verifying a receipt, tampered receipt rejection, and wrong-key rejection. Tests may use ephemeral keys.

Acceptance criteria:

- [ ] Receipts do not include raw payload bytes by default.
- [ ] Reject receipts can be created from `VerificationError`.
- [ ] Verify receipts can be created from `SignedVerifiedCallContext` or its verified context plus signer metadata.
- [ ] Execution receipts can reference `handler_id` and decision.
- [ ] Receipt kind, decision, reason, and authenticator kind are typed.
- [ ] Public-key signed receipts include `authenticator_kind`, `signer_key_id`, and `signature`.
- [ ] Tests reject tampered receipts and wrong-key verification.
- [ ] `cargo test --workspace` passes.

Verification:

```bash
cargo test -p server receipt -- --nocapture
cargo test --workspace
```

Stop condition:

Stop after in-memory receipt objects. Do not migrate SQLite yet.

### Issue 3.2 — Replace thin telemetry with receipt/event SQLite tables

Objective: Move from `node_telemetry(opcode, payload_size)` to auditable local receipt/event persistence.

Files:

- Create: `server/src/ledger.rs`
- Modify: `server/src/lib.rs`
- Modify: `server/src/bin/secz.rs`

Instructions:

1. Add `Ledger` wrapper around `SqlitePool`.
2. Create tables with runtime SQL only; do not introduce compile-time SQLx macros unless offline cache is intentionally maintained.
3. Minimum tables:
   - `events(id, timestamp, event_kind, packet_hash, opcode, operation, handler_id, reason)`
   - `receipts(receipt_id, timestamp, kind, packet_hash, session_id, nonce, opcode, operation, decision, reason, handler_id, authenticator_kind, signer_key_id, signature)`
4. Store payload size and payload hash if needed; do not store payload content by default.
5. Update route flow to emit events and receipts for reject, verify, handler started, handler succeeded, handler failed.
6. Keep migration simple with `CREATE TABLE IF NOT EXISTS` for v0.

Acceptance criteria:

- [ ] `node_telemetry` is no longer the only audit table.
- [ ] Reject path writes a reject receipt.
- [ ] Verify path writes a verify receipt.
- [ ] Handler success/failure writes execution receipt or event.
- [ ] Receipt rows persist `authenticator_kind`, `signer_key_id`, and `signature` for signed receipts.
- [ ] Payload content is not stored by default.
- [ ] SQL is runtime SQL and testable with in-memory SQLite.
- [ ] `cargo test --workspace` passes.

Verification:

```bash
cargo test -p server ledger -- --nocapture
cargo test -p server --bin secz receipt -- --nocapture
cargo test --workspace
```

Stop condition:

Do not add external proof adapters in this issue.

## Phase 4 — evidence adapter seam

### Issue 4.1 — Introduce `EvidenceAdapter` trait and `local_static` adapter

Objective: Add the first deterministic evidence seam without making Dregg or Midnight mandatory.

Files:

- Create: `server/src/evidence.rs`
- Modify: `server/src/lib.rs`
- Modify: `server/src/verifier.rs`
- Modify: `server/src/manifest.rs`

Instructions:

1. Add `pub mod evidence;` to `server/src/lib.rs`.
2. Define `EvidenceKind`, `EvidenceRequest`, `EvidenceResult`, and `EvidenceAdapter` trait.
3. Ensure `EvidenceRequest` has future-ready fields for subject, audience, operation, resource, evidence refs, public inputs, and reason-code output even if `local_static` only uses a subset.
4. Implement `LocalStaticEvidenceAdapter` for deterministic tests.
5. Label `local_static` as local/dev/test authority in evidence summaries and any generated receipts/contexts.
6. Connect descriptor `accepted_evidence` to the verifier, but allow operations with no evidence requirement in local dev only if descriptor says so.
7. Add tests for accepted static evidence, missing evidence, wrong subject/audience where represented, and insufficient evidence.
8. Prove the `local_static` result can flow into a signed context/receipt without claiming public proof.
9. Do not import Dregg, Midnight, or Cardano dependencies in this issue.

Acceptance criteria:

- [ ] Evidence verification is typed and adapter-based.
- [ ] `local_static` can satisfy a descriptor requirement in deterministic tests.
- [ ] `local_static` is visibly labeled local/dev/test in evidence summaries and signed outputs.
- [ ] Missing required evidence returns typed `insufficient_evidence` or equivalent.
- [ ] The adapter trait is shaped so wallet presentation and Midnight/ZK proof can reuse it without redefining the verifier interface.
- [ ] Dregg remains optional; no Dregg runtime dependency is introduced.
- [ ] Midnight remains optional; no Midnight verifier dependency is introduced.
- [ ] `cargo test --workspace` passes.

Verification:

```bash
cargo test -p server evidence -- --nocapture
cargo test -p server verifier -- --nocapture
cargo test --workspace
```

Stop condition:

Stop after `local_static`. Do not implement wallet or Midnight proof adapters in the same issue.

### Issue 4.2 — Add `wallet_presentation` adapter shell

Objective: Create the first real subject/key verification seam without completing every wallet proof rail.

Files:

- Modify: `server/src/evidence.rs`
- Modify: `server/src/verifier.rs`
- Add tests under existing module or create: `server/tests/wallet_presentation.rs` if integration tests are preferred.

Instructions:

1. Define the request fields the wallet adapter needs: subject id/key, audience, origin/endpoint, signature/challenge bytes or refs.
2. Implement a shell adapter that validates shape and explicit unsupported cases.
3. Add a deterministic positive test only if a simple signature fixture already exists or can be generated locally without secrets.
4. Return typed `invalid_presentation`, `wrong_audience`, and `wrong_origin` where applicable.
5. Keep this adapter behind a feature flag or clearly marked incomplete if full cryptographic verification is not ready.

Acceptance criteria:

- [ ] Wallet presentation request/response contract is explicit.
- [ ] Missing presentation returns typed failure.
- [ ] Wrong audience and wrong origin are distinguishable.
- [ ] No secrets or real wallet keys are committed.
- [ ] Adapter can be left incomplete only with explicit typed unsupported status and tests.
- [ ] `cargo test --workspace` passes.

Verification:

```bash
cargo test -p server wallet_presentation -- --nocapture
cargo test --workspace
```

Stop condition:

Do not add Midnight/Cardano/Dregg rails here.

## Phase 5 — bounded execution broker cleanup

### Issue 5.1 — Make handler execution consume `VerifiedCallContext`

Objective: Ensure local handlers run with verified context, not raw opcode/payload trust assumptions.

Files:

- Modify: `server/src/bin/secz.rs`
- Possibly create: `server/src/execution.rs`
- Modify: `server/src/verifier.rs`
- Modify: `server/src/receipt.rs`

Instructions:

1. Update `MachineProgram` trait to accept `&VerifiedCallContext` and payload bytes.
2. Update `SubprocessForwarder` and `LocalRustQueue` implementations.
3. Enforce timeout and max payload size before calling handlers.
4. Emit handler success/failure receipt/event through ledger.
5. Preserve dev subprocess bindings but mark them as dev bindings via manifest descriptor.

Acceptance criteria:

- [ ] No handler executes without a `VerifiedCallContext`.
- [ ] Handler receipts include `handler_id` and decision.
- [ ] Timeout and max payload limits exist and are tested.
- [ ] Subprocess forwarder remains bounded and does not gain broad ambient shell authority beyond explicit dev descriptors.
- [ ] Payload content is not logged by default.
- [ ] `cargo test --workspace` passes.

Verification:

```bash
cargo test -p server execution -- --nocapture
cargo test -p server --bin secz handler -- --nocapture
cargo test --workspace
```

Stop condition:

Do not redesign client/secC/secZ packaging in this issue.

## Phase 6 — client-side documentation and packet-builder boundary

### Issue 6.1 — Document local Hermes/secC/secZ as client-side packet construction surfaces

Objective: Prevent the implementation from regressing into “secZ is verifier/interface” language.

Files:

- Create or modify: `docs/client-surfaces.md`
- Possibly modify: `README.md`
- Possibly modify: `client/src/main.rs` comments/help text.

Instructions:

1. Document three outgoing client-side paths:
   - local Hermes secS tool/script/skill;
   - secC generic/non-Zenith client form;
   - secZ Zenith-oriented outgoing client surface.
2. State explicitly that all three call secS; none replaces secS-magik verification.
3. Include example flow:

```text
user / local Hermes / app / node intent
  -> local Hermes tool, secC, or secZ
  -> operation name / local opcode / target node
  -> capability / credential / evidence refs
  -> ZenithPacket
  -> target secS RPC surface
```

4. Keep docs aligned with source spec and boundary note.

Acceptance criteria:

- [ ] Docs say local Hermes/secC/secZ are client-side ways to call secS.
- [ ] Docs say secS-magik/secS remains verifier/RPC substrate.
- [ ] Docs do not call secZ the generic Castalia interface or verifier.
- [ ] CLI/help text, if touched, uses the corrected language.
- [ ] `cargo test --workspace` passes if code comments/help changed.

Verification:

```bash
rg "client-side|local Hermes|secC|secZ|verifier" docs README.md client/src server/src
cargo test --workspace
```

Stop condition:

Docs/help only. Do not combine with packet-builder implementation.

### Issue 6.2 — Extract packet-builder helper for client surfaces

Objective: Give local Hermes/secC/secZ a shared way to construct `ZenithPacket` without becoming verifiers.

Files:

- Possibly create: `core/src/packet_builder.rs`
- Modify: `core/src/lib.rs`
- Modify: `client/src/main.rs`
- Possibly add tests in `core/src/packet_builder.rs`.

Instructions:

1. Add a small builder/helper that constructs `ZenithPacket` from session id, nonce, opcode, proof/presentation bytes, TTL, encrypted payload, and MAC.
2. Keep validation limited to shape/bounds needed for packet construction; do not put server-side authority verification in the builder.
3. Use the helper from the client CLI if that reduces duplication.
4. Add tests proving the helper preserves v0 field layout and decimal opcode values.

Acceptance criteria:

- [ ] Packet-builder lives in `core` only if it is verifier-free.
- [ ] Builder does not validate capabilities, credentials, evidence, or authority.
- [ ] Client uses builder or documents why current direct construction remains clearer.
- [ ] `ZenithPacket` v0 field shape remains unchanged.
- [ ] `cargo test --workspace` passes.

Verification:

```bash
cargo test -p libsec-core packet_builder -- --nocapture
cargo test --workspace
```

Stop condition:

Do not create secC/secZ product surfaces beyond shared packet construction.

## Cross-phase acceptance checklist

The sequence is acceptable when all of the following are true:

- [ ] `cargo test --workspace` passes.
- [ ] Current CLI decimal opcode examples still work.
- [ ] `ZenithPacket` v0 still round-trips unchanged.
- [ ] Unknown opcode produces a typed reject path and no handler execution.
- [ ] Empty proof / zero TTL produce typed verifier failures, not ambiguous boolean rejection.
- [ ] Dev plaintext mode is explicit and visibly stamped.
- [ ] Receiver-local manifest owns opcode meaning within reserved ranges: core standardized `0x01`–`0x0A`, Castalia-standard candidate `0x0B`–`0x3F`, operator-defined `0x40`–`0xFF`.
- [ ] Handlers receive `VerifiedCallContext`, not raw trust assumptions.
- [ ] `VerifiedCallContext` has a signed serialized representation with signer, audience, expiry, schema version, and replay semantics.
- [ ] Receipts exist for reject, verify, and execution paths.
- [ ] Receipts and signed contexts use portable public-key signature verification for production-shaped paths; local/dev authenticators are stamped non-authoritative.
- [ ] Payload contents are not stored in logs/receipts by default.
- [ ] `local_static` evidence works as deterministic local/dev scaffold without making Dregg, Midnight, or Cardano mandatory.
- [ ] Docs distinguish local Hermes secS tool/script/skill, secC, and secZ as client-side ways to call secS.
- [ ] secZ docs say outgoing/client-side RPC construction, not Castalia interface or verifier.
- [ ] secS-magik docs say verifier/RPC substrate, not product policy.

## Suggested issue order

1. Issue 0.1 — repo spec import.
2. Issue 0.2 — regression tests for preserved packet/opcode behavior.
3. Issue 1.1 — typed verifier results and signed context types.
4. Issue 1.2 — prototype proof/TTL verifier extraction.
5. Issue 1.3 — explicit runtime mode.
6. Issue 2.1 — operation descriptors and receiver manifest.
7. Issue 2.2 — descriptor lookup through verification.
8. Issue 3.1 — receipt/event types.
9. Issue 3.2 — SQLite receipt/event ledger.
10. Issue 4.1 — evidence adapter trait and `local_static`.
11. Issue 5.1 — handlers consume `VerifiedCallContext`.
12. Issue 6.1 — corrected client-surface documentation.
13. Issue 6.2 — verifier-free packet-builder helper.
14. Issue 4.2 — `wallet_presentation` adapter shell, after the local adapter and receipt contract stabilize.

## Candidate GitHub issue titles

- `docs: import secS-magik objectives spec as implementation source of truth`
- `test: freeze ZenithPacket v0 and decimal opcode compatibility`
- `feat(server): add typed verifier result and signed VerifiedCallContext types`
- `refactor(server): extract prototype proof envelope checks into verifier`
- `feat(server): make local plaintext and tunnel runtime modes explicit`
- `feat(server): add receiver-local operation manifest descriptors`
- `feat(server): require manifest descriptor lookup before handler execution`
- `feat(server): define signed receipts and verifier event types`
- `feat(server): persist receipt and event ledger in SQLite`
- `feat(server): add EvidenceAdapter trait with local_static adapter`
- `refactor(server): pass VerifiedCallContext into machine handlers`
- `docs: clarify local Hermes secC and secZ as client-side secS callers`
- `feat(core): add verifier-free ZenithPacket builder helper`
- `feat(server): add wallet_presentation evidence adapter shell`

---

Areas:
- [[Zenith]]
- [[secS]]
- [[secC]]
- [[secZ]]
- [[planning]]
- [[projects]]
