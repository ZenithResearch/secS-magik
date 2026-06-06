# secS-magik Phase: Track E — trusted issuer/root policy

GitHub phase issue: https://github.com/ZenithResearch/secS-magik/issues/63
Underlying issue: https://github.com/ZenithResearch/secS-magik/issues/35

## Objective

Enforce production evidence acceptance through receiver-held trusted issuer/root metadata, static fixture trust registry objects, and signed membership/provisioning credential checks. Embedded evidence keys, caller-supplied root refs, wallet proof-of-possession, local_static grants, plaintext, and prototype evidence must never become production authority by themselves.

## Current baseline

- Start branch from clean `main` at or after PR #68 merge commit `536a1ae2a81731026561e85a643fe483188be9ba`.
- Track D is complete: `wallet_presentation` verifies Ed25519 proof-of-possession over the temporary secS challenge contract.
- Track D boundary still applies: wallet proof-of-possession is not issuer/root/registry authority.
- Current code surfaces:
  - `server/src/evidence.rs` owns `EvidenceKind`, `EvidenceRequest`, `EvidenceSummary`, `LocalStaticEvidenceAdapter`, and `WalletPresentationAdapter`.
  - `server/src/manifest.rs` owns `OperationDescriptor.accepted_evidence` but does not yet model production evidence policy or trust requirements.
  - `server/tests/support/wallet_fixtures.rs` owns reusable subject/audience/origin/operation/resource fixture values from Track D.
  - `docs/plans/2026-06-02-ready-for-prod-checklist.md` already defines the narrowed A5/A6 model: `TrustedIssuerEntry`, `membership_credential` / `provisioning_credential`, `registry_status` / `revocation_status`, and generic `trust_root_ref` / `registry_root_ref` metadata.

## Dependencies

Must be true before implementation starts:

- Track H local/operator ledger posture is merged and queryable.
- Track F subprocess cleanup is merged.
- Track D wallet cryptographic verification is merged.
- `main` and `origin/main` are aligned.
- The implementer has read:
  - `AGENTS.md`
  - `README.md`
  - `docs/implementation-status.md`
  - `docs/repository-schema.md`
  - `docs/plans/2026-06-02-ready-for-prod-checklist.md`, especially A5/A6/A8 Track E rows
  - `server/src/evidence.rs`
  - `server/src/manifest.rs`
  - `server/src/verifier.rs`
  - `server/tests/support/wallet_fixtures.rs`

## PR boundary

Branch:

```text
phase/track-e-production-evidence-policy
```

PR title:

```text
feat(server): enforce trusted issuer and root policy for production evidence
```

PR closes / covers:

- Closes #63.
- Closes #35.

## Non-goals / forbidden claims

Do not implement or claim:

- live Castalia registry discovery;
- live Dregg capability/proof/revocation verification;
- Midnight proof verification;
- Cardano settlement/finality proof;
- public auditability or external anchoring;
- full Castalia Wallet wallet-core parity;
- production deployment proof;
- `membership.provision` E2E success; that is Track I;
- wallet proof-of-possession as sufficient issuer/root/registry authority.

Static registry data may use generic `trust_root_ref` / `registry_root_ref` labels only. Do not call those labels live Dregg validation.

## Locked model

Track E must preserve this authority split:

1. Wallet presentation proves subject key possession under the temporary secS challenge contract.
2. Membership/provisioning credential proves a claim about a subject only if signed by an issuer key that chains to receiver-held trusted issuer/root metadata.
3. Receiver-local manifest/policy still decides whether that credential kind, issuer/root, subject, audience, operation, resource/scope, and status can satisfy the descriptor.
4. Caller-supplied embedded keys, issuer IDs, root refs, status refs, or credential claims are evidence data only; they are not authority unless matched against receiver-held registry metadata.
5. Local/dev evidence remains local/dev. It cannot satisfy production descriptors.

## Suggested target files

Expected code files:

- `server/src/evidence.rs`
- `server/src/manifest.rs`
- `server/src/verifier.rs`
- new `server/src/trust.rs` if separating registry/policy types is cleaner
- `server/src/lib.rs` if exporting a new module
- `server/tests/evidence.rs`
- new `server/tests/production_federated.rs` if the matrix outgrows `evidence.rs`
- `server/tests/support/wallet_fixtures.rs`
- new `server/tests/support/trust_fixtures.rs` or consolidated shared fixture module
- `fixtures/trust/` if file-backed fixture registry is implemented

Expected docs/status files:

- `README.md`
- `server/README.md`
- `docs/implementation-status.md`
- `docs/repository-schema.md`
- `docs/plans/2026-06-02-ready-for-prod-checklist.md`
- `docs/client-surfaces.md` if wallet-vs-issuer authority copy needs clarification
- `CHANGELOG.md`

## Task list — checkbox = commit boundary

### E0 — Branch setup, baseline audit, and RED-test plan

- [ ] Create `phase/track-e-production-evidence-policy` from clean `main` at/after `536a1ae2a81731026561e85a643fe483188be9ba`.
- [ ] Confirm `git status --short --branch` shows clean branch tracking current main.
- [ ] Read `server/src/evidence.rs`, `server/src/manifest.rs`, `server/src/verifier.rs`, `server/tests/evidence.rs`, `server/tests/wallet_presentation.rs`, and `server/tests/support/wallet_fixtures.rs` before editing.
- [ ] Inspect existing `VerificationError` variants and decide whether Track E needs new typed reasons or can reuse existing ones without ambiguity.
- [ ] Add a brief in-code or test-module TODO plan listing the E1–E4 reject/accept rows so implementation cannot quietly skip a matrix row.
- [ ] Commit only baseline docs/test-plan scaffolding if it is material; otherwise fold into E1.

Acceptance:

- [ ] Implementer can point to exact current code surfaces and current missing policy boundary.
- [ ] No production behavior changed before RED tests exist.

### E1 — Add typed evidence kinds and production policy descriptors

- [x] Extend `EvidenceKind` with first-path credential kinds: `MembershipCredential` and `ProvisioningCredential`.
- [x] Add stable `as_str()` values: `membership_credential` and `provisioning_credential`.
- [x] Add or extend descriptor/policy types so production descriptors can declare allowed evidence kinds separately from local/dev descriptors.
- [x] Add a fixture production descriptor for `membership.provision` or a narrowly named Track E test descriptor that requires membership/provisioning evidence and rejects local/dev evidence.
- [x] Add RED tests proving `local_static`, plaintext/prototype, and wallet-only evidence cannot satisfy a production descriptor.
- [x] Keep local/dev descriptors working with explicit local/dev modes or clearly named local/dev constructors.

Targeted verification:

```bash
cargo test -p server evidence production_policy_rejects_local_static -- --nocapture
cargo test -p server evidence production_policy_rejects_wallet_only_authority -- --nocapture
```

Acceptance:

- [x] `local_static` cannot satisfy production descriptors.
- [x] Prototype/plaintext evidence cannot satisfy production descriptors.
- [x] Wallet presentation proof alone cannot satisfy trusted issuer/root policy.
- [x] Local/dev fixtures remain explicitly local/dev only.
- [x] Evidence kinds are typed; no new free-form evidence-kind string drift.

### E2 — Create shared D/E/I fixture constants and helpers

- [x] Promote or reuse Track D values from `server/tests/support/wallet_fixtures.rs`: subject, audience, origin, operation, resource, timestamps, and nonce/session refs.
- [x] Add trust fixture constants for issuer id, issuer key id, trust root ref, registry root ref, credential ids, status ids, accepted credential kinds, accepted audiences, accepted operations, accepted scopes/resources, and validity windows.
- [x] Ensure wallet and trusted-issuer tests use the same subject/audience/origin/operation/resource values unless intentionally testing mismatch.
- [x] Add helper constructors for valid and mutated credentials so matrix tests do not copy-paste literals.
- [x] Document fixture-only key material as no-real-secret test material.

Targeted verification:

```bash
cargo test -p server wallet_presentation -- --nocapture
cargo test -p server production_federated fixture -- --nocapture
```

Acceptance:

- [x] No incompatible duplicate spelling of receiver audience, subject, operation, or resource is introduced.
- [x] Track I can compose the same fixture scenario without rewriting constants.
- [x] Fixture helper names distinguish happy-path, mismatch, revoked, expired, stale, malformed, and untrusted variants.

### E3 — Implement receiver-held trusted issuer/root registry objects

- [x] Implement `TrustedIssuerEntry` or equivalent with at least:
  - issuer id;
  - issuer public key / verification key bytes;
  - issuer key id / fingerprint;
  - `trust_root_ref`;
  - `registry_root_ref`;
  - accepted credential/evidence kinds;
  - accepted audiences;
  - accepted operations;
  - accepted scopes/resources;
  - issuer/key status;
  - validity window;
  - revocation/status reference fields if modeled.
- [x] Implement a static in-memory registry type or loader-backed fixture registry with explicit receiver-held ownership.
- [x] Add lookup by issuer id and key id.
- [x] Add status checks for active, unknown, revoked, expired, and not-yet-valid issuer/key states.
- [x] Add root/ref checks: wrong `trust_root_ref` and wrong `registry_root_ref` reject.
- [x] Reject embedded evidence keys/issuer/root refs unless they match receiver-held registry metadata.
- [x] Keep registry parse/load errors fail-closed and redacted.

Targeted verification:

```bash
cargo test -p server trust trusted_issuer -- --nocapture
cargo test -p server evidence untrusted_embedded_key_rejects -- --nocapture
```

Acceptance:

- [x] Receiver-held issuer/root metadata controls trust.
- [x] Embedded evidence keys are evidence data only.
- [x] Unknown issuer rejects.
- [x] Wrong key rejects.
- [x] Wrong root/ref rejects.
- [x] Revoked/expired/not-yet-valid issuer/key rejects.
- [x] Static registry is fixture-backed and explicitly not live Dregg/Castalia discovery.

### E4 — Implement signed membership/provisioning credential fixture shape

- [x] Define a fixture credential struct or parser for `membership_credential` / `provisioning_credential` with at least:
  - credential id;
  - credential kind;
  - subject;
  - audience;
  - operation;
  - resource/scope;
  - issuer id;
  - issuer key id;
  - `trust_root_ref` / `registry_root_ref` references;
  - issued-at / expires-at;
  - status or revocation reference;
  - signature suite;
  - signature bytes.
- [x] Define canonical bytes for signing that bind every authority-relevant field.
- [x] Generate deterministic no-real-secret Ed25519 fixture credentials.
- [x] Verify credential signature with the receiver-held issuer key from the registry, not with a caller-provided key alone.
- [x] Return a safe `EvidenceSummary` that includes credential kind/id, subject, audience, operation, resource/scope, issuer id, issuer key id, trust/root refs, status/ref, issued/expires metadata, and redacted proof metadata.
- [x] Ensure raw private keys, raw signature bytes, raw credential blobs, and raw secret material are absent from summaries/receipts by default.

Targeted verification:

```bash
cargo test -p server production_federated valid_membership_credential_verifies -- --nocapture
cargo test -p server evidence membership_credential -- --nocapture
```

Acceptance:

- [x] Valid trusted active membership credential satisfies a permitted descriptor.
- [x] Valid trusted active provisioning credential satisfies a permitted descriptor if descriptor permits provisioning credentials.
- [x] Signature verification uses receiver-held issuer metadata.
- [x] Evidence summary is safe for signed context / receipt use.

### E5 — Implement credential reject matrix

- [x] Test missing credential ref rejects.
- [x] Test unknown credential ref rejects.
- [x] Test malformed credential rejects.
- [x] Test unsupported signature suite rejects.
- [x] Test wrong signature rejects.
- [x] Test wrong issuer key rejects.
- [x] Test embedded caller key that does not match registry rejects.
- [x] Test unknown issuer rejects.
- [x] Test trusted issuer with wrong trust root rejects.
- [x] Test trusted issuer with wrong registry root rejects.
- [x] Test revoked issuer rejects.
- [x] Test expired issuer rejects.
- [x] Test not-yet-valid issuer rejects.
- [x] Test revoked credential/status rejects.
- [x] Test expired credential rejects.
- [x] Test not-yet-valid credential rejects if modeled.
- [x] Test stale registry/status metadata rejects if modeled.
- [x] Test wrong subject rejects.
- [x] Test wrong audience rejects.
- [x] Test wrong origin rejects if origin is represented in the credential or public inputs.
- [x] Test wrong operation rejects.
- [x] Test wrong resource/scope rejects.
- [x] Test accepted credential kind mismatch rejects: membership descriptor rejects provisioning if not allowed, and provisioning descriptor rejects membership if not allowed.
- [x] Test valid credential still fails when receiver-local manifest policy disallows the operation/scope/audience.

Targeted verification:

```bash
cargo test -p server production_federated reject_matrix -- --nocapture
cargo test -p server evidence membership_credential provisioning_credential -- --nocapture
```

Acceptance:

- [x] Every authority-relevant field has at least one negative test.
- [x] Failure reasons are typed/stable enough for debugging and future receipt policy.
- [x] No reject case leaks private key, raw signature, raw evidence body, or secret config in panic messages, summaries, docs, or logs.

### E6 — Compose wallet proof-of-possession with issuer/root policy without conflating them

- [x] Add tests showing valid wallet presentation plus missing/invalid issuer credential rejects production evidence.
- [x] Add tests showing valid issuer credential plus missing wallet presentation rejects if the descriptor requires both wallet and federated evidence.
- [x] Add tests showing valid wallet subject must match credential subject when both are required.
- [x] Add tests showing wallet audience/origin/operation/resource mismatch remains wallet-layer failure, while issuer/root mismatch remains policy-layer failure.
- [x] Ensure evidence summaries preserve both proof layers distinctly if both are present.

Targeted verification:

```bash
cargo test -p server production_federated wallet_and_issuer_composition -- --nocapture
cargo test -p server wallet_presentation -- --nocapture
```

Acceptance:

- [x] Wallet proof-of-possession is necessary where required but never sufficient issuer/root authority.
- [x] Trusted issuer credential is necessary where required but never replaces wallet possession when descriptor requires both.
- [x] Summary/context fields distinguish wallet subject possession from trusted issuer credential authority.

### E7 — Enforce descriptor-local policy before accept

- [x] Add policy checks for descriptor accepted evidence kinds.
- [x] Add policy checks for descriptor operation name.
- [x] Add policy checks for descriptor resource/payload schema/scope.
- [x] Add policy checks for receiver audience.
- [x] Add policy checks for required credentials/capabilities where existing fields are meaningful.
- [x] Add a test where a credential is cryptographically valid and registry-trusted but disallowed by the receiver-local descriptor.
- [x] Add a test where the same credential is accepted by the descriptor that explicitly allows it.

Targeted verification:

```bash
cargo test -p server production_federated valid_evidence_local_policy_rejects -- --nocapture
cargo test -p server production_federated valid_evidence_policy_accepts -- --nocapture
```

Acceptance:

- [x] Trusted foreign evidence never bypasses receiver-local manifest policy.
- [x] Descriptor policy is the final local accept gate after crypto/trust checks.

### E8 — Registry/config file fixture and fail-closed load behavior

Only implement file-backed fixture registry if the chosen registry path needs a real file for Track I. If not, explicitly document why in-memory fixture registry is enough for Track E.

- [x] If file-backed: add `fixtures/trust/membership-issuers.json` or equivalent with no real secrets.
- [x] Add parser/loader tests for valid registry fixture.
- [x] Add parser/loader tests for missing path, empty file, malformed JSON, duplicate issuer/key ids, unsupported status, unknown key suite, invalid public key length, and unsafe real-secret-looking content if applicable.
- [x] Ensure production startup/readiness still fails closed when trust registry is required but unavailable or invalid.
- [x] Redact paths/secrets in errors where appropriate; do not print raw private data.

Targeted verification:

```bash
cargo test -p server trust registry_loader -- --nocapture
cargo test -p server readiness trust -- --nocapture
```

Acceptance:

- [x] Registry readiness means parseable, policy-usable trusted issuer/root metadata, not merely non-empty JSON.
- [x] Registry load errors are fail-closed.
- [x] Fixture data is clearly no-real-secret.

### E9 — A6 production policy matrix semantic tests

- [x] Translate every A6 local/dev row into an executable test or explicit deferred marker.
- [x] Translate every A6 wallet row into an executable test or explicit Track D boundary marker.
- [x] Translate every A6 federated first-path row into an executable test.
- [x] Add explicit tests or docs-contract assertions that Dregg/Midnight/Cardano-shaped refs are inert/deferred and cannot satisfy production authority by label alone.
- [x] Add a matrix table in the test module or docs with row name, input condition, expected accept/reject reason, and test name.
- [x] Ensure no first-path A6 row is only described in prose.

Targeted verification:

```bash
cargo test -p server evidence production_federated production_wallet -- --nocapture
cargo test -p server production_federated policy_matrix -- --nocapture
```

Acceptance:

- [x] Matrix is executable for local/dev, wallet, and federated first-path rows.
- [x] Deferred Dregg/Midnight/Cardano rows are protected from accidental acceptance.
- [x] No A6 first-path row is unaccounted for.

### E10 — Receipts/context summary safety and reason-code stability

- [x] Verify accepted federated evidence contributes safe summary fields into signed verified context / receipts where applicable.
- [x] Verify reject reasons use stable `VerificationError::reason_code()` values or equivalent typed constants.
- [x] Add tests that summaries do not include raw private keys, raw credential body, raw signature bytes, bearer tokens, local absolute secret paths, or raw registry secrets.
- [x] Confirm ledger/operator inspection can distinguish wallet-layer, issuer-trust-layer, credential-status-layer, and local-policy-layer failures enough for Track I debugging.

Targeted verification:

```bash
cargo test -p server production_federated evidence_summary_redacts_private_material -- --nocapture
cargo test -p server receipt evidence -- --nocapture
cargo test -p server ledger operator_inspection -- --nocapture
```

Acceptance:

- [x] Accepted/rejected Track E evidence is receipt/context-safe.
- [x] Typed reason surfaces do not regress into ad hoc string drift.
- [x] Operator can debug policy failures without exposing secrets.

### E11 — Docs, changelog, and status synchronization

- [x] Update `CHANGELOG.md` under `[Unreleased]` with why Track E changed authority semantics.
- [x] Update `docs/implementation-status.md` to mark trusted issuer/root policy as implemented only if E1–E10 pass.
- [x] Update `docs/repository-schema.md` for any new `trust.rs`, fixtures, or test helpers.
- [x] Update `docs/plans/2026-06-02-ready-for-prod-checklist.md` Track E rows and remaining blockers.
- [x] Update `README.md` and `server/README.md` so they stop saying Track E is planned only after merge, but keep boundaries against Dregg/Midnight/Cardano/deployment/public auditability.
- [ ] Update the PR body with task checkbox status, verification evidence, forbidden claims, and closes lines for #63/#35 (deferred to E12 after push/PR).
- [ ] Update the vault master checklist and phase spec after merge evidence exists (outside this repo commit).

Docs verification:

```bash
rg "TrustedIssuerEntry|membership_credential|provisioning_credential|trust_root_ref|registry_root_ref|trusted issuer/root" README.md server/README.md docs/ CHANGELOG.md
rg "live Dregg|Midnight|Cardano|public auditability|deployment proof" README.md server/README.md docs/
git diff --check -- README.md CHANGELOG.md docs/ server/
```

Acceptance:

- [x] Docs/status exactly match implemented behavior.
- [x] No surface claims live Dregg/Midnight/Cardano/deployment/public auditability.
- [x] Repo surfaces are synchronized for E11; PR body/GitHub issue body and vault/master checklist remain deferred to E12 / after merge evidence.

### E12 — Phase gate and post-merge proof

Before PR review/merge, run:

```bash
cargo test -p server evidence production_federated production_wallet -- --nocapture
cargo test -p server wallet_presentation -- --nocapture
cargo test -p server trust trusted_issuer -- --nocapture
cargo test -p server production_federated -- --nocapture
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check -- README.md CHANGELOG.md docs/ server/ fixtures/
```

After merge:

- [ ] Confirm GitHub PR CI passed.
- [ ] Merge to `main`.
- [ ] Confirm post-merge `main` CI passed.
- [ ] Patch vault master checklist, full phase spec, repo checklist/status, GitHub #35/#63 status, and daily note with merge commit + CI run evidence.

Acceptance:

- [ ] #35 and #63 can close because trusted issuer/root policy is implemented, tested, and documented.
- [ ] Track I can start with a static trusted issuer membership/provisioning fixture path.
- [ ] Remaining forbidden claims are still explicit.

## Phase-level acceptance criteria

Track E is complete only when all of these are true:

- [ ] Production descriptors reject `local_static`, plaintext, prototype, and wallet-only evidence as sufficient authority.
- [ ] `TrustedIssuerEntry` or equivalent receiver-held registry metadata exists and controls issuer/root trust.
- [ ] `membership_credential` / `provisioning_credential` evidence is signed, canonicalized, and verified against receiver-held issuer key material.
- [ ] Credential checks bind subject, audience, operation, resource/scope, issuer, issuer key id, trust/root refs, status, issued/expires timestamps, and signature suite.
- [ ] Untrusted, wrong-root, wrong-key, revoked, expired, not-yet-valid, stale, malformed, wrong-subject, wrong-audience, wrong-origin if modeled, wrong-operation, wrong-resource/scope, wrong-kind, and local-policy-mismatch cases reject.
- [ ] Valid trusted active credential accepts only when receiver-local descriptor policy permits it.
- [ ] Wallet proof-of-possession and issuer/root authority remain distinct proof layers.
- [ ] Evidence summaries and receipts are redaction-safe and typed enough for Track I ledger debugging.
- [ ] Shared fixture helpers are reused/promoted for D/E/I context values.
- [ ] Docs/status/changelog reflect the implemented boundary and preserve all forbidden claims.
- [ ] Full local gate passes.
- [ ] GitHub PR CI and post-merge `main` CI pass before the track is marked done.

## Edge cases / implementation-test checklist

Authority and trust:

- [ ] Caller-supplied embedded public key does not create trust.
- [ ] Caller-supplied issuer id does not create trust.
- [ ] Caller-supplied root refs do not create trust.
- [ ] Trusted issuer for audience A cannot satisfy audience B.
- [ ] Trusted issuer for operation A cannot satisfy operation B.
- [ ] Trusted issuer for scope/resource A cannot satisfy scope/resource B.
- [ ] Trusted issuer accepting membership credentials cannot satisfy provisioning credentials unless explicitly allowed, and vice versa.
- [ ] Valid credential from trusted issuer still rejects if receiver-local descriptor disallows it.

Cryptography / canonicalization:

- [ ] Wrong signature rejects.
- [ ] Wrong public key rejects.
- [ ] Mismatched key id/fingerprint rejects.
- [ ] Unsupported signature suite rejects.
- [ ] Missing signature rejects.
- [ ] Malformed signature bytes reject without panic.
- [ ] Canonical bytes bind every authority field.
- [ ] Field reordering / extra fields cannot bypass canonicalization if a parser is used.

Status / freshness:

- [ ] Unknown issuer rejects.
- [ ] Revoked issuer rejects.
- [ ] Expired issuer rejects.
- [ ] Not-yet-valid issuer rejects.
- [ ] Revoked credential/status rejects.
- [ ] Expired credential rejects.
- [ ] Not-yet-valid credential rejects if modeled.
- [ ] Stale registry/status metadata rejects if modeled.
- [ ] Boundary timestamps are deterministic and tested: exactly issued_at, just before issued_at, exactly expires_at, just after expires_at.

Policy composition:

- [ ] Valid wallet + missing credential rejects when issuer credential required.
- [ ] Valid credential + missing wallet rejects when wallet presentation required.
- [ ] Wallet subject and credential subject mismatch rejects.
- [ ] Wallet audience/origin/operation/resource mismatch rejects at wallet layer.
- [ ] Credential audience/operation/resource mismatch rejects at issuer/policy layer.
- [ ] Production descriptor cannot accidentally fall back to local/dev evidence.
- [ ] Local/dev descriptor behavior remains available and clearly non-production.

Registry loading / config:

- [ ] Missing trust registry path fails closed when registry is required.
- [ ] Empty registry file fails closed.
- [ ] Malformed registry file fails closed.
- [ ] Duplicate issuer/key ids fail closed or resolve deterministically with a documented rule.
- [ ] Invalid public-key length fails closed.
- [ ] Unsupported key suite fails closed.
- [ ] File-backed fixture registry contains no real secrets.

Redaction / audit:

- [ ] Evidence summaries do not include raw private keys.
- [ ] Evidence summaries do not include raw signature bytes.
- [ ] Evidence summaries do not include raw credential blobs by default.
- [ ] Errors/logs do not leak secrets or bearer tokens.
- [ ] Receipts/context fields distinguish evidence kind, issuer id, key id, trust/root refs, status refs, and safe timestamps.
- [ ] Reject reasons are stable typed codes, not ad hoc strings.

Deferred rails:

- [ ] Dregg-shaped refs alone do not satisfy authority.
- [ ] Midnight proof-shaped bytes alone do not satisfy authority.
- [ ] Cardano settlement-shaped refs alone do not satisfy authority.
- [ ] Public auditability is not claimed.
- [ ] Production deployment proof is not claimed.

## Source references

- Vault: `/Users/bananawalnut/claude-hub/capture/2026-06-04-secs-magik-current-master-checklist.md`
- Vault: `/Users/bananawalnut/claude-hub/capture/2026-06-04-secs-magik-tracks-d-i-full-phase-spec.md`
- Repo: `/Users/bananawalnut/repos/secS-magik/docs/plans/2026-06-02-ready-for-prod-checklist.md`
- Repo: `/Users/bananawalnut/repos/secS-magik/docs/implementation-status.md`
- Code: `/Users/bananawalnut/repos/secS-magik/server/src/evidence.rs`
- Code: `/Users/bananawalnut/repos/secS-magik/server/src/manifest.rs`
- Tests: `/Users/bananawalnut/repos/secS-magik/server/tests/support/wallet_fixtures.rs`
