# Track I — production-shaped membership.provision E2E

## Objective

Build the first local production-shaped `membership.provision` end-to-end proof on top of merged Tracks H, D, and E.

This phase proves a no-real-secret local fixture packet can compose:

- a canonical receiver-local `membership.provision` descriptor;
- temporary minimal-equivalent secS wallet proof-of-possession;
- static receiver-held trusted issuer/root membership credential evidence;
- signed `VerifiedCallContext`;
- bounded descriptor-authorized handler execution;
- queryable local/operator verify + execute receipt chains.

## Branch / issue / PR boundary

- GitHub issue: #70
- Branch: `phase/track-i-membership-provision-e2e`
- PR: #76 (`feat(server): add production-shaped membership provision E2E`)
- Merge: PR #76 merged to `main` at `5e5bb7139cdf6ee7b94582391005dc59c331cff9` (`5e5bb71`); post-merge main Rust CI run 27071532041 passed.
- GitHub issue: #70 is closed. Follow-up gaps discovered in post-merge review are tracked separately as #78-#83; #77 and #84 are already closed as guard/negative-proof slices. #77 adds the fail-closed descriptor-only production runtime evidence guard and does not expand the Track I local E2E claim into live runtime authority.

## Implemented task boundaries

- I1 — `d670164 test(server): cover membership provision e2e contract`
  - Added RED contract tests for canonical descriptor presence, wallet+issuer evidence composition, verify+execute routing, and local/operator ledger inspection.
- I2 — `287f7a8 feat(server): define membership provision fixture descriptor`
  - Added canonical `0x44` `membership.provision` descriptor to `ReceiverManifest::default_v0` with `wallet_presentation` + `membership_credential` evidence and `membership/provision` handler id.
  - Aligned shared D/E/I no-real-secret fixture descriptor to the active manifest contract.
- I3 — `223523e test(server): harden membership provision reject matrix`
  - Added focused reject matrix for missing wallet evidence, missing issuer evidence, subject/audience/origin/operation/resource mismatches, descriptor-local policy rejection, invalid sessions, TTL overclaims, and replay.
  - Added redaction assertions for sensitive evidence refs, bearer tokens, local secret paths, raw credential bodies, and raw signatures in evidence summaries/operator inspection.

## Acceptance criteria

- [x] A fixture `membership.provision` descriptor exists and requires wallet + issuer + Dregg authority evidence layers.
- [x] A valid local fixture packet reaches verify + execute with signed context and local/operator ledger evidence.
- [x] Operator inspection can retrieve the receipt chain by context id.
- [x] Negative tests prove packet echo, verifier-only accept, fixture smoke output, and `local_static` fallback are not success.
- [x] #84 follow-up proof: an evidence-backed `membership.provision` verifier acceptance with no registered `membership/provision` handler records `verify accepted` plus `execute rejected` / `handler_unavailable`; fixture smoke/log output and verifier-only acceptance remain non-success without an accepted execute receipt for the same context.
- [x] Evidence summaries remain redaction-safe and distinguish wallet proof-of-possession from issuer/root authority.
- [x] Docs/status/changelog state this is local production-shaped E2E only.
- [x] Full local gate ran at final PR head.
- [x] GitHub CI was green at final PR head.
- [x] User approved merge by requesting the post-merge checklist.
- [x] PR #76 merged to `main` and post-merge `main` CI passed.

## Verification commands

Targeted evidence:

```bash
cargo test -p server --test production_federated membership_provision -- --nocapture
cargo test -p server --test production_federated -- --nocapture
```

Final PR readiness gate ran before merge:

```bash
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check -- README.md CHANGELOG.md docs/ server/ core/ client/
```

## Bounded claims / forbidden claims

This phase is local production-shaped E2E only. Issue #77 preserves that boundary by rejecting descriptor-only `production_verified` runtime verification for canonical `0x44` `membership.provision` unless the evidence-aware helper path has supplied wallet proof-of-possession, trusted issuer evidence, and the bounded static receiver-held Dregg policy-admission seam. Live TCP ingress now carries bounded evidence refs/public inputs through the #162 versioned ingress request envelope, but only into the existing evidence adapter path; it must not be claimed as production deployment proof, live Castalia/Dregg discovery, or live Dregg proof/finality. #144/M15.8 and #160 remain unsupported before #73 can close. #144/M15.8 reconciles the bounded #73 finalizer finalizes the bounded M15 Dregg authority E2E/docs without overclaiming #159 live proof/finality, #160 Dregg resource locks, or #162 live ingress. It is not:

- production deployment proof;
- public auditability beyond local SQLite operator inspection;
- live Castalia/Dregg registry discovery;
- Midnight or Cardano authority;
- full Castalia Wallet wallet-core parity.

## Post-merge evidence

- PR #76 merged to `main` at `5e5bb7139cdf6ee7b94582391005dc59c331cff9`.
- Post-merge Rust CI run 27071532041 passed.
- Follow-up issues from post-merge review: #77, #78, #79, #80, #81, #82, #83, #84. #77 is the descriptor-only production runtime fail-closed guard. #162 and #144/M15.8 live TCP evidence-ref/public-input follow-ups remain responsible for evidence-aware live ingress/runtime authority; #144/M15.8 reconciles the bounded #73 finalizer finalizes the bounded M15 Dregg authority E2E/docs without overclaiming #159/#160/#162.
- #84 is covered by `membership_provision_verifier_acceptance_without_execute_receipt_is_not_success`, which pins the non-success boundary for smoke/log/verifier-only paths without accepted execute receipts.


## #79 status note (2026-06-12)

The canonical multi-evidence-ref contract landed: Track I tests pass wallet +
membership credential refs directly through
`verify_manifest_operation_with_evidence_refs_and_inputs_and_sign` and the
test-only `AdditionalEvidenceRefsAdapter` mutation pattern is removed. This is
the verifier/caller API only — historical pre-#162 live runtime ingress was descriptor-only
and #77 still blocks `membership.provision` production runtime success until
#162 or an explicitly scoped #144 non-goal resolves the live TCP evidence-ref/public-input wire path.

## #78 status note (2026-06-12)

Runtime posture resolved as an active binding: default runtime bindings now
register the bounded native `membership/provision` handler in every mode
(`server/src/membership.rs` holds the decision record). #77's descriptor-only
guard remains in force and historical pre-#162 live ingress carried no evidence refs, so
runtime `membership.provision` authority is still not claimable; the
remaining live-wire activation rides on the #79 API contract plus future
#162 and #144/M15.8 ingress wiring; handler binding is not authority.

## #80 status note (2026-06-12)

The E2E happy path now drives the active `default_v0()` descriptor;
`membership_provision_descriptor()` is the shared canonical constructor and
the `wallet_and_membership_descriptor` fixture delegates to it. The exhaustive
contract test (`active_membership_provision_descriptor_contract_is_pinned_field_by_field`)
is the drift gate for all twelve routing/authorization fields.


## #169 trusted requested-authority attenuation boundary

#167 adds delegated attenuation / non-amplification to the live evidence path: requested authority must not exceed held authority. Amplified requested resources reject as `authority_amplification` before handler dispatch. This is not Dregg-provisioned resource-lock authority; #160 implements bounded Dregg-provisioned resource locks, and #144/M15.8 reconciles the bounded #73 finalizer reconciles #169/#160 without overclaim.


#160 implements bounded Dregg-provisioned resource locks: a Dregg authority token may bind an exact verifier-derived trusted requested resource as `resource_lock:verified`, reject mismatches as `resource_lock_violation`, and propagate the locked resource into the signed context for handler/policy use. This is separate from #169 trusted requested-authority attenuation, does not implement live Dregg revocation proof/BLS finality/rotated-replay proof verification, and #159 remains fail-closed blocker posture only. #144/M15.8 reconciles the bounded #73 finalizer.


#144/M15.8 reconciles the bounded #73 finalizer across #162 live ingress evidence refs/public inputs, #167 delegated attenuation / non-amplification, #169 trusted requested-authority attenuation, and #160 implements bounded Dregg-provisioned resource locks. The finalizer preserves `resource_lock:verified` acceptance, `resource_lock_violation` rejection, redaction-safe operator summaries, and signed-context propagation of the verified locked resource for handler/policy use. See `examples/m15-dregg-authority-demo.sh` for the bounded production-shaped demo/checklist. This is not deployment proof, not public auditability, not live Dregg revocation proof, not BLS threshold finality, not rotated-replay proof verification, not Midnight, and not Cardano.
