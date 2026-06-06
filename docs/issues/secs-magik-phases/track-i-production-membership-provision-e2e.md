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
- PR title: `feat(server): add production-shaped membership provision E2E`
- Status while branch/PR is open: in progress / pre-merge implemented, not complete.

## Implemented task boundaries on branch

- I1 — `d670164 test(server): cover membership provision e2e contract`
  - Added RED contract tests for canonical descriptor presence, wallet+issuer evidence composition, verify+execute routing, and local/operator ledger inspection.
- I2 — `287f7a8 feat(server): define membership provision fixture descriptor`
  - Added canonical `0x44` `membership.provision` descriptor to `ReceiverManifest::default_v0` with `wallet_presentation` + `membership_credential` evidence and `membership/provision` handler id.
  - Aligned shared D/E/I no-real-secret fixture descriptor to the active manifest contract.
- I3 — `223523e test(server): harden membership provision reject matrix`
  - Added focused reject matrix for missing wallet evidence, missing issuer evidence, subject/audience/origin/operation/resource mismatches, descriptor-local policy rejection, invalid sessions, TTL overclaims, and replay.
  - Added redaction assertions for sensitive evidence refs, bearer tokens, local secret paths, raw credential bodies, and raw signatures in evidence summaries/operator inspection.

## Acceptance criteria

- [x] A fixture `membership.provision` descriptor exists and requires wallet + trusted issuer evidence layers.
- [x] A valid local fixture packet reaches verify + execute with signed context and local/operator ledger evidence.
- [x] Operator inspection can retrieve the receipt chain by context id.
- [x] Negative tests prove packet echo, verifier-only accept, fixture smoke output, and `local_static` fallback are not success.
- [x] Evidence summaries remain redaction-safe and distinguish wallet proof-of-possession from issuer/root authority.
- [x] Docs/status/changelog state this is local production-shaped E2E only.
- [ ] Full local gate is run at final PR head.
- [ ] GitHub CI is green at final PR head.
- [ ] User approves merge.
- [ ] PR merges to `main` and post-merge `main` CI passes.

## Verification commands

Current targeted evidence on branch:

```bash
cargo test -p server --test production_federated membership_provision -- --nocapture
cargo test -p server --test production_federated -- --nocapture
```

Final PR readiness gate must also run:

```bash
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check -- README.md CHANGELOG.md docs/ server/ core/ client/
```

## Bounded claims / forbidden claims

This phase is local production-shaped E2E only. It is not:

- production deployment proof;
- public auditability beyond local SQLite operator inspection;
- live Castalia/Dregg registry discovery;
- Midnight or Cardano authority;
- full Castalia Wallet wallet-core parity.
