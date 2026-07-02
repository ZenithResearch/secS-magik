# I10 negative matrix status ledger discovery

Issue: I10 — Executable negative matrix status map

Canonical ledger decision: `server/tests/fixtures/dregg_negative_matrix_status_ledger.yaml` is the single machine-readable source for this PR. Parser/checker code must consume this file directly; any future guide/readme/demo snippets must link to or be checked against it rather than copying an independent status table.

Discovery commands run from this worktree:

- `rg -n "negative matrix|anonymous|unlinkable|federated|finality|light-client|light_client|recursive|signed source|live authority|audit|production|handler_did_not_run|reason_code" README.md docs examples server || true`
- `cargo test -p server -- --list | rg -n "dregg|negative|authority|finality|revocation|handler|ledger|light|recursive" || true`

Discovered claim-sensitive docs/source surfaces:

- `README.md` — current boundary and explicit non-claims for live Castalia/Dregg discovery, finality, public auditability, deployment proof, Midnight/Cardano, and production readiness.
- `docs/implementation-status.md` — repo status ledger with solid/prototype/planned/future/out-of-scope vocabulary and current Dregg/live-source/audit rows.
- `docs/repository-schema.md` — repository boundary map and status-sensitive non-claims.
- `docs/specs/dregg-authority-rail.md` — Dregg authority semantics and proof/finality blocker posture.
- `docs/specs/dregg-live-source-client-contract.md` — signed live-source client contract, no-live-network boundary, redaction and cache posture.
- `docs/specs/evidence-adapter-readiness-disclosure.md` — adapter readiness/disclosure gates.
- `docs/plans/2026-06-02-ready-for-prod-checklist.md` — older production-policy/future-rail matrix and no-overclaim language.
- `examples/README.md` and `examples/m15-dregg-authority-demo/README.md` — demo-facing claim-sensitive wording.
- `server/src/verifier.rs` — stable `VerificationError::reason_code()` strings.
- `server/src/{dregg_authority,dregg_live_source,evidence,public_audit,ledger,gateway,ingress}.rs` — source evidence for implemented/provisional rows.
- `server/tests/{dregg_live_source_client,dregg_live_finality,dregg_live_revocation,dregg_live_contracts,dregg_rotated_proof,dregg_authority_evidence,production_federated,gateway_layout,ingress,ledger,public_audit}.rs` — discovered test surfaces with exact test names for implemented/proposed wiring.

Candidate negative/status rows for the initial ledger:

- `signed_source_runtime_wireup` — owner I16; live signed authority/source wording remains target unless an implemented row can point to no-network source-client tests without claiming live runtime operation.
- `federation_checkpoint_not_finality_until_rollback_state` — owner I17; BLS threshold finality helpers exist, but federated finality/durable rollback-state claims remain blocked/target.
- `anonymous_unlinkable_membership_blocked_until_i06` — owner I06; wallet-presentation and credential primitives exist, but anonymous/unlinkable membership remains blocked until two-show unlinkability and leak checks pass.
- `light_client_verified_requires_i18_not_i08_metadata` — owner I18; proof/VK metadata or bounded proof fixtures must not render as light-client verification.
- `recursive_proof_carrying_state_future` — owner I19; recursive proof-carrying state remains future/missing.
- `audit_without_surveillance_requires_i09` — owner I09; local public-audit bundle/anchor work exists, but audit-without-surveillance remains blocked until selective audit policy exists.
- `production_ready_requires_deployment_proof` — owner I12; blocked by I11/I20 via deployment-proof policy. Local production-shaped smoke and fixtures must stay blocked until deployment proof exists.
- `handler_rejection_requires_no_handler_run` — owner I10; rejection rows must name `handler_did_not_run_expected` and implemented rows must point to handler-not-run assertions.

Unsettled Wave 1 vocabulary:

- I01 canonical evidence-tier labels are not assumed here; rows use `provisional_shape_only`, `proposed`, `missing`, `blocked`, and `not_applicable` only where needed.
- I02 privacy policy fields are represented as row-local `privacy_guard_expected` strings and do not claim privacy-safe implementation unless owner evidence exists.
- I03 context-binding labels remain referenced by owner dependencies; this PR does not invent final context-binding semantics.

Forbidden scope preserved: no verifier/runtime/privacy/finality/proof behavior, no guide promotion, no executive diagrams, and no second canonical ledger.

## Completion verification — 2026-07-02

Implemented status-safe I10 scope:

- Added the canonical machine-readable ledger at `server/tests/fixtures/dregg_negative_matrix_status_ledger.yaml`.
- Added `server/tests/negative_matrix_status_ledger.rs` to parse the ledger and reject malformed status rows, duplicate row IDs, missing required seed rows, missing handler/privacy fields, invalid owner/dependency issue IDs, invalid dates, and non-implemented rows that allow implemented docs wording.
- Added `server/tests/handler_did_not_run_negative_matrix.rs` to require each rejection row to name `handler_did_not_run_expected: true`, a non-empty expected reason code, and `last_verified_date: never` until implemented.
- Added `server/tests/docs_overclaim_status_ledger.rs` to fail stronger-than-ledger wording for federated finality, anonymous wallets, light-client verification, recursive proof-carrying state, and audit-without-surveillance, while checking current docs surfaces for the same forbidden phrases.

Commands run:

- `cargo test -p server negative_matrix_status_ledger -- --nocapture` — passed.
- `cargo test -p server docs_overclaim_status_ledger -- --nocapture` — passed.
- `cargo test -p server handler_did_not_run_negative_matrix -- --nocapture` — passed.
- `cargo test --workspace --all-targets --all-features` — passed.
- `cargo fmt --all -- --check` — passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — passed.
- `git diff --check` — passed.

Status-safe claim unlocked:

> The negative matrix is controlled by an executable status ledger. Each row records its owner issue, current tier, verification command, expected reason code, handler-not-run expectation, privacy/audit expectation, allowed docs wording, and last verified date. Rust checks fail if the ledger schema is malformed or if docs wording exceeds the row's allowed tier.

Non-claims preserved:

- I10 does not prove every negative case is implemented.
- I10 does not implement verifier/runtime/privacy/finality/proof behavior owned by I01-I09 or I14-I19.
- Blocked/target/future rows for live signed authority, federated finality, anonymous/unlinkable membership, light-client verification, recursive proof-carrying state, audit-without-surveillance, and production readiness remain non-implemented.
- Guide/readme/demo prose must still stay at or below each row's `docs_wording_allowed` value.


## Docs-overclaim scan boundary

Canonical ledger and issue/discovery docs are intentionally excluded from the naïve docs-overclaim scan until the checker supports scoped negative examples. These documents may need to discuss forbidden phrases as examples or row labels; current-facing README/spec/status surfaces are scanned instead.
