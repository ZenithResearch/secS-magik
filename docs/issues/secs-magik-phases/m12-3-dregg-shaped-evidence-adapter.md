# M12.3 — feat(evidence): Dregg-shaped receipt/capability evidence adapter seam

> Parent: [M12 demoable milestone](m12-demoable-milestone.md) (#88). Filed as GitHub issue #91 (2026-06-09).

## Objective

Add a typed evidence adapter for **Dregg-shaped** evidence (`dregg_receipt`, and a
capability-reference variant) that validates the evidence **envelope shape and the
Ed25519 author signature over canonical bytes** — and nothing more. This lets a
demo show secS ingesting and verifying Castalia-over-Dregg-shaped evidence through
the existing `EvidenceAdapter` seam, while strictly preserving the boundary that
secS does **not** own Dregg consensus, finality, capability semantics, or
revocation authority.

This mirrors how Track D (#68) landed the wallet challenge as an explicitly
temporary minimal-equivalent contract: a real cryptographic check over a bounded,
inspectable shape, clearly labeled as not the full upstream system.

## Rationale / current evidence

- `EvidenceKind` already declares `DreggReceipt`, `MidnightProof`,
  `CardanoSettlement` (`server/src/evidence.rs`) but **no adapter implements any of
  them** — the variants are inert.
- The adapter seam is established and clean: `EvidenceAdapter` trait,
  `EvidenceRequest`, `EvidenceResult`, `EvidenceSummary`, and the
  `CompositeEvidenceAdapter` that requires all of a descriptor's `accepted_evidence`
  kinds. A Dregg-shaped adapter slots in exactly like `WalletPresentationAdapter`
  and `FederatedCredentialAdapter`.
- `emberian/dregg` models receipts/inserts as **Ed25519-authenticated** entries in
  a blocklace DAG with sequence-monotonicity and equivocation detection;
  capabilities are constructive witnesses. The demo-scope seam verifies the author
  signature and the canonical field shape of a presented receipt/capability
  reference — it does not reconstruct or verify the DAG, finality (`tau` ordering),
  non-amplification, or nullifier properties.

## Dependencies

- Independent of M12.1/M12.2; composes with them in the demo.
- Strictly **distinct from #73** (Dregg capability/proof/revocation **authority**
  rail). This issue is the boundary-preserving *shape+signature* stub; #73 remains
  the future authority rail. The spec must say so and #73 must not be closed by it.

## Target files

- `server/src/evidence.rs` — `DreggReceiptFixture` (canonical-bytes contract),
  `DreggShapedEvidenceAdapter` implementing `EvidenceAdapter` for
  `EvidenceKind::DreggReceipt`; reuse `verify_ed25519_signature`,
  `append_field`/`append_line`, `redacted_reference_field`,
  `public_key_ref_for_bytes`.
- `server/src/manifest.rs` — optionally a demo descriptor accepting
  `dregg_receipt` evidence, clearly fixture/dev-bounded; do not weaken existing
  descriptors.
- Tests: `server/tests/evidence.rs` (adapter contract + reject matrix), a
  composition test alongside wallet/credential evidence.
- Fixtures: `server/tests/support/` Dregg-shaped fixture builders;
  `fixtures/` if a JSON fixture is added (clearly labeled fixture-only).
- Docs: `README.md` evidence boundary section, `docs/implementation-status.md`,
  `server/README.md`, `CHANGELOG.md`.

## Locked decisions / non-goals

Locked:
- **Shape + author-signature only.** The adapter verifies: required fields present
  and non-empty; `issued_at < expires_at` and time-window validity; signature suite
  is Ed25519; `public_key_ref` matches the public-key bytes fingerprint; the author
  Ed25519 signature verifies over canonical, length-prefixed, newline-delimited
  bytes (same construction style as `SecsWalletChallenge::canonical_bytes`).
- Canonical bytes carry a **version tag** (e.g. `secs-dregg-receipt-shape-v1`) so
  the temporary contract is explicit and replaceable.
- Subject/audience/operation/resource/origin bind to the `EvidenceRequest` exactly
  like the wallet adapter; mismatches reject with existing typed reasons.
- The summary is **redaction-safe**: hash/fingerprint references, no raw author
  keys, no raw receipt body, no raw refs.
- Dregg-shaped evidence is **necessary-where-required, never sufficient** authority
  on its own; in the demo it is composed with wallet + issuer evidence, not used as
  a standalone grant for production descriptors.
- Receiver-held trust: any author key acceptance is decided by the receiver's
  configuration/fixtures, never by bytes the caller embeds being implicitly trusted.

Non-goals:
- No blocklace DAG construction/verification, no `tau`/finality, no
  capability-amplification or nullifier checks, no CapTP, no STARK/Plonky3
  verification — all out of scope and reserved for #73/#74.
- Does not close #73.

## Task list (commit boundaries)

- [ ] M12.3.1 — RED tests: a valid Dregg-shaped fixture with a correct author
  signature satisfies the adapter; wrong signature/key/public-key-ref, missing
  fields, expired/future, wrong subject/audience/operation/resource/origin, and
  unsupported suite each reject with typed reasons.
- [ ] M12.3.2 — Define `DreggReceiptFixture` + versioned canonical bytes.
- [ ] M12.3.3 — Implement `DreggShapedEvidenceAdapter` for
  `EvidenceKind::DreggReceipt`; redaction-safe summary.
- [ ] M12.3.4 — Composition test: wallet + issuer + Dregg-shaped evidence through
  `CompositeEvidenceAdapter`; all required kinds enforced.
- [ ] M12.3.5 — Optional fixture/dev demo descriptor; never weaken existing ones.
- [ ] M12.3.6 — Docs/status/changelog with the explicit shape-only boundary and the
  distinction from #73.

## Acceptance criteria

- `dregg_receipt` evidence is no longer an inert enum variant — it has a tested
  adapter verifying shape + Ed25519 author signature.
- The full reject matrix (signature/key/ref/shape/time/binding/suite) is tested and
  fails closed with typed reasons.
- Summaries are redaction-safe (no raw keys/body/refs).
- Composition with wallet + issuer evidence works and still requires all kinds.
- Docs state shape-only boundary and that #73 (authority) remains open.
- Full workspace gate green; post-merge main CI green.

## Verification gate

```bash
cargo test -p server --test evidence dregg_shaped -- --nocapture
cargo test -p server --test evidence composite -- --nocapture
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Edge cases

- Missing any required field → `invalid_presentation`.
- `public_key_ref` not matching key bytes → `invalid_presentation`.
- Wrong author signature → `invalid_signature`.
- Non-Ed25519 suite → `unsupported_signature_suite`.
- `expires_at <= now` → `expired_claim`; `issued_at > now` → `not_yet_valid_claim`.
- Binding mismatch (subject/audience/operation/resource/origin) → typed reject.
- Standalone Dregg-shaped evidence for a production descriptor requiring more kinds
  → `insufficient_evidence`.

## Forbidden claims

Dregg consensus/finality/capability/revocation authority (#73); blocklace
verification; CapTP/STARK verification; that shape+signature is Dregg semantic
validity. This is a temporary minimal-equivalent Dregg-shaped contract only.
