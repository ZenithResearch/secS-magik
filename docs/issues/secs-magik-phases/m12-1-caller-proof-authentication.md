# M12.1 — feat(verifier): authenticate caller proof-of-origin on ingress

> Parent: [M12 demoable milestone](m12-demoable-milestone.md) (#88). Filed as GitHub issue #89 (2026-06-09).

## Objective

Verify the caller's `packet.proof` as a real Ed25519 signature over canonical
packet bytes, checked against a **receiver-held caller key seam**, and make that
verification the basis for accepting a packet in `production_verified` mode. This
replaces the current "non-empty proof + nonzero TTL" prototype check as the
authority for *who sent the packet*.

This is the single largest gap to a demoable verifier: today the gateway accepts a
forged or random proof and routes on it.

## Rationale / current evidence

- `Verifier::verify_prototype_envelope` (`server/src/verifier.rs`) returns `Ok`
  for any `proof` that is non-empty with `claim_ttl > 0`. The signature is never
  checked and no caller key is consulted.
- The client *does* sign: `build_packet` calls `generate_proof(identity, &payload)`
  (`client/src/main.rs`), an Ed25519 signature over the payload bytes — but the
  signer key is generated fresh per process (`load_or_create_identity`), so it is
  not yet a stable caller identity.
- Every verified context is stamped with the hardcoded subject
  `PROTOTYPE_LOCAL_SUBJECT` (`server/src/verifier.rs` →
  `verified_context_for_descriptor`), so the signed context does not reflect the
  actual caller.
- There is already a strong precedent for a receiver-held key registry with
  fail-closed status/validity/duplicate handling:
  `PublicVerifierKeyRegistry` in `server/src/identity.rs`. The caller seam should
  mirror its structure.

Risk if left as-is: the demo would show "verification" that authenticates nothing.

## Dependencies

- Independent of #78–#83, but composes with them: caller proof-of-origin is the
  "who sent it" layer beneath the wallet/issuer evidence layers those issues wire.
- Should land before M12.2 (response) and the demo script.

## Target files

- `server/src/verifier.rs` — new caller-proof verification step; canonical
  signed-bytes definition; thread caller key id/subject into
  `verified_context_for_descriptor`.
- `server/src/identity.rs` or a new `server/src/caller.rs` — receiver-held
  `CallerKeyRegistry` mirroring `PublicVerifierKeyRegistry` (status, validity
  window, revocation, duplicate-id fail-closed).
- `server/src/ingress.rs` — load caller registry from config; call the new
  verification before signed-context creation.
- `server/src/config.rs` — `SECS_CALLER_REGISTRY_PATH` (production-required;
  fixture-only allowed under `SECS_FIXTURE_ONLY_SMOKE` like the trust registry).
- `client/src/main.rs` — persist a stable caller identity (file-backed, reusing
  `identity.rs` key-file safety checks) and sign canonical packet bytes, not just
  the payload, so the proof binds session/nonce/opcode/ttl.
- Tests: `server/tests/verifier_context.rs`, `server/tests/ingress.rs`,
  `server/tests/identity.rs`, new caller-registry tests.
- Docs: `README.md`, `docs/implementation-status.md`,
  `docs/repository-schema.md`, `CHANGELOG.md`.

## Locked decisions / non-goals

Locked:
- The proof must sign **canonical packet bytes that include session_id, nonce,
  opcode, claim_ttl, and the encrypted payload** (not payload alone), so a captured
  proof cannot be re-bound to a different envelope.
- Caller authentication is **necessary, never sufficient** authority; it does not
  replace wallet/issuer/Dregg evidence and does not grant `membership.provision`.
- Caller key trust is **receiver-held**: caller keys come from the receiver's
  configured registry, never from bytes embedded in the packet.
- `production_verified` fails closed on unknown/revoked/expired/not-yet-valid
  caller keys and on signature failure; reuse the typed reason-code vocabulary
  (`VerificationError`) — add caller-specific reasons only if no existing code fits.
- Local/dev modes may keep a relaxed/fixture caller seam but must clearly mark
  contexts as `LocalDevUntrusted`, consistent with the existing authenticator-kind
  split.

Non-goals:
- Not wallet-core parity (#71), not issuer/root authority (Track E owns that), not
  Dregg authority (#73).
- No bincode wire-shape change unless this PR explicitly owns and tests it; prefer
  signing the existing serialized envelope.

## Task list (commit boundaries)

- [ ] M12.1.1 — RED tests: a packet with a valid caller signature over canonical
  bytes from a registered active caller key verifies; forged/absent/wrong-key/
  truncated proof rejects with a typed reason; a captured proof re-bound to a
  different session/opcode rejects.
- [ ] M12.1.2 — Add `CallerKeyRegistry` (status, validity window, revocation,
  duplicate-id fail-closed) mirroring `PublicVerifierKeyRegistry`; unit tests.
- [ ] M12.1.3 — Define canonical caller-signed bytes and a
  `verify_caller_proof(packet, &registry, now)` step; wire it into the
  `verify_manifest_operation_for_runtime` path before context creation; populate
  the context subject/key id from the authenticated caller, not the hardcoded
  prototype subject.
- [ ] M12.1.4 — Config: `SECS_CALLER_REGISTRY_PATH`, production-required with the
  same fixture-only smoke allowance as the trust registry; startup readiness check.
- [ ] M12.1.5 — Client: persist a stable caller key (file-backed, owner-private,
  reusing key-file safety helpers) and sign canonical envelope bytes.
- [ ] M12.1.6 — Audit visibility: caller-auth rejects emit inspectable reject
  receipts/events (consistent with #51/#52) and do not create replay reservations.
- [ ] M12.1.7 — Docs/status/changelog; state the boundary explicitly.

## Acceptance criteria

- A registered, active caller key + valid signature over canonical bytes is
  required to produce a signed context in `production_verified`.
- Forged, missing, wrong-key, truncated, and envelope-mismatched proofs reject
  with typed reasons and leave an inspectable reject receipt.
- The signed context's subject/key id reflects the authenticated caller.
- Replay reservation is not created for caller-auth rejects.
- Local/dev behavior remains usable and clearly `LocalDevUntrusted`.
- Full workspace gate green; post-merge main CI green.

## Verification gate

```bash
cargo test -p server --test verifier_context caller_proof -- --nocapture
cargo test -p server --test ingress caller_auth -- --nocapture
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Edge cases

- Empty proof → typed reject (not the old "missing prototype envelope" only).
- Proof valid for payload but not for full envelope → reject.
- Duplicate caller key id in registry → fail closed (mirror verifier registry).
- Caller key revoked/expired/not-yet-valid at `now` → typed reject.
- Clock-read failure interaction → must remain fail-closed (see M12.5).
- Oversized/malformed packets still rejected by bounded ingress before this step.

## Forbidden claims

Caller proof-of-origin is membership/issuer/root authority; this proves wallet/
issuer evidence; Dregg authority; or any of #33/#37/#71–#75.
