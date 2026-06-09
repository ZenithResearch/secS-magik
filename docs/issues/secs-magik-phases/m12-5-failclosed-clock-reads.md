# M12.5 — fix(server): fail-closed clock reads on the verification hot path

> Parent: [M12 demoable milestone](m12-demoable-milestone.md). Proposed 2026-06-09.

## Objective

Make wall-clock read failures fail **closed** (reject / treat as expired) on the
verification and routing path, instead of the current fail-open fallback to `0`
which makes nothing appear expired.

## Rationale / current evidence

- `current_unix_seconds()` in `server/src/gateway.rs` and `server/src/ingress.rs`
  returns `0` when `SystemTime::now().duration_since(UNIX_EPOCH)` fails. A `now` of
  `0` means every `now > expires_at` and `now > not_after` check evaluates as
  not-expired → fail-open on the hot path.
- By contrast, `current_unix_time()` in `server/src/evidence.rs` falls back to
  `u64::MAX` (fail-closed: everything appears expired). The two behaviors are
  inconsistent, and the fail-open one is the one gating live verification.
- `Ledger::init_schema` also uses a `0` fallback when pruning expired replay
  reservations; review for consistency (a `0` cutoff there merely skips pruning,
  which is safe, but should be documented).

## Dependencies

- Independent; small. Should land before the demo so expiry checks are trustworthy.
- Interacts with M12.1 (caller key validity windows) — both rely on a trustworthy
  `now`.

## Target files

- `server/src/gateway.rs` — `current_unix_seconds`.
- `server/src/ingress.rs` — `current_unix_seconds`.
- Consider a single shared helper (e.g. in `ontology.rs` or a small `clock.rs`) so
  there is one fail-closed definition.
- Tests: a unit test asserting the chosen fail-closed sentinel; behavior tests that
  an unreadable-clock sentinel rejects rather than accepts (via the helper, not by
  breaking the real clock).
- Docs: `CHANGELOG.md`.

## Locked decisions / non-goals

Locked:
- On clock-read failure, the verification/routing path must **reject** (or use a
  sentinel that forces expiry), never accept as fresh.
- Prefer one shared fail-closed clock helper used by gateway, ingress, and (where
  appropriate) evidence, so the policy is defined once.
- Pruning paths may keep a safe no-op fallback but must document why it is safe.

Non-goals:
- Not introducing a monotonic/trusted time source or NTP dependency.
- Not changing the receipt-timestamp-based key validity semantics (separate concern;
  see the review note on `verify_receipt_at`).

## Task list (commit boundaries)

- [ ] M12.5.1 — RED test: with the failure sentinel, a packet that should be expired
  is rejected (today it would route).
- [ ] M12.5.2 — Introduce a shared fail-closed clock helper; switch gateway and
  ingress to it.
- [ ] M12.5.3 — Audit `evidence.rs`/`ledger.rs` for consistency; document the prune
  fallback.
- [ ] M12.5.4 — Docs/changelog.

## Acceptance criteria

- No verification/routing decision treats a clock-read failure as "not expired."
- One shared, tested fail-closed definition of `now` for the hot path.
- Full workspace gate green; post-merge main CI green.

## Verification gate

```bash
cargo test -p server clock -- --nocapture
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Edge cases

- Replay-reservation pruning with the sentinel must not delete live reservations
  nor panic.
- Receipt timestamps already persisted with `0` (if any) are not retroactively
  reinterpreted in a way that corrupts inspection.

## Forbidden claims

Trusted/monotonic time; this fixes the fail-open fallback only.
