# M12.7 — chore(ci): supply-chain audit gate and dependency bump

> Parent: [M12 demoable milestone](m12-demoable-milestone.md). Proposed 2026-06-09.

## Objective

Add a supply-chain security gate to CI (`cargo audit` and/or `cargo deny`) and
bump dependencies with known advisories — primarily `sqlx`, currently pinned to a
version affected by RUSTSEC-2024-0363 (fixed in 0.8.1+). These are the cheapest
readiness wins in the repo and make the demo defensible.

## Rationale / current evidence

- `.github/workflows/rust.yml` runs fmt, clippy `-D warnings`, build, and test —
  but **no dependency-advisory scan**.
- `Cargo.lock` pins `sqlx 0.7.4`. RUSTSEC-2024-0363 (binary protocol
  misinterpretation under crafted input) is fixed in 0.8.1; practical exposure here
  is low (SQLite, bounded payloads) but it should be cleared.
- Other aging pins to note (not necessarily blockers): `bincode 1` (feature-frozen),
  `rand 0.8`, and the `uniffi` version skew between the workspace pin (`0.28`) and
  `core/Cargo.toml` (`0.25`).
- No `SECURITY.md` and no Dependabot config exist.

## Dependencies

- Fully independent; can land any time.

## Target files

- `.github/workflows/rust.yml` — add a `cargo audit` (or `cargo deny check
  advisories bans sources`) job/step.
- `deny.toml` — if using `cargo deny`.
- `Cargo.toml` / `core/Cargo.toml` / `server/Cargo.toml` + `Cargo.lock` — bump
  `sqlx` to a fixed line; reconcile `uniffi` skew; bump others only if clean.
- Optional: `.github/dependabot.yml`, `SECURITY.md`.
- Docs: `CHANGELOG.md`.

## Locked decisions / non-goals

Locked:
- CI must fail on known advisories (or maintain an explicit, reviewed
  `deny.toml`/audit-ignore list with justifications, not a blanket allow).
- `sqlx` bump must keep the existing runtime-SQL behavior and the SQLite feature
  set; the test suite must pass on the new line.
- The advisory gate runs on PRs to `main`, consistent with the existing workflow.

Non-goals:
- Not migrating off `bincode 1`/`rand 0.8` unless a bump is clean and tested in the
  same PR; otherwise file follow-ups.
- Not adding `cargo-vet`/SLSA provenance (heavier; out of scope here).

## Task list (commit boundaries)

- [ ] M12.7.1 — Add the audit/deny CI step; prove it runs and reports.
- [ ] M12.7.2 — Bump `sqlx` past RUSTSEC-2024-0363; update `Cargo.lock`; full test
  suite green.
- [ ] M12.7.3 — Reconcile `uniffi` version skew between workspace and `core`.
- [ ] M12.7.4 — Optional: `SECURITY.md`, Dependabot config.
- [ ] M12.7.5 — Docs/changelog.

## Acceptance criteria

- CI has a dependency-advisory gate that fails on known advisories.
- `cargo audit`/`cargo deny` reports no unaddressed advisory for `sqlx`.
- Workspace builds and tests pass on the bumped dependency line.
- Post-merge main CI green.

## Verification gate

```bash
cargo audit            # or: cargo deny check advisories bans sources
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Edge cases

- A transitive advisory with no fix available → explicit, justified ignore entry,
  not a blanket disable.
- `sqlx` bump changing a query/runtime API → adjust call sites; keep runtime-SQL
  posture (no forced offline-metadata requirement unless the repo commits the
  cache).

## Forbidden claims

A clean advisory scan is production deployment proof (#33) or a full security
audit. It is a dependency-hygiene gate only.
