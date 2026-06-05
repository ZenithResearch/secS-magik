# docs/plans

`docs/plans/` contains implementation plans, checklists, and issue-slice control surfaces. Phase-level GitHub issue specs live under `docs/issues/secs-magik-phases/` so they can be linked directly from GitHub issues and PRs.

Plans are not implementation status. Use [../implementation-status.md](../implementation-status.md) to verify what is solid, partial, planned, future, or out of scope.

## Current plan files

| Plan | Status | Use it for |
|---|---|---|
| [2026-06-02-ready-for-prod-checklist.md](2026-06-02-ready-for-prod-checklist.md) | Current control surface | Ready-for-prod track checklist, completion checkpoints, remaining D/E/I authority path, and forbidden-claim boundaries. |
| [2026-06-01-implementation-progress-checklist.md](2026-06-01-implementation-progress-checklist.md) | Historical/current progress ledger | Early issue-train progress and CI alignment notes. |
| [2026-06-01-secs-magik-implementation-issue-slices.md](2026-06-01-secs-magik-implementation-issue-slices.md) | Historical issue-slice import | Original issue-level sequence and acceptance criteria from the 2026-06-01 baseline. Many early slices have since landed. |

## How to use this directory

- Use plans to understand intended phase boundaries and acceptance criteria.
- Use the status ledger to avoid treating planned work as implemented behavior.
- Preserve issue/phase boundaries when updating plan files.
- Add dated filenames for new plans.
- If a plan becomes stale, add a status or supersession note.

## Current caveats

- Track A docs/control-surface work is complete.
- Tracks B/C/D/F/G/H have implementation checkpoints, but current claims remain bounded to the repository status ledger and PR evidence.
- Track D wallet cryptographic verification is complete only as a temporary minimal-equivalent secS challenge contract; full Castalia Wallet wallet-core parity remains future reconciliation work.
- First-prod still needs Track E production trusted issuer/root policy and a production-shaped `membership.provision` E2E.
- Track E's issue-ready phase spec lives at `docs/issues/secs-magik-phases/track-e-trusted-issuer-root-policy.md`.
- Local fixture smoke and local SQLite operator evidence are not production deployment or public auditability.
