# docs/plans

`docs/plans/` contains implementation plans, checklists, and issue-slice control surfaces. Phase-level GitHub issue specs live under `docs/issues/secs-magik-phases/` so they can be linked directly from GitHub issues and PRs.

Plans are not implementation status. Use [../implementation-status.md](../implementation-status.md) to verify what is solid, partial, planned, future, or out of scope.

## Current plan files

| Plan | Status | Use it for |
|---|---|---|
| [2026-06-02-ready-for-prod-checklist.md](2026-06-02-ready-for-prod-checklist.md) | Current control surface | Ready-for-prod track checklist, completion checkpoints, remaining D/E/I authority path, and forbidden-claim boundaries. |
| [2026-07-18-secs-hermes-peer-chat-dag.md](2026-07-18-secs-hermes-peer-chat-dag.md) | Current exact-operation control surface; P4-R in progress, descendants blocked | Active sequence `P4-R -> P4-O -> P4-H -> P4-S -> P5-C -> P6-E -> P7`, with former peer-chat P4/P5/P6 nodes superseded. Preserves one-node/one-issue/one-PR boundaries, operator ratification before implementation, repair-node insertion, post-merge gates, and exact P3/C1–P3/C12 history. |
| [2026-08-31-devgraph-issue-create-v1-dag.md](2026-08-31-devgraph-issue-create-v1-dag.md) | P4-O-DG-R1, DG-P, and DG-E1 merged; DG-E2 partial branch evidence | Dedicated sequence `P4-R -> P4-O-DG -> P4-O-DG-R1 -> DG-P -> DG-V -> DG-W -> DG-C -> DG-E`; DG-E2 proves only fixed local Wallet-to-projection plumbing and does not complete the cross-repository evidence node. |
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
