# secS-magik phase issue specs

This directory contains repo-local, issue-ready phase specs for secS-magik ready-for-production tracks. Phase GitHub issues are the tracking containers; tasks inside each phase issue are intended commit boundaries.

## Active / recent specs

| Track | GitHub issue | Local spec | Status |
|---|---:|---|---|
| Track E — trusted issuer/root policy | #63 / underlying #35 | [`track-e-trusted-issuer-root-policy.md`](track-e-trusted-issuer-root-policy.md) | complete; PR #69 merged to `main` at `baee35b`, post-merge CI run 27050361282 passed |
| Track I — production-shaped `membership.provision` E2E | #70 | GitHub issue body | open; next implementation phase |

## Gap / future-rail issues after Track E

| Gap / forbidden claim | GitHub issue | Status |
|---|---:|---|
| Production-shaped `membership.provision` E2E | #70 | open |
| Full Castalia Wallet wallet-core parity | #71 | open |
| Live Castalia trusted issuer registry discovery | #72 | open |
| Dregg capability/proof/revocation authority | #73 | open |
| Midnight proof verification | #74 | open |
| Cardano settlement/finality evidence | #75 | open |
| Production deployment proof | #33 | open |
| Public auditability beyond local SQLite receipts | #37 | open |

## Boundary

These specs are planning/control artifacts. Implementation still happens on a focused phase branch and must update `README.md`, `server/README.md`, `docs/implementation-status.md`, `docs/repository-schema.md`, `docs/plans/2026-06-02-ready-for-prod-checklist.md`, `CHANGELOG.md`, the vault master checklist, and the relevant GitHub issues/PR body when a phase lands.
