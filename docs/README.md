# secS-magik docs index

This directory separates current implementation status, architecture specs, implementation plans, and external-language drafts.

Use this index as the docs navigation layer. Use [implementation-status.md](implementation-status.md) before treating any spec or plan claim as implemented.

## Table of Contents

- [Docs by reader need](#docs-by-reader-need)
- [Current source-of-truth docs](#current-source-of-truth-docs)
- [Directory READMEs](#directory-readmes)
- [Plans and checklists](#plans-and-checklists)
- [Specs](#specs)
- [Draft / external-language docs](#draft--external-language-docs)
- [Historical / evidence docs](#historical--evidence-docs)
- [Boundary reminder](#boundary-reminder)
- [Stale-doc cleanup policy](#stale-doc-cleanup-policy)

## Docs by reader need

| Need | Start here |
|---|---|
| What is implemented now? | [implementation-status.md](implementation-status.md) |
| What is the architecture target? | [specs/2026-06-01-secs-magik-objectives-spec.md](specs/2026-06-01-secs-magik-objectives-spec.md) |
| Where should code live? | [repository-schema.md](repository-schema.md) |
| What is client vs verifier? | [client-surfaces.md](client-surfaces.md) |
| What is the current production-readiness plan? | [plans/2026-06-02-ready-for-prod-checklist.md](plans/2026-06-02-ready-for-prod-checklist.md) |
| What is the Track E local phase status? | [issues/secs-magik-phases/track-e-trusted-issuer-root-policy.md](issues/secs-magik-phases/track-e-trusted-issuer-root-policy.md) |
| What was the original issue-slice sequence? | [plans/2026-06-01-secs-magik-implementation-issue-slices.md](plans/2026-06-01-secs-magik-implementation-issue-slices.md) |
| What is public-language draft material? | [announcement-thread.md](announcement-thread.md) |

## Current source-of-truth docs

| Path | Status | Purpose |
|---|---|---|
| [implementation-status.md](implementation-status.md) | Current source of truth | Status ledger separating solid/current, partial/prototype, planned, future, and out-of-scope surfaces. |
| [repository-schema.md](repository-schema.md) | Current schema map | Objective file-system schema and module ownership map. |
| [client-surfaces.md](client-surfaces.md) | Current boundary doc | Client-side local Hermes/secC/secZ packet-construction boundary. |
| [specs/2026-06-01-secs-magik-objectives-spec.md](specs/2026-06-01-secs-magik-objectives-spec.md) | Current architecture spec | Architecture/objectives spec. Check status ledger before treating target behavior as implemented. |
| [plans/2026-06-02-ready-for-prod-checklist.md](plans/2026-06-02-ready-for-prod-checklist.md) | Current control surface | Ready-for-prod track checklist and completion checkpoints through the current implementation train. |
| [issues/secs-magik-phases/track-e-trusted-issuer-root-policy.md](issues/secs-magik-phases/track-e-trusted-issuer-root-policy.md) | Local phase spec/status | Track E trusted issuer/root policy implementation spec; Track E is complete on `main` after PR #69. |
| [issues/secs-magik-phases/track-i-production-membership-provision-e2e.md](issues/secs-magik-phases/track-i-production-membership-provision-e2e.md) | Local phase spec/status | Track I local production-shaped `membership.provision` E2E spec; complete on `main` after PR #76 / post-merge CI run 27071532041. |

## Directory READMEs

| Directory | README | Owns |
|---|---|---|
| `specs/` | [specs/README.md](specs/README.md) | Architecture/objective specifications. |
| `plans/` | [plans/README.md](plans/README.md) | Plans, checklists, issue-slice history, and phase controls. |

The root repository also has child READMEs for [../core/](../core/README.md), [../client/](../client/README.md), [../server/](../server/README.md), [../examples/](../examples/README.md), and [../scripts/](../scripts/README.md).

## Plans and checklists

| Path | Status | Purpose |
|---|---|---|
| [plans/2026-06-02-ready-for-prod-checklist.md](plans/2026-06-02-ready-for-prod-checklist.md) | Current control surface | Track A-I readiness, completion checkpoints, remaining D/E/I path, and forbidden claims. |
| [issues/secs-magik-phases/track-e-trusted-issuer-root-policy.md](issues/secs-magik-phases/track-e-trusted-issuer-root-policy.md) | Local phase spec/status | Track E E0–E12 commit-boundary tasks, phase acceptance criteria, implementation-test matrix, and local E1–E11 synchronization status. |
| [plans/2026-06-01-implementation-progress-checklist.md](plans/2026-06-01-implementation-progress-checklist.md) | Historical/current progress ledger | Early issue train and CI alignment notes. |
| [plans/2026-06-01-secs-magik-implementation-issue-slices.md](plans/2026-06-01-secs-magik-implementation-issue-slices.md) | Historical issue-slice import | Original 2026-06-01 issue-level sequence. Many early slices have since landed. |

Plans define intended sequence and acceptance criteria. They do not override [implementation-status.md](implementation-status.md).

## Specs

| Path | Status | Purpose |
|---|---|---|
| [specs/2026-06-01-secs-magik-objectives-spec.md](specs/2026-06-01-secs-magik-objectives-spec.md) | Current architecture spec | Corrected secS-magik architecture, target verifier pipeline, repository boundary, and non-goals. |

## Draft / external-language docs

| Path | Status | Purpose |
|---|---|---|
| [announcement-thread.md](announcement-thread.md) | Draft | External-language sketch. It is caveated until verifier/signature/receipt claims are implemented and evidenced. |

## Historical / evidence docs

No tracked `docs/reviews/` directory is present in the current tree. If historical reviews are reintroduced later, keep them as provenance with supersession notes pointing readers back to [implementation-status.md](implementation-status.md).

## Boundary reminder

- local Hermes/secC/secZ are client-side / outgoing-call surfaces.
- secS-magik/secS is the verifier and permissioned RPC substrate.
- receiver-local manifests own opcode-to-handler meaning after verification.
- `wallet_presentation` now verifies signed presentation/challenge material cryptographically through the explicitly temporary minimal-equivalent secS challenge contract; full Castalia Wallet wallet-core parity/import remains future reconciliation work.
- Track E static trusted issuer/root policy is implemented on `main`; Track I local production-shaped `membership.provision` E2E is implemented on `main` via PR #76 at `5e5bb71` with post-merge CI run 27071532041. Follow-up runtime/live-ingress hardening remains tracked separately (#77-#84).
- the current receipt/event ledger is local/operator SQLite evidence only, not public auditability.
- Dregg, Midnight, Cardano, and wallet presentation enter through typed evidence adapters or anchors; they do not replace secS verification.
- Client packaging boundary: browser extension = WASM binding; secZ/secC/local clients = native/client binding or packet/evidence carrier; secS = verifier subset/artifact consumer that consumes signed presentation/challenge plus public verification material, not UI session state.

## Stale-doc cleanup policy

- Prefer status/supersession notes over rewriting historical plan provenance.
- Remove or caveat paths that do not exist in the current tree.
- Keep forbidden-claim language explicit: no “production-secure,” “fully ZK-verified,” “deployed production,” or “public auditability” unless code and deployment evidence prove it.
