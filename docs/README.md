# secS-magik docs index

This directory separates current implementation guidance from historical reviews and external-language drafts.

## Current docs

| Path | Purpose |
|---|---|
| `implementation-status.md` | Status ledger separating solid/current, partial/prototype, planned, future, and out-of-scope surfaces. |
| `repository-schema.md` | Objective file-system schema and module ownership map for the next implementation pass. |
| `specs/2026-06-01-secs-magik-objectives-spec.md` | Current architecture/objectives spec. |
| `plans/2026-06-01-secs-magik-implementation-issue-slices.md` | Issue-level implementation sequence with acceptance criteria. |
| `announcement-thread.md` | External-language draft, caveated until verifier/signature/receipt work lands. |

## Historical / evidence docs

| Path | Purpose |
|---|---|
| `reviews/` | Code reviews and audits. Historical findings should remain evidence/provenance, not silently rewritten as current architecture. |

## Boundary reminder

- local Hermes/secC/secZ are client-side / outgoing-call surfaces.
- secS-magik/secS is the verifier and permissioned RPC substrate.
- receiver-local manifests own opcode-to-handler meaning after verification.
- Dregg, Midnight, Cardano, and wallet presentation enter through typed evidence adapters or anchors; they do not replace secS verification.
