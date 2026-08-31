# `devgraph.issue.create.v1` stacked contract DAG

Date: 2026-08-31
Status: P4-O-DG ratified; every implementation node remains unimplemented
Contract: [../specs/devgraph-issue-create-v1.md](../specs/devgraph-issue-create-v1.md)
Predecessor: P4-R completed by Issue #270 / merged PR #271 / green post-merge Rust CI run `33448400000`

## Purpose

This plan registers the operator-ratified first exact Devgraph operation after
P4-R completed. It is a separate Devgraph-owned delivery branch, not a
relabeling of the Hermes P4-H/P4-S path and not a generic Work API
implementation plan.

## Dependency DAG

```mermaid
graph TD
  P4R[P4-R — peer-chat reconciliation]
  DGO[P4-O-DG — devgraph.issue.create.v1 operator ratification]
  DGP[DG-P — portable secS authority projection]
  DGV[DG-V — Devgraph exact-operation verifier adapter]
  DGW[DG-W — Wallet exact-operation approval and signing]
  DGC[DG-C — bounded CLI caller]
  DGE[DG-E — end-to-end and negative evidence]

  P4R --> DGO
  DGO --> DGP
  DGP --> DGV
  DGV --> DGW
  DGW --> DGC
  DGC --> DGE
```

The serialized sequence is exactly:

```text
P4-R -> P4-O-DG -> DG-P -> DG-V -> DG-W -> DG-C -> DG-E
```

## Node table

| Node | Status | Owner and exact objective | Gate |
|---|---|---|---|
| P4-R | Complete via #270/#271 | secS governance only: supersede peer chat and preserve exact-operation gate. | Merge `5dfeb950da1d6baf80d98e0843684625c9af6f4f` plus green post-merge Rust CI run `33448400000`. |
| P4-O-DG | Operator-ratified exact contract | secS contract: pin exactly `devgraph.issue.create.v1` and no runtime mechanism. | This contract merged with its static contract checks green. |
| DG-P | Next; unimplemented | secS: implement only the portable signed authority projection and exact operation/receiver-policy verification. | Producer vectors, strict decoder, signature, expiry/replay, redaction, and negative matrix. |
| DG-V | Blocked by DG-P | Devgraph: verify the exact secS projection and hand off only to canonical Issue creation/outbox. | Consumer vectors, exact operation/resource/request/idempotency binding, zero-effect denials, receipt correlation. |
| DG-W | Blocked by DG-V | Wallet: add a user-confirmed exact v1 Ed25519 signing surface using the shared vector. | Chrome-owned approval, private-key non-disclosure, origin/operation disclosure, exact vector parity. |
| DG-C | Blocked by DG-W | Devgraph CLI/client: construct one bounded call without exposing credentials or caller-selected receiver controls. | Idempotent retry and safe output/denial behavior. |
| DG-E | Blocked by DG-C | Cross-repository evidence: prove one create, exact duplicate, denial matrix, receipt correlation, and no credential/log leakage. | Reproducible local evidence; all discovered repair nodes merged first. |

## Sequencing rules

- One node equals one issue and one PR in its owning repository.
- No implementation node begins before its predecessor is merged and green.
- Contract/vector changes land producer-first only after consumers can retain
  compatibility; exact shared fixtures must be byte-identical across repos.
- A defect outside a node's boundary creates a separate owner-specific repair
  node before dependent work resumes.
- Devgraph owns Work semantics and `EventReceipt`; secS verifies/routes; Wallet
  owns the root key and approval; the CLI only constructs the bounded call.
- `.castaway` is a vault and is not a DAG authority node.

## Current claim

P4-R is complete and the exact P4-O-DG contract is operator-ratified. There is
still no runtime projection, Devgraph verifier, Wallet method, CLI mutation,
deployment, hybrid/PQ authorization, or end-to-end success evidence.
