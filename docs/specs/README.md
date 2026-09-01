# docs/specs

`docs/specs/` contains architecture and objective specifications.

Specs define the intended/current architecture. They are not, by themselves, implementation status. For implemented vs partial vs planned behavior, read [../implementation-status.md](../implementation-status.md).

## Current specs

| Spec | Use it for |
|---|---|
| [2026-06-01-secs-magik-objectives-spec.md](2026-06-01-secs-magik-objectives-spec.md) | Corrected secS-magik architecture, v0 packet compatibility, client-vs-verifier boundary, receiver-local manifests, target verifier pipeline, evidence adapters, receipts, and non-goals. |
| [dregg-authority-rail.md](dregg-authority-rail.md) | Dregg authority rail M15.1 / #137 spec that rewrites #73 acceptance criteria while keeping `dregg_authority` distinct from shape-only and fixture-backed rails. |
| [dregg-live-source-client-contract.md](dregg-live-source-client-contract.md) | Live Castalia Dregg source/client contract for #206: request/response, authentication, freshness/status, timeout/retry/cache, fail-closed readiness, and non-overclaim boundaries before runtime implementation. |
| [evidence-adapter-readiness-disclosure.md](evidence-adapter-readiness-disclosure.md) | Shared readiness/config/disclosure gate for future production-facing evidence adapters: #71, #74, #75, and #206. |
| [secs-hermes-peer-chat-contract.md](secs-hermes-peer-chat-contract.md) | Superseded peer-chat delivery contract and preserved historical filename. Use it for the Matrix conversation/secS exact-operation boundary, explicit supersession of `agent.chat.v1` and its chat delivery surfaces, preserved P1/P3 authority and bounded-response invariants, and the P4-R non-ratification gate. There is no replacement operation or delivery mechanism ratified. |
| [devgraph-issue-create-v1.md](devgraph-issue-create-v1.md) | Operator-ratified `devgraph.issue.create.v1` contract with merged P4-O-DG-R1, DG-P, and DG-E1; the DG-E2 branch adds only a fixed one-shot Wallet adapter, not Work success. |

## How to read specs

1. Start with the [root README](../../README.md) for orientation.
2. Use this directory for architecture intent and accepted objectives.
3. Check [../implementation-status.md](../implementation-status.md) before treating a spec claim as implemented.
4. Use [../plans/README.md](../plans/README.md) for sequencing and checklist surfaces.

## Update rules

- Keep specs reviewable and caveated.
- If a spec becomes stale, add a supersession note instead of silently rewriting historical context.
- Keep Dregg, Midnight, Cardano, wallet crypto, public audit, and production deployment claims bounded to what current code actually implements.
