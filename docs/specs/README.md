# docs/specs

`docs/specs/` contains architecture and objective specifications.

Specs define the intended/current architecture. They are not, by themselves, implementation status. For implemented vs partial vs planned behavior, read [../implementation-status.md](../implementation-status.md).

## Current specs

| Spec | Use it for |
|---|---|
| [2026-06-01-secs-magik-objectives-spec.md](2026-06-01-secs-magik-objectives-spec.md) | Corrected secS-magik architecture, v0 packet compatibility, client-vs-verifier boundary, receiver-local manifests, target verifier pipeline, evidence adapters, receipts, and non-goals. |
| [dregg-authority-rail.md](dregg-authority-rail.md) | Dregg authority rail M15.1 / #137 spec that rewrites #73 acceptance criteria while keeping `dregg_authority` distinct from shape-only and fixture-backed rails. |

## How to read specs

1. Start with the [root README](../../README.md) for orientation.
2. Use this directory for architecture intent and accepted objectives.
3. Check [../implementation-status.md](../implementation-status.md) before treating a spec claim as implemented.
4. Use [../plans/README.md](../plans/README.md) for sequencing and checklist surfaces.

## Update rules

- Keep specs reviewable and caveated.
- If a spec becomes stale, add a supersession note instead of silently rewriting historical context.
- Keep Dregg, Midnight, Cardano, wallet crypto, public audit, and production deployment claims bounded to what current code actually implements.
