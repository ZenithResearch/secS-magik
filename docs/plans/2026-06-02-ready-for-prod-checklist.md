# secS-magik ready-for-prod checklist

This is the repo-local control surface for turning secS-magik from the current prototype verifier/RPC substrate into the first production-shaped implementation train.

Source captures:

- Claude Hub capture: `/Users/bananawalnut/claude-hub/capture/2026-06-02-secs-magik-track-a-ready-for-prod-slices.md`
- Parent work surface: `/Users/bananawalnut/claude-hub/capture/2026-06-02-secs-magik-ready-for-prod-work-surface.md`

Status: A0 production definition locked. Later slices should expand this file phase-by-phase without weakening the production target.

## A0 — Production target

First-prod readiness requires all three Track A rails:

1. Local single-node production-shaped deployment.
2. Castalia Wallet-backed app/user auth.
3. Cross-Hub/federated evidence.

secS-magik is ready for first prod only when one Hub can run a production-shaped secS verifier service that:

- rejects insecure/local-dev authority in production mode;
- verifies wallet-core-defined presentations for app/user subjects;
- evaluates federated evidence produced, signed, anchored, revoked, or vouched for by another Hub, Castalia authority, or Dregg-shaped root/ref seam while still applying the receiver's local manifest policy;
- signs and persists operator-visible receipts/contexts;
- executes only bounded descriptor-authorized handlers;
- proves a membership-provisioning flow end-to-end without relying on hand-wavy future rails.

## A0 — Required rails

| Rail | Required for first prod? | Meaning | First proof |
|---|---:|---|---|
| Local single-node production-shaped deployment | Yes | One Hub/secS instance can run with production config, explicit keys, fail-closed runtime mode, bounded handlers, redacted ledger, and documented smoke commands. | Local production-mode smoke with signed context, receipt chain, and no local-dev evidence satisfying authority. |
| Castalia Wallet-backed app/user auth | Yes | Browser/app user presents wallet-core-defined challenge/signature evidence; secS verifies the same canonical wallet-core semantics used by the extension/secZ/secC. | Wallet presentation cryptographic happy path plus wrong signature/key/subject/audience/origin/replay/expiry rejects. |
| Cross-Hub/federated evidence | Yes | Hub A can evaluate evidence produced/signed/anchored/revoked/vouched for by Hub B, Castalia, or Dregg-shaped authority while still applying Hub A local manifest policy. | Fixture federation evidence adapter or policy path that accepts a trusted issuer/root and rejects untrusted/revoked/stale evidence. |

## A0 — Not enough for prod

Local smoke readiness alone is not enough for first prod.

The current implemented surfaces prove important substrate behavior, but they do not by themselves satisfy the production target:

- `local_static` evidence is a deterministic local/dev/test scaffold. It must not satisfy production authority.
- `wallet_presentation` is currently a typed fail-closed shell. It does not yet prove production wallet crypto.
- The local SQLite receipt/event ledger is local audit evidence. It is not public auditability or cross-Hub federation by itself.
- Dregg, Midnight, and Cardano are not current runtime dependencies in this repo. They enter only through future adapter/evidence/anchor semantics unless explicitly promoted by a later slice.
- Matrix room/message federation is not the cross-Hub/federated evidence rail.
- Browser WalletAuth/session UX is not owned by secS-magik, except for the wallet presentation evidence that secS must verify.

## A0 — Language discipline

Use these phrases until code proves stronger claims:

- local production-shaped deployment;
- wallet-core-defined presentation;
- typed fail-closed wallet shell;
- cross-Hub/federated evidence rail;
- fixture trusted issuer/root;
- Dregg-shaped root/ref seam;
- production-mode reject path;
- receiver-local manifest policy.

Avoid these phrases for current code:

- production-secure wallet auth;
- fully federated Dregg authority;
- fully ZK-verified proof;
- public auditability;
- Cardano-backed membership provisioning;
- Matrix federation as the authority rail.

## A0 — Stop condition

A0 stops here: the production definition is explicit, all three rails are required, and local smoke readiness is explicitly insufficient.

Do not start coding from A0. The next slice is A1 repo status reconciliation, followed by A2 rail taxonomy/non-goals.

## Future expansion placeholders

Later slices should expand this checklist in place:

- A1 — repo status reconciliation;
- A2 — rail taxonomy and non-goals;
- A3 — identity/key lifecycle decision gate;
- A4 — wallet-core integration decision gate;
- A5 — federated evidence model decision gate;
- A6 — production policy matrix;
- A7 — first membership-provisioning E2E shape;
- A8 — issue-ready phase/branch/PR checklist for Tracks A–I;
- A9 — Dregg/Midnight/Cardano defer-or-promote decision.

A8 must preserve the repo workflow pattern: phases are branch/PR boundaries, and issues inside each phase are commit boundaries.
