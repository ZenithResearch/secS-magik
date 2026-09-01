# secS-magik current state

Last verified: 2026-09-01 against `main` after merged DG-E1 PR #285 at `212b6e537bcdf4c1c6847ec1d24820d9ca27cdea`; this branch adds only the fixed DG-E2 one-shot Wallet adapter

This is the short orientation page for the repository. The detailed and authoritative status ledger remains [implementation-status.md](implementation-status.md). If this page and the ledger disagree, use the ledger and correct this page in the same change.

## At a glance

| Area | Current state | Boundary |
|---|---|---|
| Repository | Active Rust prototype with `core`, `client`, `server`, `permissions`, and `panel` workspace members. | Not deployment or production-readiness evidence. |
| Packet contract | `ZenithPacket` v0 and `opcode: u8` are preserved; bounded ingress and versioned payload envelopes exist. | A packet is a transport envelope, not authority by itself. |
| Verification | Receiver-held caller identity, descriptor, audience, freshness, replay, permission, evidence, and signed-context checks exist across tested paths. | Several external/federated/proof rails remain bounded, fixture-backed, design-gated, or future. |
| Devgraph exact-operation authority | P4-O-DG-R1, DG-P, and DG-E1 are merged. The current DG-E2 branch adds one fixed-origin, owner-private three-file Wallet ceremony around exactly the existing Ed25519 producer. | Local projection production only: no ingress/manifest route, generic browser RPC, Devgraph mutation/receipt, Wallet custody, deployment, or hybrid/PQ v1 authority. |
| Execution | Receiver-local manifests bind verified operations to bounded handlers. | secS is not a generic shell, centralized orchestrator, or product-policy engine. |
| Responses | P3 provides a separate receiver-signed, exact-request-correlated, bounded `ExecutionResponse`. | `DecisionResponse` is still not arbitrary handler output. |
| Audit | Signed receipts/events persist to local SQLite; redacted bundle/chain verification and a bounded Gist publication witness exist. | This is not blockchain immutability, deployment proof, or unrestricted payload retention. |
| Chat/generation | `OPCODE_GENERATE = 0x01` and `OPCODE_CHAT = 0x02` exist as legacy/core examples and manifest descriptors. | No generic inference backend, managed conversation store, or weave runtime is implemented on `main`. |
| Documentation delivery | The root README is the canonical front door; the Pages workflow renders it with tracked docs, generated host/wasm32 Rust API docs, and the existing no-network permission panel. | Documentation hosting does not establish gateway deployment, public auditability, or remote policy administration. |

## Current request path

The canonical prototype path is:

```text
client or local service
  -> ZenithPacket v0
  -> bounded TCP ingress and payload handling
  -> receiver-local descriptor lookup
  -> caller/evidence/context verification or typed rejection
  -> replay, session, expiry, and permission enforcement
  -> receiver-local bounded handler routing
  -> signed execution response
  -> signed receipt/event persistence and redacted inspection
```

Important distinctions:

- Client surfaces construct outgoing calls; they do not decide receiver authority.
- The secS verifier/RPC substrate verifies and produces signed handoff/audit objects.
- Receiver manifests own opcode-to-operation and handler bindings after verification.
- Raw payload, handler output, credentials, and private evidence do not enter ordinary receipt/operator/public-audit projections.
- DG-P is a separate non-routed producer library seam. DG-E1 invokes it only through fixed owner-private files. DG-E2 obtains its exact Wallet presentation through a fixed one-shot loopback page, closes the listener, and then invokes the same typed producer/output seam. Neither enters the canonical Packet/manifest handler path or makes Devgraph Work success a secS outcome.

## What is solid enough to build on

The implementation ledger records the exact evidence and caveats. At orientation level, current `main` includes DG-P and DG-E1; the DG-E2 adapter is explicitly limited to the current branch:

- the stable Packet v0 shape and legacy opcode constants;
- bounded ingress, explicit runtime payload modes, and tunnel context binding;
- receiver-held caller-key and verifier-key lifecycle checks;
- signed `VerifiedCallContext` and receipt helpers;
- receiver-local manifests, permissions, replay/session/expiry enforcement, and bounded handler dispatch;
- multiple bounded evidence-policy seams, including local fixtures, wallet presentation verification over the temporary secS challenge contract, static trusted issuer/root policy, and bounded Dregg-shaped authority work;
- local SQLite receipt/event persistence with redacted operator inspection;
- receiver-signed bounded execution-output transport with exact-request correlation;
- on `main`, one fixed `devgraph.issue.create.v1` portable authority producer with byte-exact consumer vectors, receiver policy, production Ed25519 signer verification, durable exact replay, and bounded DG-E1 file adapter; on this branch, its fixed DG-E2 Wallet ceremony;
- versioned redacted public-audit bundle/chain verification and bounded publication-witness tooling.

These are components of a production-shaped verifier path. They do not collectively prove a deployed production service, live federation finality, every future proof tier, or public-chain settlement.

## What is not currently implemented

- A generic model-inference or agent-harness service behind `legacy.generate` or `legacy.chat`.
- Conversation continuity, branching histories, a loom UI, or a durable weave store.
- A caller-selectable model, provider, prompt template, toolset, workspace, route, or receiver-local credential.
- General orchestration or arbitrary shell authority.
- Production deployment evidence for an operator-run gateway.
- Every reserved stronger verification tier, including the full future I16-I19 chain.
- A trusted CLI response mapping for arbitrary non-legacy `hub` opcodes; the current shipped client refuses them before TCP dispatch.
- Any in-repository evidence that a Devgraph consumer performed Work mutation/outbox/`EventReceipt`, that the DG-E2 ceremony was exercised in a loaded Wallet browser, or that the cross-repository end-to-end path succeeded. DG-E2 writes only the secS projection file.

## Active architecture decisions

### Exact operations versus conversation

[Issue #270](https://github.com/ZenithResearch/secS-magik/issues/270) and merged [PR #271](https://github.com/ZenithResearch/secS-magik/pull/271) superseded the retained peer-chat direction: Matrix owns conversation and secS admits only exact authority-bearing machine operations. Merged [PR #280](https://github.com/ZenithResearch/secS-magik/pull/280) then ratified the first exact contract, `devgraph.issue.create.v1`.

[P4-O-DG-R1 / Issue #282](https://github.com/ZenithResearch/secS-magik/issues/282) merged through PR #283 and binds every RFC 8785-canonicalized integer to the interoperable IEEE-754 safe range with committed boundary, escaping, Unicode no-normalization, and array-order vectors. DG-P then merged through PR #284, and DG-E1 through PR #285 as [the fixed local adapter](reference/devgraph-issue-create-v1-cli.md). DG-E2 adds only [the fixed Wallet adapter](reference/devgraph-issue-create-v1-wallet-cli.md); cross-repository Devgraph mutation and receipt correlation remain separate evidence.

### Optional inference weaving

[Issue #274](https://github.com/ZenithResearch/secS-magik/issues/274) records a design-gated idea for optional record/managed weave middleware around receiver-local inference handlers. The proposal is documented in [ideas/optional-inference-weave-middleware.md](ideas/optional-inference-weave-middleware.md).

This is an idea, not accepted architecture. Runtime work is blocked until compatibility with #270, ownership, privacy, storage, and context semantics are resolved.

### Stronger authority and deployment rails

The implementation ledger remains the source for current I16-I19, wallet-core parity, Dregg, Midnight, Cardano, production-deployment, and auditability status. Do not infer a stronger outcome from a configured label, fixture, local smoke, or redacted publication witness.

## Where to look next

| Question | Source |
|---|---|
| What is implemented in detail? | [implementation-status.md](implementation-status.md) |
| What is the repository boundary? | [repository-schema.md](repository-schema.md) |
| What is the target architecture? | [specs/2026-06-01-secs-magik-objectives-spec.md](specs/2026-06-01-secs-magik-objectives-spec.md) |
| What is the first ratified Devgraph operation and its current sequence? | [specs/devgraph-issue-create-v1.md](specs/devgraph-issue-create-v1.md) and [plans/2026-08-31-devgraph-issue-create-v1-dag.md](plans/2026-08-31-devgraph-issue-create-v1-dag.md) |
| What remains on the readiness path? | [plans/2026-06-02-ready-for-prod-checklist.md](plans/2026-06-02-ready-for-prod-checklist.md) |
| Which documents are exploratory? | [ideas/README.md](ideas/README.md) |
| How do the binaries and environment variables behave? | [reference/runtime.md](reference/runtime.md) |
| What is published as WASM/API/Pages documentation? | [reference/wasm-and-pages.md](reference/wasm-and-pages.md) |

## Maintenance rule

Update this page when a change alters the top-level request path, production/status posture, active architecture decisions, or the location of authoritative documentation. Always update [implementation-status.md](implementation-status.md) first or in the same change.
