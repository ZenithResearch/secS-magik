# secS-magik current state

Last verified: 2026-08-31 against `main` after merged [PR #280](https://github.com/ZenithResearch/secS-magik/pull/280), at [`bfe1a453`](https://github.com/ZenithResearch/secS-magik/commit/bfe1a453b097991fce0b57dfbe662c85d284ef82)

This is the short orientation page for the repository. The detailed and authoritative status ledger remains [implementation-status.md](implementation-status.md). If this page and the ledger disagree, use the ledger and correct this page in the same change.

## At a glance

| Area | Current state | Boundary |
|---|---|---|
| Repository | Active Rust prototype with `core`, `client`, `server`, `permissions`, and `panel` workspace members. | Not deployment or production-readiness evidence. |
| Packet contract | `ZenithPacket` v0 and `opcode: u8` are preserved; bounded ingress and versioned payload envelopes exist. | A packet is a transport envelope, not authority by itself. |
| Verification | Receiver-held caller identity, descriptor, audience, freshness, replay, permission, evidence, and signed-context checks exist across tested paths. | Several external/federated/proof rails remain bounded, fixture-backed, design-gated, or future. |
| Execution | Receiver-local manifests bind verified operations to bounded handlers. | secS is not a generic shell, centralized orchestrator, or product-policy engine. |
| Responses | P3 provides a separate receiver-signed, exact-request-correlated, bounded `ExecutionResponse`. | `DecisionResponse` is still not arbitrary handler output. |
| Audit | Signed receipts/events persist to local SQLite; redacted bundle/chain verification and a bounded Gist publication witness exist. | This is not blockchain immutability, deployment proof, or unrestricted payload retention. |
| Devgraph exact operation | P4-O-DG operator-ratified `devgraph.issue.create.v1`; P4-O-DG-R1 is the current safe-integer contract repair before DG-P. | Contract and canonicalization vectors only; no producer, verifier adapter, Wallet method, CLI, transport, route, opcode, handler, or deployment is implemented. |
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

## What is solid enough to build on

The implementation ledger records the exact evidence and caveats. At orientation level, current `main` includes:

- the stable Packet v0 shape and legacy opcode constants;
- bounded ingress, explicit runtime payload modes, and tunnel context binding;
- receiver-held caller-key and verifier-key lifecycle checks;
- signed `VerifiedCallContext` and receipt helpers;
- receiver-local manifests, permissions, replay/session/expiry enforcement, and bounded handler dispatch;
- multiple bounded evidence-policy seams, including local fixtures, wallet presentation verification over the temporary secS challenge contract, static trusted issuer/root policy, and bounded Dregg-shaped authority work;
- local SQLite receipt/event persistence with redacted operator inspection;
- receiver-signed bounded execution-output transport with exact-request correlation;
- versioned redacted public-audit bundle/chain verification and bounded publication-witness tooling.

These are components of a production-shaped verifier path. They do not collectively prove a deployed production service, live federation finality, every future proof tier, or public-chain settlement.

## What is not currently implemented

- A generic model-inference or agent-harness service behind `legacy.generate` or `legacy.chat`.
- Conversation continuity, branching histories, a loom UI, or a durable weave store.
- A caller-selectable model, provider, prompt template, toolset, workspace, route, or receiver-local credential.
- General orchestration or arbitrary shell authority.
- Production deployment evidence for an operator-run gateway.
- The `devgraph.issue.create.v1` secS producer, Devgraph verifier, Wallet signer,
  bounded CLI caller, transport adapter, or end-to-end evidence; P4-O-DG and
  P4-O-DG-R1 are contract-only.
- Every reserved stronger verification tier, including the full future I16-I19 chain.
- A trusted CLI response mapping for arbitrary non-legacy `hub` opcodes; the current shipped client refuses them before TCP dispatch.

## Active architecture decisions

### Exact operations versus conversation

P4-R completed through [Issue #270](https://github.com/ZenithResearch/secS-magik/issues/270) and merged PR #271: Matrix owns conversation and secS admits only exact authority-bearing machine operations. P4-O-DG then operator-ratified [`devgraph.issue.create.v1`](specs/devgraph-issue-create-v1.md) as the first named operation without selecting a runtime mechanism.

[P4-O-DG-R1 / Issue #282](https://github.com/ZenithResearch/secS-magik/issues/282) is the current contract-only repair. It bounds every RFC 8785-canonicalized integer to the interoperable IEEE-754 safe range and inserts a repair node before DG-P. Do not describe the operation, portable projection producer, Devgraph consumer, Wallet surface, CLI, transport, or deployment as implemented runtime behavior.

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
