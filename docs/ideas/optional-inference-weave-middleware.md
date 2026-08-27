# Optional inference weave middleware

Status: **Design-gated idea; not implemented or accepted architecture**

Tracking issue: [#274](https://github.com/ZenithResearch/secS-magik/issues/274)

First candidate library: [`universal-weave`](https://github.com/transkatgirl/universal-weave)

## Summary

secS can wrap receiver-local machine handlers after it verifies the caller, operation, evidence, freshness, replay state, and receiver policy. Some future handlers could be model inference servers or agent harnesses.

This idea asks whether secS should optionally record or manage branching inference state around those handlers:

```text
verified invocation
  -> optional weave middleware
  -> receiver-local harness or inference adapter
  -> optional weave middleware
  -> bounded execution response and redacted receipt projection
```

The weave would be application/inference state. It would not become caller authority, proof evidence, verifier state, or a replacement for receiver-local manifests.

## Why this could be useful

Inference systems already retry, sample alternatives, compare candidates, and revisit earlier context. A weave can make that branching explicit and persistent:

- `generate` can append multiple sibling continuations to one parent;
- `chat` can append a user node and one or more assistant children;
- callers can continue from an older node without overwriting later history;
- a stateless backend can receive only the selected node ancestry;
- operators can inspect failed and alternate paths without placing raw content in secS receipts;
- different inference backends can share one backend-neutral branch contract.

`universal-weave` is relevant because it provides Rust tree/DAG primitives, node operations, traversal, serialization, and optional collaboration-oriented machinery. It is only a candidate: dependency, persistence, security, license, migration, concurrency, and operational fit require explicit evaluation.

## Current architecture conflict

Open [Issue #270](https://github.com/ZenithResearch/secS-magik/issues/270) proposes that Matrix owns conversation/history and secS admits only exact authority-bearing machine operations. That proposal's draft PR was not merged into the `main` snapshot used when this idea was recorded.

Managed conversational weaving could conflict directly with that boundary. Record-only weaving behind an already ratified exact operation might not, but that has not been decided.

Before implementation, the repository must explicitly choose whether to:

1. reject this idea as outside the secS boundary;
2. allow record-only tracing behind exact operations;
3. allow managed branching only for a separately ratified inference operation; or
4. revise the Matrix/secS ownership split.

This note chooses none of those outcomes.

## Proposed integration seam

If accepted, the middleware belongs after all authority gates and around bounded receiver-local handler invocation. It must not run on unverified or policy-denied requests.

```text
bounded ingress
  -> payload decode
  -> descriptor and evidence verification
  -> signed context
  -> replay/session/expiry and permission gates
  -> optional weave pre-invocation step
  -> existing handler/backend adapter
  -> optional weave post-invocation step
  -> bounded signed execution response
  -> redacted receipt/event projection
```

The integration should be expressed as an internal middleware/trait boundary. `universal-weave` node types, serialization bytes, and implementation-specific identifiers should not leak into Packet v0 or the public response contract.

## Modes to evaluate

The following names are illustrative rather than accepted configuration:

| Mode | Behavior | Compatibility cost |
|---|---|---|
| `off` | Existing pass-through behavior; no weave read or write. | None; must remain the default during evaluation. |
| `record` | Send the existing request to the backend and record request/result nodes afterward. | Can wrap more backends, but records only what the adapter can normalize. |
| `managed` | Resolve a `weave_id` and parent, materialize ancestry, invoke the backend, and append results. | Requires ownership, storage, schema, privacy, retry, streaming, and branching decisions. |

Activation should require both:

- explicit runtime configuration; and
- receiver-manifest opt-in for the named operation/handler.

A global flag must not silently capture arbitrary operator-defined operations.

## Context ownership

Wrapping “any harness or inference server” requires declaring who owns conversational context.

### secS-owned context

Appropriate for stateless inference servers. The weave layer materializes the selected ancestry into a backend-neutral request and submits it to the adapter.

### Backend-owned context

Appropriate for a stateful harness that already owns sessions or memory. secS may record request/result events, but must not replay the same ancestry into the backend unless the backend exposes explicit checkpoint, fork, import, or restore semantics.

### Unsupported hybrid

A backend that silently mixes server-held sessions with caller-supplied history risks duplicated context and divergent branches. Hybrid ownership should fail readiness until a deterministic contract exists.

## Candidate internal contracts

The public contract should stay implementation-neutral. A future versioned encrypted-payload DTO might carry concepts such as:

```json
{
  "schema": "secs.inference.request.v1",
  "weave": {
    "id": "opaque-weave-id",
    "parent": "opaque-node-id",
    "branch_count": 3
  },
  "request": {
    "kind": "generate",
    "input": "backend-neutral input"
  }
}
```

This is an example only. No schema, field, ID format, or operation is ratified.

Internal seams to evaluate:

```text
InferenceBackend
  invoke(materialized request) -> bounded event/result stream

WeaveManager
  resolve authorized weave/parent
  materialize ancestry when secS owns context
  begin pending node(s)
  complete or fail node(s)
```

## Identity and lifetime

- `weave_id` must not be the Packet v0 `session_id`; authorization sessions may expire or rotate while retained inference state has a different lifecycle.
- Access to a weave must derive from verified receiver policy and resource binding, never from possession of an opaque ID alone.
- A parent/version expectation is required for deterministic concurrent appends.
- Retries need an idempotency binding derived from verified invocation identity, not raw message text.

## Streaming and failure lifecycle

Streaming introduces state that a simple request/response tree does not solve automatically. A future contract must distinguish:

- `pending`: invocation accepted after authority gates, backend not complete;
- `completed`: bounded backend result finished and passed response validation;
- `failed`: timeout, disconnect, malformed response, policy-safe backend error, or persistence failure.

Partial text must not be presented as a completed authoritative result. The design must decide whether safe partial output is retained, deleted, or stored as a visibly failed node.

## Harness side effects

A branch records an execution history; it does not reverse reality. If a harness can call tools, send messages, mutate databases, or deploy software:

- deleting or deactivating a branch does not undo those effects;
- replaying a branch may duplicate effects;
- managed mode requires a backend capability declaration and idempotency/compensation contract;
- record-only mode must still mark external-effect references without storing secret or unrestricted tool traces.

The first accepted slice, if any, should prefer text-only or otherwise effect-free inference.

## Privacy and storage boundary

Raw prompts, responses, branch content, tool traces, and backend credentials must remain outside ordinary secS receipts, logs, readiness output, operator exports, and public-audit bundles.

A real weave store requires separate decisions for:

- encryption at rest and key ownership;
- per-weave authorization and resource binding;
- retention, deletion, export, backup, and recovery;
- content versus metadata separation;
- storage quotas and branch-explosion limits;
- redaction and privacy scanning;
- crash consistency and concurrent writers;
- schema/version migration.

Receipts may eventually carry only safe correlation data such as a versioned schema label, bounded counts, and domain-separated digests. Even those fields require privacy review before acceptance.

## Relationship to current opcodes

Current `main` preserves:

- `OPCODE_GENERATE = 0x01` / `legacy.generate`;
- `OPCODE_CHAT = 0x02` / `legacy.chat`.

They are legacy/core examples, not implemented generic inference services. This idea does not promote, reassign, or ratify them. A future weave capability should attach to receiver-owned operation descriptors or a separately accepted inference operation rather than hard-coded numbers alone.

## `universal-weave` evaluation gate

Before adding the crate, a design spike should answer:

- Does its dependent tree match ancestry-dependent chat/generation state?
- Which payload types and stable IDs remain owned by secS?
- Does its serialization support the required schema/version migration posture?
- What persistence layer and transaction boundary wrap it?
- How are concurrent appends, crashes, and partial streams represented?
- Is its optional DAG/CRDT behavior necessary or avoidable in the first slice?
- What are the memory/branch-growth limits and pruning rules?
- Does its license and dependency/supply-chain posture meet repository policy?
- Can the integration remain optional without infecting `core` or Packet v0?

## Promotion gates

This idea can move into a spec only after:

- compatibility or conflict with #270 is resolved;
- secS versus receiver-adapter ownership is ratified;
- `off`, `record`, and `managed` are individually accepted, revised, or rejected;
- stateful versus stateless backend context ownership is deterministic;
- authorization, privacy, retention, streaming, retry, concurrency, and side-effect contracts are locked;
- the public payload remains independent of `universal-weave` implementation details;
- an implementation is split into separately authorized issue/PR boundaries.

## Non-claims

This document does not implement or accept inference, chat, conversation continuity, branching, a loom UI, a weave store, `universal-weave`, a harness adapter, streaming, deployment, production readiness, Matrix integration, or new executable authority.
