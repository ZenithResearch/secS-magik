# secS/Hermes peer-chat contract supersession

Date: 2026-07-18
Reconciled: 2026-07-23
Status: superseded by Issue #270; P3 bounded execution-output transport remains implemented; no replacement operation or delivery mechanism is ratified

## Decision

The former peer-chat delivery design is explicitly superseded, never relabeled as an exact machine operation. Matrix owns conversation, including human-agent and agent-agent rooms, direct messages, history, E2EE, membership, identity presentation, and conversational continuity. Chat text and Matrix events are not executable authority.

secS admits exact authority-bearing machine operations only. A Matrix message may discuss or request an action, but it cannot create, renew, delegate, or widen secS authority and cannot itself invoke a protected handler. Any consequential operation requires a separately constructed secS call that satisfies its own ratified authority contract.

The first cloud Hermes profile keeps Matrix as its remote conversational ingress. The generic Hermes API server remains disabled. This document's historical filename is preserved so existing links and git history continue to resolve; its active effect is supersession and invariant preservation, not peer-chat acceptance.

## Superseded commitments

The following commitments are inactive and must not be restored by renaming them or substituting a generic operation label:

- the `agent.chat.v1` operation profile;
- the `agent.chat.request.v1` and `agent.chat.response.v1` chat message/conversation schemas;
- projection of trusted metadata as a system prompt;
- local delivery through `/v1/chat/completions` or the former profile-prefixed chat-completions route;
- the receiver-local `API_SERVER_KEY` chat adapter;
- a dedicated peer-chat profile;
- an outbound chat plugin;
- a mutual-chat target or A-to-B/B-to-A chat evidence milestone.

These names remain only as historical identifiers for the design that Issue #270 supersedes. They are not aliases for a future exact operation. `legacy.chat` at `0x02` also remains a legacy example and is not promoted or relabeled.

## Matrix and secS boundary

### Matrix conversation plane

Matrix owns conversational transport and continuity. Matrix identity, room membership, decrypted message text, mentions, reactions, and power levels are communication facts only. They grant no permission to deploy, mutate a protected resource, use a secret, spend funds, invoke a tool, or widen another principal's authority.

Matrix integration is not implemented or changed by this reconciliation. The boundary is ratified; no Matrix account, room, bridge, client, or deployment work is authorized here.

### secS authority plane

secS may admit only a named operation whose complete contract has been separately ratified. The receiver verifies the caller and the operation's authority bindings before fixed handler dispatch. Generic prompts, arbitrary chat, and generic machine-operation multiplexers are outside this boundary.

No future operation may treat conversation text, a Matrix event, a caller-selected operation string, or a model decision as authority. The operation descriptor, handler binding, resource, limits, and receiver policy remain receiver-owned.

## Preserved P1 and P3 invariants

Superseding peer chat does not weaken the transport and authority work already accepted and implemented:

1. Credential references remain outside model-visible payloads and configuration exports, and distinct caller identities remain distinct. No credential forwarding or ambient inheritance is permitted.
2. The receiver verifies caller identity, audience, operation, freshness, replay, expiry, and receiver-local policy before protected handler lookup or dispatch.
3. `VerifiedCallContext` is the sole authority metadata source presented to protected routing. Caller prose, Matrix metadata, display labels, and request fields cannot replace it.
4. Receiver-owned descriptor and handler binding, exact resource binding, attenuation, and non-amplification remain mandatory. The caller cannot widen held authority or select an undeclared handler.
5. Successful or rejected execution uses the signed, exact-request-correlated, bounded `ExecutionResponse`. Admission is not execution success, and a missing response frame is failure.
6. `DecisionResponse` remains unchanged as the redaction-safe decision projection and does not carry arbitrary handler output.
7. Accepted output persistence remains limited to receipt schema v3 metadata: schema ID, byte count, and domain-separated SHA-256 digest. Raw output bytes are never persisted, logged, debug-rendered, or exported.
8. No credential forwarding and no caller-selected receiver-local controls are permitted. The caller cannot select a model, provider, prompt, role, tool, toolset, workspace, session, plugin, handler, path, header, key, URL, opcode, or local delivery mechanism.

These are abstract secS invariants. They do not define the first operation, its request or response schema, or its local delivery mechanism.

## P3 bounded transport remains implemented

P3 bounded execution-output transport remains implemented on `main` through closed Issue #263 and merged PR #264. The protected 12-commit head is `c3c87bedb9a3cee8aeb9ad4d25f52cb096cb2c27`; merge commit `358b232a3c0de2f96f63b41ffa276c5ae469c19e` landed it; post-merge Rust CI run [30047659428](https://github.com/ZenithResearch/secS-magik/actions/runs/30047659428) succeeded.

The three response states remain `verifier_rejected`, `execution_rejected`, and `executed`. The exact four P3 output reasons remain `handler_output_missing`, `handler_output_unexpected`, `output_too_large`, and `execution_response_too_large`. Existing reasons such as `handler_unavailable` and `handler_timeout` remain existing handler reasons rather than new P3 output reasons.

`ExecutionResponse` remains receiver-signed and binds the SHA-256 digest of the exact raw ingress bytes. Caller verification remains against one directly supplied pinned key, with no peer-key resolver or registry. Receipt schema v3 stores only the output schema/count/digest projection. Historical pre-c4b6218, receipt-v1, and receipt-v2 encodings remain verifiable under their exact historical semantics. New operator projections remain operator export v3. New public export remains `bundle-v2/chain-v2`, while historical `bundle-v1/chain-v1` remains verifiable only under v1 semantics.

Issue #270 adds no P3 commit, changes no wire or receipt behavior, and does not authorize P3/C13. The exact P3/C1–P3/C12 governance recorded in `CHANGELOG.md` remains terminal for Issue #263.

## P4-R reconciliation boundary

Issue #270 implements only P4-R: contract supersession and active-plan reconciliation. It authorizes no implementation. The next gate is operator ratification of one named exact operation, not selection of an implementation mechanism.

Before implementation can be considered, a separate P4-O issue must ratify one named operation and its exact:

- authority and caller policy;
- receiver-owned resource binding and attenuation rules;
- request and response semantics;
- input, output, and timeout bounds;
- freshness, replay, and idempotency behavior;
- receipt and disclosure rules;
- negative matrix and explicit non-claims.

P4-O cannot use a placeholder, generic operation identifier, arbitrary prompt, or machine-operation multiplexer to keep the delivery DAG moving.

## Explicit non-ratifications

- No first operation or operation identifier is ratified.
- No generic machine-operation multiplexer is ratified.
- No local ABI, IPC, transport, socket, route, or endpoint is ratified.
- No new request or response schema is ratified beyond the preserved abstract P3 invariants.
- No package or repository ownership is ratified for a Hermes adapter, secS adapter, or outbound caller.
- No runtime implementation is authorized.
- No generic Hermes API server is enabled or accepted as an authority gate.
- No caller control over model, provider, prompt, role, tool, toolset, workspace, session, plugin, handler, path, header, key, URL, or opcode is ratified.
- No deployment, production readiness, Dregg finality, OS containment, Matrix integration, streaming, discovery, federation, or public-auditability claim is made.

## Stop conditions

Return to design if later work:

- relabels chat, an arbitrary prompt, or `agent.chat.v1` as the first exact operation;
- invents a generic operation identifier or multiplexer;
- authorizes implementation before one named operation is operator-ratified;
- changes P3 runtime, wire, response, receipt, or historical verification behavior;
- permits caller-selected receiver-local controls;
- relies on generic Hermes HTTP, internal tool dispatch, middleware, or plugin hooks as a mandatory authority gate;
- makes Matrix or another product integration depend on this reconciliation.

## Non-claims

This reconciliation does not implement an operation, operation identifier, schema, adapter, endpoint, ABI, IPC mechanism, transport, socket, route, package, plugin, caller, Matrix integration, deployment, or production-ready system. It does not identify where future code belongs. It supersedes the old peer-chat delivery contract while preserving the already implemented secS authority and bounded-response invariants.