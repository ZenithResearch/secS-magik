# secS/Hermes symmetric peer-chat contract

Date: 2026-07-18
Status: P3 bounded execution-output transport implemented by #263; broader peer-chat runtime and P4–P7 unimplemented/blocked
Profile: `agent.chat.v1`

## Decision

The first secS/Hermes slice is symmetric authenticated peer chat. Each Hermes agent has its own secS caller identity and invokes only configured symbolic operations on configured peers. The receiving secS node verifies the caller and receiver-local policy before a fixed handler may invoke the local Hermes agent.

```text
Hermes A
  -> A's `secs_agent_identity` credential reference
  -> configured secS Server B and expected audience
  -> Server B caller registry + verifier + receiver-local policy
  -> installed `agent.chat.v1` handler
  -> fixed receiver-local Hermes adapter
  -> bounded execution response + receipt correlation
```

Hermes B uses B's distinct identity for the reverse direction. No implicit credential forwarding occurs when B later talks to C.

Internal Hermes tool gating is deferred. It is not a dependency of this peer-chat contract.

## Existing evidence boundary

Current secS `main` already provides:

- receiver-held Ed25519 caller-key verification;
- signed `VerifiedCallContext` with authenticated subject, audience, operation, replay, expiry, descriptor, and handler bindings;
- receiver-local permission policy before handler dispatch;
- bounded handler payload/output/timeout accounting;
- typed verify and execute receipts;
- a versioned, redaction-safe `DecisionResponse`.

At the P1/P2 baseline, secS did not return handler output: `MachineProgram::execute` returned only a decision, reason, and output-byte count. P3 replaces that count-only outcome with receiver-owned bounded bytes and a separate authenticated response. `DecisionResponse` remains explicitly not handler output, and `legacy.chat` at `0x02` remains a legacy example rather than `agent.chat.v1`.

The P1/P2 contract below locks the full peer-chat target. P3 is now implemented at the bounded transport layer; P4–P7 remain contract-only.

## P3 implementation status

**P3 implementation status: implemented by #263** on its issue branch, subject to exact-head CI and merge authorization. The implementation adds a separate receiver-signed `ExecutionResponse`; the `DecisionResponse wire shape and version remain unchanged`. Execution responses bind the SHA-256 digest of the exact raw ingress bytes, expose only one authenticated bounded frame, and verify against one directly supplied pinned key. There is no peer-key resolver or registry.

The three response states remain `verifier_rejected`, `execution_rejected`, and `executed`. The exact four new P3 output reasons are `handler_output_missing`, `handler_output_unexpected`, `output_too_large`, and `execution_response_too_large`. Existing reasons such as `handler_unavailable` and `handler_timeout` remain existing handler reasons rather than new P3 output reasons. Receipt-persistence failure produces no execution frame rather than a synthetic rejection or success.

Accepted execution output crosses the persistence boundary only as a signed receipt schema v3 projection containing schema ID, byte count, and domain-separated SHA-256 digest. Raw output bytes are never persisted, logged, debug-rendered, or exported. Verification preserves the exact `pre-c4b6218`, receipt-v1, and receipt-v2 historical encodings, with constrained v1-first fallback. Every new operator projection uses operator export v3, while historical operator v1/v2 shapes remain immutable. New public export uses `bundle-v2/chain-v2`; historical `bundle-v1/chain-v1` and its external anchor remain verifiable only under v1 semantics.

P4 remains unimplemented: this status does not add a Hermes call, receiver-local Hermes adapter, plugin/profile/tool gating, trusted peer resolution, `agent.chat.v1`, mutual chat, deployment proof, or production-readiness claim.

## 1. Symmetric identity and configuration

### Local caller identity

Each enabled Hermes node declares exactly one secure credential reference for its outbound secS identity:

```yaml
credential_slots:
  - id: secs_agent_identity
    purpose: Authenticate this Hermes agent to configured secS peers
    required: true

secs:
  local_identity_ref: secs_agent_identity
```

The plugin resolves the reference from secure plugin/application storage. Private key bytes never appear in:

- plugin schemas or exported peer config;
- prompts or model-visible setup;
- chat request/response payloads;
- tool arguments;
- logs, decisions, receipts, or operator summaries.

The initial credential is the existing secS Ed25519 caller identity. The receiver registers the corresponding public caller key and lifecycle state. A caller key is necessary but not sufficient authority: receiver policy still binds caller, audience, operation, profile, validity, and replay state.

### Peer profile configuration

```yaml
secs:
  peers:
    - id: agent-b
      server_ref: agent-b-secs
      audience: secS://agent-b
      response_verifier_key_ref: agent-b-response-key
      operations:
        chat:
          profile: agent.chat.v1
          enabled: true
```

The peer entry is operator/application configuration, not model input. It may name only a registered server reference, expected audience, pinned receiver response-verifier key reference, and symbolic profile. It cannot contain arbitrary receiver-local URLs, paths, headers, handler IDs, opcodes, bearer tokens, models, providers, toolsets, or workspaces.

The receiver manifest owns the local `u8` opcode binding for `agent.chat.v1`. The outbound peer profile resolves that binding through trusted peer configuration. No global opcode is ratified by this issue, and `0x02` remains `legacy.chat`.

### Inbound configuration

```yaml
secs:
  inbound:
    enabled: true
    audience: secS://agent-b
    operations:
      chat:
        profile: agent.chat.v1
        enabled: true
```

Inbound declaration does not self-grant authority. The receiver separately owns caller keys, permission policy, descriptor-to-handler binding, limits, local Hermes adapter config, and receipt disclosure.

## 2. `agent.chat.request.v1`

The caller payload is exactly one non-streaming user message:

```json
{
  "schema_version": 1,
  "message": "Hello from Agent A",
  "conversation_ref": null
}
```

Rules:

1. `schema_version` is exactly `1`.
2. Unknown JSON fields reject as `malformed_request`.
3. `message` is a non-empty UTF-8 string after decoding and is at most 65,536 UTF-8 bytes.
4. The complete encoded request is at most 69,632 bytes; the stricter of this profile limit and receiver `SECS_MAX_PAYLOAD_BYTES` applies.
5. `conversation_ref` must be absent or `null` in slice one. A non-null value rejects as `conversation_ref_unsupported`.
6. The caller cannot submit system, developer, assistant, or tool roles.
7. The caller cannot select receiver-local models, providers, toolsets, or workspaces.
8. The caller cannot set a local URL, path, Authorization header, API key, session header, idempotency header, or handler ID.
9. Caller identity is not accepted from a `from_agent` field, display label, or message prose.
10. Unknown caller, wrong audience, wrong operation, replay, expired/not-yet-valid requests, and policy denial fail closed before handler lookup or local Hermes delivery.

The stable failure vocabulary must preserve the distinctions `unknown caller`, `wrong audience`, `wrong operation`, `replay`, `expired`, and `policy denial`; none may collapse into acceptance or reach the protected handler.

The profile uses the existing packet/envelope caller proof, audience, TTL, nonce, and replay checks. This JSON is only the operation payload; it does not replace the secS envelope.

## 3. Trusted caller metadata handoff

Authority-bearing peer metadata comes only from `VerifiedCallContext.subject`, not the request body. The handler receives receiver-owned typed metadata alongside the untrusted request:

```text
AuthenticatedPeerMetadata {
  subject_id: VerifiedCallContext.subject.subject_id,
  key_id: VerifiedCallContext.subject.key_id,
  audience: VerifiedCallContext.audience,
  operation: VerifiedCallContext.operation,
  context_id: VerifiedCallContext.context_id
}
```

The metadata object is constructed after context verification and active-manifest/policy checks. It is structurally separate from `agent.chat.request.v1.message` inside the secS handler API.

For the loopback Hermes adapter, the receiver may project this value into a fixed receiver-owned system-context template. The adapter must:

- use only the verified stable subject/key identifiers;
- JSON-escape all inserted values;
- keep the caller message in a separate user message;
- reject an unexpected operation/audience before local HTTP;
- never concatenate caller message text into the metadata template;
- never represent a caller-provided label as authenticated identity.

This is provenance context for the local Hermes agent, not a delegation grant and not authority to bypass the receiving Hermes profile's own restrictions.

## 4. Bounded execution response

### Preserve the decision projection

`DecisionResponse remains unchanged`. It continues to be the small redaction-safe admission/decision projection. It must not grow arbitrary handler output.

P3 introduces a separate versioned `ExecutionResponse` frame for operations that explicitly declare an output profile.

### Outer response

Contract ID: `secs-execution-response-v1`.

```text
ExecutionResponse {
  schema_version: 1,
  status: verifier_rejected | execution_rejected | executed,
  reason_code: optional stable typed reason,
  request_digest: SHA-256 of the exact sent ingress frame,
  context_id: optional receiver-generated id,
  receipt_id: optional receiver-generated id,
  output_schema: optional symbolic schema id,
  output: optional bounded bytes,
  authenticator_kind: ed25519_receiver,
  signer_key_id: receiver response key id,
  signature: receiver signature over canonical response bytes
}
```

State rules:

| Status | Context | Receipt | Output | Meaning |
|---|---|---|---|---|
| `verifier_rejected` | absent unless verification created one | reject receipt when available | absent | Caller/envelope/audience/operation/freshness/replay/policy failed before execution. |
| `execution_rejected` | required | execute-reject receipt required | absent | Verification succeeded, but handler was unavailable, timed out, rejected, failed, or exceeded bounds. |
| `executed` | required | accepted execute receipt required | required | The fixed handler completed and returned output conforming to the declared output schema. |

Invalid state combinations reject during decode. `executed` is never inferred from admission alone. A missing response frame is failure, never legacy success.

The signature preimage is the domain separator `secs-execution-response-v1/signature` followed by the canonical unsigned response. The canonical unsigned response contains `schema_version`, `status`, `reason_code`, `request_digest`, `context_id`, `receipt_id`, `output_schema`, the exact output bytes, `authenticator_kind`, and `signer_key_id`; it excludes only the signature field. Canonical field order, option tags, integer encoding, and byte lengths are fixed by the versioned codec. This makes the preimage finite and unambiguous while binding every non-signature field and the exact output bytes.

`request_digest` binds the response to the exact encoded ingress frame the caller sent, including its session/nonce/opcode/TTL/payload bindings; the caller recomputes and compares it before accepting the response. The caller then verifies `authenticator_kind`, `signer_key_id`, and `signature` against the peer's pinned `response_verifier_key_ref` before accepting status, reason, references, or output. Missing/mismatched request correlation, unknown keys, key-id mismatch, invalid signatures, unsigned responses, replayed responses, and output substitution reject as `response_authentication_failed`. Transport/session correlation alone is not response authenticity.

### Chat output

Output schema ID: `agent.chat.response.v1`.

```json
{
  "schema_version": 1,
  "message": "Hello from Agent B",
  "conversation_ref": null
}
```

Rules:

- output is UTF-8 JSON with unknown fields rejected;
- message is at most 262,144 UTF-8 bytes;
- the encoded `ExecutionResponse` is at most 266,240 bytes;
- the stricter of the profile cap and receiver `SECS_MAX_OUTPUT_BYTES` applies;
- `conversation_ref` remains absent/null in slice one;
- malformed response, unknown schema/status, missing required references, duplicate frame, no frame, trailing frame, and oversized output fail closed;
- output is useful handler data, not new caller authority.

### Receipts and disclosure

Receipts store:

- execution status and stable reason;
- context and receipt correlation;
- output schema ID;
- output byte count;
- a domain-separated output digest.

Receipts never store raw chat text. Slice one provides no configuration, disclosure mode, debug switch, or error path that can persist it. Receipts also exclude private key bytes, bearer tokens, raw headers, internal URLs, provider credentials, receiver configuration, stack traces, and unrestricted tool traces. The output digest is correlation evidence, not proof of model quality or public auditability.

## 5. Receiver-local Hermes delivery

The first implementation uses Hermes' receiver-profile route over fixed loopback HTTP:

```text
POST /p/<receiver-owned-profile>/v1/chat/completions
```

The adapter constructs a non-streaming request with:

- one fixed receiver-owned provenance/system message derived from authenticated metadata;
- one user message containing only `agent.chat.request.v1.message`;
- `stream: false`;
- a receiver-configured dedicated peer-chat Hermes profile reference resolved locally into the profile route;
- receiver-created timeout and idempotency values when supported.

`API_SERVER_KEY` is receiver-local plumbing. It is loaded from receiver-owned secret storage and inserted only by the local adapter. It never identifies the remote peer and never leaves the receiver node.

The dedicated slice-one Hermes profile is text-only and has no tools, delegation, shell/browser/file access, gateway sends, cron, skill/memory mutation, deployment capability, and no writable workspace. This profile constraint prevents authenticated chat from becoming an indirect arbitrary-effect channel while internal tool gating remains deferred.

The caller cannot influence the loopback host, port, profile reference, path, Authorization header, model route, provider credentials, system template, tools, workspace, or session controls. The receiver resolves the profile reference against installed local profiles and constructs the route; it never accepts a raw path. Redirects are disabled.

The adapter must use a proxy-disabled HTTP client with environment and system proxy discovery disabled. `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, system proxy settings, and proxy auto-configuration must not affect this request; `NO_PROXY` alone is not sufficient. Readiness fails closed if the client implementation cannot guarantee direct loopback connection without proxy routing.

The configured origin must use a numeric loopback address (`127.0.0.1` or `[::1]`); hostnames, userinfo, query strings, fragments, unknown profiles, and non-loopback targets reject at readiness. Raw upstream errors are normalized to stable secS reasons.

Required adapter failures include:

- `handler_unavailable` for no installed adapter;
- `hermes_unavailable` for connection/readiness failure;
- `handler_timeout` for the fixed deadline;
- `hermes_auth_failed` for receiver-local auth rejection;
- `hermes_response_malformed` for invalid upstream shape;
- `output_too_large` for profile or receiver limit violation;
- `handler_rejected` for a bounded upstream execution rejection not covered above.

All failures become `execution_rejected`; none degrade to verifier acceptance or legacy no-frame success.

## Fail-closed matrix

At minimum, P3–P6 must prove:

- unknown/revoked/expired/not-yet-valid caller key rejects before Hermes;
- wrong audience and wrong operation reject before Hermes;
- replay and expired claim reject before Hermes;
- receiver-local policy denial rejects before Hermes;
- missing descriptor/handler rejects before local HTTP;
- malformed/empty/oversized request rejects before local HTTP;
- unavailable Hermes, receiver-local auth failure, timeout, malformed response, and oversized response produce `execution_rejected`;
- accepted verification cannot be mistaken for `executed`;
- missing/malformed/oversized/duplicate output frames fail closed at the caller;
- unsigned, wrong-key, invalid-signature, replayed, wrong-request, or output-substituted responses fail closed at the caller;
- receipts/logs/config exports contain no credential material, raw chat text, local URL/header, or unrestricted trace;
- A→B uses A's credential and B→A uses B's distinct credential;
- no undeclared operation can be selected through schema or payload strings.

## Stop conditions

Return to design if implementation requires:

- one private credential shared by multiple Hermes agents;
- payload text determining caller identity;
- a remote Hermes bearer token as secS caller identity;
- arbitrary receiver-local URLs, headers, handlers, models, providers, toolsets, or workspaces;
- denied requests reaching Hermes;
- forwarding A's credential through B to C;
- changing `DecisionResponse` into an output carrier;
- raw private chat or credentials in receipts;
- relabeling `legacy.chat` as the peer protocol;
- internal Hermes tool hooks for the first chat slice.
- a slice-one receiver profile with ambient tools or writable effect surfaces.

## Non-claims

This contract does not implement a Hermes adapter, an outbound plugin client, mutual peer chat, streaming, conversation continuity, delegated authority, arbitrary endpoint exposure, discovery, federation, Dregg finality, public auditability, OS containment, deployment, or production readiness.
