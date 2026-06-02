# Client-side surfaces

Status: solid boundary documentation for Phase 6.1. The shared verifier-free packet builder now lives in `core/src/packet_builder.rs`; future local Hermes/secC/secZ surfaces can use it without becoming verifiers.

secS-magik / secS remains the verifier and permissioned RPC substrate. The client-side surfaces described here construct outbound secS-compatible calls; they do not verify authority, replace receiver-side manifests, or replace secS-magik verification.

## The three outgoing client-side paths

1. local Hermes secS tool/script/skill
   - A local operator or agent tool that prepares a secS call from a user's or process author's intent.
   - It can choose an operation name, target node, local opcode, and evidence references, then construct or request a `ZenithPacket`.
   - It is a client-side way to call secS, not a verifier.

2. secC generic/non-Zenith client form
   - A generic client surface for non-Zenith or cross-context callers that need to send secS-compatible packets.
   - It should stay verifier-free: it may format packet inputs and submit packets, but capability, credential, evidence, replay, origin, and audience decisions are secS responsibilities.
   - It is a client-side way to call secS, not a verifier.

3. secZ Zenith-oriented outgoing client surface
   - A Zenith-oriented client surface for constructing outgoing secS calls using Zenith naming, defaults, or local UX conventions.
   - secZ is not the generic Castalia interface and is not the verifier. It should not be described as replacing secS or secS-magik.
   - It is a client-side way to call secS, not a verifier.

Together, local Hermes/secC/secZ are client-side ways to call secS, and none of them replaces secS-magik verification.

## Example flow

```text
user / local Hermes / app / node intent
  -> local Hermes tool, secC, or secZ
  -> operation name / local opcode / target node
  -> capability / credential / evidence refs
  -> ZenithPacket
  -> target secS RPC surface
```

At the target, secS receives the packet, validates the envelope and verifier inputs, looks up the receiver-local operation descriptor, evaluates evidence/capabilities/credentials according to the manifest, and only then hands a signed `VerifiedCallContext` to local handlers.

## Boundary rules

- Client surfaces may construct packet inputs and submit packets.
- Client surfaces may carry evidence references or presentation bytes, but they do not decide that the evidence is authoritative.
- Client surfaces may use operation names or local opcode conventions, but receiver-local manifests bind concrete `u8` opcode meaning after verification.
- Client surfaces must preserve the `ZenithPacket` v0 field shape unless a versioned migration is explicitly approved.
- Client surfaces must not silently add server-side authority logic such as capability validation, credential validation, evidence verification, revocation checks, replay checks, or verifier receipts.
- secS-magik / secS remains the verifier and permissioned RPC substrate.

## Current repository mapping

- `client/` is the current secC-like CLI packet sender. It builds and sends packets; it does not verify inbound authority.
- `server/src/bin/secz.rs` is a historical compatibility wrapper for the prototype gateway binary. Despite the name, it is not canonical verifier ownership and should not be treated as the generic Castalia interface.
- Future local Hermes/secC/secZ surfaces should share verifier-free packet construction helpers from `core` when that avoids duplication.
