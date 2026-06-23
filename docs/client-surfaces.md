# Client-side surfaces

Status: solid boundary documentation for Phase 6.1 plus Track D D4 packaging notes. The shared verifier-free packet builder now lives in `core/src/packet_builder.rs`; future local Hermes/secC/secZ surfaces can use it without becoming verifiers.

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

## Wallet presentation packaging boundary

Wallet presentation verification is now cryptographic inside secS, but the current challenge contract is explicitly temporary and minimal-equivalent. It is not a full Castalia Wallet wallet-core import and must be replaced or reconciled when wallet-core binds every secS-required challenge field.

Client/package roles:

| Surface | Packaging role | Boundary |
|---|---|---|
| Browser extension | WASM binding to wallet semantics/presentation construction. | Owns user-facing wallet UX; does not make secS trust browser UI session state. |
| secZ/secC/local clients | Native/client binding or packet/evidence carrier. | May construct requests, invoke local wallet bindings, or carry signed presentation/challenge evidence; does not verify authority. |
| secS/server | Verifier subset and artifact consumer. | Consumes signed presentation/challenge bytes plus public verification material; emits typed evidence results/receipts; does not own extension UI, WalletAuth HTTP sessions, or product login policy. |

The secS verifier boundary is data-oriented: subject, audience, origin, operation, resource, nonce/replay id, issued/expires timestamps, signature suite, public key ref/id, signature bytes, and public key material are verifier inputs. UI session state, app cookies, extension process state, and bearer-login assertions are not verifier inputs.

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

## `0x44 membership.provision` evidence-carrier boundary

For canonical `0x44 membership.provision`, client surfaces may carry `wallet_presentation` and `membership_credential` refs/material, but they do not verify authority and do not mint evidence-backed runtime contexts. secS remains the verifier: the server-side evidence-backed helper/API path consumes those refs/public inputs for local production-shaped E2E, while live TCP ingress still carries no evidence refs/public inputs for `0x44` until future wire-path work lands.

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
