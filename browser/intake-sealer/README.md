# secS provider intake sealer

Status: **source-qualified browser producer; not a released package or deployed provider**.

This package adapts secS's canonical Rust/WASM
`wasm_seal_intake_envelope_v1` export to the Service Management
`IntakeEnvelopeSealer` interface. It generates a fresh X25519 ephemeral secret
and ChaCha20-Poly1305 nonce with `globalThis.crypto.getRandomValues`, validates
the closed provider profile, and checks that the returned envelope carries the
same recipient-key identifier and expiry.

```js
import { createBrowserIntakeEnvelopeSealer } from
  "@zenithresearch/secs-provider-intake-sealer";

const sealer = await createBrowserIntakeEnvelopeSealer();
const prepared = await serviceClient.prepareEncrypted(request, catalog, {
  authority,
  sealer,
});
await indexedDb.put(prepared.request_id, prepared); // before first send
await serviceClient.sendPreparedEncrypted(prepared, authority);
```

The browser receives only the provider's published X25519 public key. The
recipient secret remains in the native `secs-provider-intake-v1` custody root.
The package does not create membership, consent, transport credentials,
Service authority, or a `ServiceRequest`.

Persist the exact `PreparedEncryptedSubmission` before the first send. A lost
response is an unknown outcome: obtain fresh outer authorization and retry the
same envelope, request identity, idempotency identity and digest until expiry.
Do not reseal or replace requester evidence under the same logical request.

The build emits `SHA256SUMS` for the distributable files. Verify those hashes
against the reviewed release before loading the JavaScript or WASM. The stable
interop vector remains in
`docs/contracts/provider-intake-envelope-v1.md`.

Original reference asset bytes are outside `service.intake-envelope.v1` and
must use a separately versioned encrypted reference-object contract. Do not use
Service Management's legacy plaintext artifact upload as a production fallback.

