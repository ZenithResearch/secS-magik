# Provider intake envelope v1

Status: **solid core primitive; integration and deployment remain incomplete**.

`service.intake-envelope.v1` seals one canonical `service.intake.v1` request and its exact requester evidence to a provider's pinned X25519 intake key. It is intended for a public gateway that publishes opaque bytes to a durable queue. The gateway may see routing metadata, expiry, sizes, and a stable opaque deduplication key; it must not receive the request plaintext or requester evidence.

This contract does not create a `ServiceRequest`, grant service authority, verify Zenith membership, acknowledge queue delivery, or prove that a provider processed a request. Those decisions remain with Service Management after the provider has durably stored and verified the opened request.

## Cryptographic profile

- Recipient key: X25519 public key, 32 bytes.
- Ephemeral key: a fresh X25519 key pair for every envelope.
- Key derivation: the existing `derive_tunnel_key_hkdf` primitive, with a domain-separated 16-byte session identifier derived from the recipient public key, ephemeral public key, and expiry.
- Authenticated encryption: ChaCha20-Poly1305 with a fresh 12-byte nonce.
- Associated data: the complete public header through the nonce.
- Recipient key identifier: the existing `tunnel_public_key_id` value derived from the recipient public key.

The producer must generate the ephemeral secret and nonce with a cryptographically secure random source and must never reuse the pair. The WASM export accepts these bytes from its caller so the host can use `crypto.getRandomValues`; deterministic values are only valid in tests.

## Binary frame

All integers are unsigned big-endian. No trailing bytes are allowed.

| Field | Size | Meaning |
|---|---:|---|
| magic | 8 | ASCII `SECSI01` followed by NUL |
| expires_at_ms | 8 | Exclusive Unix epoch expiry in milliseconds |
| recipient_key_id_len | 1 | Length of the printable key identifier |
| recipient_key_id | variable | Provider-published intake-key identifier |
| ephemeral_public_key | 32 | X25519 ephemeral public key |
| nonce | 12 | ChaCha20-Poly1305 nonce |
| ciphertext_len | 4 | Ciphertext bytes including the Poly1305 tag |
| ciphertext | variable | Authenticated encrypted payload |

The encrypted payload is:

| Field | Size | Meaning |
|---|---:|---|
| payload_magic | 8 | ASCII `SECSIP1` followed by NUL |
| intake_len | 4 | Canonical intake JSON byte length |
| requester_evidence_len | 4 | Exact requester-evidence byte length |
| intake | variable | Canonical `service.intake.v1` bytes |
| requester_evidence | variable | Deterministic evidence bound to this exact request |

Limits are 65,536 intake bytes, 262,144 requester-evidence bytes, and 327,712 ciphertext bytes. The opener rejects wrong recipients, expired envelopes, authentication failures, unsupported versions, length mismatches, empty parts, and trailing data.

## Stable interop vector

This vector uses public test material and must never be used as an operator key.

```text
recipient_secret = 0707070707070707070707070707070707070707070707070707070707070707
recipient_public = 13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d
ephemeral_secret = 0808080808080808080808080808080808080808080808080808080808080808
nonce = 090909090909090909090909
expires_at_ms = 2000
intake = {"schema":"service.intake.v1"}
requester_evidence = signed-membership-proof
envelope_sha256 = 51e76c5367fb192e9ae967c910dce2dd739797253d34bf762b53f1ad287219e4
```

Full envelope hex:

```text
534543534930310000000000000007d02e74756e6e656c3a7832353531393a306636643235353366663063306634343761653230326564643834333833653131d4ab6aceec961137917037936e60716fac573afe94d9da84a8020448dfc112090909090909090909090909000000556c98aa8a4d53f3ec53c1a9ca7046f4c54e6a50d6e2338cdb72a85ea9af30bea22047fb0d0b09e84d93c68fdfc3fc8dc2f7e4610cc016b6b6a74311b1460512147ce165141538a15bccf39a5bb443a133bcc2b5a282
```

## Integration boundary

`core/src/intake_envelope.rs` provides native seal/open functions. With the `uniffi` feature on `wasm32`, `wasm_seal_intake_envelope_v1` provides the producer-side browser/WASM primitive. The recipient secret remains provider-local; no browser opener is exported.

The current implementation has focused native tests and a wasm32 compile check. A released WASM artifact, public gateway deployment, provider key publication/rotation, queue provisioning, membership verifier, durable local consumer, and end-to-end production qualification are separate work and must not be inferred from this primitive.
