# Provider reference-object envelope v1

Status: **solid bounded crypto primitive; integration and deployment remain incomplete**.

`service.reference-object-envelope.v1` seals one original reference object and
the exact requester evidence to a provider's pinned X25519 intake key. It is a
separate, additive contract: `service.intake-envelope.v1` remains unchanged and
continues to carry the reviewed brief and reference manifest.

The public relay may see the recipient key identifier, expiry, envelope size,
and an opaque transport deduplication value. The request ID, idempotency key,
artifact ID, expected digest, original bytes, and requester evidence remain in
authenticated ciphertext.

## Cryptographic profile

- Recipient key: X25519 public key, 32 bytes.
- Ephemeral key: a fresh X25519 key pair for every object envelope.
- Key derivation: `derive_tunnel_key_hkdf` with the domain-separated
  `service.reference-object-envelope.v1/session` identifier.
- Authenticated encryption: ChaCha20-Poly1305 with a fresh 12-byte nonce.
- Associated data: the complete public header through the nonce.
- Recipient key identifier: `tunnel_public_key_id(recipient_public_key)`.

The producer must generate the ephemeral secret and nonce from a
cryptographically secure random source and must never reuse the pair.

## Binary frame

All integers are unsigned big-endian. No trailing bytes are allowed.

| Field | Size | Meaning |
|---|---:|---|
| magic | 8 | ASCII `SECSR01` followed by NUL |
| expires_at_ms | 8 | Exclusive Unix epoch expiry in milliseconds |
| recipient_key_id_len | 1 | Length of the printable key identifier |
| recipient_key_id | variable | Provider-published key identifier |
| ephemeral_public_key | 32 | X25519 ephemeral public key |
| nonce | 12 | ChaCha20-Poly1305 nonce |
| ciphertext_len | 4 | Ciphertext bytes including the authentication tag |
| ciphertext | variable | Authenticated encrypted payload |

The encrypted payload is:

| Field | Size | Meaning |
|---|---:|---|
| payload_magic | 8 | ASCII `SECSRP1` followed by NUL |
| object_len | 4 | Original object byte length |
| requester_evidence_len | 4 | Exact requester-evidence byte length |
| content_sha256 | 32 | SHA-256 of the exact original object bytes |
| request_id_len + request_id | 1 + variable | Stable request identity |
| idempotency_key_len + idempotency_key | 1 + variable | Stable submission identity |
| artifact_id_len + artifact_id | 1 + variable | Reference-manifest artifact identity |
| object | variable | Exact original reference bytes |
| requester_evidence | variable | Evidence bound to this request and object |

The object limit is 524,288 bytes, the evidence limit is 262,144 bytes, and
each identifier is 1–128 visible ASCII bytes. The sealer verifies the supplied
digest before encryption. The opener re-verifies it after authenticated
decryption and rejects wrong recipients, expiry, tampering, malformed lengths,
empty fields, and trailing data.

## Stable interop vector

This vector is public test material and must never be used as an operator key.

```text
recipient_secret = 0707070707070707070707070707070707070707070707070707070707070707
recipient_public = 13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d
ephemeral_secret = 0808080808080808080808080808080808080808080808080808080808080808
nonce = 090909090909090909090909
expires_at_ms = 2000
request_id = request-1
idempotency_key = submit-1
artifact_id = reference-1
object = original visual reference
requester_evidence = signed-requester-evidence
envelope_sha256 = bb7e6b159d244cffee2f15005cd880d53aa05acf3780bfdc03548cf27253157c
```

Native Rust and generated WASM tests assert the same digest.

## Integration boundary

The contract transports one source object only. It does not create a
`ServiceRequest`, grant authority, verify membership, acknowledge queue
delivery, store an object, approve a Case or Run, or expose source bytes to an
executor. Service Management must durably store and verify opened objects,
match them to the canonical intake manifest and requester evidence, and commit
Runtime artifacts before admission. The execution adapter must separately
hydrate those artifacts under digest and length checks.

