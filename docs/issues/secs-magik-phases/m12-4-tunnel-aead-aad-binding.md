# M12.4 — fix(core): bind tunnel AEAD to session_id and opcode via associated data

> Parent: [M12 demoable milestone](m12-demoable-milestone.md). Proposed 2026-06-09.

## Objective

Bind the ChaCha20Poly1305 tunnel ciphertext to the packet's `session_id` and
`opcode` (and ideally `claim_ttl`) using AEAD associated data, so a captured
`(nonce, ciphertext)` pair cannot be spliced onto a different envelope to bypass
replay/routing controls.

## Rationale / current evidence

- `core/src/tunnel.rs` calls `cipher.encrypt(nonce, plaintext)` /
  `cipher.decrypt(nonce, ciphertext)` with **no associated data**. Authentication
  covers key + nonce + ciphertext only.
- The replay reservation key is `(session_id, opcode, nonce, replay_scope)`
  (`server/src/schema.rs`). Because the AEAD does not bind `session_id`/`opcode`,
  an attacker who observes a valid tunnel packet can resubmit the same
  `(nonce, ciphertext)` under a **different** `session_id` or `opcode`: decryption
  still authenticates (key+nonce unchanged), but the replay key differs, so the
  reservation is fresh and the payload executes again — potentially under a
  different handler.
- The tunnel key is a single shared static key (`SECS_TUNNEL_KEY_HEX`,
  `server/src/payload.rs`), which makes the captured-ciphertext scenario realistic.

## Dependencies

- Independent. Touches `core` (used by client and server) so client and server must
  change together. Only relevant to `local_dev_tunnel`/tunnel paths today, but the
  fix is correctness for any future production tunnel.

## Target files

- `core/src/tunnel.rs` — add AAD parameters to `encrypt_payload`/`decrypt_payload`
  (use `aead::Payload { msg, aad }`).
- `server/src/payload.rs` — pass canonical AAD (`session_id || opcode`, and
  `claim_ttl` if cheap) on decrypt.
- `client/src/main.rs` — pass the same canonical AAD on encrypt when a tunnel key
  is configured.
- `core/src/ffi.rs` — update wasm wrappers' signatures (and stop panicking on bad
  lengths — see M12.6 cross-reference; at minimum keep them compiling).
- Tests: `core/src/tunnel.rs` unit tests (AAD round-trip, wrong-AAD rejection),
  `server/tests` splice-rejection test.
- Docs: `CHANGELOG.md`, `docs/implementation-status.md` payload-handling row.

## Locked decisions / non-goals

Locked:
- AAD is a **canonical, fixed-order** byte string derived from the envelope header
  fields that must not be reattributable: at minimum `session_id` (16) and `opcode`
  (1). Document the exact construction.
- Decrypt with mismatched AAD must fail (`aead::Error`) and surface as the existing
  `BadMac`/undecryptable-payload reject — no new silent path.
- Keep the existing `RuntimeMode` plaintext behavior unchanged; AAD only applies
  when the tunnel key path is used.

Non-goals:
- Not introducing per-session key derivation or the X25519 handshake (separate
  future work — the dead `SessionHandshake`/`derive_shared_secret` wiring and HKDF
  are out of scope here).
- No bincode packet-shape change; AAD is computed from existing fields.

## Task list (commit boundaries)

- [ ] M12.4.1 — RED tests: encrypt with AAD = `session||opcode`, decrypt with a
  different `session` or `opcode` fails; correct AAD round-trips; a server-level
  test proves a spliced tunnel packet is rejected and no second replay reservation
  is created.
- [ ] M12.4.2 — Add AAD params to `encrypt_payload`/`decrypt_payload`.
- [ ] M12.4.3 — Wire canonical AAD in `server/src/payload.rs` decrypt and client
  encrypt; update wasm wrappers to compile.
- [ ] M12.4.4 — Docs/changelog.

## Acceptance criteria

- Tunnel decryption fails when `session_id`/`opcode` differ from those used at
  encryption time.
- A captured tunnel packet replayed under a different session/opcode is rejected
  before routing; no fresh replay reservation is created.
- Correct AAD round-trips; plaintext modes unaffected.
- Full workspace gate green; post-merge main CI green.

## Verification gate

```bash
cargo test -p libsec-core tunnel -- --nocapture
cargo test -p server --test ingress tunnel_splice -- --nocapture
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Edge cases

- Empty plaintext with AAD still round-trips.
- Wrong key still rejects (existing behavior preserved).
- AAD field ordering is fixed and tested (swap session/opcode order must not
  collide).
- wasm `ffi` wrappers updated and still build under the `uniffi` feature.

## Forbidden claims

Per-session key agreement; forward secrecy; transport security/TLS. This is AEAD
context-binding only.
