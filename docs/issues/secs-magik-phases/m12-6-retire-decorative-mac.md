# M12.6 — fix(core,client): retire the decorative `mac` field

> Parent: [M12 demoable milestone](m12-demoable-milestone.md) (#88). Filed as GitHub issue #94 (2026-06-09).

## Objective

Resolve the `ZenithPacket.mac` field, which is currently security-theater: the
client fills it with random bytes and the server never checks it. A field named
`mac` that carries no authentication is a footgun in a verifier substrate. Choose
one: (a) make it a real MAC that is verified, (b) rename/document it as a reserved
field and zero it, or (c) remove it behind an owned wire-format migration.

## Rationale / current evidence

- `build_packet` sets `mac: OsRng.gen::<[u8; 16]>()` (`client/src/main.rs`) — random
  bytes per packet.
- No server module references `packet.mac` for verification (confirmed across
  `server/src`). It is persisted into receipts/inspection as part of the packet
  hash only.
- With M12.1 (caller proof-of-origin) and M12.4 (tunnel AEAD) providing real
  authentication, the `mac` field has no remaining cryptographic role unless
  deliberately defined.

## Dependencies

- Best decided **after** M12.1 and M12.4, since those establish where real
  authentication lives, clarifying whether `mac` is redundant.
- If option (c) removal is chosen, this becomes a wire-format migration touching
  `core`, `client`, and the bincode round-trip/packet-layout tests — scope it
  explicitly. Preserving the v0 packet shape is a standing repo rule, so option (b)
  (reserve + zero + document) is the recommended low-risk default.

## Target files

- `core/src/lib.rs` — `ZenithPacket` field definition/comment (and any rename).
- `client/src/main.rs` — stop emitting random MAC bytes.
- `server/src/*` — if option (a), add verification; if (b), document non-use.
- Tests: `core` packet round-trip, `server/tests/packet_opcode_regression.rs`,
  `server/tests/payload_layout.rs`.
- Docs: `README.md` Packet v0 section, `CHANGELOG.md`.

## Locked decisions / non-goals

Locked:
- The end state must not ship a field literally named `mac` that is filled with
  meaningless bytes and never verified.
- Recommended default = option (b): keep the v0 byte layout, zero the field,
  document it as reserved/unused, and update the README Packet v0 section so readers
  do not mistake it for authentication. This preserves the v0-shape compatibility
  rule without a migration.
- If option (a) is chosen, define exactly what the MAC covers and verify it on
  ingress with a typed reject.
- If option (c) is chosen, it must be an explicit, tested wire-format migration
  with the README/compat note updated.

Non-goals:
- Do not silently change the byte layout without owning the migration and tests.

## Task list (commit boundaries)

- [x] M12.6.1 — Decide option (a/b/c) in the PR description with rationale.
- [x] M12.6.2 — Implement: client stops emitting random MAC; field is verified,
  reserved+zeroed+documented, or removed-with-migration per the decision.
- [x] M12.6.3 — Update packet round-trip / layout / regression tests.
- [x] M12.6.4 — Update README Packet v0 section and CHANGELOG.

## Acceptance criteria

- No code path emits a meaningless `mac` while naming it as if it authenticated.
- The README accurately describes the field's status.
- Packet round-trip/layout/regression tests pass.
- Full workspace gate green; post-merge main CI green.

## Verification gate

```bash
cargo test -p libsec-core -- --nocapture
cargo test -p server --test packet_opcode_regression -- --nocapture
cargo test -p server --test payload_layout -- --nocapture
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Edge cases

- Existing persisted receipts/packet hashes computed over the old `mac` bytes must
  still inspect without error (hash is over serialized bytes regardless of value).
- If reserved+zeroed: assert the field is zero in newly built packets.

## Forbidden claims

That zeroing/reserving the field adds authentication. Authentication comes from
M12.1 (caller proof) and M12.4 (tunnel AEAD), not this field.
