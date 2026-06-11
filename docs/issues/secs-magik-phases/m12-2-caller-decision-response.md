# M12.2 — feat(gateway): return a signed accept/reject decision to the caller

> Parent: [M12 demoable milestone](m12-demoable-milestone.md) (#88). Filed as GitHub issue #90 (2026-06-09).

## Objective

Give the caller a response: a typed, signed decision frame carrying accept/reject,
the typed reason on reject, and a reference (context id / receipt id) the caller or
operator can use to inspect the ledger. Today the call is fire-and-forget, so a
demo cannot show the verifier answering the party that made the request.

## Rationale / current evidence

- `dispatch_packet` (`client/src/main.rs`) writes the packet, flushes, and
  returns; it never reads from the socket.
- `handle_gateway_connection_with_limits` (`server/src/ingress.rs`) reads the
  request to EOF and routes; it never writes a response.
- All decisions already exist internally as signed receipts
  (`server/src/receipt.rs`) and typed `VerificationError` reason codes — this issue
  surfaces a safe projection of that to the caller, it does not invent new state.

## Dependencies

- Best after M12.1 (so the response reflects real authentication) but can be
  developed in parallel.
- Must respect the redaction boundary established by Track H operator inspection:
  no raw payload, raw evidence, or raw signature bytes in the caller response.

## Target files

- `core/src/lib.rs` or a new `core/src/response.rs` — a versioned
  `DecisionResponse` type (decision, typed reason, context id, receipt id,
  schema/version), serialized with the existing bincode discipline.
- `server/src/ingress.rs` — write the response frame before closing the
  connection, on both reject and accept paths, under a bounded write timeout.
- `server/src/gateway.rs` — return a decision summary from the route path so
  ingress can serialize it (instead of only logging to stderr).
- `client/src/main.rs` — read and print the decision frame; non-zero exit on
  reject so scripts/demo can branch.
- Tests: `server/tests/ingress.rs`, `core` round-trip tests, an end-to-end client
  test if feasible.
- Docs: `README.md`, `docs/implementation-status.md`, `docs/client-surfaces.md`,
  `CHANGELOG.md`.

## Locked decisions / non-goals

Locked:
- The response is a **redaction-safe projection**: decision, typed reason code,
  context id, receipt id, schema version. No payload bytes, no raw evidence, no raw
  signature bytes (a signature *digest* or signer key id is acceptable, matching
  operator-inspection redaction).
- The response carries the same typed reason vocabulary already used internally; no
  free-form strings derived from caller input.
- Response writes are bounded (size + timeout) like ingress reads; a slow/dead
  client must not block the gateway.
- One request → at most one response frame; preserve the current one-packet
  connection model unless a framing change is explicitly owned and tested.

Non-goals:
- Not a streaming/multiplexed protocol; not handler output return (handler output
  stays bounded server-side per Track F).
- No transport security change (still no TLS in this issue).

## Task list (commit boundaries)

- [x] M12.2.1 — RED tests: client receives an accept response with context/receipt
  reference for a valid call; client receives a typed reject reason for a bad call.
- [x] M12.2.2 — Define versioned `DecisionResponse` in `core`; bincode round-trip
  tests; explicit schema version.
- [x] M12.2.3 — Thread a decision summary out of the gateway route path.
- [x] M12.2.4 — Write the response frame from ingress on accept and reject under a
  bounded write timeout; keep all existing reject/receipt behavior.
- [x] M12.2.5 — Client reads/prints the response and sets exit code by decision.
- [x] M12.2.6 — Docs/status/changelog; update `examples/hello-world.sh` to show the
  returned decision.

## Acceptance criteria

- A valid call returns an accept decision with an inspectable context/receipt
  reference; the operator can look up that reference in the ledger.
- A rejected call returns the typed reason matching the persisted reject receipt.
- The response never contains payload, raw evidence, or raw signature bytes.
- Response write is bounded; a non-reading client cannot stall the server.
- Full workspace gate green; post-merge main CI green.

## Verification gate

```bash
cargo test -p server --test ingress decision_response -- --nocapture
cargo test -p libsec-core decision_response -- --nocapture
cargo test --workspace
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Edge cases

- Client disconnects before reading → bounded write timeout, no server stall, no
  panic.
- Reject before a context exists (pre-decode/malformed) → response still returns a
  typed reason and the synthetic reject-receipt reference where one is emitted.
- Response larger than a configured cap → must not happen by construction
  (fixed-shape projection); assert size in tests.
- Backward compatibility: older clients that don't read the frame still succeed at
  the send step.

## Forbidden claims

This returns handler output; this is public auditability (#37); this proves
deployment (#33). The response is a local decision projection only.
