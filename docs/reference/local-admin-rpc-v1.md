# Owner-local administration RPC v1

Status: implemented standalone native adapter; this is not a generic Packet v0
route, new network listener, remote administration deployment or shell API.

`tools/local-admin-rpc` owns `secs-local-admin-rpc-v1`. It accepts only
`--instance-id <canonical UUID>` and one bounded JSON stdin request, then returns
one correlated JSON stdout response. This process IPC is the direct same-machine
transport. HTTPS is not used or proxied by this adapter. Remote clients continue
using their existing separately pinned HTTPS connection.

The effective account's passwd home selects an owner-private
`~/.zenith/rpc/v1/<instance>.json`. Request bytes cannot select a program, policy,
key, data directory, callback, environment or configuration path. The protected
installation binds graph/instance, logical receiver/issuer/profile digest, native
binary digest, existing Python interpreter digest, exact handler source inventory
and the existing owner runtime. The existing venv interpreter keeps the same OS
and package-manager dependency custody as the HTTPS deployment; this does not
claim isolation from other programs/admins with the same OS identity.

The closed operations are `inspect`, `challenge`, `execute`. `inspect` discloses
only local readiness/capabilities after rechecking the actual signed owner record.
`challenge` permits only the current named credential actions and bounded public
Wallet identity. DevGraph rechecks whether that Wallet is admitted before creating
its challenge; no inbox or ceiling is disclosed without a valid signed execution.

`execute` verifies the existing `castalia/access-request-approval/v1\0` Ed25519
transcript, exact logical receiver/issuer, action-operation pairing, portable JSON,
nonce/identity shape and 120-second lifetime before handler dispatch. The DevGraph
handler then rechecks current owner/policy, stored challenge, nonce/replay, exact
selection and hierarchy boundaries under the existing database transaction.
Same-machine access alone conveys no authority. Wallet custody remains in Transfer.

## Wire binding

- Request schema: `secs.local-admin-request.v1`.
- Required: request UUID, graph UUID, instance UUID, logical receiver, issuer,
  portable connection-profile SHA-256, closed operation and body.
- Response schema: `secs.local-admin-response.v1` with the same request/graph/
  instance/receiver, bounded application result status and object body.
- Request limit524,288bytes (protected configuration remains65,536bytes), response limit1,048,576bytes, canonical challenge
  limit131,072bytes for operator consent (member consent remains16,384bytes), nesting limit16. Duplicate keys/floats/nonportable integers
  are rejected. This initial command vocabulary uses nonnegative safe integers.
- A fixed isolated Python invocation dispatches to `devgraph.ops.local_admin_rpc`.
  It constructs the canonical operator runtime without opening an HTTP listener.
  The response must match the original request before release to the caller.
- Handler stdin/stdout are bounded and concurrently drained; a30-second deadline
  kills the direct handler and reports an unknown result. No mutation is retried.

HTTPS and IPC use the same operator inbox, assignment policy, audit and recovery
records. A challenge can execute on either transport, and an uncertain decision
can be recovered through the other using the original action identity. Transfer
retains its pre-dispatch journal and requires native Wallet approval in both cases.

## Service commands

This first slice does not admit deployment, configuration writes, shell commands,
new exposure, owner replacement or delegation. They fail closed. Future service
commands require distinct versioned descriptors, exact proposed-config hashes,
expected configuration revision, explicit Wallet consent, retained results and
rollback/recovery evidence. They must call bounded service handlers rather than
turning an owner Wallet into arbitrary process execution authority.

## Validation

Run `cargo test --workspace` and `cargo build --workspace --release` from
`tools/local-admin-rpc`; its independent workspace preserves existing gateway and
URL/crypto pins. Native tests include Python-issued Wallet signature vectors,
invalid signatures/receiver/expiry/action pairing, closed input, private-file
fences, bounds and response identity. DevGraph and Swift conformance runs cover
same-state HTTPS/IPC, exact original-result recovery and zero-HTTP native dispatch.
Deployment and actual unlocked-Wallet acceptance are separately recorded evidence.


## Explicit secondary HTTPS adapter v3

`secs-local-admin-rpc-v3` is a separate fixed binary for protected
`secs.local-admin-config.v3` records. The closed configuration keys and the
`secs.local-admin-request.v1` / `secs.local-admin-response.v1` envelopes are
unchanged. Only inspect, challenge and execute are admitted. V1 remains
loopback-only and v2 remains canonical private IPv4; neither accepts the new
DNS/public receiver shape. V3 requires a canonical HTTPS origin, including a
Tailnet DNS origin. This is a logical receiver, never an outgoing network target.

The protected record still chooses the exact graph, instance, receiver, issuer,
profile digest, interpreter and handler source inventory. The current Devgraph
handler additionally requires a v10 secondary runtime, its original active signed
owner and unmodified ceiling, and the exact current owner-private service record
and complete public profile. Removal or replacement of that service closes RPC.
HTTP administration remains closed on the member URL. Existing grants and the
original owner registration are not copied or recreated by installation.

The new binary uses nonblocking bounded stdin/stdout with one total 30-second
deadline, including after direct handler exit. Timeout/output overflow kills the
handler's isolated process group and returns an unknown result. No blocking
reader/writer join can retain an inherited pipe indefinitely. It never retries
an uncertain decision. Tests include held descendant pipes, blocked stdin,
output overflow, exact HTTPS signature binding and unchanged old receiver rules.

Source tests/builds and actual installed inspection are separate from real
Wallet consent. A real owner must unlock Wallet and approve the exact decision;
synthetic test keys or direct database edits cannot qualify credential issuance.

## Canonical service access-point operations

`service_challenge` and `service_execute` wrap `{service_access_point, request}`.
The public issuer key comes only from the protected selected service profile.
The shared secS verifier authenticates the bounded route binding before checking
the original Wallet signature against its canonical authority receiver. The
outer instance/profile/receiver binding and response correlation stay unchanged.
Unknown bindings, changed registration, signatures and expired bindings fail
closed. `inspect` may return a public signed binding; it never unlocks a Wallet.
These are source-qualified additive operations, not an installed upgrade claim.
