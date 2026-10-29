# Finite holder sessions v1

Status: additive shared contract and native verifier source candidate. No service,
Wallet, runtime policy, grant or installed client is activated by this source.
Browser and native session custody are consumers, not issuer-policy authorities.

`crates/secs-grant-contract/src/holder_sessions.rs` implements a separately named
session-key contract. Existing signed holder v1/v2 formats and same-holder
derivation are unchanged. Only v2 parents are supported by this first profile;
an existing v1 grant stays on its existing path and is never auto-converted.

## Ownership and authorization

The Wallet keeps the reusable parent grant and long-term holder key. An
application creates a temporary key and a fresh `session_installation_id`. The
approving Wallet's `installation_id` is a different binding; it must match a
parent restriction when one exists. An unbound parent does not fabricate a
restriction: the explicit approval selects that Wallet installation.

The issuer prepares an immutable `secs.holder-session-challenge.v1`. Both keys
sign the exact challenge with different domains. The holder authorization and
parent grant travel only on the Wallet-to-issuer/broker-private path; a page or
MCP receives neither reusable grant nor long-term key. The issuer verifies the
two signatures, current parent and policy, exact permission subset, original
request and challenge state before signing a finite session credential.

This is an explicit issuer session exchange, not ordinary same-holder
attenuation, an operator `access.decide` approval, membership, or an onward grant.
The parent `onward_delegation` flag remains false. A temporary key cannot approve
a new session or renew its own authority. The existing owner-bootstrap session
interface remains a separate, unchanged entry point.

## Absolute time bounds

All dates are safe-integer Unix seconds. `expires_at` is fixed before holder
consent and cannot exceed any of:

- challenge issuance plus the requested lifetime;
- challenge issuance plus the parent `max_credential_lifetime_seconds`;
- a dated parent's end;
- the issuer's current session cap.

`review_deadline = min(issued_at + 120, expires_at)` and approval at or after
that deadline fails. A later issuer response does not move the original end.
Per-call proofs end at `min(now + 60, expires_at)`. A read, navigation, reconnect,
Wallet lock/unlock or activity update never extends any expiry. Fresh authority
requires a new explicit review. Closing custody destroys the temporary key; it
does not assert issuer-side revocation. Status proofs are bounded by the same
end; after that end a client can render the retained request as expired locally.

## Wire and transcripts

Every struct is closed to unknown fields. JSON uses the existing RFC 8785 JCS
profile, rejecting floats, unsafe integers, duplicate keys, excessive depth and
oversized envelopes. Digests are lowercase SHA-256 hex of those canonical bytes.
Every signature is Ed25519 over ASCII domain, one NUL byte, then JCS payload:

| Record | Domain | Signed payload |
|---|---|---|
| Holder approval | `secs.holder-session-authorization.v1/signature` | Exact challenge |
| Temporary-key possession | `secs.holder-session-possession.v1/signature` | Exact challenge |
| Issuer session credential | `secs.holder-session-credential.v1/signature` | Credential claims |
| Per-call proof | `secs.holder-session-presentation.v1/signature` | Proof except signature |
| Original-result status | `secs.holder-session-status.v1/signature` | Status except signature |

The challenge binds canonical service and issuer/key, origin and audience,
parent ID/digest/revision, original holder and Wallet installation, temporary key
and application installation, exact permissions, request/challenge IDs, nonce and
all times. A credential contains the challenge and its digest, a fresh credential
ID and issuer signature. It contains only parent references, not the parent grant.

Permissions reuse the existing v2 role selectors and conservative subset test.
No prefix is reinterpreted as an exact object, no hierarchy guard is dropped and
source/destination permissions cannot be mixed. Object existence, placement,
paired effects and transactional pre/postconditions remain receiver duties.

The complete synthetic signed interoperability vector is
`crates/secs-grant-contract/tests/fixtures/holder-session-v1.json`. It contains
public fixture records only, not any installed grant or production secret.

## Mandatory stateful receiver checks

Cryptographic verification alone is insufficient. A provider must explicitly
enable this version, fix trusted origins/audience and read operations, bound
pending challenges, reserve original exchange IDs and consume proof nonces. A
public preparation route must not query or reveal a grant by digest: require
the caller to supply the full parent privately and return only metadata already
derivable from that supplied object and explicit requested permissions.

Only after both signatures verify may the issuer consult current parent state
and activate a session. Exact exchange retries recover the same committed result;
conflicting requests fail. Unknown outcomes reconcile the original ID and key,
never create a new session automatically.

Every call must check the current canonical parent grant, revision/revocation,
policy snapshot and permission ceiling before and after protected work. It must
verify session issuer signature, expected origin/audience, exact call binding,
freshness and replay, then apply its ordinary resource and transaction checks.
Reject unknown sessions and unsupported versions. Never treat possession of an
issuer-signed session alone as proof the parent is still active.

The native tool adds `review_holder_session`,
`verify_holder_session_authorization`, `issue_holder_session`,
`verify_holder_session`, and `verify_holder_session_status`. Only issuance can
load the separately supplied issuer key. These commands perform structural and
cryptographic verification; they do not implement registry or HTTP authority.

## Compatibility and qualification

The first provider integration is read-only and default-off. Existing grants,
scope, issuer defaults, replay stores, operator commands, old signed decoders and
the owner session-review protocol are preserved. Changing source or passing
tests does not install native binaries, enable this profile, upgrade an existing
v1 parent or grant access. Browser/native consumer fixtures, current-parent
revocation tests, real native receiver tests and separate rollout review remain
necessary before a live deployment claim.
