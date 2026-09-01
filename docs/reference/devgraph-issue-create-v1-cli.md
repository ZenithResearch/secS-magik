# Fixed `devgraph.issue.create.v1` producer adapter

Status: DG-E1 implemented on this branch as a local file adapter; no deployment
or cross-repository end-to-end success is claimed.

Contract: [../specs/devgraph-issue-create-v1.md](../specs/devgraph-issue-create-v1.md)

## Boundary

`secs-devgraph-issue-create-v1` invokes exactly
`server::devgraph_authority::issue_devgraph_issue_create_authority_v1`. It has
no operation, audience, scope, policy, signer, key, database, route, handler,
URL, header, proxy, or transport selector. It does not contact Devgraph and
does not produce a Work mutation or `EventReceipt`.

Version 1 remains Ed25519-only. The binary never reads `.castaway`, exports a
Wallet or service key, reuses a Wallet root as the service key, or claims
ML-DSA/hybrid/PQ authority. A one-shot loopback Wallet page is intentionally
deferred to DG-E2 so the file adapter can be reviewed without a new browser or
network boundary.

## Canonical receiver data root

The path is derived from the effective user's passwd-database home; `$HOME`,
XDG variables, command-line flags, and environment variables cannot redirect
it.

| Platform | Data root |
|---|---|
| macOS | `~/Library/Application Support/Zenith/secS` |
| other Unix | `~/.local/share/Zenith/secS` |

The data root and fixed `authority/devgraph.issue.create.v1` directory must
already exist, be owned by the effective user, and deny every group/other mode
bit. The binary never creates receiver authority or a service key.

The fixed directory contains exactly these adapter inputs:

| File | Required meaning |
|---|---|
| `producer-manifest.json` | Strict `secs-devgraph-issue-create-producer-manifest.v1` binding. |
| `verifier.key` | Existing 32-byte Ed25519 service secret encoded as 64 hex characters. It is never generated. |
| `receiver-policy.json` | Strict `secs-devgraph-issue-create-policy.v1` receiver policy. |
| `secs-public-key-registry.json` | Strict `secs-public-verifier-key-registry.v1`; the service key must be a unique active production authority at issuance time. |
| `replay.sqlite3` | Existing owner-private regular SQLite file for the DG-P replay table. |

Every file is opened read-only first with no-follow, close-on-exec, and
nonblocking flags; it must be a regular file owned by the effective user, have
no group/other permission bits, and remain within its role-specific size cap.
Symlinks, FIFOs, devices, wrong-owner files, over-permissive modes, oversize
files, and replaced replay inodes fail closed. Holding the replay file open and
rechecking its inode after SQLite schema initialization protects the fixed
reopen boundary. The service key bytes are passed directly from that checked
file descriptor into the private typed DG-P identity constructor.

The strict manifest has these fields:

```json
{
  "audience": "devgraph://receiver-local",
  "operation": "devgraph.issue.create.v1",
  "receiver_policy_digest_sha256": "<64 lowercase hex>",
  "replay_schema": "secs-devgraph-authority-replay.v1",
  "schema": "secs-devgraph-issue-create-producer-manifest.v1",
  "schema_version": 1,
  "secs_public_key_registry_sha256": "<raw-file SHA-256, 64 lowercase hex>",
  "secs_verifier_key_id": "<receiver-controlled safe key id>"
}
```

The policy's canonical binding digest and exact audience must match the
manifest. The registry's raw file digest must match the manifest. DG-P then
checks the manifest-selected service identity against the receiver-held
registry, including algorithm, duplicate ID, production-authority flag, public
key equality, status, validity, revocation, and exclusive expiry.

## Caller files and command

The two input paths name owner-private regular files. The output path must not
exist and must name a new file inside an effective-user-owned
non-group/world-writable directory:

```text
secs-devgraph-issue-create-v1 \
  --request-file <FILE> \
  --idempotency-key-file <FILE> \
  --signed-projection-output <FILE>
```

The request file is a strict envelope with no unknown or duplicate fields:

```json
{
  "request": {
    "id": "issue-example",
    "kind": "Issue",
    "title": "Example issue"
  },
  "schema": "secs-devgraph-issue-create-producer-input.v1",
  "schema_version": 1,
  "wallet_presentation": {
    "actor_public_key": "<fixed v1 value>",
    "actor_signature_suite": "Ed25519",
    "audience": "<receiver audience>",
    "expires_at": 0,
    "idempotency_key_digest_sha256": "<digest>",
    "issued_at": 0,
    "nonce": "<12-byte base64url>",
    "operation": "devgraph.issue.create.v1",
    "request_digest_sha256": "<digest>",
    "resource": "Issue/issue-example",
    "schema": "devgraph.issue.create.wallet-presentation.v1",
    "schema_version": 1,
    "session_id": "<16-byte base64url>",
    "signature": "<64-byte Ed25519 base64url>"
  }
}
```

The idempotency file contains exactly one valid key followed by one LF. Raw
request and Wallet JSON are preserved as raw nested values until DG-P's strict
decoders apply their canonicalization and bounds.

Before loading authority state or reserving replay, the adapter rejects an
output that already exists, aliases either caller input or any fixed manifest,
service-key, policy, registry, or replay file, or falls anywhere beneath the
canonical authority subtree. The subtree exclusion also covers SQLite
`-journal`, `-wal`, and `-shm` sidecars. The comparison covers the canonical
parent plus entry name and existing-file device/inode identity, so direct
equality, `..` spellings, symlinked ancestors, and hard links cannot turn
projection output into trust, replay, or input destruction. Even an unrelated
existing owner-private projection is preserved and rejected: output
publication is create-only.

The adapter resolves the output parent once, opens that canonical directory
with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, verifies the held descriptor is the
same owner-controlled directory it resolved, and performs temporary creation,
publication, cleanup, and directory sync only with descriptor-relative
`openat`/`linkat`/`unlinkat` operations. Replacing the output parent pathname
after preflight therefore cannot redirect publication into a different
directory.

The fail-closed wall clock is read only after all authority files and replay
storage have loaded, immediately before DG-P issuance. It is read again before
publication, and DG-P fully revalidates the same request, Wallet presentation,
service-key registry, receiver policy, and projection at that current time. If
that second validation crosses an exclusive expiry or otherwise fails, no
projection is written. The first successful issuance may already have reserved
its replay tuple; that reservation remains until its normal expiry/pruning and
prevents the request from being executed afresh, but it is not a Devgraph Work
mutation.

On success, the output is the exact canonical
`secs-devgraph-authority.v1` projection plus one LF. It is written to a new
mode-`0600` temporary regular file in the output directory and synced, then an
atomic create-only hard-link publication makes the complete inode visible only
if the output entry is still absent. The temporary entry is removed and the
directory is synced. A denial or output failure never overwrites an existing
entry or leaves a partial projection. An exact DG-P retry therefore uses a new,
absent output path.

Standard output on success is bounded JSON containing only `ok`, the fixed
operation, `exact_retry`, and `output_written`. Standard error on denial is
bounded JSON containing only `ok` and a stable reason code. Neither surface
prints paths, raw idempotency keys, requests, Wallet presentations/signatures,
service keys, policies, registries, replay rows, or signed projections. Invalid
arguments produce only `{"error":"invalid_arguments","ok":false}` with exit
status 2; Clap diagnostics never echo raw argument text.
