# Provider intake v1 native CLI

Status: **implemented native custody/opener; release installation and provider qualification remain incomplete**.

`secs-provider-intake-v1` is the fixed local adapter for
`service.intake-envelope.v1` and
`service.reference-object-envelope.v1`. Both contracts use one pinned X25519
recipient key at the effective user's canonical secS data root:

```text
~/Library/Application Support/Zenith/secS/authority/service.intake-envelope.v1/recipient.x25519.key
```

The path shown is the macOS projection of the passwd-database home. `$HOME`, XDG variables, caller-selected roots, key paths, algorithms, operations, and output paths are not accepted.

## Commands

```text
secs-provider-intake-v1 provision
secs-provider-intake-v1 status
secs-provider-intake-v1 open
secs-provider-intake-v1 open-reference-object
```

- `provision` creates the authority directory and raw 32-byte X25519 recipient key exactly once. Existing keys are not replaced. The containing directories must already satisfy secS owner-private checks; the key is atomically published at mode `0600`.
- `status` reads the same held key and emits only `secs.provider-intake-status.v1`, its public key hex, and the derived key identifier. It emits no secret path or secret bytes.
- `open` reads one bounded opaque envelope from stdin and writes one binary opened frame to stdout. It reads no requester-selected configuration and collapses all cryptographic failures to `envelope_rejected`.
- `open-reference-object` reads one bounded encrypted reference-object envelope
  and writes the distinct `SECSOR1` binary frame documented below. It uses the
  same held provider key and the same generic cryptographic failure surface.

Provisioning is an explicit operator action. Startup and `open` never create or replace a key.

## Opened frame

Successful `open` stdout contains exactly:

| Field | Size | Meaning |
|---|---:|---|
| magic | 8 | ASCII `SECSO01` followed by NUL |
| intake_len | 4 | Unsigned big-endian intake byte length |
| requester_evidence_len | 4 | Unsigned big-endian evidence byte length |
| intake | variable | Opened canonical `service.intake.v1` bytes |
| requester_evidence | variable | Exact evidence that was inside the authenticated ciphertext |

No trailing bytes are allowed. The maximum input is 328,032 bytes. The maximum output is 327,696 bytes. The intended caller captures stdout directly; it must not route opened bytes to logs or a terminal.

Successful `open-reference-object` stdout contains exactly:

| Field | Size | Meaning |
|---|---:|---|
| magic | 8 | ASCII `SECSOR1` followed by NUL |
| request_id_len | 1 | Request ID byte length |
| idempotency_key_len | 1 | Idempotency key byte length |
| artifact_id_len | 1 | Artifact ID byte length |
| content_sha256 | 32 | Verified object digest |
| object_len | 4 | Unsigned big-endian object byte length |
| requester_evidence_len | 4 | Unsigned big-endian evidence byte length |
| request_id | variable | Authenticated request identity |
| idempotency_key | variable | Authenticated submission identity |
| artifact_id | variable | Authenticated manifest identity |
| object | variable | Exact original object bytes |
| requester_evidence | variable | Exact authenticated evidence bytes |

No trailing bytes are allowed. The object contract and bounds are specified in
[Provider reference-object envelope v1](../contracts/provider-reference-object-envelope-v1.md).

Failures return nonzero and write one bounded JSON object to stderr with a stable reason. `envelope_rejected`, `envelope_too_large`, and `input_failed` describe an unusable delivery. Missing/unsafe key, data-root, clock, provisioning, and output failures describe provider configuration or availability failure.

## Boundary

The binary decrypts and authenticates transport only. It does not verify Zenith membership, grant Service authority, persist the intake or reference, acknowledge a queue delivery, create a `ServiceRequest`, execute a workflow, or publish a receipt. Service Management must separately verify the exact requester evidence, commit its durable inbox before queue acknowledgement, and invoke its own authorized command boundary.

The current source has create-only provisioning, public status, native open, wrong-key/tamper/expiry/size rejection through the core contract, strict private-file checks, and focused unit coverage. A merged release, installer wiring, key publication/rotation runbook, Service Management executable pin, and live queue/offline/restart proof remain required.
