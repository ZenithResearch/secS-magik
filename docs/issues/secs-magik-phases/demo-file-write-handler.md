# demo.file.write — sandboxed demo handler (M13.2)

## What it is

`server/src/file_write.rs::DemoFileWriteProgram` is a deliberately constrained
demo handler for opcode `0x50 demo.file.write`. Given a verified context and a
JSON payload `{ "resource": "file:///<sandbox>/...", "content": "..." }`, it
writes `content` to the target **only** if the target resolves inside a
configured sandbox root. It exists to make M13 permission enforcement concrete:
an operator grants a caller permission to write a specific resource, runs the
call, and watches allowed/denied outcomes with inspectable receipts.

`demo_file_write_descriptor(opcode)` is **dev-bounded** (`dev_binding: true`)
and **not** part of `ReceiverManifest::default_v0()` — M13.3 installs it
explicitly into the demo manifest, exactly like `dregg_demo_descriptor`.
Production runtime (`production_verified`) rejects dev-bounded descriptors, so
this surface cannot be reached as production authority.

## What it is NOT (forbidden claims)

- **Not** arbitrary filesystem authority. It writes only inside one sandbox
  root; traversal (`..`), absolute paths outside the sandbox, symlink escape,
  and non-`file://` URIs are rejected before any write.
- **Not** shell execution or a general file manager.
- **Not** production deployment proof (#33), public auditability (#37), Dregg
  capability/revocation authority (#73), or live Castalia Dregg authority
  source/client discovery (#206).
- Permission acceptance happens before the side effect; every failure emits a
  typed reject reason (`demo_file_write_*`) for the execution receipt without
  echoing payload content or the target path.

## Production-hardening backlog (required before any production file/resource handler)

A production file/resource handler is a **separate issue/checklist**, never a
silent promotion of this demo handler. Before any production claim, the
following must be designed, implemented, and tested:

- **Path canonicalization policy** — a documented, audited canonicalization
  strategy (current handler canonicalizes the parent and, when present, the
  target; production needs a reviewed policy incl. TOCTOU handling).
- **Symlink policy** — explicit decision on following vs rejecting symlinks at
  every path component, with tests; current handler rejects parents/targets
  that resolve outside the sandbox.
- **Payload/content limits** — production limits, streaming vs buffered writes,
  and partial-write/atomicity semantics (temp file + rename).
- **OS-level permissions** — file mode/ownership, umask, and the principle of
  least privilege for the process; no writes outside a dedicated, restricted
  mount.
- **Audit retention** — receipt/ledger retention, redaction guarantees, and
  operator-vs-public inspection boundaries (see the credential-summary
  disclosure boundary, #83, for the metadata-disclosure pattern).
- **Concurrency** — behavior under concurrent writes to the same target.
- **Deployment posture** — production deployment proof (#33) and the runtime
  configuration of the sandbox root before any production-readiness claim.

## Status

M13.2: handler + descriptor + unit tests (`server/tests/file_write_handler.rs`)
implemented in isolation. Router/config wiring and the live ingress E2E
permission matrix are M13.3.
