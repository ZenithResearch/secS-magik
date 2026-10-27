# DevGraph session attachment v2

Status: source candidate; no installed authorization changes.

The closed `devgraph.work-request.v2` payload for `session.attach` is:

```json
{"session":{"application":"codex","source_instance_id":"store","external_session_id":"native-id"},"observed_at":"2026-10-27T20:00:00Z","basis":"inspected","link":null}
```

It requires an existing Proposal, Initiative, Project, Issue or Task with an exact
expected version. Native identity fields derive a SessionRef ID using SHA-256 of
the canonical three-field identity object. Optional `link` supplies source_instance_id,
event_id, attempt_id, relation, origin, target, observed_at and basis. Relations are
`delegated_to`, `forked_from`, `uses_runtime`; both endpoints must differ and the
attached session must be one endpoint. The event's stable SessionLink ID hashes
`[source_instance_id,event_id]`. Every derived record and the Work subject require
permission. Source metadata is a signed assertion, never an authority token or
proof of task completion. Payload bases are inspected, declared_scope and
source_observed; witnessed links use declared or source_observed.

UTC times permit Z or +00:00 and at most six fractional digits. Unknown fields,
invalid native atoms, base Todo and Work v1 are rejected. Shared vectors under
`server/tests/fixtures/session-attachment-v2.json` verify bytes, IDs and digest
against the Python consumer, and join the existing signed/replay/denial tests.
Existing v1/v2 grant bytes and Packet v0 retain their previous interpretation.
