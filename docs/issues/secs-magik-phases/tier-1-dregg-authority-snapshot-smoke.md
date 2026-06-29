# Tier 1 Dregg authority snapshot smoke (#72/#195)

## Objective

Provide a deterministic local evidence surface for the Castalia Tier 1 demo: secS-magik can load a Dregg-shaped authority snapshot for an arbitrary entity and prove that resource authorization is receiver-held, scoped, and fail-closed.

## Fixture

The local fixture is:

```text
fixtures/dregg/david-lab-authority-snapshot.json
```

It models `did:example:david-lab` controlling `resource://david-lab/*` through a fixture snapshot named `secs-dregg-authority-snapshot-v1`.

This is a Dregg-shaped export/snapshot consumed by secS. It is not a claim that secS mints Castalia credentials, owns the Castalia registry, runs a full Dregg node, proves live Dregg finality, or provides production deployment/public auditability.

## Current smoke command

```bash
./scripts/tier-1-dregg-authority-snapshot-smoke.sh
```

The script prints a redaction-safe evidence summary, audits the fixture for raw secret/private-token markers, and runs:

```bash
cargo test -p server --test dregg_authority_registry dregg_authority_snapshot -- --nocapture
cargo test -p server --test dregg_authority_evidence dregg_authority_snapshot_adapter -- --nocapture
```

Production startup/readiness can require the file-backed snapshot source by setting:

```bash
SECS_ALLOWED_EVIDENCE_ADAPTERS=dregg_authority_snapshot
SECS_DREGG_AUTHORITY_SNAPSHOT_PATH=/path/to/dregg-authority-snapshot.json
```

The current source is synchronous and file-backed only. Missing, unreadable, malformed, unsupported, or stale snapshots fail closed; cached snapshots are retained only for inspection and do not bypass an unavailable source.

The smoke covers:

- active fixture snapshot accepts `did:example:david-lab` for `resource://david-lab/demo-agent`;
- matched resource scope is `resource://david-lab/*`, not a hardcoded Zenith path;
- stale snapshot rejects;
- revoked issuer/resource status rejects;
- wrong namespace rejects;
- wrong resource rejects;
- missing source rejects;
- unknown issuer rejects;
- unsupported schema/mode rejects;
- duplicate issuer keys and duplicate resources reject;
- wrong trust root and wrong authority root reject;
- the checked-in fixture file loads and produces the same authority decision;
- the snapshot-backed evidence adapter accepts only a trusted requested resource controlled by `did:example:david-lab`;
- spoofed subjects and caller-declared `requested_resource` public inputs cannot amplify authority.


## #72 acceptance matrix

| #72 criterion | Status | Evidence |
|---|---|---|
| Castalia credentials/registry authority belong to Castalia Dregg, not secS-magik. | Done / documented boundary. | This runbook's non-claims plus #72 issue text and `CHANGELOG.md` state secS consumes Dregg-shaped authority only. |
| Local/demo Dregg-shaped authority snapshot defines an arbitrary non-Zenith entity and controlled resources. | Done. | `fixtures/dregg/david-lab-authority-snapshot.json`; direct lookup tests in `server/tests/dregg_authority_registry.rs`. |
| Verification succeeds only when evidence matches active receiver-held issuer/resource state. | Done. | `DreggAuthoritySnapshot::lookup_entity_resource_authority`; `DreggAuthoritySnapshotEvidenceAdapter`; `dregg_authority_snapshot_adapter_accepts_controlled_resource_with_redacted_summary`. |
| Unknown/missing authority, revoked/stale/wrong namespace/wrong resource/wrong roots/duplicates/malformed cases fail closed. | Done. | Snapshot registry tests plus evidence-adapter negative tests; the smoke command runs both test groups. |
| Snapshot data cannot be replaced or amplified by caller-supplied embedded keys/roots/resources. | Done. | Root-binding lookup checks; `dregg_authority_snapshot_adapter_rejects_spoofed_entity_and_caller_declared_resource`. |
| Startup/readiness fails closed when a snapshot source is required but unavailable/invalid/stale. | Done. | `SECS_DREGG_AUTHORITY_SNAPSHOT_PATH`; `readiness_reports_snapshot_source_status_when_snapshot_adapter_is_enabled`; runtime config snapshot-source tests. |
| Tests cover source outage/cache/freshness and resource-scope rejects. | Done. | `dregg_authority_snapshot_file_source_loads_valid_and_rejects_stale_or_missing`; `dregg_authority_snapshot_cache_fails_closed_when_source_disappears`; wrong-resource tests. |
| Docs distinguish fixture snapshots from live Dregg APIs, production federation, finality, Midnight/Cardano, deployment, and public auditability. | Done. | Non-claims section here, `server/README.md`, `docs/implementation-status.md`, and `CHANGELOG.md`. |
| Live Castalia Dregg API/client discovery. | Out of scope / future follow-up. | #72 closes the bounded fixture/file snapshot seam only; no HTTP/live API, full-node requirement, or finality/revocation proof claim is made. |

## Non-claims

This smoke proves a local Tier 1 consumption seam only. It does not prove:

- live Castalia Dregg API discovery;
- full Dregg node operation per Hub;
- live Dregg revocation/finality proof verification;
- Midnight or Cardano evidence rails;
- production deployment proof;
- public auditability beyond the separate audit-bundle/anchor rails.


## Expected smoke output

The stable evidence lines are:

```text
fixture_ok: secs-dregg-authority-snapshot-v1 did:example:david-lab castalia-demo:david-lab
resource_ok: resource://david-lab/demo-agent controller=did:example:david-lab status=active
redaction_ok: fixture contains no raw secret/private-token markers
smoke_ok: active snapshot accepts the controlled David Lab resource through direct lookup and the evidence adapter; stale, revoked, wrong namespace, wrong resource, missing source, unknown issuer, unsupported schema/mode, duplicate issuer key/resource, wrong trust root, wrong authority root, spoofed subject, and caller-declared resource amplification reject.
```

These lines are suitable for a redacted Tier 1 evidence packet because they expose only fixture identifiers, entity/resource/controller IDs, status, and reason classes. They do not expose private keys, bearer tokens, raw authority tokens, credential bodies, local ledger rows, or production endpoints.
