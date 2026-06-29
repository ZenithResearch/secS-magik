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
```

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
- the checked-in fixture file loads and produces the same authority decision.

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
smoke_ok: active snapshot accepts the controlled David Lab resource; stale, revoked, wrong namespace, wrong resource, missing source, unknown issuer, unsupported schema/mode, duplicate issuer key/resource, wrong trust root, and wrong authority root reject.
```

These lines are suitable for a redacted Tier 1 evidence packet because they expose only fixture identifiers, entity/resource/controller IDs, status, and reason classes. They do not expose private keys, bearer tokens, raw authority tokens, credential bodies, local ledger rows, or production endpoints.
