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
cargo test -p server --test dregg_authority_registry dregg_authority_snapshot -- --nocapture
```

The smoke covers:

- active fixture snapshot accepts `did:example:david-lab` for `resource://david-lab/demo-agent`;
- matched resource scope is `resource://david-lab/*`, not a hardcoded Zenith path;
- stale snapshot rejects;
- revoked issuer/resource status rejects;
- wrong namespace rejects;
- wrong resource rejects;
- the checked-in fixture file loads and produces the same authority decision.

## Non-claims

This smoke proves a local Tier 1 consumption seam only. It does not prove:

- live Castalia Dregg API discovery;
- full Dregg node operation per Hub;
- live Dregg revocation/finality proof verification;
- Midnight or Cardano evidence rails;
- production deployment proof;
- public auditability beyond the separate audit-bundle/anchor rails.
