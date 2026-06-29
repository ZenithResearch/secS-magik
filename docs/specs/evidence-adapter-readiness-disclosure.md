# Evidence adapter readiness and disclosure gates

This spec is the shared checklist for new production-facing evidence adapters after the #72 Dregg-shaped snapshot seam. It applies to #71 wallet-core parity, #74 Midnight proof verification, #75 Cardano settlement/finality evidence, and #206 live Castalia Dregg authority source/client.

A future evidence adapter is not implementation-ready until this page's contract is answered in its issue body, local spec, or first docs PR.

## Adapter readiness contract

Every adapter that can satisfy production descriptors must define:

- adapter name as it appears in `SECS_ALLOWED_EVIDENCE_ADAPTERS`;
- evidence kind(s) it can satisfy;
- required config/env when enabled in `production_verified`;
- startup validation behavior before the gateway binds;
- readiness status fields and redaction rules;
- fixture/local/testnet/mainnet/live mode boundary;
- dependency unavailable behavior;
- malformed/stale/expired/wrong-binding behavior;
- whether cached state can be used, and when stale cache must fail closed;
- exact typed reject reasons for missing dependency, invalid input, wrong binding, stale/future data, unsupported version, and insufficient evidence.

Production mode must not silently fall back to local fixtures, caller-provided embedded authority, browser/session state, or proof-shaped labels.

## Disclosure contract

Before adapter runtime wiring, specify redaction-safe summary fields:

- public class/kind labels;
- source mode (`fixture`, `file`, `live`, `testnet`, `mainnet`, etc.);
- stable verifier/source/circuit/network/version ids where safe;
- hashes or fingerprints of opaque evidence refs;
- status/finality/freshness reason classes;
- descriptor-local operation/audience/resource binding result;
- no raw private keys, bearer tokens, wallet secrets, witnesses, signatures when not necessary, full proof bytes, raw credentials, API tokens, local DB rows, or payload bodies.

If an adapter needs raw material to verify, that material must not appear in operator summaries, receipts, runbook examples, CI logs, or issue/PR evidence comments.

## Required docs before code

For each future adapter rail, the first PR should either implement this list or explicitly link to a spec that does:

1. Source of truth / upstream contract.
2. Input schema and canonical bytes or public input layout.
3. Config/readiness surface.
4. Fixture generation process with no real secrets.
5. Happy-path and reject-matrix test plan.
6. Disclosure taxonomy and forbidden claims.
7. Stop conditions for missing upstream contracts or unavailable verifier dependencies.

## Rail-specific notes

### #71 Castalia Wallet wallet-core parity

Define the wallet-core source of truth before changing verifier runtime behavior: repo/path/API, canonical challenge bytes, key-id/public-key-ref semantics, signature suite, and fixture vectors. Browser WalletAuth sessions and extension UX remain outside secS verifier authority unless separately specified.

### #74 Midnight proof verification

Define proof system, statement id, verifying-key source, proof encoding, public input schema, subject/audience/origin/operation/resource binding, freshness/replay fields, and fixture/testnet/production boundary before accepting any Midnight-shaped bytes.

### #75 Cardano settlement/finality evidence

Define network, transaction/block/slot/inclusion/finality model, policy/asset/script binding, verifier/indexer dependency, stale/unavailable-chain behavior, and whether evidence supports authorization or settlement receipt inspection.

### #206 Live Castalia Dregg authority source/client

Define API/client request/response contract, source authentication, timeout/retry/cache behavior, readiness, and mapping into `DreggAuthoritySnapshot` semantics or an explicitly versioned successor. Do not require every normal Hub to run a full Dregg node.

## Non-claims

This spec does not implement any adapter. It prevents future adapter issues from starting runtime work before their readiness and disclosure boundaries are testable.
