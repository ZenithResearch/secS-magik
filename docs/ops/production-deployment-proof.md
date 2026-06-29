# Production deployment proof profile (#33)

Status: **planned / contract-only**. This document defines the first evidence packet required before anyone can claim that secS-magik is deployed in production. It does **not** claim a deployed service exists today.

Profile name: `secs-gateway-production-v1`

## Purpose

The existing `production_verified` runtime mode and `scripts/production-gateway-smoke.sh` prove local production-shaped startup checks. They do not prove a production service is deployed, reachable, supervised, configured with operator-owned keys, or healthy on an operator host. This profile is the minimum deployment-proof checklist for promoting a real `secs-gateway` instance from local source readiness to deployed production authority.

## Evidence levels

| Level | What it proves | Required evidence | Non-claim |
|---|---|---|---|
| source build | The repository builds the intended binary from a known revision. | Git commit SHA, clean `cargo build -p server --bin secs-gateway` output, CI run URL if available. | Does not prove any host is running it. |
| local smoke | The real gateway binary can start locally with explicit fixture-only config and reject malformed/oversized input. | `./scripts/production-gateway-smoke.sh` output from an ephemeral machine-local environment. | `scripts/production-gateway-smoke.sh is fixture-only local smoke`; it is not deployed production. |
| deployed runtime | A named host/service manager runs the expected artifact with operator-owned config and passes readiness checks. | Host/service identifier, service manager status, deployed artifact/source version, config source fingerprint, readiness endpoint/CLI output, and timestamp. | Does not by itself prove production authority unless trust inputs are real and non-fixture. |
| production authority | The deployed runtime is bound to non-fixture operator identities, trust registries, caller registries, evidence-adapter config, ledger path, and no-secret handling. | Redacted config summary, key ids/fingerprints, registry fingerprints/status counts, enabled adapter readiness, receipt/ledger health, and operator sign-off. | Does not prove live Dregg/Midnight/Cardano/wallet-core parity unless those rails are separately implemented and verified. |

## Required deployment-proof packet

A `secs-gateway-production-v1` deployment packet must include:

1. **artifact/source version**
   - repository URL and commit SHA;
   - build command and binary path;
   - CI run URL or local build transcript;
   - checksum of the deployed artifact when available.
2. **config source**
   - named config mechanism: systemd environment file, launchd plist/env, container secret mount, or equivalent;
   - redacted `SECS_*` runtime summary;
   - explicit `SECS_RUNTIME_MODE=production_verified`;
   - config file fingerprints for trust registry, caller registry, Dregg/live-adapter inputs, tunnel keys, and ledger path when enabled;
   - no raw private keys, bearer tokens, wallet secrets, production packet captures, or unredacted credentials.
3. **service manager/host target**
   - host identifier or deployment environment name;
   - service manager (`systemd`, `launchd`, container orchestrator, or equivalent);
   - bind address / listener exposure policy;
   - restart policy and log destination.
4. **health/readiness check**
   - startup-readiness result after bind;
   - trust registry and caller registry readiness;
   - ledger open/read-write check;
   - enabled evidence-adapter readiness and stale/unavailable status;
   - malformed and unauthorized request reject proof without leaking payloads or secrets.
5. **rollback**
   - previous artifact/source version;
   - command or operator runbook to stop the new service and restore the previous version/config;
   - verification that rollback preserves or safely migrates ledger state.
6. **no-secret handling**
   - keys loaded from operator-controlled secret storage or private files with restrictive permissions;
   - proof packet may expose only key ids, public-key fingerprints, registry fingerprints, counts, statuses, and redacted paths;
   - logs and receipts must not print raw private key material, bearer tokens, wallet session state, or raw proof/private witness material.

## Minimum runbook

```bash
# 1. Record source/build evidence.
git rev-parse HEAD
git status --short --branch
cargo build -p server --bin secs-gateway

# 2. Run the local fixture-only smoke as a source-level regression gate.
./scripts/production-gateway-smoke.sh

# 3. On the operator host, inspect the service manager state.
# Example only; use the real service manager for the deployment target.
systemctl status secs-gateway
journalctl -u secs-gateway --since "15 minutes ago"

# 4. Capture redacted runtime readiness/config evidence.
# Use an operator-local command or endpoint that reports readiness without secrets.
# The packet must include runtime mode, registry readiness, ledger readiness, and adapter readiness.
```

The runbook intentionally separates local smoke from deployed runtime proof. A passing local smoke is necessary source-level evidence, but it is not sufficient deployment proof.

## Acceptance checklist

- [ ] Artifact/source version recorded.
- [ ] Config source and `production_verified` runtime mode recorded with redacted `SECS_*` summary.
- [ ] Service manager/host target recorded.
- [ ] Health/readiness check proves the deployed service state, not only a local binary start.
- [ ] Operator key/trust config is non-fixture and fails closed if missing.
- [ ] Rollback path names previous version/config and ledger handling.
- [ ] No-secret handling is documented and followed.
- [ ] Local smoke remains described as fixture-only local smoke, not production deployment.

## Forbidden claims

Do not claim:

- the fixture-only local smoke script as evidence of a live deployed production service;
- fixture-only local smoke as production deployment;
- local production-shaped smoke as deployed runtime;
- production deployment from CI alone;
- production authority from fixture trust registries, fixture caller registries, or local/dev identities;
- live Castalia Dregg, Midnight, Cardano, wallet-core parity, or public audit guarantees from this deployment-proof profile.

## Stop conditions

Stop before claiming production deployment if any of these are true:

- the deployed host/service manager target is not named;
- the artifact/source version cannot be tied to a commit or checksum;
- config evidence would require exposing secrets;
- operator key/trust/caller registry inputs are missing, fixture-only, or unreadable;
- readiness proves only process start, not registry/ledger/evidence-adapter readiness;
- rollback would lose or corrupt ledger state without an explicit operator decision.
