# Live Castalia Dregg source/client contract (#206)

Status: specification plus no-network config/readiness, typed decision-helper, source-authentication, and transport-seam slices. This document defines `secs-dregg-live-source-client-v1`; runtime config now recognizes `dregg_live_source` and the reserved `SECS_DREGG_LIVE_SOURCE_*` knobs, startup readiness fail-closes on missing/unreadable local credential configuration, and `server::dregg_live_source` pins the request/response/cache/source-signature/transport-seam semantics with in-memory tests. It still does not implement an HTTP client, make live network calls, wire live responses into verification, or close #206 by itself.

## Purpose

The first live Castalia Dregg source/client slice defines the deterministic API contract that secS-magik may consume to replace or augment the file-backed `secs-dregg-authority-snapshot-v1` authority source. The contract preserves the existing receiver-held authority boundary: caller-supplied refs remain evidence inputs only until they match receiver-configured live source trust state.

This is not a full Dregg node requirement, not production deployment proof, not public auditability, not Midnight, not Cardano, and not live Dregg finality/proof verification beyond the separately implemented bounded proof verifier rails.

## Contract name and version

- Contract id: `secs-dregg-live-source-client-v1`
- Owning receiver mode: secS `production_verified` when explicitly configured
- Mapping target: existing `DreggAuthoritySnapshot` lookup semantics unless a later PR introduces a versioned successor with migration tests
- Compatibility boundary: additive docs/spec contract plus no-network typed helper module; no runtime network calls are implied until a later code PR adds an HTTP/signed-request client, source authentication, and verification-path wiring

## Configuration surface

A later implementation PR must add explicit, fail-closed runtime config. The names below are reserved by this contract:

- `SECS_DREGG_LIVE_SOURCE_URL`: base URL for the receiver-approved live Castalia Dregg authority source.
- `SECS_DREGG_LIVE_SOURCE_AUTH_TOKEN_PATH`: owner-private file containing the bearer or signed-request credential for the live source. The token value must never be printed, committed, included in receipts, or exposed by readiness output.
- `SECS_DREGG_LIVE_SOURCE_TIMEOUT_MS`: per-request timeout.
- `SECS_DREGG_LIVE_SOURCE_RETRY_MAX`: bounded retry count for transport failures only.
- `SECS_DREGG_LIVE_SOURCE_CACHE_TTL_SECONDS`: maximum age for fresh cache reuse.
- `SECS_DREGG_LIVE_SOURCE_STALE_MAX_SECONDS`: maximum authoritative status age allowed by policy; exceeding it must reject rather than warn.

If the live source adapter is enabled in `production_verified`, missing URL/auth/timeout/cache policy must fail readiness. There must be no fixture fallback and no implicit network call when only the local snapshot path is configured.

## Request fields

Every request fields set must bind the live lookup to the verified secS context and receiver-held policy:

| Field | Requirement |
|---|---|
| `contract_version` | Must equal `secs-dregg-live-source-client-v1`. |
| `receiver_audience` | Must equal the configured secS receiver audience. |
| `entity_ref` | Canonical entity/namespace being authorized. |
| `resource_ref` | Canonical resource or resource prefix requested by the verified operation. |
| `operation` | Receiver-local operation descriptor name, e.g. `membership.provision`. |
| `opcode` | Decimal `u8` opcode from the active receiver manifest. |
| `subject` | Authenticated caller / verified subject from secS context, not caller-declared authority. |
| `issuer_key_id` | Optional hint only; accepted authority still comes from live response plus receiver trust policy. |
| `authority_root_ref` | Optional hint only; wrong root rejects and caller-provided roots cannot create authority. |
| `validation_time` | Receiver-known validation instant used for freshness/status decisions. |
| `request_nonce` | Receiver-generated nonce for traceability/replay correlation at the source boundary. |

The client must not send raw encrypted payloads, private keys, bearer tokens, wallet secrets, or raw proof bodies as request fields.

## Response fields

Every response fields set must be deterministic enough to map into `DreggAuthoritySnapshot` semantics:

| Field | Requirement |
|---|---|
| `contract_version` | Must equal `secs-dregg-live-source-client-v1`. |
| `source_id` | Stable live source identifier for operator diagnostics. |
| `source_key_id` | Stable receiver-trusted live source signing key id; wrong or missing key ids reject before mapping to authority. |
| `source_status` | `active`, `degraded`, or `unavailable`; only `active` may satisfy production readiness. |
| `entity_ref` / `resource_ref` | Must match the request after canonicalization; wrong entity/namespace/resource rejects. |
| `issuer_key_id` / `issuer_status` | Issuer identity and status; revoked/inactive issuer/resource rejects. |
| `authority_root_ref` / `root_fingerprint` / `root_status` | Receiver-trusted root identity and status; wrong root rejects. |
| `namespace_status` / `resource_status` | Per-namespace/resource status with active/revoked/inactive semantics. |
| `status_observed_at` | Source-observed status time used for freshness/status semantics. |
| `valid_from` / `valid_until` | Authority validity window, bounded by receiver policy. |
| `snapshot_generation` | Monotonic/source generation or opaque digest for cache replacement. |
| `duplicate_policy` | Explicit result if duplicate issuer/resource entries are detected; duplicates reject unless the source returns a deterministic conflict status. |
| `redacted_summary` | Operator-safe refs/fingerprints/status only; no bearer tokens or raw proof material. |
| `response_signature` | Ed25519 signature over the request/response binding payload, including contract version, receiver audience, operation, opcode, entity/resource, subject, nonce, source id/key id, status fields, validity window, generation, duplicate policy, and redacted summary. |

A malformed response, unsupported contract version, missing required field, duplicate issuer/resource conflict, stale response, or wrong binding must reject with typed failures.

## Authentication

The live source must be authenticated as a receiver-approved authority source before any response can influence verification.

Current no-network helper posture:

- `DreggLiveSourceTrustedKey` holds the receiver-configured `source_id`, `source_key_id`, active flag, and Ed25519 verifying key.
- `DreggLiveSourceResponse::signature_payload(...)` builds deterministic length-prefixed bytes over the source response and the request binding fields.
- `validate_live_source_response(..., Some(trusted_key))` rejects wrong source id, wrong source key id, inactive/unconfigured trust, malformed signature length, bad signature, and request/response rebinding as `UnauthorizedSource`.
- `execute_live_source_lookup(...)` requires auth material and a trusted source key before calling the transport seam, so missing trust cannot trigger a live adapter call.

Minimum remaining authentication posture for implementation:

1. Load source credentials from `SECS_DREGG_LIVE_SOURCE_AUTH_TOKEN_PATH` or a stricter signed-request mechanism.
2. Require HTTPS or an explicitly documented local test transport that cannot be enabled in `production_verified`.
3. Bind request authentication to `contract_version`, `receiver_audience`, `operation`, `opcode`, `entity_ref`, `resource_ref`, `subject`, and `request_nonce`.
4. Redact credentials from logs, receipts, readiness, error strings, and operator summaries.
5. Fail closed on missing credential, missing trusted source key, wrong source identity/key id, unauthorized source response, or replayed/rebound source response.

## Freshness/status semantics

Freshness/status semantics are authority decisions, not observability only:

- `validation_time - status_observed_at` must be within receiver policy.
- Future timestamps reject instead of satisfying freshness.
- `source_status != active` cannot satisfy live production readiness.
- `issuer_status`, `root_status`, `namespace_status`, and `resource_status` must all be active for acceptance.
- Revoked/inactive issuer/resource/root decisions reject with typed reason codes.
- Stale response and stale cache states reject in `production_verified`; they may be visible in readiness as not ready.

## Timeout/retry/cache policy

The timeout/retry/cache policy must be deterministic and bounded:

- A live source outage rejects once the fresh cache window is exceeded.
- Transport timeout may retry up to `SECS_DREGG_LIVE_SOURCE_RETRY_MAX`; semantic rejects must not be retried as if transient.
- The no-network `DreggLiveSourceTransport` seam requires explicit auth material before any adapter call and distinguishes disabled transport, missing auth material, timeout, source-unavailable, unauthorized-source, malformed-response, and semantic validation rejects.
- Fresh cache use is allowed only when the cache entry matches the same entity/resource/operation/opcode/subject/root binding and is within `SECS_DREGG_LIVE_SOURCE_CACHE_TTL_SECONDS`.
- Stale cache fail closed: stale cache may support diagnostics, but cannot authorize production calls.
- Cache replacement must prefer newer `snapshot_generation` / status timestamp and must reject duplicate issuer/resource ambiguity.

## Mapping to `DreggAuthoritySnapshot`

Until a versioned successor is approved, the live source maps into `DreggAuthoritySnapshot` semantics as receiver-held authority state:

- entity/namespace/resource rows map to snapshot authority entries;
- issuer/root/status/freshness fields map to the same fail-closed lookup checks used by file snapshots;
- request subject/resource hints never widen authority beyond the live/source-provided and receiver-trusted snapshot state;
- live source summaries must identify `source_kind:live_castalia_dregg` so operators can distinguish them from fixture/file snapshot evidence.

## Failure matrix

Runtime work must keep these cases tested before claiming #206 implementation. The current helper slice covers the deterministic in-memory decision/cache cases; transport/authentication/readiness wiring remains future work.

| Case | Required result |
|---|---|
| live source outage | Reject or readiness-not-ready; no local fixture fallback. |
| timeout after bounded retry | Reject with typed timeout/source-unavailable reason. |
| malformed response | Reject before mapping to authority. |
| stale response | Reject as stale. |
| wrong entity/namespace/resource | Reject as wrong binding/resource. |
| wrong root | Reject as wrong root. |
| revoked/inactive issuer/resource | Reject with revoked/inactive status. |
| duplicate issuer/resource | Reject unless deterministic conflict policy returns a typed reject. |
| missing authentication | Reject/readiness failure without printing the secret path contents. |
| missing source trust or bad source signature | Reject as unauthorized source before authority mapping; do not make or continue a transport call when trust config is absent. |
| disabled live adapter | Do not call network; continue using only explicitly configured non-live sources. |

## Readiness and disclosure

Readiness reports may show:

- contract id/version;
- source URL host/path without credentials;
- source status (`ready`, `not_ready`, `degraded`, `unavailable`);
- last successful status timestamp;
- cache freshness age;
- redacted source id / fingerprint.

Readiness reports must not show auth token contents, raw proof material, private keys, or bearer-token-bearing URLs.

## Non-goals and forbidden claims

This contract does not claim that:

- secS-magik mints or owns Castalia credentials;
- secS-magik replaces the Castalia registry or nameserver;
- normal Hubs must operate Dregg consensus infrastructure;
- #206 implements live Dregg finality, Midnight proofs, Cardano settlement, public auditability, or production deployment proof;
- local fixture/file snapshots are production live Dregg source evidence.

## Stop condition before runtime

Stop before runtime implementation if the Castalia Dregg API cannot provide deterministic request/response fields, source authentication, freshness/status timestamps, duplicate handling, and fail-closed outage semantics matching this contract.
