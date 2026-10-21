# Standing Work policy v2 — source review candidate

Status: partial / review candidate, 2026-10-20. No installed policy or verifier is changed by this source.

`secs-devgraph-work-policy.v2` (`schema_version: 2`) keeps the exact actor,
operation, resource match, status and deny-precedence model. Each rule replaces
`not_before` and `not_after` with `validity`, a closed
`castalia.grant-validity.v1` value. `dated` requires both bounds;
`until_revoked` has only `not_before`. Missing, null, mixed, duplicate, unsafe
integer and unknown fields are rejected. Until-revoked is explicit, never an
infinite timestamp. Shared portable vectors are in
[vectors/grant-validity-v1.json](vectors/grant-validity-v1.json).

The v1 decoder and canonical bytes remain finite and unchanged. V1 cannot
silently accept validity v2 rules; the policy digest domain is versioned as
`secs-devgraph-work-policy.v2\0`. Receiver binding must pin the resulting
policy ID, version and digest. Any changed source/policy requires a matched
receiver; there is no older-policy fallback or trusted-localhost exception.

A standing rule is reusable authorization, not an immortal signing key or
access token. Request credentials and signed projections retain their existing
short finite expiry, exact request/resource binding, holder signature and
replay contract. Future denies clamp the projected lifetime; current policy
is checked again at authorization. Policy status/revocation still applies.

Owner-local provision/renew/rotate with a v2 policy requires a separate
`--verifier-not-after` future safe-integer timestamp. It cannot be inferred
from an until-revoked grant. Key expiry makes readiness fail even while the
standing rule remains unbounded. V1 rejects the new option and retains its
finite policy-derived key deadline. New key creation, registry installation,
receiver activation and application trust remain separate operator actions.

Coverage: legacy vectors, explicit validity vectors, finite projections from
until-revoked rules, private CLI preflight/presentation/durable replay, and
admin missing/expired verifier-key deadlines. These are source fixture checks;
they do not establish loaded browser, iPad, live graph, deployment or sync
qualification. Devgraph owns hierarchical membership at access time; secS
still admits only its exact native operation/resource ceiling.
