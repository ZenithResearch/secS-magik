# Credential-summary disclosure boundary (#83)

## Scope

This policy governs the **evidence summary** fields produced for
`membership_credential` / `provisioning_credential` (and the wallet/composite
evidence they compose with) in `server/src/evidence.rs`, and everything those
summaries propagate into: `VerifiedCallContext.evidence_summary` (via
`EvidenceSummary::to_context_fields()`), signed contexts, receipts, and
local/operator ledger inspection.

It is a **local/operator inspection** boundary only. It is **not**:

- public auditability (#37),
- production deployment proof (#33),
- live Castalia Dregg authority source/client (#206), wallet-core parity (#71), or
  Dregg/Midnight/Cardano authority (#73/#74/#75).

It refines — it does not replace — the redaction proof from #70/PR #76 and the
fail-closed descriptor-only runtime guard from #77/PR #85. Accepted
`membership.provision` still requires both wallet proof-of-possession and a
trusted-issuer membership credential.

## Disclosure classes

Every credential-summary field is exactly one of:

- **cleartext** — default local/operator metadata, shown raw.
- **digest** — deterministic SHA-256 fingerprint (`*_sha256:<hex>` or
  `pubkey:sha256:<hex>`); correlatable across receipts, never the raw value.
- **absent** — never present in any default summary, context, receipt, debug
  output, or operator inspection row.

There is no privileged/public export mode in v0; any future one is #37's work
and must be an explicit opt-in, never the default.

## Field-by-field policy

| Field | Class | Rationale |
|---|---|---|
| `evidence_kind` | cleartext | evidence type, not an identity |
| `credential_kind` | cleartext | credential type, not an identity |
| `subject` | cleartext (linkable) | the authenticated provisioning subject; binds authorization and is operator-necessary. Documented as linkable. |
| `audience` | cleartext | the receiver's own audience |
| `operation` | cleartext | receiver-scoped routing metadata |
| `resource` | cleartext | resource/schema descriptor, not an identity |
| `issuer_id` | cleartext | **authority layer** — which trusted issuer approved; a receiver-held trust anchor (already in the receiver's trusted-issuer registry), so not a new disclosure |
| `trust_root_ref` | cleartext | receiver-held trust anchor (in `TrustedIssuerEntry`) |
| `registry_root_ref` | cleartext | receiver-held trust anchor (in `TrustedIssuerEntry`) |
| `status` | cleartext | active / revoked / expired **outcome** |
| `signature_suite` | cleartext | crypto-agility metadata |
| `issued_at`, `expires_at` | cleartext | validity window; operators need it to reason about expiry |
| `local_dev_test_only`, `public_proof` | cleartext | posture booleans |
| `issuer_key_id` | **digest** | issuer public-key fingerprint (`pubkey:sha256:`) |
| `evidence_ref` | **digest** | `evidence_ref_sha256:`; raw ref can carry paths/URLs/tokens |
| `credential_id` | **digest** | `credential_id_sha256:`; an externally-linkable opaque per-credential handle |
| `status_ref` | **digest** | `status_ref_sha256:`; an external status/revocation pointer (can be a URL) |
| `proof` | redacted marker | `proof:redacted_ed25519_signature` |
| raw evidence refs/paths/URLs, bearer tokens, raw signatures, private seeds/keys, raw credential canonical bodies | **absent** | private material; never constructed into a summary |

### Why digest the linkable handles but keep issuer/root cleartext

`credential_id` and `status_ref` are **opaque handles that point outward** — a
credential identifier that recurs across uses, and a status/revocation endpoint
that can be a URL. Digesting them keeps an operator's ability to *correlate* the
same credential across receipt rows (the fingerprint is deterministic) without
exposing a value that can be cross-referenced against external systems.

`issuer_id`, `trust_root_ref`, and `registry_root_ref` are the **authority
anchors the receiver already holds** in its trusted-issuer registry. Showing
them is how an operator sees *which* authority layer approved an operation;
digesting them would remove audit value while disclosing nothing new (the
receiver defined them). They stay cleartext.

## Tests

- `server/tests/production_federated.rs::evidence_summary_redacts_private_material`
  — pins the cleartext set, asserts the digest prefixes
  (`credential_id_sha256:`, `status_ref_sha256:`, `evidence_ref_sha256:`,
  `issuer_key_id:pubkey:sha256:`), and proves the raw `credential_id` /
  `status_ref` values are absent alongside all raw private material.
- `server/tests/production_federated.rs::provisioning_credential_summary_follows_disclosure_taxonomy`
  — same taxonomy for `provisioning_credential`, plus digest determinism.
- `server/tests/production_federated.rs::membership_provision_rejects_remain_inspectable_and_redacted`
  — proves the authority anchors stay cleartext and refs stay digested on the
  composed wallet + membership path.

## Forbidden claims

Local SQLite receipts and operator inspection are **not** public auditability.
This policy does not add deployment proof, public audit/export, live registry
discovery, or any Dregg/Midnight/Cardano authority.
