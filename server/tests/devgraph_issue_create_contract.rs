const CONTRACT: &str = include_str!("../../docs/specs/devgraph-issue-create-v1.md");
const DAG: &str = include_str!("../../docs/plans/2026-08-31-devgraph-issue-create-v1-dag.md");
const DOCS_INDEX: &str = include_str!("../../docs/README.md");
const SPECS_INDEX: &str = include_str!("../../docs/specs/README.md");
const PLANS_INDEX: &str = include_str!("../../docs/plans/README.md");
const CURRENT_STATE: &str = include_str!("../../docs/current-state.md");
const IMPLEMENTATION_STATUS: &str = include_str!("../../docs/implementation-status.md");
const ROOT_README: &str = include_str!("../../README.md");
const CHANGELOG: &str = include_str!("../../CHANGELOG.md");
const CANONICALIZATION_BOUNDARIES: &str =
    include_str!("fixtures/devgraph_issue_create_v1/canonicalization-boundaries.json");
const PRODUCER_REFERENCE: &str =
    include_str!("../../docs/reference/devgraph-issue-create-v1-producer.md");
const PRODUCER_SOURCE: &str = include_str!("../src/devgraph_authority.rs");
const IDENTITY_SOURCE: &str = include_str!("../src/identity.rs");
const SCHEMA_SOURCE: &str = include_str!("../src/schema.rs");
const FIXTURE_MANIFEST: &str = include_str!("fixtures/devgraph_issue_create_v1/manifest.json");

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write;

fn contains_all(name: &str, text: &str, required: &[&str]) {
    let normalized_text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    for item in required {
        let normalized_item = item.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            normalized_text.contains(&normalized_item),
            "{name} must define `{item}`"
        );
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[test]
fn ratified_contract_is_exact_and_p4r_evidence_is_pinned() {
    contains_all(
        "ratified contract status",
        CONTRACT,
        &[
            "Status: P4-O-DG and P4-O-DG-R1 merged; DG-P producer implemented on the #281 branch; consumers unimplemented",
            "P4-R completed by PR #271 merge",
            "green post-merge Rust CI run `33448400000`",
            "PR #280 merged this operator-ratified contract at `bfe1a453`",
            "`devgraph.issue.create.v1`",
            "It creates exactly one canonical Devgraph `Issue`",
            "DG-P now implements only the secS producer",
            "It is not a generic Work API, HTTP, RPC, tool, prompt, route, or handler",
        ],
    );
    contains_all(
        "registration surfaces",
        DOCS_INDEX,
        &[
            "specs/devgraph-issue-create-v1.md",
            "plans/2026-08-31-devgraph-issue-create-v1-dag.md",
            "P4-O-DG-R1 merged; DG-P producer implemented on #281",
            "reference/devgraph-issue-create-v1-producer.md",
        ],
    );
    assert!(
        CHANGELOG.contains("P4-O-DG-R1 / #282")
            && CHANGELOG.contains("devgraph.issue.create.v1")
            && CHANGELOG.contains("cross-language request/projection digest divergence"),
        "the safe-integer repair and its reason must be recorded in the changelog"
    );
    contains_all(
        "repair status surfaces",
        &[
            ROOT_README,
            CURRENT_STATE,
            IMPLEMENTATION_STATUS,
            SPECS_INDEX,
            PLANS_INDEX,
        ]
        .join("\n"),
        &[
            "P4-O-DG-R1",
            "9007199254740991",
            "RFC 8785",
            "merge/post-merge",
            "DG-P",
        ],
    );
}

#[test]
fn p4o_dg_r1_pins_rfc8785_safe_integers_and_rejects_the_old_wide_domain() {
    contains_all(
        "safe-integer repair",
        CONTRACT,
        &[
            "P4-O-DG-R1 / Issue #282, before DG-P",
            "MAX_SAFE_INTEGER = 9007199254740991",
            "MIN_SAFE_INTEGER = -9007199254740991",
            "`-9007199254740991..=9007199254740991`",
            "`0..=MAX_SAFE_INTEGER`",
            "Wallet proof or presentation",
            "receiver-policy input or decision",
            "unsigned authority projection",
            "full signed authority projection",
            "ECMAScript's number serialization model",
            "IEEE-754 binary64",
            "reject an out-of-range number before canonicalization",
            "RFC 8785 does not normalize JSON strings",
            "object-property sorting does not reorder arrays",
            "canonicalization-boundaries.json",
            "The fixture file is a manifest, not a signing preimage",
            "independently apply RFC 8785",
        ],
    );
    assert!(
        !CONTRACT.contains("signed 64-bit JSON integer"),
        "the original unrestricted i64 request claim must be removed"
    );
    assert!(
        !CONTRACT.contains("within unsigned 64-bit range"),
        "the original unrestricted u64 projection claim must be removed"
    );
}

#[test]
fn committed_canonicalization_vectors_pin_boundaries_escapes_order_and_no_normalization() {
    let vectors: Value = serde_json::from_str(CANONICALIZATION_BOUNDARIES)
        .expect("canonicalization boundary fixture must be valid JSON");
    assert_eq!(
        vectors["schema"],
        "secs-devgraph-issue-create-canonicalization-boundaries-v1"
    );
    assert_eq!(vectors["operation"], "devgraph.issue.create.v1");
    assert_eq!(
        vectors["minimum_safe_integer"].as_i64(),
        Some(-9_007_199_254_740_991)
    );
    assert_eq!(
        vectors["maximum_safe_integer"].as_u64(),
        Some(9_007_199_254_740_991)
    );

    let domain = vectors["request_digest_domain_separator"]
        .as_str()
        .expect("digest domain separator must be a string");
    assert_eq!(domain.as_bytes().last(), Some(&0));

    let accepted = vectors["request_accept"]
        .as_array()
        .expect("request_accept must be an array");
    for case in accepted {
        let canonical = case["canonical_json_utf8"]
            .as_str()
            .expect("accepted case must contain canonical JSON");
        let recanonicalized = serde_json::to_string(&case["materialized_request"])
            .expect("the strict request subset must reserialize");
        assert_eq!(
            recanonicalized, canonical,
            "materialized request must independently recanonicalize for {}",
            case["name"]
        );
        let decoded: Value =
            serde_json::from_str(canonical).expect("canonical JSON must decode as strict JSON");
        assert_eq!(
            decoded, case["materialized_request"],
            "canonical bytes must decode to the materialized request for {}",
            case["name"]
        );
        assert!(
            !canonical.contains(": ") && !canonical.contains(", "),
            "canonical JSON must not contain structural whitespace for {}",
            case["name"]
        );
        let digest = lowercase_hex(&Sha256::digest(
            [domain.as_bytes(), canonical.as_bytes()].concat(),
        ));
        assert_eq!(digest, case["request_digest_sha256"]);
    }

    let by_name = |name: &str| {
        accepted
            .iter()
            .find(|case| case["name"] == name)
            .expect("named accepted vector must exist")
    };
    assert_eq!(
        by_name("priority-min-control-array-order")["materialized_request"]["priority"].as_i64(),
        Some(-9_007_199_254_740_991)
    );
    assert_eq!(
        by_name("priority-max")["materialized_request"]["priority"].as_u64(),
        Some(9_007_199_254_740_991)
    );

    let controls = by_name("priority-min-control-array-order")["canonical_json_utf8"]
        .as_str()
        .expect("control vector must contain canonical JSON");
    for escape in ["\\u0000", "\\b", "\\t", "\\n", "\\f", "\\r", "\\\"", "\\\\"] {
        assert!(
            controls.contains(escape),
            "missing canonical escape {escape}"
        );
    }
    assert!(
        controls.contains("slash:/"),
        "solidus must remain unescaped"
    );
    assert!(
        !controls.contains("slash:\\/"),
        "solidus must not be escaped"
    );

    let nfc = by_name("unicode-nfc");
    let nfd = by_name("unicode-nfd");
    assert_eq!(nfc["title_code_points"], serde_json::json!(["U+00E9"]));
    assert_eq!(
        nfd["title_code_points"],
        serde_json::json!(["U+0065", "U+0301"])
    );
    assert_ne!(
        nfc["canonical_json_utf8"], nfd["canonical_json_utf8"],
        "RFC 8785 must not normalize distinct Unicode sequences"
    );
    assert_ne!(nfc["request_digest_sha256"], nfd["request_digest_sha256"]);

    let za = by_name("array-order-z-a");
    let az = by_name("array-order-a-z");
    assert_ne!(za["materialized_request"], az["materialized_request"]);
    assert_ne!(za["canonical_json_utf8"], az["canonical_json_utf8"]);
    assert_ne!(za["request_digest_sha256"], az["request_digest_sha256"]);

    let rejected = vectors["request_reject"]
        .as_array()
        .expect("request_reject must be an array");
    assert_eq!(
        rejected[0]["priority"].as_i64(),
        Some(-9_007_199_254_740_992)
    );
    assert_eq!(
        rejected[1]["priority"].as_u64(),
        Some(9_007_199_254_740_992)
    );
    assert!(rejected
        .iter()
        .all(|case| case["reason"] == "priority_out_of_safe_integer_range"));

    let max = 9_007_199_254_740_991_u64;
    for case in vectors["canonical_nonnegative_integer_accept"]
        .as_array()
        .expect("accepted nonnegative cases must be an array")
    {
        assert!(case["integers"]
            .as_object()
            .expect("accepted integer set must be an object")
            .values()
            .all(|value| value.as_u64().is_some_and(|integer| integer <= max)));
    }
    for case in vectors["canonical_nonnegative_integer_reject"]
        .as_array()
        .expect("rejected nonnegative cases must be an array")
    {
        assert_eq!(case["value"].as_u64(), Some(max + 1));
        assert_eq!(case["reason"], "canonical_integer_out_of_safe_range");
    }
}

#[test]
fn operation_resource_and_request_digest_are_exact() {
    contains_all(
        "operation contract",
        CONTRACT,
        &[
            "| Operation ID | `devgraph.issue.create.v1` |",
            "| Devgraph operation | `create_work_object` |",
            "| Work kind | exactly `Issue` |",
            "| Resource | exactly `Issue/<id>`",
            "`devgraph.write`",
            "`If-Match` is not part of create",
            "^[a-z0-9](?:[a-z0-9-]{0,254}[a-z0-9])?$",
            "RFC 8785 JSON Canonicalization Scheme",
            "devgraph.issue.create.request.v1\\0",
            "request_digest_sha256",
            "including `kind`",
            "Unknown or duplicate JSON object fields reject",
            "at most 65,536 bytes",
        ],
    );
    for field in [
        "artifact_ids",
        "description",
        "external_link_ids",
        "id",
        "kind",
        "priority",
        "title",
    ] {
        assert!(
            CONTRACT.contains(&format!("\"{field}\"")),
            "strict request must contain {field}"
        );
    }
}

#[test]
fn actor_idempotency_and_portable_projection_are_fully_bound() {
    contains_all(
        "actor and idempotency",
        CONTRACT,
        &[
            "actor_id = \"pubkey:sha256:\"",
            "actor_signature_suite = \"Ed25519\"",
            "idempotency_key_digest_sha256",
            "SHA-256(UTF8(exact_idempotency_key))",
            "16 through 128 ASCII",
            "[A-Za-z0-9._~-]",
            "receiver-owned policy",
            "necessary but not sufficient",
        ],
    );
    contains_all(
        "portable projection",
        CONTRACT,
        &[
            "strict UTF-8 JSON, not Rust `bincode`",
            "secs-devgraph-authority.v1",
            "secs-devgraph-authority.v1/signature\\0",
            "RFC8785_JCS(unsigned_projection)",
            "secs_authority_projection_digest_sha256",
            "actor_id",
            "audience",
            "operation",
            "resource",
            "request_digest_sha256",
            "idempotency_key_digest_sha256",
            "session_id",
            "nonce",
            "issued_at",
            "expires_at",
            "receiver_policy_id",
            "receiver_policy_version",
            "receiver_policy_digest_sha256",
            "secs_context_id",
            "secs_verifier_key_id",
            "secs_verifier_signature_suite",
            "secs_verifier_signature",
            "wallet_presentation_digest_sha256",
        ],
    );
}

#[test]
fn producer_hardening_and_v1_interoperability_erratum_are_pinned() {
    contains_all(
        "v1 compatibility erratum",
        CONTRACT,
        &[
            "V1 canonical-integer compatibility erratum",
            "`-9007199254740991..=9007199254740991`",
            "`0..=9007199254740991`",
            "raw request is at most 131,072 bytes before JSON parsing",
            "raw Wallet presentation is at most 16,384 bytes",
            "Raw receiver-policy JSON is at most 262,144 bytes",
            "raw projection is at most 16,384 bytes",
            "UTF-8 strings are not Unicode-normalized",
            "array order remains significant",
        ],
    );
    contains_all(
        "producer hardening",
        PRODUCER_REFERENCE,
        &[
            "Raw receiver-policy JSON is capped at 262,144 bytes",
            "separately configured receiver-owned public-key registry",
            "opaque typed `devgraph.issue.create.v1` projection preimage",
            "there is no arbitrary-byte or suffix signing seam",
            "database `CHECK`",
            "selected and compared on retry",
            "without trimming",
        ],
    );
    for required in [
        "DEVGRAPH_ISSUE_CREATE_MAX_REQUEST_JSON_BYTES_V1",
        "DEVGRAPH_WALLET_PRESENTATION_MAX_JSON_BYTES_V1",
        "DEVGRAPH_ISSUE_CREATE_POLICY_MAX_JSON_BYTES_V1",
        "DEVGRAPH_AUTHORITY_PROJECTION_MAX_JSON_BYTES_V1",
        "DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1",
        "DevgraphAuthoritySignaturePreimageV1",
        ".verify_strict(",
        "verifier_registry: &PublicVerifierKeyRegistry",
    ] {
        assert!(PRODUCER_SOURCE.contains(required), "missing {required}");
    }
    assert!(IDENTITY_SOURCE.contains("require_devgraph_authority_signer_v1"));
    assert!(IDENTITY_SOURCE.contains("DevgraphAuthoritySignaturePreimageV1"));
    assert!(!IDENTITY_SOURCE.contains(
        "preimage.starts_with(crate::devgraph_authority::DEVGRAPH_AUTHORITY_SIGNATURE_DOMAIN_V1)"
    ));
    assert!(SCHEMA_SOURCE.contains("CHECK(replay_scope = 'session:operation:nonce')"));
    contains_all(
        "cross-language manifest",
        FIXTURE_MANIFEST,
        &[
            "secs-devgraph-issue-create-fixture-bundle.v1",
            "expected_now",
            "idempotency-key.txt",
            "receiver-policy.json",
            "receiver-policy-binding.json",
            "secs-public-key-registry.json",
            "canonical-request-nondefault.json",
            "canonicalization-boundaries.json",
            "without normalization",
        ],
    );
}

#[test]
fn freshness_expiry_and_replay_fail_closed_at_the_exact_boundary() {
    contains_all(
        "freshness contract",
        CONTRACT,
        &[
            "`issued_at < expires_at`",
            "at most 60 seconds",
            "`issued_at <= now < expires_at`",
            "`now >= expires_at` rejects as expired",
            "future-issued projection",
            "session:operation:nonce",
            "Clock-read failure rejects",
            "performs no second mutation",
            "idempotency conflict",
        ],
    );
}

#[test]
fn devgraph_owns_work_and_receipts_are_correlated_without_secrets() {
    contains_all(
        "ownership and handoff",
        CONTRACT,
        &[
            "Devgraph independently verifies",
            "Devgraph derives exactly `devgraph.write`",
            "secS never owns Work lifecycle",
            "Success means Devgraph atomically persists the `Issue`",
            "canonical `EventReceipt`",
            "Verification acceptance or a secS verify receipt alone is not Work success",
            "secs_context_id",
            "secs_verifier_key_id",
            "secs_authority_projection_digest_sha256",
            "The raw idempotency key",
            "do not enter receipt or log projections",
            "If required Devgraph or secS receipt persistence fails, no successful execution response exists",
        ],
    );
}

#[test]
fn contract_forbids_generic_routes_bypasses_and_castaway_authority() {
    contains_all(
        "non-ratifications",
        CONTRACT,
        &[
            "No generic Work API or machine-operation multiplexer is ratified",
            "No arbitrary route, URL, path, method, header, handler, opcode",
            "No reusable bearer token, OAuth flow, trusted-localhost exception",
            "direct Neo4j access",
            "`.castaway` grants no identity or authority",
            "No API route, CLI command, Wallet method, manifest descriptor, handler, Devgraph consumer",
        ],
    );
    contains_all(
        "authority boundary",
        CONTRACT,
        &[
            "`.castaway` is a protected vault",
            "It is not the identity, signer, wallet",
            "credential, trust root, authority projection, or gateway",
            "caller cannot supply a URL, origin, path, method, header name/value, redirect, proxy, handler ID, opcode",
        ],
    );
}

#[test]
fn wallet_v1_is_ed25519_only_and_pq_requires_v2() {
    contains_all(
        "Wallet compatibility",
        CONTRACT,
        &[
            "Version 1 uses the Wallet root's Ed25519 public key and signature only",
            "compatible with the Ed25519 half of Wallet's one-root Dregg hybrid",
            "It is not hybrid or post-quantum authorization",
            "ML-DSA-65",
            "new `devgraph.issue.create.v2` contract",
            "cannot be inferred from, appended to, or relabeled as v1",
        ],
    );
}

#[test]
fn producer_reference_pins_consumable_vectors_and_no_route_boundary() {
    contains_all(
        "DG-P producer reference",
        PRODUCER_REFERENCE,
        &[
            "Status: DG-P implemented in secS",
            "devgraph.issue.create.wallet-presentation.v1",
            "devgraph.issue.create.wallet-presentation.v1/signature\\0",
            "secs-devgraph-issue-create-policy.v1",
            "`(session_id, operation, nonce)`",
            "request.json",
            "canonical-request.json",
            "manifest.json",
            "canonicalization-boundaries.json",
            "receiver-policy.json",
            "secs-public-key-registry.json",
            "idempotency-key.txt",
            "Unicode/escaping/negative-priority",
            "wallet-presentation.json",
            "unsigned-projection.json",
            "signed-projection.json",
            "correlation-digest.txt",
            "It is not an ingress route, gateway descriptor, opcode, handler",
            "Hybrid Ed25519 + ML-DSA-65 authorization requires a separately ratified v2",
        ],
    );
}

#[test]
fn dedicated_dag_stays_serialized_after_p4o_dg_r1_and_dg_p() {
    contains_all(
        "stacked DAG",
        DAG,
        &[
            "Status: P4-O-DG-R1 merged; DG-P implemented on the #281 branch with merge/green-CI evidence pending; downstream nodes blocked",
            "P4-R -> P4-O-DG -> P4-O-DG-R1 -> DG-P -> DG-V -> DG-W -> DG-C -> DG-E",
            "P4-R | Complete via #270/#271",
            "P4-O-DG | Operator-ratified exact contract",
            "P4-O-DG-R1 | Complete via #282 / merged PR #283",
            "DG-P | Implemented on the #281 branch; merge/green-CI evidence pending",
            "DG-V | Blocked by DG-P merge and green CI",
            "DG-W | Blocked by DG-V",
            "DG-C | Blocked by DG-W",
            "DG-E | Blocked by DG-C",
            "One node equals one issue and one PR",
            "Devgraph owns Work semantics and `EventReceipt`",
            "`.castaway` is a vault and is not a DAG authority node",
            "There is still no Devgraph verifier or Work mutation",
        ],
    );

    let edges: Vec<_> = DAG
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("-->"))
        .collect();
    assert_eq!(
        edges,
        [
            "P4R --> DGO",
            "DGO --> DGOR1",
            "DGOR1 --> DGP",
            "DGP --> DGV",
            "DGV --> DGW",
            "DGW --> DGC",
            "DGC --> DGE",
        ],
        "the stacked Devgraph contract must remain one serialized path"
    );
}
