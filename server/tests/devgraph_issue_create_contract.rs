const CONTRACT: &str = include_str!("../../docs/specs/devgraph-issue-create-v1.md");
const DAG: &str = include_str!("../../docs/plans/2026-08-31-devgraph-issue-create-v1-dag.md");
const DOCS_INDEX: &str = include_str!("../../docs/README.md");
const CHANGELOG: &str = include_str!("../../CHANGELOG.md");

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

#[test]
fn ratified_contract_is_exact_and_p4r_evidence_is_pinned() {
    contains_all(
        "ratified contract status",
        CONTRACT,
        &[
            "Status: operator-ratified P4-O-DG contract; runtime unimplemented",
            "P4-R completed by PR #271 merge",
            "green post-merge Rust CI run `33448400000`",
            "`devgraph.issue.create.v1`",
            "It creates exactly one canonical Devgraph `Issue`",
            "enables DG-P after this contract lands",
            "It is not a generic Work API, HTTP, RPC, tool, prompt, route, or handler",
        ],
    );
    contains_all(
        "registration surfaces",
        DOCS_INDEX,
        &[
            "specs/devgraph-issue-create-v1.md",
            "plans/2026-08-31-devgraph-issue-create-v1-dag.md",
            "Operator-ratified P4-O-DG contract; runtime unimplemented",
        ],
    );
    assert!(
        CHANGELOG.contains("devgraph.issue.create.v1"),
        "the contract reasoning must be recorded in the changelog"
    );
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
            "No runtime source, API route, CLI command, Wallet method",
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
fn dedicated_dag_stays_serialized_after_p4o_ratification() {
    contains_all(
        "stacked DAG",
        DAG,
        &[
            "Status: P4-O-DG ratified; every implementation node remains unimplemented",
            "P4-R -> P4-O-DG -> DG-P -> DG-V -> DG-W -> DG-C -> DG-E",
            "P4-R | Complete via #270/#271",
            "P4-O-DG | Operator-ratified exact contract",
            "DG-P | Next; unimplemented",
            "DG-V | Blocked by DG-P",
            "DG-W | Blocked by DG-V",
            "DG-C | Blocked by DG-W",
            "DG-E | Blocked by DG-C",
            "One node equals one issue and one PR",
            "Devgraph owns Work semantics and `EventReceipt`",
            "`.castaway` is a vault and is not a DAG authority node",
            "There is still no runtime projection",
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
            "DGO --> DGP",
            "DGP --> DGV",
            "DGV --> DGW",
            "DGW --> DGC",
            "DGC --> DGE",
        ],
        "the stacked Devgraph contract must remain one serialized path"
    );
}
