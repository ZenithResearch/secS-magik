const CONTRACT: &str = include_str!("../../docs/specs/secs-hermes-peer-chat-contract.md");
const DAG: &str = include_str!("../../docs/plans/2026-07-18-secs-hermes-peer-chat-dag.md");
const STATUS: &str = include_str!("../../docs/implementation-status.md");
const SPECS_INDEX: &str = include_str!("../../docs/specs/README.md");
const PLANS_INDEX: &str = include_str!("../../docs/plans/README.md");
const CHANGELOG: &str = include_str!("../../CHANGELOG.md");

fn contains_all(name: &str, text: &str, required: &[&str]) {
    for item in required {
        assert!(text.contains(item), "{name} must define `{item}`");
    }
}

#[test]
fn peer_chat_contract_locks_identity_request_metadata_response_and_delivery() {
    contains_all(
        "peer-chat contract",
        CONTRACT,
        &[
            "agent.chat.v1",
            "secs_agent_identity",
            "agent.chat.request.v1",
            "schema_version",
            "conversation_ref",
            "VerifiedCallContext.subject",
            "receiver-owned typed metadata",
            "ExecutionResponse",
            "response_verifier_key_ref",
            "request_digest",
            "ed25519_receiver",
            "response_authentication_failed",
            "canonical unsigned response",
            "excludes only the signature field",
            "exact output bytes",
            "verifier_rejected",
            "execution_rejected",
            "executed",
            "DecisionResponse remains unchanged",
            "POST /p/<receiver-owned-profile>/v1/chat/completions",
            "API_SERVER_KEY",
            "receiver-local plumbing",
            "dedicated peer-chat Hermes profile",
            "no tools, delegation, shell/browser/file access",
            "no writable workspace",
            "127.0.0.1",
            "[::1]",
            "proxy-disabled HTTP client",
            "environment and system proxy discovery disabled",
            "Redirects are disabled",
            "unknown caller",
            "wrong audience",
            "wrong operation",
            "replay",
            "expired",
            "policy denial",
            "handler_unavailable",
            "handler_timeout",
            "output_too_large",
            "malformed response",
            "fail closed",
        ],
    );

    contains_all(
        "peer-chat contract non-leakage",
        CONTRACT,
        &[
            "private key bytes",
            "Receipts never store raw chat text",
            "no configuration, disclosure mode, debug switch, or error path that can persist it",
            "output digest",
            "arbitrary receiver-local URLs",
            "models, providers, toolsets, or workspaces",
            "No implicit credential forwarding",
            "wrong-request",
            "output substitution",
        ],
    );
}

#[test]
fn peer_chat_dag_serializes_runtime_pr_boundaries_and_defers_internal_gating() {
    contains_all(
        "peer-chat DAG",
        DAG,
        &[
            "P1/P2 — contract gate",
            "P3 — bounded execution-output transport",
            "P4 — receiver-local Hermes adapter",
            "P5 — outbound Hermes plugin client",
            "P6 — mutual peer and negative evidence",
            "P7 — schema-driven extension",
            "P1/P2 --> P3",
            "P3 --> P4",
            "P4 --> P5",
            "P5 --> P6",
            "P6 --> P7",
            "one DAG node = one issue = one PR",
            "P6-S1",
            "P6-H1",
            "inserted as explicit prerequisite DAG nodes",
            "internal Hermes tool gating",
            "deferred",
            "#261",
        ],
    );
}

#[test]
fn docs_index_and_status_keep_contract_distinct_from_implementation() {
    assert!(SPECS_INDEX.contains("secs-hermes-peer-chat-contract.md"));
    assert!(PLANS_INDEX.contains("2026-07-18-secs-hermes-peer-chat-dag.md"));
    contains_all(
        "implementation status",
        STATUS,
        &[
            "secS/Hermes peer-chat contract (#261/#262)",
            "Only P3 is implemented; P4–P7 remain blocked/planned",
            "P3 bounded execution-output transport (#263)",
        ],
    );
}

#[test]
fn p3_docs_reconcile_implemented_transport_without_promoting_p4() {
    contains_all(
        "peer-chat contract P3 status",
        CONTRACT,
        &[
            "P3 implementation status: implemented by #263",
            "DecisionResponse wire shape and version remain unchanged",
            "exact raw ingress bytes",
            "handler_unavailable",
            "handler_timeout",
            "output_too_large",
            "handler_output_missing",
            "handler_output_unexpected",
            "execution_response_too_large",
            "receipt schema v3",
            "pre-c4b6218",
            "operator export v3",
            "bundle-v2/chain-v2",
            "bundle-v1/chain-v1",
            "no execution frame",
            "one directly supplied pinned key",
            "no peer-key resolver or registry",
            "P4 remains unimplemented",
        ],
    );
    contains_all(
        "peer-chat DAG P3 status",
        DAG,
        &[
            "P1/P2 — contract gate | Complete via #261/#262",
            "P3 — bounded execution-output transport | Implemented by #263",
            "P4 — receiver-local Hermes adapter | Blocked by authorized P3 merge and green post-merge main CI",
        ],
    );
    contains_all(
        "implementation status P3",
        STATUS,
        &[
            "P3 bounded execution-output transport (#263)",
            "Implemented on the #263 issue branch",
            "Hermes delivery, trusted peer resolution, and peer chat remain unimplemented",
        ],
    );
}

#[test]
fn peer_chat_contract_does_not_promote_forbidden_first_slice_claims() {
    for forbidden in [
        "legacy.chat is agent.chat.v1",
        "0x02 is the production peer-chat protocol",
        "API_SERVER_KEY identifies the remote peer",
        "payload text determines caller identity",
        "internal Hermes tool gating is required for peer chat",
        "streaming is implemented",
        "production ready",
    ] {
        assert!(
            !CONTRACT.contains(forbidden) && !DAG.contains(forbidden),
            "peer-chat docs must not claim: {forbidden}"
        );
    }
}

#[test]
fn p3_review_hardening_reconciles_current_claims_and_changelog_governance() {
    contains_all(
        "peer-chat P3 hardening status",
        CONTRACT,
        &[
            "Status: P3 bounded execution-output transport implemented by #263; broader peer-chat runtime and P4–P7 unimplemented/blocked",
            "The exact four new P3 output reasons are `handler_output_missing`, `handler_output_unexpected`, `output_too_large`, and `execution_response_too_large`.",
            "P4 remains unimplemented",
            "Hermes adapter",
            "outbound plugin client",
            "trusted peer resolution",
            "streaming",
            "deployment",
            "production readiness",
        ],
    );
    contains_all(
        "peer-chat P3 current DAG boundary",
        DAG,
        &[
            "Issue #263 and draft PR #264 implement this node through exactly eight ordered commits",
            "Commits 1–8 are an immutable protected prefix ending at `3d14174c966f075debce84cccb9e8c9d9b887bf2`",
            "Commit 9 is the single additive final-review correction",
            "Commits 1–9 are an immutable protected prefix ending at `ada11e55a90d3e59632b90af67a07ef54bc5b53d`",
            "Commit 10 is the single additive final CTO correction",
            "Commits 1–10 are an immutable protected prefix ending at `e5012a36b4cb166c71928c746fec014de330fd03`",
            "Commit 11 is the single additive roundtable correction",
            "P4 remains blocked until #263 is authorized to merge and post-merge `main` CI is green",
        ],
    );

    for stale in [
        "Status: accepted contract gate for issue #261; runtime not implemented",
        "This contract does not implement handler output transport",
        "## P3 — bounded execution-output transport\n\nFuture issue must include these commit boundaries:",
        "The P3 transport adds exactly four execution reason codes: `handler_unavailable`, `handler_timeout`, `output_too_large`, and `internal_transport_failure`.",
    ] {
        assert!(
            !CONTRACT.contains(stale) && !DAG.contains(stale) && !STATUS.contains(stale),
            "P3 docs must reject stale claim: {stale}"
        );
    }

    for commit in 1..=11 {
        let marker = format!("- P3/C{commit}:");
        assert_eq!(
            CHANGELOG.matches(&marker).count(),
            1,
            "CHANGELOG must contain exactly one rationale for C{commit}"
        );
    }
}
