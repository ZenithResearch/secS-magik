const CONTRACT: &str = include_str!("../../docs/specs/secs-hermes-peer-chat-contract.md");
const DAG: &str = include_str!("../../docs/plans/2026-07-18-secs-hermes-peer-chat-dag.md");
const STATUS: &str = include_str!("../../docs/implementation-status.md");
const SPECS_INDEX: &str = include_str!("../../docs/specs/README.md");
const PLANS_INDEX: &str = include_str!("../../docs/plans/README.md");

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
            "raw chat text",
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
            "secS/Hermes peer-chat contract (#261)",
            "Planned / contract-only",
            "does not implement handler output transport",
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
