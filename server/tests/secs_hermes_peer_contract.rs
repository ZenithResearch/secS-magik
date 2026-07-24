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
fn contract_explicitly_supersedes_peer_chat_instead_of_relabeling_it() {
    contains_all(
        "superseded peer-chat contract",
        CONTRACT,
        &[
            "Status: superseded by Issue #270",
            "explicitly superseded, never relabeled",
            "`agent.chat.v1`",
            "`agent.chat.request.v1`",
            "`agent.chat.response.v1`",
            "trusted metadata as a system prompt",
            "`/v1/chat/completions`",
            "`API_SERVER_KEY`",
            "dedicated peer-chat profile",
            "outbound chat plugin",
            "mutual-chat target",
            "historical filename",
        ],
    );

    contains_all(
        "conversation and authority boundary",
        CONTRACT,
        &[
            "Matrix owns conversation",
            "Chat text and Matrix events are not executable authority",
            "secS admits exact authority-bearing machine operations only",
            "generic Hermes API server remains disabled",
        ],
    );
}

#[test]
fn contract_preserves_p1_and_p3_authority_and_response_invariants() {
    contains_all(
        "preserved contract invariants",
        CONTRACT,
        &[
            "distinct caller identities",
            "audience, operation, freshness, replay",
            "receiver-local policy",
            "`VerifiedCallContext` is the sole authority metadata source",
            "Receiver-owned descriptor and handler binding",
            "exact resource",
            "attenuation",
            "non-amplification",
            "signed, exact-request-correlated, bounded `ExecutionResponse`",
            "schema ID, byte count, and domain-separated SHA-256 digest",
            "Raw output bytes are never persisted",
            "No credential forwarding",
            "caller-selected receiver-local controls",
            "`DecisionResponse` remains unchanged",
        ],
    );
}

#[test]
fn contract_ratifies_no_operation_or_delivery_mechanism() {
    contains_all(
        "contract non-ratifications",
        CONTRACT,
        &[
            "No first operation or operation identifier is ratified",
            "No generic machine-operation multiplexer is ratified",
            "No local ABI, IPC, transport, socket, route, or endpoint is ratified",
            "No new request or response schema is ratified",
            "No package or repository ownership is ratified",
            "No runtime implementation is authorized",
            "model, provider, prompt, role, tool, toolset, workspace, session, plugin, handler, path, header, key, URL, or opcode",
        ],
    );
}

#[test]
fn replacement_dag_serializes_exact_operation_gates_and_supersedes_old_nodes() {
    contains_all(
        "replacement DAG",
        DAG,
        &[
            "P1/P2 — contract gate",
            "P3 — bounded execution-output transport",
            "P4-R — peer-chat contract reconciliation",
            "P4-O — first named exact-operation ratification",
            "P4-H — stable Hermes exact-operation endpoint",
            "P4-S — secS receiver-side adapter",
            "P5-C — outbound authorized caller",
            "P6-E — exact-operation E2E and negative evidence",
            "P7 — separately ratified extensions",
            "P4-R -> P4-O -> P4-H -> P4-S -> P5-C -> P6-E -> P7",
            "operator-ratified first named operation before any implementation",
            "one DAG node = one issue = one PR",
            "Former P4 — receiver-local Hermes adapter | Superseded",
            "Former P5 — outbound Hermes plugin client | Superseded",
            "Former P6 — mutual peer and negative evidence | Superseded",
            "repair node",
            "post-merge `main` CI passes",
        ],
    );
}

#[test]
fn status_and_indexes_expose_only_the_superseded_chat_and_exact_operation_gate() {
    contains_all(
        "reconciled implementation status",
        STATUS,
        &[
            "Superseded secS/Hermes peer-chat delivery contract (#261/#262/#270)",
            "P3 bounded execution-output transport (#263)",
            "P3/C1–P3/C12 remain the exact governance sequence; No Commit 13 is authorized by #263",
            "Matrix owns conversation",
            "chat text and Matrix events are not executable authority",
            "P4-R is in progress through Issue #270",
            "P4-O is blocked until an operator ratifies one named exact operation before any implementation",
            "No replacement operation, identifier, schema, endpoint, ABI, IPC, transport, socket, route, package, repository owner, or runtime implementation is ratified",
        ],
    );
    contains_all(
        "specs index",
        SPECS_INDEX,
        &[
            "secs-hermes-peer-chat-contract.md",
            "Superseded peer-chat delivery contract",
            "Matrix conversation/secS exact-operation boundary",
            "no replacement operation or delivery mechanism ratified",
        ],
    );
    contains_all(
        "plans index",
        PLANS_INDEX,
        &[
            "2026-07-18-secs-hermes-peer-chat-dag.md",
            "Current exact-operation control surface",
            "P4-R -> P4-O -> P4-H -> P4-S -> P5-C -> P6-E -> P7",
            "former peer-chat P4/P5/P6 nodes superseded",
        ],
    );

    let discovery = [STATUS, SPECS_INDEX, PLANS_INDEX].join("\n");
    for stale in [
        "The pre-existing peer-chat contract is retained without endorsement or demotion",
        "P4 is dependency-ready but contract-reconciliation-pending",
        "Accepted P1/P2 contract plus implemented #263 P3",
        "Current P1/P2–P7 control surface; P3 implemented by #263, P4 blocked",
        "Dependency-ordered path for symmetric authenticated Hermes peer chat",
    ] {
        assert!(
            !discovery.contains(stale),
            "discovery surfaces must reject stale peer-chat claim: {stale}"
        );
    }
}

#[test]
fn p3_transport_history_and_terminal_governance_remain_exact() {
    contains_all(
        "P3 transport history",
        CONTRACT,
        &[
            "P3 bounded execution-output transport remains implemented",
            "c3c87bedb9a3cee8aeb9ad4d25f52cb096cb2c27",
            "358b232a3c0de2f96f63b41ffa276c5ae469c19e",
            "30047659428",
            "handler_output_missing",
            "handler_output_unexpected",
            "output_too_large",
            "execution_response_too_large",
            "receipt schema v3",
            "pre-c4b6218",
            "operator export v3",
            "bundle-v2/chain-v2",
            "bundle-v1/chain-v1",
            "one directly supplied pinned key",
            "no peer-key resolver or registry",
        ],
    );
    contains_all(
        "P3 governance history",
        DAG,
        &[
            "protected P3 head `c3c87bedb9a3cee8aeb9ad4d25f52cb096cb2c27` contains exactly 12 ordered commits",
            "Commit 12 is the sole additive governance-test correction",
            "No Commit 13 is authorized by #263",
            "P3 is complete on `main` through merge commit `358b232a3c0de2f96f63b41ffa276c5ae469c19e`",
            "post-merge Rust CI run [30047659428]",
        ],
    );

    let mut marker_counts = std::collections::BTreeMap::new();
    for (offset, _) in CHANGELOG.match_indices("P3/C") {
        let suffix = &CHANGELOG[offset + "P3/C".len()..];
        let digit_count = suffix.bytes().take_while(u8::is_ascii_digit).count();
        assert!(digit_count > 0, "malformed P3/C marker at byte {offset}");
        assert_eq!(
            suffix.as_bytes().get(digit_count),
            Some(&b':'),
            "malformed P3/C marker at byte {offset}"
        );
        let digits = &suffix[..digit_count];
        let commit: u32 = digits
            .parse()
            .unwrap_or_else(|_| panic!("malformed P3/C marker at byte {offset}"));
        assert_eq!(
            digits,
            commit.to_string(),
            "non-canonical P3/C marker at byte {offset}"
        );
        assert!(
            (1..=12).contains(&commit),
            "out-of-range P3/C{commit} marker"
        );
        *marker_counts.entry(commit).or_insert(0usize) += 1;
    }
    let expected = (1..=12).map(|commit| (commit, 1usize)).collect();
    assert_eq!(
        marker_counts, expected,
        "CHANGELOG P3 rationale markers must be exactly C1 through C12, each once"
    );
}

#[test]
fn contract_rejects_active_peer_chat_and_implementation_claims() {
    for forbidden in [
        "Status: accepted peer-chat contract",
        "agent.chat.v1 remains active",
        "peer chat is the active transport",
        "chat text is executable authority",
        "The generic Hermes API server is enabled.",
        "first exact operation is ratified",
        "Runtime implementation is authorized.",
        "production ready",
    ] {
        assert!(
            !CONTRACT.contains(forbidden),
            "superseded contract must not claim: {forbidden}"
        );
    }
}
