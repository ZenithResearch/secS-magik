const CONTRACT: &str = include_str!("../../docs/specs/secs-hermes-peer-chat-contract.md");
const DAG: &str = include_str!("../../docs/plans/2026-07-18-secs-hermes-peer-chat-dag.md");
const STATUS: &str = include_str!("../../docs/implementation-status.md");
const SPECS_INDEX: &str = include_str!("../../docs/specs/README.md");
const PLANS_INDEX: &str = include_str!("../../docs/plans/README.md");
const CHANGELOG: &str = include_str!("../../CHANGELOG.md");

const P3_CHANGELOG_ENTRIES: [&str; 12] = [
    "- P3/C1: added the manual bounded receiver-signed `ExecutionResponse` codec and supplied-key verifier — this prevents ambiguous serialization, wrong-request acceptance, and output substitution without changing `DecisionResponse`.",
    "- P3/C2: replaced trusted handler byte counts with receiver-bounded owned output and private post-receipt routing state — this makes output-declaring success reflect completed handler execution rather than verifier admission.",
    "- P3/C3: added exact ingress-byte correlation, receiver-domain signing, single-frame execution routing, and a bounded fail-closed client verifier — this prevents captured, unsigned, wrong-key, or substituted execution responses from being accepted.",
    "- P3/C4: added signed redacted execution-output correlation with exact historical receipt/operator layouts, mandatory operator v3 projections, and pinned public-audit v1/v2 compatibility — this preserves verifiable history while preventing raw handler output from crossing the receipt projection boundary.",
    "- P3/C5: reconciled the execution-output contract, DAG, indexes, and implementation ledger around implemented P3 while keeping Hermes delivery, trusted peer resolution, `agent.chat.v1`, and P4–P7 blocked — this prevents transport evidence from being overstated as peer chat or deployment readiness.",
    "- P3/C6: replaced optional environment-selected response decoding with complete trusted per-operation expectations and receiver-locked signed verifier rejections — this prevents legacy-mode downgrade, caller-chosen response keys or bounds, and unsigned post-descriptor denial paths.",
    "- P3/C7: made public-audit and anchor decoding deny unknown fields and bound public/operator projection shapes to compatible receipt versions and accepted-execute state — this prevents raw-field smuggling, schema relabelling, and output-projection downgrade acceptance.",
    "- P3/C8: reconciled the accepted contract, implementation DAG, status ledger, and changelog guards around the completed canonical P3 sequence of C1 through C12 while preserving every Hermes/P4/deployment non-claim — this prevents bounded output transport from being described as either unimplemented or as completed peer chat.",
    "- P3/C9: made authenticated rejection responses schema-less under trusted execution expectations and restored persisted-schema-selected historical operator export shapes — this preserves canonical rejection semantics and exact v1/v2 inspection compatibility without weakening executed-response authentication or v3 projection rules.",
    "- P3/C10: redacted raw execution bytes from response, handler-outcome, and route-projection debug formatting and made post-start output-profile rejections require atomically persisted execute-reject receipts — this prevents debug disclosure and signed rejection frames from referencing receipts that were never stored.",
    "- P3/C11: permitted an authenticated missing handler binding through active-manifest matching only for output-profile descriptors, so public ingress reaches required atomic `handler_unavailable` receipt persistence instead of a pre-start verifier rejection while exact supplied-handler and legacy descriptor checks remain unchanged.",
    "- P3/C12: replaced permissive expected-marker counting with exact changelog marker-set parsing and pinned the terminal Commit 13 prohibition — this makes gaps, duplicates, malformed markers, and unauthorized P3 governance extensions fail mechanically.",
];

fn contains_all(name: &str, text: &str, required: &[&str]) {
    for item in required {
        assert!(text.contains(item), "{name} must define `{item}`");
    }
}

fn section_between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let start_offset = text
        .find(start)
        .unwrap_or_else(|| panic!("missing section start `{start}`"));
    let body = &text[start_offset + start.len()..];
    let end_offset = body
        .find(end)
        .unwrap_or_else(|| panic!("missing section end `{end}`"));
    &body[..end_offset]
}

fn table_status<'a>(text: &'a str, node: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let cells: Vec<_> = line.split('|').map(str::trim).collect();
        (cells.len() > 2 && cells[1] == node).then(|| cells[2])
    })
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
fn required_receipt_persistence_failure_emits_no_execution_response_frame() {
    contains_all(
        "P3 persistence exception",
        CONTRACT,
        &[
            "When required receipt persistence fails, the receiver emits no `ExecutionResponse` frame.",
            "It never synthesizes a signed rejection or success",
            "no post-verification outcome is described as framed unless its required receipt was persisted",
        ],
    );
    assert!(
        !CONTRACT.contains("Every post-verification outcome emits an `ExecutionResponse` frame"),
        "the contract must not universalize framed post-verification outcomes"
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

    let mermaid = section_between(DAG, "```mermaid\n", "```");
    let nodes: Vec<_> = mermaid
        .lines()
        .map(str::trim)
        .filter(|line| line.contains('[') && !line.contains("-->"))
        .collect();
    assert_eq!(
        nodes,
        [
            "P12[P1/P2 — contract gate]",
            "P3[P3 — bounded execution-output transport]",
            "P4R[P4-R — peer-chat contract reconciliation]",
            "P4O[P4-O — first named exact-operation ratification]",
            "P4H[P4-H — stable Hermes exact-operation endpoint]",
            "P4S[P4-S — secS receiver-side adapter]",
            "P5C[P5-C — outbound authorized caller]",
            "P6E[P6-E — exact-operation E2E and negative evidence]",
            "P7[P7 — separately ratified extensions]",
        ],
        "active Mermaid nodes must remain exact"
    );
    let edges: Vec<_> = mermaid
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("-->"))
        .collect();
    assert_eq!(
        edges,
        [
            "P12 --> P3",
            "P3 --> P4R",
            "P4R --> P4O",
            "P4O --> P4H",
            "P4H --> P4S",
            "P4S --> P5C",
            "P5C --> P6E",
            "P6E --> P7",
        ],
        "active Mermaid edges must be one serialized path through P4-O"
    );
    assert_eq!(
        DAG.matches("P4-R -> P4-O -> P4-H -> P4-S -> P5-C -> P6-E -> P7")
            .count(),
        1,
        "the active serialized sequence must be stated exactly once"
    );
    for stale_edge in ["P3 --> P4", "P4 --> P5", "P5 --> P6", "P6 --> P7"] {
        assert!(
            !edges.contains(&stale_edge),
            "old active DAG edge must remain absent: {stale_edge}"
        );
    }

    for (node, status) in [
        ("P1/P2 — contract gate", "Complete via #261/#262"),
        (
            "P3 — bounded execution-output transport",
            "Complete on `main` via #263/#264",
        ),
        (
            "P4-R — peer-chat contract reconciliation",
            "In progress via #270",
        ),
        (
            "P4-O — first named exact-operation ratification",
            "Blocked by P4-R",
        ),
        (
            "P4-H — stable Hermes exact-operation endpoint",
            "Blocked by P4-O",
        ),
        ("P4-S — secS receiver-side adapter", "Blocked by P4-H"),
        ("P5-C — outbound authorized caller", "Blocked by P4-S"),
        (
            "P6-E — exact-operation E2E and negative evidence",
            "Blocked by P5-C",
        ),
        ("P7 — separately ratified extensions", "Future after P6-E"),
    ] {
        assert_eq!(
            table_status(DAG, node),
            Some(status),
            "active node status drifted for {node}"
        );
    }
    for node in [
        "Former P4 — receiver-local Hermes adapter",
        "Former P5 — outbound Hermes plugin client",
        "Former P6 — mutual peer and negative evidence",
    ] {
        assert_eq!(
            table_status(DAG, node),
            Some("Superseded"),
            "former peer-chat node must remain superseded: {node}"
        );
    }
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
            "P4-R completed through merged #270/#271",
            "P4-O-DG then ratified exactly `devgraph.issue.create.v1` in merged PR #280",
            "DG-P merged through PR #284",
            "DG-E1 merged through PR #285",
            "DG-E2 is only a fixed local Wallet ceremony around that exact producer",
            "No peer-chat runtime, generic Work API/browser RPC, generic route, Wallet custody, Devgraph mutation, or end-to-end result was revived or inferred",
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
    assert!(
        !CHANGELOG.contains("P3/C13"),
        "CHANGELOG must not authorize P3/C13"
    );
    for (index, expected_entry) in P3_CHANGELOG_ENTRIES.iter().enumerate() {
        let marker = format!("P3/C{}:", index + 1);
        let matches: Vec<_> = CHANGELOG
            .lines()
            .filter(|line| line.contains(&marker))
            .map(str::trim)
            .collect();
        assert_eq!(
            matches,
            [*expected_entry],
            "{marker} must retain its exact historical meaning"
        );
    }
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

    let headings: Vec<_> = CONTRACT
        .lines()
        .filter(|line| line.starts_with("## "))
        .collect();
    assert_eq!(
        headings,
        [
            "## Decision",
            "## Superseded commitments",
            "## Matrix and secS boundary",
            "## Preserved P1 and P3 invariants",
            "## P3 bounded transport remains implemented",
            "## P4-R reconciliation boundary",
            "## Explicit non-ratifications",
            "## Stop conditions",
            "## Non-claims",
        ],
        "active contract section structure must remain closed"
    );

    let superseded = section_between(
        CONTRACT,
        "## Superseded commitments",
        "## Matrix and secS boundary",
    );
    let stop_conditions = section_between(CONTRACT, "## Stop conditions", "## Non-claims");
    for marker in [
        "`agent.chat.request.v1`",
        "`agent.chat.response.v1`",
        "trusted metadata as a system prompt",
        "`/v1/chat/completions`",
        "chat-completions route",
        "`API_SERVER_KEY`",
        "dedicated peer-chat profile",
        "outbound chat plugin",
        "mutual-chat target",
    ] {
        assert_eq!(
            CONTRACT.matches(marker).count(),
            1,
            "historical marker must occur exactly once: {marker}"
        );
        assert!(
            superseded.contains(marker),
            "historical marker must remain inside the superseded section: {marker}"
        );
    }
    assert_eq!(CONTRACT.matches("`agent.chat.v1`").count(), 2);
    assert_eq!(superseded.matches("`agent.chat.v1`").count(), 1);
    assert_eq!(stop_conditions.matches("`agent.chat.v1`").count(), 1);

    for forbidden_heading in [
        "## Symmetric identity and configuration",
        "## Trusted caller metadata handoff",
        "## Receiver-local Hermes delivery",
        "## Chat output",
        "## Outbound Hermes plugin client",
        "## Mutual peer evidence",
    ] {
        assert!(
            !CONTRACT.contains(forbidden_heading),
            "superseded active section must remain absent: {forbidden_heading}"
        );
    }

    contains_all(
        "scope and downstream non-claims",
        CONTRACT,
        &[
            "No generic Hermes API server is enabled or accepted as an authority gate",
            "No caller control over model, provider, prompt, role, tool, toolset, workspace, session, plugin, handler, path, header, key, URL, or opcode is ratified",
            "makes Matrix or another product integration depend on this reconciliation",
            "does not implement an operation, operation identifier, schema, adapter, endpoint, ABI, IPC mechanism, transport, socket, route, package, plugin, caller, Matrix integration, deployment, or production-ready system",
        ],
    );
}
