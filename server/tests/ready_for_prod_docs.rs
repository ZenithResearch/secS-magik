const READY_FOR_PROD_CHECKLIST: &str =
    include_str!("../../docs/plans/2026-06-02-ready-for-prod-checklist.md");
const IMPLEMENTATION_STATUS: &str = include_str!("../../docs/implementation-status.md");

fn detailed_track_h_section() -> &'static str {
    READY_FOR_PROD_CHECKLIST
        .split("### A8 — Track H issue/commit details: receipt/event ledger production posture")
        .nth(1)
        .expect("Track H detail section should exist")
        .split("### Track I — first production-shaped membership-provisioning E2E")
        .next()
        .expect("Track H section should be bounded by Track I")
}

#[test]
fn ready_for_prod_checklist_uses_real_workspace_package_names() {
    assert!(
        !READY_FOR_PROD_CHECKLIST.contains("-p libsec-server"),
        "ready-for-prod commands must use the actual server package name, not libsec-server"
    );
    assert!(
        READY_FOR_PROD_CHECKLIST.contains("cargo test -p server"),
        "checklist should retain executable server package test commands"
    );
}

#[test]
fn implementation_status_reconciles_track_a_through_a9_without_runtime_overclaim() {
    assert!(
        IMPLEMENTATION_STATUS.contains("Ready-for-prod checklist A0–A9"),
        "implementation status should record Track A docs/control-surface completion through A9"
    );
    assert!(
        IMPLEMENTATION_STATUS.contains("docs/control surface")
            || IMPLEMENTATION_STATUS.contains("docs/control-surface"),
        "Track A status must remain scoped to docs/control-surface completion"
    );
    assert!(
        !IMPLEMENTATION_STATUS.contains("Ready-for-prod checklist A0/A1"),
        "status ledger should no longer imply Track A stopped at A0/A1"
    );
}

#[test]
fn track_h_summary_and_detail_issue_numbering_match() {
    let track_h = detailed_track_h_section();
    assert!(
        READY_FOR_PROD_CHECKLIST
            .contains("H3 receipt schema/versioning; H4 receipt-chain integration tests"),
        "Track H phase summary should keep schema/versioning and receipt-chain tests distinct"
    );
    assert!(
        track_h.contains("| H3 — Receipt schema/versioning |"),
        "Track H detail section must define H3 schema/versioning if the summary lists it"
    );
    assert!(
        track_h.contains("| H4 — Receipt-chain integration tests |"),
        "Track H detail section must define H4 receipt-chain integration tests if the summary lists it"
    );
}

#[test]
fn merged_track_a_status_has_no_unresolved_final_hygiene_condition() {
    assert!(
        !READY_FOR_PROD_CHECKLIST.contains("after final docs hygiene"),
        "merged Track A docs must not retain an unresolved final-docs-hygiene precondition"
    );
    assert!(
        READY_FOR_PROD_CHECKLIST.contains("Track A is now complete through A9"),
        "checklist should state the post-merge Track A completion boundary"
    );
}

#[test]
fn track_c_status_documents_receiver_local_bounded_replay_enforcement() {
    for required in [
        "Track C is implemented",
        "receiver-local/local durable replay/session/expiry enforcement",
        "Duplicate `(session_id, opcode, nonce, replay_scope)` verified contexts reserve atomically in local SQLite",
        "replay_detected",
        "before handler execution",
        "claim_ttl_exceeds_descriptor_max",
        "before signed context issuance",
        "invalid_session",
        "Expired/wrong-audience/invalid-signature signed contexts emit signed reject receipts/events",
        "before replay reservation",
        "Pre-verification/signature failures do not consume replay slots",
    ] {
        assert!(
            IMPLEMENTATION_STATUS.contains(required),
            "implementation status should document Track C bounded replay claim: {required}"
        );
    }

    assert!(
        IMPLEMENTATION_STATUS
            .contains("not distributed/global/cross-Hub/cluster-wide replay protection"),
        "Track C status must explicitly negate distributed/global/cross-Hub replay protection"
    );
    assert!(
        !IMPLEMENTATION_STATUS.contains("Solid / implemented as distributed"),
        "Track C status must not mark distributed replay as implemented"
    );
}

#[test]
fn ready_for_prod_checklist_records_track_c_completion_without_global_overclaim() {
    for required in [
        "Track C is complete as a receiver-local bounded-claim implementation",
        "within the configured receiver-local replay store/scope",
        "pre-verification/signature failures do not consume replay slots",
        "claim_ttl_exceeds_descriptor_max",
        "invalid_session",
        "replay_detected",
    ] {
        assert!(
            READY_FOR_PROD_CHECKLIST.contains(required),
            "ready-for-prod checklist should record bounded Track C completion: {required}"
        );
    }

    assert!(
        !READY_FOR_PROD_CHECKLIST.contains("Stop when production packets cannot execute twice,"),
        "Track C stop condition must be qualified by receiver-local replay store/scope"
    );
}
