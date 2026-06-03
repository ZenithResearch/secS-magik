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
