const README: &str = include_str!("../../README.md");
const READY_FOR_PROD_CHECKLIST: &str =
    include_str!("../../docs/plans/2026-06-02-ready-for-prod-checklist.md");
const IMPLEMENTATION_STATUS: &str = include_str!("../../docs/implementation-status.md");
const TRACK_I_STATUS: &str = include_str!(
    "../../docs/issues/secs-magik-phases/track-i-production-membership-provision-e2e.md"
);
const SERVER_README: &str = include_str!("../../server/README.md");
const CHANGELOG: &str = include_str!("../../CHANGELOG.md");

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
fn readme_gateway_quickstart_does_not_suggest_bare_production_config() {
    assert!(
        !README
            .lines()
            .any(|line| line.trim() == "cargo run -p server --bin secs-gateway"),
        "README must not suggest bare secs-gateway startup because default production_verified intentionally requires explicit SECS_* limits and operator config"
    );
    assert!(
        README.contains("SECS_RUNTIME_MODE=local_dev_plaintext cargo run -p server --bin secs-gateway")
            || README.contains("./scripts/production-gateway-smoke.sh"),
        "README should give either an explicit local-dev command or the fixture-only production smoke script"
    );
}

#[test]
fn docs_do_not_suggest_bare_secz_startup_without_local_dev_mode() {
    for (name, text) in [
        ("README.md", README),
        ("server/README.md", include_str!("../../server/README.md")),
        (
            "examples/README.md",
            include_str!("../../examples/README.md"),
        ),
    ] {
        for line in text.lines().map(str::trim) {
            let bare_secz =
                line == "cargo run -p server --bin secz" || line == "cargo run --bin secz";
            assert!(
                !bare_secz || line.contains("SECS_RUNTIME_MODE=local_dev_plaintext"),
                "{name} must not suggest bare secz startup because the compatibility wrapper is a local/dev surface and should be explicit"
            );
        }
    }
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
        "Track C was completed on fresh branch `phase/track-c-replay-session-expiry-v2`",
        "receiver-local bounded-claim implementation",
        "within the configured receiver-local replay store/scope",
        "including concurrent identical routes",
        "server/src/schema.rs",
        "schema ontology",
        "server/src/ontology.rs",
        "default receiver audience",
        "Pre-verification/signature failures emit signed reject receipts/events",
        "do not consume replay slots",
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

#[test]
fn track_d_docs_close_wallet_verification_without_full_wallet_core_overclaim() {
    let client_surfaces = include_str!("../../docs/client-surfaces.md");
    let server_readme = include_str!("../../server/README.md");

    for required in [
        "Track D is complete through D4",
        "temporary minimal-equivalent secS challenge contract",
        "not a full Castalia Wallet wallet-core import",
        "Browser extension: owns user-facing wallet UX and should consume wallet semantics through a WASM binding",
        "secZ/secC/local clients: may use native/client bindings or carry packet/evidence bytes",
        "secS/server: owns only the verifier subset and artifact-consumer boundary",
        "signed presentation/challenge bytes plus public verification material",
        "proof-of-possession for the claimed subject key",
        "not trusted issuer/root/registry policy",
        "ShapeValidatedSignatureUnsupported",
    ] {
        assert!(
            READY_FOR_PROD_CHECKLIST.contains(required)
                || client_surfaces.contains(required)
                || server_readme.contains(required),
            "Track D closeout docs should contain bounded wallet packaging/status language: {required}"
        );
    }

    assert!(
        !READY_FOR_PROD_CHECKLIST.contains(
            "remaining first-prod path still needs Track D wallet cryptographic verification"
        ),
        "Track D should no longer be listed as an incomplete remaining first-prod track"
    );
}

#[test]
fn membership_provision_runtime_guard_docs_preserve_live_ingress_boundary() {
    for (name, text) in [
        ("README.md", README),
        ("server/README.md", SERVER_README),
        ("docs/implementation-status.md", IMPLEMENTATION_STATUS),
        (
            "docs/plans/2026-06-02-ready-for-prod-checklist.md",
            READY_FOR_PROD_CHECKLIST,
        ),
        (
            "docs/issues/secs-magik-phases/track-i-production-membership-provision-e2e.md",
            TRACK_I_STATUS,
        ),
    ] {
        assert!(
            text.contains("#77") || text.contains("Issue #77"),
            "{name} should name the #77 membership.provision runtime evidence guard boundary"
        );
        assert!(
            text.contains("fail-closed") || text.contains("fail closed"),
            "{name} should describe #77 as a fail-closed runtime guard"
        );
        assert!(
            text.contains("descriptor-only"),
            "{name} should keep the #77 guard scoped to descriptor-only runtime verification"
        );
    }

    for required in [
        "Complete for local production-shaped E2E",
        "PR #76",
        "live runtime ingress still does not verify wallet + issuer evidence",
        "handler binding is not authority",
        "live TCP ingress",
        "no evidence refs",
        "#141/#144",
        "not production deployment",
        "not public auditability",
        "not live Castalia/Dregg discovery",
        "full Castalia Wallet wallet-core parity",
    ] {
        assert!(
            README.contains(required)
                || SERVER_README.contains(required)
                || IMPLEMENTATION_STATUS.contains(required)
                || READY_FOR_PROD_CHECKLIST.contains(required)
                || TRACK_I_STATUS.contains(required),
            "docs should preserve membership.provision runtime guard boundary language: {required}"
        );
    }
}

#[test]
fn membership_provision_docs_do_not_regress_active_binding_into_live_ingress_authority() {
    let docs = [
        ("README.md", README),
        ("server/README.md", SERVER_README),
        ("docs/implementation-status.md", IMPLEMENTATION_STATUS),
        (
            "docs/plans/2026-06-02-ready-for-prod-checklist.md",
            READY_FOR_PROD_CHECKLIST,
        ),
        (
            "docs/issues/secs-magik-phases/track-i-production-membership-provision-e2e.md",
            TRACK_I_STATUS,
        ),
        ("CHANGELOG.md", CHANGELOG),
    ];

    for forbidden in [
        "must not claim active `membership.provision` runtime authority until #78/#79-style follow-ups land",
        "until #78 lands the activation path",
        "evidence-aware live ingress/runtime authority remains tracked in #78/#79-style follow-ups",
        "live ingress/runtime wallet + issuer evidence verification remains tracked separately in #78/#79-style follow-ups",
    ] {
        for (name, text) in docs {
            assert!(
                !text.contains(forbidden),
                "{name} contains stale membership.provision live-authority wording: {forbidden}"
            );
        }
    }

    for required in [
        "handler binding is not authority",
        "descriptor-only `production_verified`",
        "fail-closed",
        "live TCP ingress",
        "no evidence refs",
        "public inputs",
        "#141/#144",
        "#73 Dregg authority remains future",
    ] {
        assert!(
            docs.iter().any(|(_, text)| text.contains(required)),
            "membership.provision docs should preserve current #151 lockstep boundary phrase: {required}"
        );
    }
}
