const README: &str = include_str!("../../README.md");
const READY_FOR_PROD_CHECKLIST: &str =
    include_str!("../../docs/plans/2026-06-02-ready-for-prod-checklist.md");
const IMPLEMENTATION_STATUS: &str = include_str!("../../docs/implementation-status.md");
const TRACK_I_STATUS: &str = include_str!(
    "../../docs/issues/secs-magik-phases/track-i-production-membership-provision-e2e.md"
);
const SERVER_README: &str = include_str!("../../server/README.md");
const CHANGELOG: &str = include_str!("../../CHANGELOG.md");
const SPECS_README: &str = include_str!("../../docs/specs/README.md");
const DOCS_README: &str = include_str!("../../docs/README.md");
const DREGG_AUTHORITY_SPEC: &str = include_str!("../../docs/specs/dregg-authority-rail.md");

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
        "versioned request envelope carrying bounded evidence refs/public inputs",
        "handler binding is not authority",
        "live TCP ingress",
        "configured evidence adapter path",
        "#144/#160",
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
        "live TCP ingress still carries no evidence refs/public inputs",
        "live TCP ingress still has no evidence refs/public inputs",
        "live TCP ingress remains descriptor-only",
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
        "bounded evidence refs/public inputs",
        "public inputs",
        "#144/#160",
        "#73 remains open until #144",
    ] {
        assert!(
            docs.iter().any(|(_, text)| text.contains(required)),
            "membership.provision docs should preserve current #162 live-ingress boundary phrase: {required}"
        );
    }
}

#[test]
fn dregg_authority_docs_preserve_169_trusted_requested_authority_without_resource_lock_overclaim() {
    let docs = [
        ("README.md", README),
        ("server/README.md", SERVER_README),
        ("docs/implementation-status.md", IMPLEMENTATION_STATUS),
        ("docs/specs/dregg-authority-rail.md", DREGG_AUTHORITY_SPEC),
        (
            "docs/plans/2026-06-02-ready-for-prod-checklist.md",
            READY_FOR_PROD_CHECKLIST,
        ),
        (
            "docs/issues/secs-magik-phases/track-i-production-membership-provision-e2e.md",
            TRACK_I_STATUS,
        ),
    ];

    for required in [
        "#169",
        "trusted requested-authority",
        "delegated attenuation / non-amplification",
        "requested authority must not exceed held authority",
        "#160 remains future for Dregg-provisioned resource locks",
        "#73 remains open until #144",
    ] {
        assert!(
            docs.iter().any(|(_, text)| text.contains(required)),
            "docs should preserve #169 trusted requested-authority attenuation boundary phrase: {required}"
        );
    }

    for forbidden in [
        "#169 closes #160",
        "#167 closes #160",
        "attenuation implements Dregg resource locks",
        "Dregg resource-lock authority is implemented",
        "Dregg admit verdict grants resource scope",
        "Call.args.resource is a trusted authorization gate",
        "live runtime ingress remains descriptor-only",
        "live ingress still carries no evidence refs",
        "future #162/#144 ingress wiring",
        "until #162 or an explicitly scoped #144",
    ] {
        for (name, text) in docs {
            assert!(
                !text.contains(forbidden),
                "{name} contains stale or overclaimed #169/#162 boundary wording: {forbidden}"
            );
        }
    }
}

fn contains_all(name: &str, text: &str, required: &[&str]) {
    for phrase in required {
        assert!(
            text.contains(phrase),
            "{name} should contain Dregg authority boundary phrase: {phrase}"
        );
    }
}

#[test]
fn dregg_authority_spec_exists_and_answers_m15_1_bundle_questions() {
    contains_all(
        "docs/specs/dregg-authority-rail.md",
        DREGG_AUTHORITY_SPEC,
        &[
            "# Dregg authority rail",
            "M15.1",
            "#137",
            "#73",
            "receiver-held production trust policy",
            "authority object taxonomy",
            "token",
            "issuer",
            "federation root",
            "epoch",
            "revocation/status",
            "freshness",
            "proof/finality",
            "subject",
            "audience",
            "opcode",
            "operation",
            "resource",
            "validity",
            "nonce/replay",
            "root",
            "status",
            "receiver-held root/trust data",
            "epoch-scoped",
            "freshness/revocation/finality/non-amplification",
            "which Dregg API verifies each",
            "out of scope",
            "#33",
            "#37",
            "#74",
            "#75",
        ],
    );

    for forbidden in [
        "Dregg-shaped refs alone satisfy production authority",
        "caller-supplied roots alone satisfy production authority",
        "local SQLite receipts prove Dregg authority",
        "closes #73",
    ] {
        assert!(
            !DREGG_AUTHORITY_SPEC.contains(forbidden),
            "Dregg authority spec must not contain forbidden overclaim: {forbidden}"
        );
    }
}

#[test]
fn dregg_authority_spec_preserves_m12_m14_m15_boundaries() {
    contains_all(
        "docs/specs/dregg-authority-rail.md",
        DREGG_AUTHORITY_SPEC,
        &[
            "M12.3 shape-only",
            "M14 `dregg_backed`",
            "M15 `dregg_authority`",
            "shape + author signature only",
            "`dregg-auth::policy::Verifier::admit`",
            "subject + tool + clock",
            "receiver-local resource scope",
            "necessary but not sufficient",
            "production trust policy",
            "epoch-scoped federation/root",
            "revocation/freshness",
        ],
    );

    for forbidden in [
        "M12.3 Dregg-shaped evidence is Dregg authority",
        "M14 `dregg_backed` is full Dregg authority",
        "`dregg-auth::policy::Verifier::admit` checks resource scope",
        "`Call.args.resource` is a trusted authorization gate",
        "Dregg admit verdict alone authorizes a handler side effect",
    ] {
        assert!(
            !DREGG_AUTHORITY_SPEC.contains(forbidden),
            "Dregg authority spec must not contain forbidden tier overclaim: {forbidden}"
        );
    }
}

#[test]
fn dregg_authority_spec_defines_failure_taxonomy_and_proof_posture() {
    contains_all(
        "docs/specs/dregg-authority-rail.md",
        DREGG_AUTHORITY_SPEC,
        &[
            "wrong_root",
            "wrong_epoch",
            "stale",
            "revoked",
            "not_final",
            "equivocated",
            "malformed",
            "unsupported_suite",
            "wrong_binding",
            "wrong subject",
            "wrong audience",
            "wrong operation",
            "wrong resource",
            "rotated-replay IR-v2 chain",
            "verify_effect_vm_proof",
            "not the whole live path",
        ],
    );

    for forbidden in [
        "verify_effect_vm_proof is the whole live path",
        "proof verification is complete because verify_effect_vm_proof exists",
        "rotated-replay proof is out of scope without a follow-up issue",
    ] {
        assert!(
            !DREGG_AUTHORITY_SPEC.contains(forbidden),
            "Dregg authority spec must not contain proof/finality overclaim: {forbidden}"
        );
    }
}

#[test]
fn dregg_authority_spec_documents_composition_without_bypass() {
    contains_all(
        "docs/specs/dregg-authority-rail.md",
        DREGG_AUTHORITY_SPEC,
        &[
            "wallet proof-of-possession",
            "trusted-issuer credential",
            "Dregg is not a bypass",
            "wallet PoP",
            "necessary where required but never sufficient",
            "receiver-local manifest policy",
            "descriptor-local policy",
            "trusted issuer/root",
            "resource canonicalization",
            "before side effects",
        ],
    );

    for forbidden in [
        "Dregg bypasses wallet",
        "Dregg bypasses trusted issuer",
        "Dregg bypasses receiver-local",
        "Dregg authority replaces secS verification",
        "wallet-only evidence is sufficient Dregg authority",
    ] {
        assert!(
            !DREGG_AUTHORITY_SPEC.contains(forbidden),
            "Dregg authority spec must not contain composition overclaim: {forbidden}"
        );
    }
}

#[test]
fn dregg_authority_docs_indexes_and_checklist_rewrite_issue_73_acceptance() {
    contains_all(
        "docs/specs/README.md",
        SPECS_README,
        &[
            "dregg-authority-rail.md",
            "Dregg authority rail",
            "M15.1",
            "#137",
            "#73",
        ],
    );
    assert!(
        DOCS_README.contains("dregg-authority-rail.md") && DOCS_README.contains("dregg_authority"),
        "docs/README.md should index the M15 dregg_authority spec"
    );

    contains_all(
        "docs/plans/2026-06-02-ready-for-prod-checklist.md",
        READY_FOR_PROD_CHECKLIST,
        &[
            "M15.1",
            "#137",
            "rewrote #73",
            "docs/specs/dregg-authority-rail.md",
            "Dregg-shaped refs alone remain rejected until a real adapter verifies them",
            "receiver-held production trust policy",
            "epoch-scoped federation/root",
            "revocation/freshness",
            "wrong subject/audience/operation/resource",
            "stale/revoked",
            "wrong root",
            "unsupported suite",
            "redaction-safe",
            "Midnight/Cardano/public auditability/deployment overclaims",
        ],
    );
}

#[test]
fn dregg_authority_docs_record_m15_4_fail_closed_posture_and_blockers() {
    contains_all(
        "docs/specs/dregg-authority-rail.md",
        DREGG_AUTHORITY_SPEC,
        &[
            "M15.4 / #140",
            "require_revocation_check",
            "require_finality",
            "future status timestamps",
            "token expires at the validation instant",
            "named blockers",
            "expected_revocation_root",
            "RevocationVerifier",
            "ReceiptQc::Threshold",
            "rotated_replay",
        ],
    );

    contains_all(
        "docs/plans/2026-06-02-ready-for-prod-checklist.md",
        READY_FOR_PROD_CHECKLIST,
        &[
            "M15.4 / #140",
            "revocation/freshness/finality posture",
            "Missing revocation check material rejects as `missing_status`",
            "Required finality without finality material rejects as `not_final`",
            "Equivocation rejects as `equivocated`",
            "#73 remains open",
        ],
    );
}

#[test]
fn dregg_authority_docs_record_m15_5_descriptor_composition_without_overclaim() {
    contains_all(
        "docs/specs/dregg-authority-rail.md",
        DREGG_AUTHORITY_SPEC,
        &[
            "M15.5 / #141",
            "membership.provision",
            "wallet_presentation",
            "membership_credential",
            "dregg_authority",
            "#159",
            "#160",
            "does not close #73",
        ],
    );
    contains_all(
        "docs/plans/2026-06-02-ready-for-prod-checklist.md",
        READY_FOR_PROD_CHECKLIST,
        &[
            "M15.5 / #141",
            "wallet + issuer + Dregg authority",
            "M12.3 shape-only `dregg_receipt` cannot satisfy",
            "#159 is resolved as explicit fail-closed blocker posture",
            "#160 remains future",
        ],
    );
}

#[test]
fn dregg_authority_docs_record_m15_6_operator_disclosure_boundary() {
    contains_all(
        "docs/specs/dregg-authority-rail.md",
        DREGG_AUTHORITY_SPEC,
        &[
            "M15.6 / #142 operator inspection and disclosure boundary",
            "authority_class:dregg_authority",
            "root_ref_sha256",
            "issuer_key_id_sha256",
            "federation_id_sha256",
            "token:dga1_[redacted]",
            "local operator inspection only",
            "not public auditability",
            "does not implement #159",
            "does not implement #162",
        ],
    );
}

#[test]
fn dregg_authority_docs_record_m15_7_proof_finality_blockers_without_overclaim() {
    let docs = [
        ("docs/specs/dregg-authority-rail.md", DREGG_AUTHORITY_SPEC),
        (
            "docs/plans/2026-06-02-ready-for-prod-checklist.md",
            READY_FOR_PROD_CHECKLIST,
        ),
        ("docs/implementation-status.md", IMPLEMENTATION_STATUS),
        ("CHANGELOG.md", CHANGELOG),
    ];

    for required in [
        "M15 proof hardening / #159 proof/finality blocker posture",
        "expected_revocation_root",
        "RevocationVerifier",
        "RevocationTree",
        "ReceiptQc::Threshold",
        "BLS FederationCommittee",
        "verify_rotated_replay_chain",
        "missing_revocation_root",
        "wrong_revocation_root",
        "unsupported_revocation_verifier",
        "unsupported_bls_threshold_finality",
        "unsupported_rotated_replay_verifier",
        "no live Dregg revocation proof",
        "no BLS threshold finality",
        "no rotated-replay proof verification",
        "#144",
        "#73 remains open",
    ] {
        assert!(
            docs.iter().any(|(_, text)| text.contains(required)),
            "M15.7 docs should record #159 proof/finality blocker phrase: {required}"
        );
    }

    for forbidden in [
        "live Dregg revocation proof is implemented",
        "BLS threshold finality is implemented",
        "rotated-replay proof verification is implemented",
        "ReceiptQc::Threshold verifies production finality",
        "verify_rotated_replay_chain is wired into secS",
        "closes #73",
    ] {
        for (name, text) in docs {
            assert!(
                !text.contains(forbidden),
                "{name} contains forbidden #159 overclaim: {forbidden}"
            );
        }
    }
}

#[test]
fn dregg_seam_migration_docs_remove_stale_live_ingress_and_future_authority_claims() {
    let docs = [
        ("README.md", README),
        ("server/README.md", SERVER_README),
        ("docs/README.md", DOCS_README),
        ("docs/implementation-status.md", IMPLEMENTATION_STATUS),
        (
            "docs/plans/2026-06-02-ready-for-prod-checklist.md",
            READY_FOR_PROD_CHECKLIST,
        ),
        (
            "docs/issues/secs-magik-phases/track-i-production-membership-provision-e2e.md",
            TRACK_I_STATUS,
        ),
        ("docs/specs/dregg-authority-rail.md", DREGG_AUTHORITY_SPEC),
    ];

    for forbidden in [
        "#141/#144 live TCP evidence-ref/public-input",
        "#141/#144 live TCP evidence refs",
        "#141/#144 land the live TCP evidence-ref/public-input wire path",
        "#141/#144 ingress wiring",
        "#73 Dregg authority remains future",
        "production `dregg_authority` code remains future until M15.2",
        "handler binding is not authority until #141/#144 wire-path work lands",
    ] {
        for (name, text) in docs {
            assert!(
                !text.contains(forbidden),
                "{name} contains stale #143 seam-migration wording: {forbidden}"
            );
        }
    }

    contains_all(
        "docs/issues/secs-magik-phases/track-i-production-membership-provision-e2e.md",
        TRACK_I_STATUS,
        &[
            "wallet + issuer + Dregg authority",
            "#162/#144",
            "#73 remains open until #144",
            "#159",
            "#160",
            "bounded static receiver-held Dregg policy-admission",
        ],
    );
    contains_all(
        "docs/specs/dregg-authority-rail.md",
        DREGG_AUTHORITY_SPEC,
        &[
            "M12.3 Dregg-shaped evidence",
            "M14 `dregg_backed`",
            "M15 `dregg_authority`",
            "M15.2–M15.6 now implement",
            "#160/#144",
        ],
    );
}
