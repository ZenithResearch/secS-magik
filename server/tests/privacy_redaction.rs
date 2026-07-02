use server::config::{GatewayReadiness, ReadinessStatus};
use server::privacy::{scan_json_value, DisclosurePolicy, PrivacySurface};

#[test]
fn privacy_policy_scans_log_readiness_demo_and_operator_projections() {
    let policy = DisclosurePolicy::default_i02();
    let readiness = GatewayReadiness {
        config_loaded: ReadinessStatus::Ready,
        ledger_ready: ReadinessStatus::Ready,
        trust_registry_ready: ReadinessStatus::FixtureOnly,
        caller_registry_ready: ReadinessStatus::FixtureOnly,
        dregg_authority_registry_ready: ReadinessStatus::FixtureOnly,
        dregg_authority_snapshot_ready: ReadinessStatus::FixtureOnly,
        dregg_live_source_ready: ReadinessStatus::FixtureOnly,
        privacy_policy_ready: ReadinessStatus::Ready,
        redaction_scanner_ready: ReadinessStatus::Ready,
    };
    let readiness_json = serde_json::to_value(readiness.privacy_projection()).unwrap();
    scan_json_value(PrivacySurface::ReadinessStatus, &readiness_json, &policy).unwrap();

    let log_projection = serde_json::json!({
        "correlation_id": "corr-i02-ephemeral",
        "reason_code": "over_disclosed_presentation",
        "policy_id": "secs-i02-deny-by-default",
        "policy_version": 1,
        "handler_ran": false,
        "scanner_result": "passed"
    });
    scan_json_value(PrivacySurface::Log, &log_projection, &policy).unwrap();

    let operator_projection = serde_json::json!({
        "action_required": "none",
        "policy_id": "secs-i02-deny-by-default",
        "scanner_result": "passed",
        "receipt_kind": "reject"
    });
    scan_json_value(PrivacySurface::OperatorCli, &operator_projection, &policy).unwrap();

    let demo_projection = serde_json::json!({
        "timeline": ["verify rejected"],
        "reason_code": "over_disclosed_presentation",
        "identity": "identity hidden by policy",
        "evidence_tier": "local_fixture"
    });
    scan_json_value(PrivacySurface::DemoProjection, &demo_projection, &policy).unwrap();

    let public_audit_projection = serde_json::json!({
        "receipt_id": "receipt-i02",
        "policy_id": "secs-i02-deny-by-default",
        "policy_version": 1,
        "decision": "rejected",
        "reason": "over_disclosed_presentation"
    });
    scan_json_value(
        PrivacySurface::PublicAudit,
        &public_audit_projection,
        &policy,
    )
    .unwrap();
}

#[test]
fn privacy_scanner_rejects_forbidden_names_and_sentinels_on_outward_surfaces() {
    let policy = DisclosurePolicy::default_i02();
    for (surface, projection) in [
        (
            PrivacySurface::ReadinessStatus,
            serde_json::json!({ "wallet_id": "I02_SENTINEL_WALLET" }),
        ),
        (
            PrivacySurface::DemoProjection,
            serde_json::json!({ "proof": "I02_SENTINEL_PROOF" }),
        ),
        (
            PrivacySurface::Log,
            serde_json::json!({ "authorization": "I02_SENTINEL_TOKEN" }),
        ),
        (
            PrivacySurface::OperatorCli,
            serde_json::json!({ "stable_nullifier": "I02_SENTINEL_NULLIFIER" }),
        ),
        (
            PrivacySurface::PublicAudit,
            serde_json::json!({ "subject_handle": "I02_SENTINEL_SUBJECT" }),
        ),
    ] {
        assert!(
            scan_json_value(surface, &projection, &policy).is_err(),
            "{surface:?} should reject {projection}"
        );
    }
}
