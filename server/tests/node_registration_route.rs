use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use server::gateway::{init_telemetry_schema, register_runtime_bindings, ConfigurableRouter};
use server::ledger::Ledger;
use server::manifest::node_registration_descriptor;
use server::node_registration::{
    NodeRegistrationRequestV0, NODE_REGISTRATION_AUTHORITY_SOURCE_ID,
    NODE_REGISTRATION_DISCLOSURE_POLICY_ID, NODE_REGISTRATION_OPCODE, NODE_REGISTRATION_OPERATION,
};
use server::runtime_mode::RuntimeMode;
use server::verifier::{VerifiedCallContext, VerifiedSubject};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn resource() -> &'static str {
    "node:castalia:node-public-1:keyfp:endpoint-hash:v0"
}

fn request(at: u64) -> NodeRegistrationRequestV0 {
    NodeRegistrationRequestV0 {
        schema_version: 0,
        operation: NODE_REGISTRATION_OPERATION.to_string(),
        opcode: NODE_REGISTRATION_OPCODE,
        request_id: "route-registration-request".to_string(),
        audience: "secS://receiver-a".to_string(),
        resource: resource().to_string(),
        node_public_key_fingerprint: "keyfp".to_string(),
        endpoint_hash: "endpoint-hash".to_string(),
        authority_source_id: NODE_REGISTRATION_AUTHORITY_SOURCE_ID.to_string(),
        evidence_ref: "fixture:route-registration".to_string(),
        evidence_tier: "local_verified".to_string(),
        descriptor_fingerprint: node_registration_descriptor().authorization_fingerprint(),
        disclosure_policy_id: NODE_REGISTRATION_DISCLOSURE_POLICY_ID.to_string(),
        issued_at: at,
        expires_at: at + 300,
        requested_disclosure: vec!["public_node_id".to_string(), "endpoint_hash".to_string()],
    }
}

async fn pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    pool
}

fn signed_for(
    router: &ConfigurableRouter,
    request: &NodeRegistrationRequestV0,
) -> server::verifier::SignedVerifiedCallContext {
    let context = VerifiedCallContext {
        schema_version: server::verifier::VERIFIED_CALL_CONTEXT_SCHEMA_VERSION,
        context_id: format!("ctx-{}", request.request_id),
        packet_hash: [7; 32],
        session_id: [8; 16],
        nonce: [9; 12],
        opcode: NODE_REGISTRATION_OPCODE,
        operation: NODE_REGISTRATION_OPERATION.to_string(),
        resource: Some(resource().to_string()),
        subject: VerifiedSubject {
            subject_id: "fixture-local-registration-caller".to_string(),
            key_id: "fixture-local-registration-caller#key".to_string(),
        },
        audience: "secS://receiver-a".to_string(),
        evidence_summary: vec![
            "authority_mode:local_fixture".to_string(),
            "evidence_tier:local_verified".to_string(),
            format!("authority_source_id:{NODE_REGISTRATION_AUTHORITY_SOURCE_ID}"),
            "evidence_ref_kind:fixture".to_string(),
        ],
        proof_metadata: None,
        capability_result: NODE_REGISTRATION_OPERATION.to_string(),
        credential_result: "accepted".to_string(),
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        descriptor_fingerprint: node_registration_descriptor().authorization_fingerprint(),
        replay_scope: "session:opcode:nonce".to_string(),
        handler_id: Some(server::node_registration::NODE_REGISTRATION_HANDLER_ID.to_string()),
    };
    router.identity().sign_context(context).unwrap()
}

async fn untouched_counts(pool: &SqlitePool) -> (i64, i64, i64, i64) {
    let replay: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM replay_reservations")
        .fetch_one(pool)
        .await
        .unwrap();
    let nullifiers: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM scoped_nullifier_uses")
        .fetch_one(pool)
        .await
        .unwrap();
    let accepted_execute: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE kind = 'execute' AND decision = 'accepted'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let lifecycle: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_kind IN ('handler_started', 'handler_succeeded', 'handler_failed')",
    ).fetch_one(pool).await.unwrap();
    (replay.0, nullifiers.0, accepted_execute.0, lifecycle.0)
}

#[tokio::test]
async fn real_verified_route_parses_registration_and_dispatches_registration_program_once() {
    let pool = pool().await;
    let executions = Arc::new(AtomicU64::new(0));
    let mut router = ConfigurableRouter::new(pool.clone());
    register_runtime_bindings(&mut router, RuntimeMode::LocalDevPlaintext);
    router.install_node_registration_program(executions.clone());
    let request = request(now());
    let signed = signed_for(&router, &request);

    let response = router
        .route_verified(&signed, serde_json::to_vec(&request).unwrap())
        .await;

    assert!(response.is_accepted());
    assert_eq!(executions.load(Ordering::SeqCst), 1);
    let counts = untouched_counts(&pool).await;
    assert_eq!(counts.0, 1);
    assert_eq!(counts.2, 1);
    assert_eq!(counts.3, 2);

    let chain = Ledger::new(pool)
        .inspect_receipt_chain_by_context_id(&signed.context.context_id)
        .await
        .unwrap();
    let execute = chain
        .iter()
        .find(|receipt| receipt.kind == "execute")
        .unwrap();
    let projection = execute.evidence_summary.join("|");
    for required in [
        "registration_scope:local_fixture_only",
        "registration_evidence_tier:local_verified",
        "registration_resource_hash:resource:sha256:",
        "registration_disclosure_policy:registration_public_directory_v0",
        "registration_schema_version:0",
    ] {
        assert!(
            projection.contains(required),
            "missing {required}: {projection}"
        );
    }
    for forbidden in [
        "route-registration-request",
        "keyfp",
        "endpoint-hash",
        "fixture:route",
    ] {
        assert!(
            !projection.contains(forbidden),
            "leaked {forbidden}: {projection}"
        );
    }
}

#[tokio::test]
async fn real_verified_route_reject_families_precede_all_mutable_routing_state() {
    type Mutation = Box<dyn Fn(&mut NodeRegistrationRequestV0, &mut VerifiedCallContext)>;
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "malformed payload",
            Box::new(|request, _| request.operation.clear()),
        ),
        (
            "descriptor",
            Box::new(|request, _| request.descriptor_fingerprint = "wrong".into()),
        ),
        (
            "authority",
            Box::new(|request, _| request.authority_source_id = "caller".into()),
        ),
        (
            "tier",
            Box::new(|request, _| request.evidence_tier = "shape_only".into()),
        ),
        (
            "audience",
            Box::new(|request, _| request.audience = "secs://wrong".into()),
        ),
        (
            "resource",
            Box::new(|request, _| request.resource = "node:wrong".into()),
        ),
        (
            "manifest",
            Box::new(|_request, context| context.descriptor_fingerprint = "wrong".into()),
        ),
        (
            "privacy",
            Box::new(|request, _| request.requested_disclosure.push("holder_id".into())),
        ),
        (
            "freshness",
            Box::new(|request, _| request.expires_at = request.issued_at - 1),
        ),
    ];

    for (name, mutate) in cases {
        let pool = pool().await;
        let executions = Arc::new(AtomicU64::new(0));
        let mut router = ConfigurableRouter::new(pool.clone());
        register_runtime_bindings(&mut router, RuntimeMode::LocalDevPlaintext);
        router.install_node_registration_program(executions.clone());
        let mut request = request(now());
        let mut signed = signed_for(&router, &request);
        mutate(&mut request, &mut signed.context);
        signed = router.identity().sign_context(signed.context).unwrap();

        let response = router
            .route_verified(&signed, serde_json::to_vec(&request).unwrap())
            .await;

        assert!(!response.is_accepted(), "{name}");
        assert_eq!(executions.load(Ordering::SeqCst), 0, "{name}");
        assert_eq!(untouched_counts(&pool).await, (0, 0, 0, 0), "{name}");
    }
}

#[tokio::test]
async fn malformed_registration_json_rejects_before_mutable_routing_state() {
    let pool = pool().await;
    let executions = Arc::new(AtomicU64::new(0));
    let mut router = ConfigurableRouter::new(pool.clone());
    register_runtime_bindings(&mut router, RuntimeMode::LocalDevPlaintext);
    router.install_node_registration_program(executions.clone());
    let request = request(now());
    let signed = signed_for(&router, &request);

    let response = router.route_verified(&signed, b"not-json".to_vec()).await;

    assert_eq!(
        response.reason_code.as_deref(),
        Some("malformed_registration_payload")
    );
    assert_eq!(executions.load(Ordering::SeqCst), 0);
    assert_eq!(untouched_counts(&pool).await, (0, 0, 0, 0));
}
