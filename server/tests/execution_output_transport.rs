use async_trait::async_trait;
use libsec_core::execution_response::{
    ExecutionAuthenticatorKind, ExecutionResponse, ExecutionStatus,
    EXECUTION_RESPONSE_SCHEMA_VERSION, EXECUTION_RESPONSE_TOO_LARGE, HANDLER_OUTPUT_MISSING,
    HANDLER_OUTPUT_UNEXPECTED, MAX_EXECUTION_RESPONSE_BYTES, OUTPUT_TOO_LARGE,
};
use server::gateway::{
    init_telemetry_schema, ConfigurableRouter, ExecutionLimits, HandlerOutcome, MachineProgram,
};
use server::manifest::{
    OpcodeRange, OperationDescriptor, OperationName, OutputProfile, ReceiverManifest, ReplayScope,
    TargetKind,
};
use server::privacy::DisclosurePolicy;
use server::verifier::{VerifiedCallContext, Verifier};
use sqlx::sqlite::SqlitePoolOptions;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct OutputProgram;

#[async_trait]
impl MachineProgram for OutputProgram {
    async fn execute(
        &self,
        _context: &VerifiedCallContext,
        _payload: &[u8],
        _limits: ExecutionLimits,
    ) -> HandlerOutcome {
        HandlerOutcome::succeeded_with_output(b"bounded".to_vec())
    }
}

async fn memory_pool() -> sqlx::SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    pool
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn node_identity_signs_domain_specific_execution_response() {
    let identity = server::identity::explicit_test_fixture_identity("receiver-key-1", [7; 32]);
    let response = ExecutionResponse {
        schema_version: EXECUTION_RESPONSE_SCHEMA_VERSION,
        status: ExecutionStatus::Executed,
        reason_code: None,
        request_digest: [4; 32],
        context_id: Some("ctx-1".into()),
        receipt_id: Some("receipt-1".into()),
        output_schema: Some("fixture.response.v1".into()),
        output: Some(b"bounded".to_vec()),
        authenticator_kind: ExecutionAuthenticatorKind::Ed25519Receiver,
        signer_key_id: "receiver-key-1".into(),
        signature: [0; 64],
    };
    let signed = identity.sign_execution_response(response).unwrap();
    let frame = signed.encode_frame(MAX_EXECUTION_RESPONSE_BYTES).unwrap();
    let verified = ExecutionResponse::decode_and_verify(
        &frame,
        MAX_EXECUTION_RESPONSE_BYTES,
        7,
        "receiver-key-1",
        identity.public_key(),
        [4; 32],
        Some("fixture.response.v1"),
    )
    .unwrap();
    assert_eq!(verified.output.as_deref(), Some(b"bounded".as_slice()));
}

#[tokio::test]
async fn bounded_ingress_carries_digest_of_exact_raw_bytes() {
    use libsec_core::ZenithPacket;
    use sha2::{Digest, Sha256};
    let packet = ZenithPacket {
        session_id: [1; 16],
        nonce: [2; 12],
        opcode: 0x10,
        proof: vec![3],
        claim_ttl: 30,
        encrypted_payload: vec![4, 5],
        mac: [0; 16],
    };
    let bytes = bincode::serialize(&packet).unwrap();
    let decoded = server::ingress::read_bounded_ingress_request(
        bytes.as_slice(),
        bytes.len(),
        Duration::from_secs(1),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        decoded.request_digest,
        <[u8; 32]>::from(Sha256::digest(&bytes))
    );
}

#[tokio::test]
async fn public_execution_route_signs_all_three_execution_states() {
    use libsec_core::ZenithPacket;
    let identity =
        server::identity::explicit_test_fixture_identity("verifier:local-prototype", [7; 32]);
    let profile = OutputProfile {
        schema_id: "fixture.response.v1".into(),
        max_output_bytes: 8,
        max_execution_response_bytes: 512,
    };
    let manifest = ReceiverManifest::new([descriptor(Some(profile))]);
    let signed_for = |nonce: u8, audience: &str| {
        let packet = ZenithPacket {
            session_id: [1; 16],
            nonce: [nonce; 12],
            opcode: 0x52,
            proof: vec![1],
            claim_ttl: 30,
            encrypted_payload: b"request".to_vec(),
            mac: [0; 16],
        };
        Verifier::verify_manifest_operation_and_sign(
            &packet,
            &manifest,
            audience,
            now(),
            "verifier:local-prototype",
            &[7; 32],
        )
        .unwrap()
    };

    let executed_pool = memory_pool().await;
    let mut executed_router =
        ConfigurableRouter::with_identity(executed_pool.clone(), identity.clone());
    executed_router.set_manifest(manifest.clone());
    executed_router.register(0x52, Box::new(OutputProgram));
    let executed = executed_router
        .route_verified_for_execution(
            &signed_for(2, "secS://receiver-a"),
            b"request".to_vec(),
            [2; 32],
        )
        .await
        .unwrap();
    assert_eq!(executed.status, ExecutionStatus::Executed);
    assert_eq!(executed.output.as_deref(), Some(b"bounded".as_slice()));
    let executed_frame = executed.encode_frame(512).unwrap();
    ExecutionResponse::decode_and_verify(
        &executed_frame,
        512,
        8,
        "verifier:local-prototype",
        identity.public_key(),
        [2; 32],
        Some("fixture.response.v1"),
    )
    .unwrap();
    let receipt_id = executed.receipt_id.as_deref().unwrap();
    let persisted: (String, i64, Vec<u8>) = sqlx::query_as(
        "SELECT output_schema_id, output_byte_count, output_digest_sha256 FROM receipts WHERE receipt_id = ?",
    )
    .bind(receipt_id)
    .fetch_one(&executed_pool)
    .await
    .unwrap();
    assert_eq!(persisted.0, "fixture.response.v1");
    assert_eq!(persisted.1, 7);
    assert_eq!(persisted.2.len(), 32);

    let mut rejected_router =
        ConfigurableRouter::with_identity(memory_pool().await, identity.clone());
    rejected_router.set_manifest(manifest.clone());
    let rejected = rejected_router
        .route_verified_for_execution(
            &signed_for(3, "secS://receiver-a"),
            b"request".to_vec(),
            [3; 32],
        )
        .await
        .unwrap();
    assert_eq!(rejected.status, ExecutionStatus::ExecutionRejected);
    assert_eq!(rejected.reason_code.as_deref(), Some("handler_unavailable"));

    let mut verifier_router = ConfigurableRouter::with_identity(memory_pool().await, identity);
    verifier_router.set_manifest(manifest.clone());
    let verifier_rejected = verifier_router
        .route_verified_for_execution(&signed_for(4, "secS://other"), b"request".to_vec(), [4; 32])
        .await
        .unwrap();
    assert_eq!(verifier_rejected.status, ExecutionStatus::VerifierRejected);
    assert_eq!(
        verifier_rejected.reason_code.as_deref(),
        Some("wrong_audience")
    );
    assert_eq!(verifier_rejected.output, None);
}

fn descriptor(output_profile: Option<OutputProfile>) -> OperationDescriptor {
    OperationDescriptor {
        opcode: 0x52,
        name: OperationName::new("fixture.output.v1"),
        payload_schema: Some("fixture.request.v1".into()),
        output_profile,
        target_kind: TargetKind::LocalDevProcess,
        required_credentials: vec!["fixture".into()],
        required_capabilities: vec!["fixture.execute".into()],
        accepted_evidence: vec!["prototype-proof-envelope".into()],
        required_authority_mode: None,
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 30,
        handler_id: "fixture/output".into(),
        dev_binding: true,
        range: OpcodeRange::OperatorDefined,
        disclosure_policy: DisclosurePolicy::default_i02(),
    }
}

#[test]
fn output_profile_is_receiver_owned_fingerprinted_and_effectively_bounded() {
    let profile = OutputProfile {
        schema_id: "fixture.response.v1".into(),
        max_output_bytes: 8,
        max_execution_response_bytes: 512,
    };
    let with_output = descriptor(Some(profile.clone()));
    let without_output = descriptor(None);
    assert_ne!(
        with_output.authorization_fingerprint(),
        without_output.authorization_fingerprint()
    );

    for mutated in [
        OutputProfile {
            schema_id: "fixture.response.v2".into(),
            ..profile.clone()
        },
        OutputProfile {
            max_output_bytes: 7,
            ..profile.clone()
        },
        OutputProfile {
            max_execution_response_bytes: 511,
            ..profile.clone()
        },
    ] {
        assert_ne!(
            with_output.authorization_fingerprint(),
            descriptor(Some(mutated)).authorization_fingerprint()
        );
    }

    let limits = ExecutionLimits {
        max_payload_bytes: 1024,
        max_output_bytes: 6,
        handler_timeout: Duration::from_secs(1),
    };
    let effective = limits.for_output_profile(&profile).unwrap();
    assert_eq!(effective.max_output_bytes, 6);
    assert_eq!(effective.max_execution_response_bytes, 512);
}

#[test]
fn handler_outcome_owns_bytes_and_reason_vocabulary_is_exact() {
    assert_eq!(HandlerOutcome::succeeded().output, None);
    assert_eq!(
        HandlerOutcome::succeeded_with_output(Vec::new()).output,
        Some(Vec::new())
    );
    assert_eq!(HandlerOutcome::rejected("handler_timeout").output, None);
    assert_eq!(
        [
            HANDLER_OUTPUT_MISSING,
            HANDLER_OUTPUT_UNEXPECTED,
            OUTPUT_TOO_LARGE,
            EXECUTION_RESPONSE_TOO_LARGE,
        ],
        [
            "handler_output_missing",
            "handler_output_unexpected",
            "output_too_large",
            "execution_response_too_large",
        ]
    );
}

#[test]
fn invalid_output_profiles_fail_closed_without_clamping() {
    for profile in [
        OutputProfile {
            schema_id: String::new(),
            max_output_bytes: 1,
            max_execution_response_bytes: 128,
        },
        OutputProfile {
            schema_id: "fixture.response.v1".into(),
            max_output_bytes: 0,
            max_execution_response_bytes: 128,
        },
        OutputProfile {
            schema_id: "fixture.response.v1".into(),
            max_output_bytes: 1,
            max_execution_response_bytes: 0,
        },
    ] {
        assert!(descriptor(Some(profile)).validate().is_err());
    }
}
