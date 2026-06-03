use libsec_core::ZenithPacket;
use server::identity::{load_node_verifier_identity, VerifierIdentityConfig};
use server::manifest::ReceiverManifest;
use server::runtime_mode::RuntimeMode;
use server::verifier::{
    AuthenticatorKind, VerificationError, VerifiedCallContext, VerifiedSubject, Verifier,
};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn sample_context() -> VerifiedCallContext {
    VerifiedCallContext {
        schema_version: 1,
        context_id: "ctx_test".to_string(),
        packet_hash: [7u8; 32],
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode: 0x10,
        operation: "queue.enqueue".to_string(),
        subject: VerifiedSubject {
            subject_id: "did:example:alice".to_string(),
            key_id: "did:example:alice#key-1".to_string(),
        },
        audience: "secS://receiver-a".to_string(),
        evidence_summary: vec!["local_static:test".to_string()],
        capability_result: "allowed".to_string(),
        credential_result: "accepted".to_string(),
        issued_at: 100,
        expires_at: 200,
        replay_scope: "session:opcode:nonce".to_string(),
        handler_id: Some("local_queue_bridge".to_string()),
    }
}

#[test]
fn verification_error_has_stable_reason_code() {
    assert_eq!(
        VerificationError::WrongAudience.reason_code(),
        "wrong_audience"
    );
}

#[test]
fn signed_context_verifies_and_rejects_tampering() {
    let key = [9u8; 32];
    let context = sample_context();
    let signed = context
        .sign_ed25519("verifier:test", &key, AuthenticatorKind::Ed25519Verifier)
        .unwrap();

    signed
        .verify_ed25519(&key, "secS://receiver-a", 150)
        .unwrap();

    let mut tampered = signed.clone();
    tampered.context.operation = "agent.chat".to_string();
    assert_eq!(
        tampered
            .verify_ed25519(&key, "secS://receiver-a", 150)
            .unwrap_err(),
        VerificationError::InvalidSignature
    );
}

#[test]
fn signed_context_rejects_wrong_audience_and_expiry() {
    let key = [3u8; 32];
    let signed = sample_context()
        .sign_ed25519("verifier:test", &key, AuthenticatorKind::Ed25519Verifier)
        .unwrap();

    assert_eq!(
        signed
            .verify_ed25519(&key, "secS://other", 150)
            .unwrap_err(),
        VerificationError::WrongAudience
    );
    assert_eq!(
        signed
            .verify_ed25519(&key, "secS://receiver-a", 201)
            .unwrap_err(),
        VerificationError::ExpiredClaim
    );
}

#[test]
fn signed_context_rejects_wrong_key() {
    let signed = sample_context()
        .sign_ed25519(
            "verifier:test",
            &[3u8; 32],
            AuthenticatorKind::Ed25519Verifier,
        )
        .unwrap();

    assert_eq!(
        signed
            .verify_ed25519(&[4u8; 32], "secS://receiver-a", 150)
            .unwrap_err(),
        VerificationError::InvalidSignature
    );
}

fn prototype_packet(proof: Vec<u8>, ttl: u64) -> ZenithPacket {
    ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode: 0x10,
        proof,
        claim_ttl: ttl,
        encrypted_payload: b"payload".to_vec(),
        mac: [0u8; 16],
    }
}

fn unique_temp_key_path(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("secs-magik-{name}-{nanos}.key"))
}

fn write_key_file(bytes: [u8; 32]) -> std::path::PathBuf {
    let path = unique_temp_key_path("b3-verifier-context");
    fs::write(
        &path,
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .expect("key fixture should be writable");
    path
}

#[test]
fn prototype_envelope_accepts_non_empty_proof_and_positive_ttl() {
    let packet = prototype_packet(vec![1], 1);

    Verifier::verify_prototype_envelope(&packet).unwrap();
}

#[test]
fn prototype_envelope_rejects_empty_proof_with_typed_error() {
    let packet = prototype_packet(vec![], 1);

    assert_eq!(
        Verifier::verify_prototype_envelope(&packet).unwrap_err(),
        VerificationError::MissingPrototypeProofEnvelope
    );
}

#[test]
fn prototype_envelope_rejects_zero_ttl_with_typed_error() {
    let packet = prototype_packet(vec![1], 0);

    assert_eq!(
        Verifier::verify_prototype_envelope(&packet).unwrap_err(),
        VerificationError::ExpiredClaim
    );
}

#[test]
fn verifier_signs_manifest_described_context_before_execution() {
    let packet = prototype_packet(vec![1], 600);
    let manifest = ReceiverManifest::default_v0();
    let key = [7u8; 32];

    let signed = Verifier::verify_manifest_operation_and_sign(
        &packet,
        &manifest,
        "secS://receiver-a",
        1_000,
        "verifier:local-test",
        &key,
    )
    .unwrap();

    assert_eq!(signed.signer_key_id, "verifier:local-test");
    assert_eq!(
        signed.authenticator_kind,
        AuthenticatorKind::Ed25519Verifier
    );
    assert_eq!(signed.context.opcode, 0x10);
    assert_eq!(signed.context.operation, "candidate.dev.bash_echo");
    assert_eq!(signed.context.handler_id.as_deref(), Some("dev/bash-echo"));
    assert_eq!(signed.context.audience, "secS://receiver-a");
    assert_eq!(signed.context.issued_at, 1_000);
    assert_eq!(signed.context.expires_at, 1_300);
    assert_eq!(signed.context.replay_scope, "session:opcode:nonce");

    signed
        .verify_ed25519(&key, "secS://receiver-a", 1_100)
        .unwrap();
}

#[test]
fn verifier_signs_manifest_context_with_loaded_production_identity() {
    let path = write_key_file([0x44; 32]);
    let identity = load_node_verifier_identity(&VerifierIdentityConfig {
        runtime_mode: RuntimeMode::ProductionVerified,
        verifier_key_path: Some(path.clone()),
        verifier_key_id: None,
    })
    .expect("production identity should load from configured key path");
    let packet = prototype_packet(vec![1], 600);
    let manifest = ReceiverManifest::default_v0();

    let signed = Verifier::verify_manifest_operation_and_sign_with_identity(
        &packet,
        &manifest,
        "secS://receiver-a",
        1_000,
        &identity,
    )
    .expect("production identity should sign manifest context");

    assert_eq!(signed.signer_key_id, identity.signer_key_id());
    assert_eq!(
        signed.authenticator_kind,
        AuthenticatorKind::Ed25519NodeAndVerifier
    );
    assert!(!signed.signature.is_empty());
    signed
        .verify_ed25519_with_key(identity.public_key(), "secS://receiver-a", 1_100)
        .expect("configured public key should verify the context");

    let _ = fs::remove_file(path);
}

#[test]
fn verifier_rejects_unknown_opcode_before_signed_context() {
    let mut packet = prototype_packet(vec![1], 600);
    packet.opcode = 0x99;
    let manifest = ReceiverManifest::default_v0();

    assert_eq!(
        Verifier::verify_manifest_operation_and_sign(
            &packet,
            &manifest,
            "secS://receiver-a",
            1_000,
            "verifier:local-test",
            &[7u8; 32],
        )
        .unwrap_err(),
        VerificationError::UnknownOperation
    );
}
