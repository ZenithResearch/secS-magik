use libsec_core::ZenithPacket;
use server::verifier::{
    AuthenticatorKind, VerificationError, VerifiedCallContext, VerifiedSubject, Verifier,
};

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
