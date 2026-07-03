use server::nullifier::NullifierReason;
use server::receipt::{Decision, Receipt};
use server::verifier::{
    SignedVerifiedCallContext, VerifiedCallContext, VerifiedSubject,
    VERIFIED_CALL_CONTEXT_SCHEMA_VERSION,
};

fn context() -> VerifiedCallContext {
    VerifiedCallContext {
        schema_version: VERIFIED_CALL_CONTEXT_SCHEMA_VERSION,
        context_id: "ctx-i04-privacy".to_string(),
        packet_hash: [4u8; 32],
        session_id: [5u8; 16],
        nonce: [6u8; 12],
        opcode: 0x50,
        operation: "demo.file.write".to_string(),
        resource: Some("file:///tmp/secS/private-note.txt".to_string()),
        subject: VerifiedSubject {
            subject_id: "holder:must-not-appear".to_string(),
            key_id: "wallet-key:must-not-appear".to_string(),
        },
        audience: "secS://receiver-a".to_string(),
        evidence_summary: vec![
            "scoped_use_required".to_string(),
            "nullifier_epoch:epoch-1".to_string(),
            "nullifier_issuer:issuer-a".to_string(),
            "nullifier_root:root-a".to_string(),
            "subject_commitment:subject-commitment-private".to_string(),
            "nullifier_commitment:nullifier-secret-private".to_string(),
            "raw_credential_id:credential-private".to_string(),
        ],
        capability_result: "ok".to_string(),
        credential_result: "ok".to_string(),
        issued_at: 10,
        expires_at: 310,
        descriptor_fingerprint: "descriptor:fixture".to_string(),
        replay_scope: "session_opcode_nonce".to_string(),
        handler_id: Some("demo/file-write".to_string()),
    }
}

fn serialized_summary(receipt: &Receipt) -> String {
    serde_json::to_string(&receipt.evidence_summary).expect("receipt summary serializes")
}

fn assert_no_forbidden_material(serialized: &str) {
    for forbidden in [
        "holder:must-not-appear",
        "wallet-key:must-not-appear",
        "subject-commitment-private",
        "nullifier-secret-private",
        "credential-private",
        "raw_credential_id",
        "remaining_allowance",
        "balance",
        "quota_remaining",
        "spent_count",
        "counter",
        "private-note.txt",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "forbidden nullifier/private material leaked into receipt summary: {forbidden} in {serialized}"
        );
    }
}

#[test]
fn nullifier_receipt_contains_only_redacted_fingerprints() {
    let receipt = Receipt::execution("receipt-i04-ok", &context(), Decision::Accepted, None, 100);
    let serialized = serialized_summary(&receipt);

    assert!(serialized.contains("scoped_use_enforced:true"));
    assert!(serialized.contains("nullifier_domain_version:nullifier-domain-v1"));
    assert!(serialized.contains("nullifier_outcome:scoped_use_recorded"));
    assert!(serialized.contains("nullifier_domain_fingerprint:"));
    assert!(serialized.contains("nullifier_commitment_fingerprint:"));
    assert_no_forbidden_material(&serialized);
}

#[test]
fn nullifier_reject_trace_omits_forbidden_private_fields() {
    let receipt = Receipt::execution(
        "receipt-i04-duplicate",
        &context(),
        Decision::Rejected,
        Some(NullifierReason::DuplicateNullifier.as_str()),
        101,
    );
    let serialized = serialized_summary(&receipt);

    assert!(serialized.contains("nullifier_outcome:duplicate_nullifier"));
    assert!(serialized.contains("nullifier_domain_fingerprint:"));
    assert!(serialized.contains("nullifier_commitment_fingerprint:"));
    assert_no_forbidden_material(&serialized);
}

#[test]
fn remaining_allowance_not_emitted_without_counter_state() {
    let receipt = Receipt::execution("receipt-i04-ok", &context(), Decision::Accepted, None, 100);
    let serialized = serialized_summary(&receipt);

    assert!(!serialized.contains("remaining_allowance"));
    assert!(!serialized.contains("quota_remaining"));
    assert!(!serialized.contains("spent_count"));
    assert!(!serialized.contains("counter"));
}

#[test]
fn verify_receipts_sanitize_scoped_nullifier_evidence_summary() {
    let signed = SignedVerifiedCallContext {
        context: context(),
        signer_key_id: "fixture-verifier".to_string(),
        authenticator_kind: server::receipt::AuthenticatorKind::Ed25519Verifier,
        signature: vec![1, 2, 3],
    };
    let receipt = Receipt::verify_from_signed_context("receipt-i04-verify", &signed, 102);
    let serialized = serialized_summary(&receipt);

    assert!(serialized.contains("nullifier_outcome:scoped_use_recorded"));
    assert_no_forbidden_material(&serialized);
}
