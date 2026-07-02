use server::verification_context::{
    VerificationContext, CANONICAL_SERIALIZATION, CONTEXT_FINGERPRINT_VERSION, CONTEXT_SCHEMA_ID,
    CONTEXT_SCHEMA_VERSION,
};

#[test]
fn context_binding_canonical_serialization() {
    let context = VerificationContext::fixture();

    assert_eq!(CONTEXT_SCHEMA_ID, "secs-verification-context");
    assert_eq!(CONTEXT_SCHEMA_VERSION, 1);
    assert_eq!(CANONICAL_SERIALIZATION, "secs-verification-context-json-v1");
    assert_eq!(CONTEXT_FINGERPRINT_VERSION, "secs-vctx-fp-v1");

    let first = context.canonical_json().unwrap();
    let second = context.canonical_json().unwrap();
    assert_eq!(first, second);
    assert!(first.contains("\"context_schema_id\":\"secs-verification-context\""));
    assert!(first.contains("\"canonical_serialization\":\"secs-verification-context-json-v1\""));

    let fingerprint = context.context_fingerprint().unwrap();
    assert!(fingerprint.starts_with("secs-vctx-fp-v1:sha256:"));
    assert_eq!(fingerprint, context.context_fingerprint().unwrap());

    let changed = context.with_audience_id("audience.changed");
    assert_ne!(fingerprint, changed.context_fingerprint().unwrap());
}

#[test]
fn context_binding_public_data_contract() {
    let context = VerificationContext::fixture();
    let json = context.canonical_json().unwrap();
    let forbidden = [
        "raw_credential",
        "credential_attribute",
        "raw_proof",
        "proof_witness",
        "wallet_id",
        "holder_id",
        "bearer_token",
        "source_auth_token",
        "private_key",
        "nullifier_preimage",
        "payload_bytes",
        "signature_bytes",
    ];

    for needle in forbidden {
        assert!(
            !json.contains(needle),
            "serialized context leaked {needle}: {json}"
        );
    }
}
