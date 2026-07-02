use server::verification_context::{
    ContextProjectionError, VerificationContext, CANONICAL_SERIALIZATION,
    CONTEXT_FINGERPRINT_VERSION, CONTEXT_SCHEMA_ID, CONTEXT_SCHEMA_VERSION,
};
use server::manifest::membership_provision_descriptor;

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

#[test]
fn context_binding_manifest_projection() {
    let descriptor = membership_provision_descriptor();
    let expected = VerificationContext::expected_from_descriptor(
        "receiver.alpha",
        "audience.alpha",
        &descriptor,
        Some("resource://demo/membership"),
        "request.fixture",
        "challenge.fixture",
        "nonce:sha256:fixture",
        1_700_000_000,
    )
    .unwrap();

    assert_eq!(expected.receiver_id, "receiver.alpha");
    assert_eq!(expected.audience_id, "audience.alpha");
    assert_eq!(expected.operation_id, descriptor.name.as_str());
    assert_eq!(expected.opcode, descriptor.opcode);
    assert_eq!(expected.handler_id, descriptor.handler_id);
    assert_eq!(expected.resource_id, "resource://demo/membership");
    assert_eq!(
        expected.descriptor_fingerprint,
        descriptor.authorization_fingerprint()
    );
    assert_eq!(expected.manifest_id, "receiver-local-default-v0");
    assert_eq!(expected.privacy_policy_id, "secs-i02-compat-privacy-policy");
    assert_eq!(
        expected.disclosure_scope_id,
        "secs-i02-compat-disclosure-scope"
    );
    assert_eq!(
        expected.required_adapter_kind,
        "wallet_presentation+membership_credential+dregg_authority"
    );

    let changed_resource = VerificationContext::expected_from_descriptor(
        "receiver.alpha",
        "audience.alpha",
        &descriptor,
        Some("resource://demo/other"),
        "request.fixture",
        "challenge.fixture",
        "nonce:sha256:fixture",
        1_700_000_000,
    )
    .unwrap();
    assert_ne!(
        expected.context_fingerprint().unwrap(),
        changed_resource.context_fingerprint().unwrap()
    );
}

#[test]
fn context_binding_expected_context_required_fields() {
    let descriptor = membership_provision_descriptor();
    let error = VerificationContext::expected_from_descriptor(
        "receiver.alpha",
        "audience.alpha",
        &descriptor,
        None,
        "request.fixture",
        "challenge.fixture",
        "nonce:sha256:fixture",
        1_700_000_000,
    )
    .unwrap_err();

    assert_eq!(
        error,
        ContextProjectionError::MissingRequiredField("resource_id")
    );
    assert_eq!(error.reason_code(), "context_missing_required_field");
}
