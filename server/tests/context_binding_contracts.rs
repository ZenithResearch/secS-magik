use server::manifest::membership_provision_descriptor;
use server::verification_context::{
    verify_context_binding, verify_context_binding_then_run, ContextBindingReason,
    ContextProjectionError, VerificationContext, CANONICAL_SERIALIZATION,
    CONTEXT_FINGERPRINT_VERSION, CONTEXT_SCHEMA_ID, CONTEXT_SCHEMA_VERSION,
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

#[test]
fn context_binding_expected_observed_positive() {
    let expected = VerificationContext::fixture();
    let observed = expected.clone();
    let binding = verify_context_binding(&expected, &observed).unwrap();

    assert_eq!(
        binding.context_fingerprint,
        expected.context_fingerprint().unwrap()
    );
    assert_eq!(binding.reason_code(), "context_binding_verified");
}

#[test]
fn context_binding_observed_missing_required_fields() {
    let expected = VerificationContext::fixture();
    let mut observed = expected.clone();
    observed.federation_id = None;

    let error = verify_context_binding(&expected, &observed).unwrap_err();
    assert_eq!(
        error.reason,
        ContextBindingReason::ContextMissingRequiredField
    );
    assert_eq!(error.dimension, "federation_id");
    assert_eq!(error.reason_code(), "context_missing_required_field");
}

#[test]
fn context_binding_handler_not_run_on_reject() {
    let expected = VerificationContext::fixture();
    let observed = expected.with_audience_id("audience.other");
    let mut handler_ran = false;

    let error = verify_context_binding_then_run(&expected, &observed, || {
        handler_ran = true;
    })
    .unwrap_err();

    assert_eq!(error.reason, ContextBindingReason::AudienceMismatch);
    assert!(!handler_ran);
}

#[test]
fn context_binding_one_field_mismatch_matrix() {
    let cases: Vec<(&str, ContextBindingReason, fn(&mut VerificationContext))> = vec![
        ("receiver_id", ContextBindingReason::AudienceMismatch, |c| c.receiver_id = "receiver.other".into()),
        ("audience_id", ContextBindingReason::AudienceMismatch, |c| c.audience_id = "audience.other".into()),
        ("operation_id", ContextBindingReason::OperationMismatch, |c| c.operation_id = "operation.other".into()),
        ("handler_id", ContextBindingReason::OperationMismatch, |c| c.handler_id = "handler/other".into()),
        ("resource_id", ContextBindingReason::ResourceMismatch, |c| c.resource_id = "resource://other".into()),
        ("subject_commitment", ContextBindingReason::SubjectBindingMismatch, |c| c.subject_commitment = Some("subject:other".into())),
        ("issuer_id", ContextBindingReason::AuthoritySourceMismatch, |c| c.issuer_id = Some("issuer.other".into())),
        ("authority_source_id", ContextBindingReason::AuthoritySourceMismatch, |c| c.authority_source_id = Some("source.other".into())),
        ("federation_id", ContextBindingReason::FederationMismatch, |c| c.federation_id = Some("federation.other".into())),
        ("committee_id", ContextBindingReason::FederationMismatch, |c| c.committee_id = Some("committee.other".into())),
        ("root_id", ContextBindingReason::RootCheckpointMismatch, |c| c.root_id = Some("root.other".into())),
        ("checkpoint_id", ContextBindingReason::RootCheckpointMismatch, |c| c.checkpoint_id = Some("checkpoint.other".into())),
        ("root_epoch", ContextBindingReason::EpochMismatch, |c| c.root_epoch = Some("epoch-other".into())),
        ("validity_window_id", ContextBindingReason::EpochMismatch, |c| c.validity_window_id = "window.other".into()),
        ("request_id", ContextBindingReason::ChallengeMismatch, |c| c.request_id = "request.other".into()),
        ("challenge_id", ContextBindingReason::ChallengeMismatch, |c| c.challenge_id = "challenge.other".into()),
        ("manifest_id", ContextBindingReason::ManifestMismatch, |c| c.manifest_id = "manifest.other".into()),
        ("manifest_version", ContextBindingReason::ManifestMismatch, |c| c.manifest_version = "2".into()),
        ("manifest_fingerprint", ContextBindingReason::ManifestMismatch, |c| c.manifest_fingerprint = "manifest:other".into()),
        ("descriptor_id", ContextBindingReason::DescriptorMismatch, |c| c.descriptor_id = "descriptor.other".into()),
        ("descriptor_version", ContextBindingReason::DescriptorMismatch, |c| c.descriptor_version = "2".into()),
        ("descriptor_fingerprint", ContextBindingReason::DescriptorMismatch, |c| c.descriptor_fingerprint = "descriptor:other".into()),
        ("privacy_policy_id", ContextBindingReason::PrivacyPolicyMismatch, |c| c.privacy_policy_id = "privacy.other".into()),
        ("privacy_policy_version", ContextBindingReason::PrivacyPolicyMismatch, |c| c.privacy_policy_version = "2".into()),
        ("privacy_policy_fingerprint", ContextBindingReason::PrivacyPolicyMismatch, |c| c.privacy_policy_fingerprint = "privacy:other".into()),
        ("disclosure_scope_id", ContextBindingReason::DisclosureScopeMismatch, |c| c.disclosure_scope_id = "disclosure.other".into()),
        ("proof_adapter_id", ContextBindingReason::ProofMetadataMismatch, |c| c.proof_adapter_id = Some("proof.adapter.other".into())),
        ("proof_system_id", ContextBindingReason::ProofMetadataMismatch, |c| c.proof_system_id = Some("proof.system.other".into())),
        ("circuit_id", ContextBindingReason::ProofMetadataMismatch, |c| c.circuit_id = Some("circuit.other".into())),
        ("vk_id", ContextBindingReason::VkMismatch, |c| c.vk_id = Some("vk.other".into())),
        ("vk_fingerprint", ContextBindingReason::VkMismatch, |c| c.vk_fingerprint = Some("vk:other".into())),
        ("public_input_schema_id", ContextBindingReason::PublicInputSchemaMismatch, |c| c.public_input_schema_id = Some("schema.other".into())),
        ("public_input_fingerprint", ContextBindingReason::PublicInputSchemaMismatch, |c| c.public_input_fingerprint = Some("public-input:other".into())),
        ("nullifier_domain_id", ContextBindingReason::NullifierDomainMismatch, |c| c.nullifier_domain_id = Some("nullifier.other".into())),
        ("evidence_tier", ContextBindingReason::EvidenceTierMismatch, |c| c.evidence_tier = "lower_tier".into()),
        ("adapter_kind", ContextBindingReason::AdapterKindMismatch, |c| c.adapter_kind = "local_static".into()),
    ];

    for (dimension, reason, mutate) in cases {
        let expected = VerificationContext::fixture();
        let mut observed = expected.clone();
        mutate(&mut observed);
        let mut handler_ran = false;
        let error = verify_context_binding_then_run(&expected, &observed, || {
            handler_ran = true;
        })
        .unwrap_err();
        assert_eq!(error.reason, reason, "dimension {dimension}");
        assert_eq!(error.dimension, dimension);
        assert!(!handler_ran, "handler ran for {dimension}");
        assert!(!format!("{error:?}").contains("raw_proof"));
    }
}
