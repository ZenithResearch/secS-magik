use server::manifest::{
    OpcodeRange, ReceiverManifest, ReplayScope, TargetKind, CASTALIA_STANDARD_CANDIDATE_END,
    CASTALIA_STANDARD_CANDIDATE_START, CORE_STANDARDIZED_END, CORE_STANDARDIZED_START,
    OPERATOR_DEFINED_START,
};
use server::verifier::VerificationError;

#[test]
fn default_manifest_looks_up_receiver_local_descriptors_by_u8_opcode() {
    let manifest = ReceiverManifest::default_v0();

    let generate = manifest.lookup(0x01).unwrap();
    assert_eq!(generate.opcode, 0x01);
    assert_eq!(generate.name.as_str(), "legacy.generate");
    assert_eq!(generate.range, OpcodeRange::CoreStandardized);
    assert!(!generate.dev_binding);

    let chat = manifest.lookup(0x02).unwrap();
    assert_eq!(chat.name.as_str(), "legacy.chat");
    assert_eq!(chat.range, OpcodeRange::CoreStandardized);

    let bash_echo = manifest.lookup(0x10).unwrap();
    assert_eq!(bash_echo.name.as_str(), "candidate.dev.bash_echo");
    assert_eq!(bash_echo.handler_id, "dev/bash-echo");
    assert_eq!(bash_echo.range, OpcodeRange::CastaliaStandardCandidate);
    assert_eq!(bash_echo.target_kind, TargetKind::LocalDevProcess);
    assert!(bash_echo.dev_binding);

    let jq = manifest.lookup(0x30).unwrap();
    assert_eq!(jq.name.as_str(), "candidate.dev.jq_identity");
    assert_eq!(jq.handler_id, "dev/jq-identity");
    assert!(jq.dev_binding);
}

#[test]
fn default_manifest_represents_all_seeded_v0_operations() {
    let manifest = ReceiverManifest::default_v0();

    for opcode in [0x01, 0x02, 0x10, 0x20, 0x30] {
        assert!(
            manifest.lookup(opcode).is_ok(),
            "missing seeded descriptor for opcode {opcode:#04x}"
        );
    }
}

#[test]
fn unknown_manifest_opcode_fails_with_typed_unknown_operation_error() {
    let manifest = ReceiverManifest::default_v0();

    assert_eq!(
        manifest.lookup(0x0B),
        Err(VerificationError::UnknownOperation)
    );
    assert_eq!(
        manifest.lookup(0xFF),
        Err(VerificationError::UnknownOperation)
    );
}

#[test]
fn opcode_range_classification_documents_reserved_governance_ranges() {
    assert_eq!(CORE_STANDARDIZED_START, 0x01);
    assert_eq!(CORE_STANDARDIZED_END, 0x0A);
    assert_eq!(CASTALIA_STANDARD_CANDIDATE_START, 0x0B);
    assert_eq!(CASTALIA_STANDARD_CANDIDATE_END, 0x3F);
    assert_eq!(OPERATOR_DEFINED_START, 0x40);

    assert_eq!(OpcodeRange::classify(0x00), OpcodeRange::Reserved);
    assert_eq!(OpcodeRange::classify(0x01), OpcodeRange::CoreStandardized);
    assert_eq!(OpcodeRange::classify(0x0A), OpcodeRange::CoreStandardized);
    assert_eq!(
        OpcodeRange::classify(0x0B),
        OpcodeRange::CastaliaStandardCandidate
    );
    assert_eq!(
        OpcodeRange::classify(0x3F),
        OpcodeRange::CastaliaStandardCandidate
    );
    assert_eq!(OpcodeRange::classify(0x40), OpcodeRange::OperatorDefined);
    assert_eq!(OpcodeRange::classify(0xFF), OpcodeRange::OperatorDefined);
}

#[test]
fn descriptor_fields_capture_semantics_above_local_opcode() {
    let manifest = ReceiverManifest::default_v0();
    let descriptor = manifest.lookup(0x20).unwrap();

    assert_eq!(descriptor.opcode, 0x20);
    assert_eq!(descriptor.name.as_str(), "candidate.dev.json_validate");
    assert_eq!(
        descriptor.payload_schema.as_deref(),
        Some("application/json")
    );
    assert_eq!(descriptor.target_kind, TargetKind::LocalDevProcess);
    assert_eq!(
        descriptor.required_credentials,
        vec!["prototype.local-dev".to_string()]
    );
    assert_eq!(
        descriptor.required_capabilities,
        vec!["dev.execute".to_string()]
    );
    assert_eq!(
        descriptor.accepted_evidence,
        vec!["prototype-proof-envelope".to_string()]
    );
    assert_eq!(descriptor.replay_scope, ReplayScope::SessionOpcodeNonce);
    assert_eq!(descriptor.max_ttl_seconds, 300);
    assert_eq!(descriptor.handler_id, "dev/json-validate");
    assert!(descriptor.dev_binding);
}

#[test]
fn dregg_demo_descriptor_is_dev_bounded_and_absent_from_default_manifest() {
    let descriptor = server::manifest::dregg_demo_descriptor(0x31);

    assert!(
        descriptor.dev_binding,
        "demo descriptor must be dev-bounded"
    );
    assert_eq!(descriptor.accepted_evidence, vec!["dregg_receipt"]);

    // Never weaken existing descriptors: the default manifest carries no
    // dregg_receipt acceptance anywhere.
    let manifest = server::manifest::ReceiverManifest::default_v0();
    for opcode in [0x01u8, 0x02, 0x10, 0x20, 0x30, 0x44] {
        let descriptor = manifest.lookup(opcode).unwrap();
        assert!(
            !descriptor
                .accepted_evidence
                .iter()
                .any(|kind| kind == "dregg_receipt"),
            "default descriptor {opcode:#04x} must not accept dregg_receipt"
        );
    }
}

#[test]
fn dregg_demo_descriptor_rejects_in_production_runtime() {
    use libsec_core::ZenithPacket;
    use server::runtime_mode::RuntimeMode;
    use server::verifier::{VerificationError, Verifier};

    let manifest =
        server::manifest::ReceiverManifest::new([server::manifest::dregg_demo_descriptor(0x31)]);
    let packet = ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode: 0x31,
        proof: vec![1],
        claim_ttl: 300,
        encrypted_payload: b"demo".to_vec(),
        mac: [0u8; 16],
    };

    assert_eq!(
        Verifier::verify_manifest_operation_for_runtime(
            &packet,
            &manifest,
            "secS://receiver-a",
            1_000,
            RuntimeMode::ProductionVerified,
        )
        .unwrap_err(),
        VerificationError::PrototypeOperationNotProductionAuthorized
    );
}
