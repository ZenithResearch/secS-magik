use libsec_core::{ZenithPacket, OPCODE_CHAT, OPCODE_GENERATE};
use server::manifest::ReceiverManifest;
use server::runtime_mode::RuntimeMode;
use server::verifier::{VerificationError, Verifier};

fn packet_for_opcode(opcode: u8) -> ZenithPacket {
    ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode,
        proof: vec![1],
        claim_ttl: 300,
        encrypted_payload: b"fixture payload".to_vec(),
        mac: [0u8; 16],
    }
}

#[test]
fn production_rejects_prototype_evidence_for_legacy_descriptors() {
    let manifest = ReceiverManifest::default_v0();

    for opcode in [OPCODE_GENERATE, OPCODE_CHAT] {
        let packet = packet_for_opcode(opcode);

        assert_eq!(
            Verifier::verify_manifest_operation_for_runtime(
                &packet,
                &manifest,
                "secS://operator-receiver",
                1_000,
                RuntimeMode::ProductionVerified,
            )
            .unwrap_err(),
            VerificationError::PrototypeOperationNotProductionAuthorized,
            "legacy opcode {opcode:#04x} must not mint production verified context from prototype proof evidence"
        );
    }
}

#[test]
fn local_dev_runtime_still_accepts_legacy_fixture_descriptors() {
    let manifest = ReceiverManifest::default_v0();
    let packet = packet_for_opcode(OPCODE_GENERATE);

    let context = Verifier::verify_manifest_operation_for_runtime(
        &packet,
        &manifest,
        "secS://receiver-a",
        1_000,
        RuntimeMode::LocalDevPlaintext,
    )
    .expect("local-dev fixture paths may still exercise legacy descriptors");

    assert_eq!(context.operation, "legacy.generate");
    assert_eq!(context.handler_id.as_deref(), Some("legacy/generate"));
}

#[test]
fn legacy_server_entrypoint_is_retired_from_direct_dispatch() {
    let lib = include_str!("../src/lib.rs");
    let package_manifest = include_str!("../Cargo.toml");

    assert!(
        !lib.contains("pub trait PayloadRouter")
            && !lib.contains("run_node(")
            && !lib.contains("bincode::deserialize::<ZenithPacket>(&buf"),
        "legacy run_node/PayloadRouter must not remain as a bypassable direct opcode dispatch path"
    );
    assert!(
        package_manifest.contains("[[bin]]") && package_manifest.contains("secs-gateway"),
        "the server package should expose explicit canonical bins instead of an implicit legacy src/main.rs server"
    );
}
