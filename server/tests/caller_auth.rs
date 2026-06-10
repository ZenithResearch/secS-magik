use ed25519_dalek::SigningKey;
use libsec_core::caller_proof::{
    caller_canonical_bytes, encode_caller_proof, CALLER_SIGNATURE_LEN,
};
use libsec_core::ZenithPacket;
use server::caller::{verify_caller_proof, CallerKey, CallerKeyRegistry};
use server::identity::VerificationKeyStatus;
use server::verifier::VerificationError;

const NOW: u64 = 1_000;

fn caller_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn registry_with_active_caller(seed: u8) -> CallerKeyRegistry {
    CallerKeyRegistry::from_keys([CallerKey::active(
        "caller:alpha",
        "did:example:alpha",
        caller_signing_key(seed).verifying_key(),
    )])
}

fn signed_packet(signer: &SigningKey, key_id: &str) -> ZenithPacket {
    let session_id = [0xAA; 16];
    let nonce = [0xBB; 12];
    let opcode = 0x10;
    let claim_ttl = 300;
    let payload = b"caller bound payload".to_vec();

    let canonical = caller_canonical_bytes(&session_id, &nonce, opcode, claim_ttl, &payload);
    let signature_bytes = libsec_core::zk::generate_proof(signer, &canonical);
    let mut signature = [0u8; CALLER_SIGNATURE_LEN];
    signature.copy_from_slice(&signature_bytes);

    ZenithPacket {
        session_id,
        nonce,
        opcode,
        proof: encode_caller_proof(key_id, &signature),
        claim_ttl,
        encrypted_payload: payload,
        mac: [0u8; 16],
    }
}

#[test]
fn valid_caller_proof_from_registered_active_key_authenticates() {
    let registry = registry_with_active_caller(1);
    let packet = signed_packet(&caller_signing_key(1), "caller:alpha");

    let caller = verify_caller_proof(&packet, &registry, NOW).unwrap();

    assert_eq!(caller.subject_id, "did:example:alpha");
    assert_eq!(caller.key_id, "caller:alpha");
}

#[test]
fn forged_signature_rejects_with_bad_caller_proof() {
    let registry = registry_with_active_caller(1);
    let mut packet = signed_packet(&caller_signing_key(1), "caller:alpha");
    let last = packet.proof.len() - 1;
    packet.proof[last] ^= 0x01;

    assert_eq!(
        verify_caller_proof(&packet, &registry, NOW).unwrap_err(),
        VerificationError::BadCallerProof
    );
}

#[test]
fn proof_signed_by_unregistered_key_rejects_with_bad_caller_proof() {
    let registry = registry_with_active_caller(1);
    // Signed by key 2 but claiming registered id "caller:alpha" (key 1):
    // verification runs against the registry key and must fail.
    let packet = signed_packet(&caller_signing_key(2), "caller:alpha");

    assert_eq!(
        verify_caller_proof(&packet, &registry, NOW).unwrap_err(),
        VerificationError::BadCallerProof
    );
}

#[test]
fn unknown_caller_key_id_rejects() {
    let registry = registry_with_active_caller(1);
    let packet = signed_packet(&caller_signing_key(1), "caller:unknown");

    assert_eq!(
        verify_caller_proof(&packet, &registry, NOW).unwrap_err(),
        VerificationError::UnknownCallerKey
    );
}

#[test]
fn empty_and_truncated_proofs_reject_with_bad_caller_proof() {
    let registry = registry_with_active_caller(1);

    let mut empty = signed_packet(&caller_signing_key(1), "caller:alpha");
    empty.proof = Vec::new();
    assert_eq!(
        verify_caller_proof(&empty, &registry, NOW).unwrap_err(),
        VerificationError::BadCallerProof
    );

    let mut truncated = signed_packet(&caller_signing_key(1), "caller:alpha");
    truncated.proof.truncate(truncated.proof.len() - 1);
    assert_eq!(
        verify_caller_proof(&truncated, &registry, NOW).unwrap_err(),
        VerificationError::BadCallerProof
    );
}

#[test]
fn legacy_opaque_proof_bytes_reject_with_bad_caller_proof() {
    // The old prototype check accepted any non-empty proof; the caller seam
    // must reject bytes that are not a versioned caller proof envelope.
    let registry = registry_with_active_caller(1);
    let mut packet = signed_packet(&caller_signing_key(1), "caller:alpha");
    packet.proof = vec![1];

    assert_eq!(
        verify_caller_proof(&packet, &registry, NOW).unwrap_err(),
        VerificationError::BadCallerProof
    );
}

#[test]
fn captured_proof_rebound_to_different_envelope_rejects() {
    let registry = registry_with_active_caller(1);
    let original = signed_packet(&caller_signing_key(1), "caller:alpha");

    // Re-bind the captured proof to a different session.
    let mut rebound_session = original.clone();
    rebound_session.session_id = [0xCC; 16];
    assert_eq!(
        verify_caller_proof(&rebound_session, &registry, NOW).unwrap_err(),
        VerificationError::BadCallerProof
    );

    // Re-bind to a different opcode.
    let mut rebound_opcode = original.clone();
    rebound_opcode.opcode = 0x20;
    assert_eq!(
        verify_caller_proof(&rebound_opcode, &registry, NOW).unwrap_err(),
        VerificationError::BadCallerProof
    );

    // Re-bind to a different payload.
    let mut rebound_payload = original.clone();
    rebound_payload.encrypted_payload = b"different payload".to_vec();
    assert_eq!(
        verify_caller_proof(&rebound_payload, &registry, NOW).unwrap_err(),
        VerificationError::BadCallerProof
    );

    // Re-bind to a different TTL.
    let mut rebound_ttl = original;
    rebound_ttl.claim_ttl = 600;
    assert_eq!(
        verify_caller_proof(&rebound_ttl, &registry, NOW).unwrap_err(),
        VerificationError::BadCallerProof
    );
}

#[test]
fn revoked_caller_key_rejects() {
    let registry = CallerKeyRegistry::from_keys([CallerKey::active(
        "caller:alpha",
        "did:example:alpha",
        caller_signing_key(1).verifying_key(),
    )
    .with_status(VerificationKeyStatus::Revoked)]);
    let packet = signed_packet(&caller_signing_key(1), "caller:alpha");

    assert_eq!(
        verify_caller_proof(&packet, &registry, NOW).unwrap_err(),
        VerificationError::RevokedCallerKey
    );
}

#[test]
fn revoked_at_timestamp_in_past_rejects() {
    let registry = CallerKeyRegistry::from_keys([CallerKey::active(
        "caller:alpha",
        "did:example:alpha",
        caller_signing_key(1).verifying_key(),
    )
    .with_revoked_at(Some(NOW - 1))]);
    let packet = signed_packet(&caller_signing_key(1), "caller:alpha");

    assert_eq!(
        verify_caller_proof(&packet, &registry, NOW).unwrap_err(),
        VerificationError::RevokedCallerKey
    );
}

#[test]
fn expired_caller_key_rejects() {
    let registry = CallerKeyRegistry::from_keys([CallerKey::active(
        "caller:alpha",
        "did:example:alpha",
        caller_signing_key(1).verifying_key(),
    )
    .with_validity_window(None, Some(NOW - 1))]);
    let packet = signed_packet(&caller_signing_key(1), "caller:alpha");

    assert_eq!(
        verify_caller_proof(&packet, &registry, NOW).unwrap_err(),
        VerificationError::ExpiredCallerKey
    );
}

#[test]
fn not_yet_valid_caller_key_rejects() {
    let registry = CallerKeyRegistry::from_keys([CallerKey::active(
        "caller:alpha",
        "did:example:alpha",
        caller_signing_key(1).verifying_key(),
    )
    .with_validity_window(Some(NOW + 10), None)]);
    let packet = signed_packet(&caller_signing_key(1), "caller:alpha");

    assert_eq!(
        verify_caller_proof(&packet, &registry, NOW).unwrap_err(),
        VerificationError::NotYetValidCallerKey
    );
}

#[test]
fn duplicate_caller_key_id_fails_closed() {
    let registry = CallerKeyRegistry::from_keys([
        CallerKey::active(
            "caller:alpha",
            "did:example:alpha",
            caller_signing_key(1).verifying_key(),
        ),
        CallerKey::active(
            "caller:alpha",
            "did:example:impostor",
            caller_signing_key(2).verifying_key(),
        ),
    ]);

    // Lookup must fail closed regardless of which entry was inserted last.
    let packet_one = signed_packet(&caller_signing_key(1), "caller:alpha");
    let packet_two = signed_packet(&caller_signing_key(2), "caller:alpha");
    assert_eq!(
        verify_caller_proof(&packet_one, &registry, NOW).unwrap_err(),
        VerificationError::UnknownCallerKey
    );
    assert_eq!(
        verify_caller_proof(&packet_two, &registry, NOW).unwrap_err(),
        VerificationError::UnknownCallerKey
    );
}

#[test]
fn clock_failure_sentinel_rejects_caller_verification() {
    let registry = registry_with_active_caller(1);
    let packet = signed_packet(&caller_signing_key(1), "caller:alpha");

    assert_eq!(
        verify_caller_proof(
            &packet,
            &registry,
            server::clock::CLOCK_READ_FAILURE_SENTINEL
        )
        .unwrap_err(),
        VerificationError::ExpiredClaim
    );
}

mod runtime_wiring {
    use super::*;
    use server::manifest::{
        OpcodeRange, OperationDescriptor, OperationName, ReceiverManifest, ReplayScope, TargetKind,
    };
    use server::runtime_mode::RuntimeMode;
    use server::verifier::Verifier;

    const PRODUCTION_OPCODE: u8 = 0x77;
    const AUDIENCE: &str = "secS://receiver-production";

    fn production_manifest() -> ReceiverManifest {
        ReceiverManifest::new([OperationDescriptor {
            opcode: PRODUCTION_OPCODE,
            name: OperationName::new("test.production.echo"),
            payload_schema: None,
            target_kind: TargetKind::LocalDevProcess,
            required_credentials: vec![],
            required_capabilities: vec![],
            accepted_evidence: vec!["wallet_presentation".to_string()],
            replay_scope: ReplayScope::SessionOpcodeNonce,
            max_ttl_seconds: 300,
            handler_id: "prod/echo".to_string(),
            dev_binding: false,
            range: OpcodeRange::classify(PRODUCTION_OPCODE),
        }])
    }

    fn signed_packet_for_opcode(signer: &SigningKey, key_id: &str, opcode: u8) -> ZenithPacket {
        let session_id = [0xAA; 16];
        let nonce = [0xBB; 12];
        let claim_ttl = 300;
        let payload = b"caller bound payload".to_vec();

        let canonical = caller_canonical_bytes(&session_id, &nonce, opcode, claim_ttl, &payload);
        let signature_bytes = libsec_core::zk::generate_proof(signer, &canonical);
        let mut signature = [0u8; CALLER_SIGNATURE_LEN];
        signature.copy_from_slice(&signature_bytes);

        ZenithPacket {
            session_id,
            nonce,
            opcode,
            proof: encode_caller_proof(key_id, &signature),
            claim_ttl,
            encrypted_payload: payload,
            mac: [0u8; 16],
        }
    }

    #[test]
    fn production_runtime_without_registry_fails_closed() {
        let packet =
            signed_packet_for_opcode(&caller_signing_key(1), "caller:alpha", PRODUCTION_OPCODE);

        let result = Verifier::verify_manifest_operation_for_runtime_with_caller(
            &packet,
            &production_manifest(),
            AUDIENCE,
            NOW,
            RuntimeMode::ProductionVerified,
            None,
        );

        assert_eq!(
            result.unwrap_err(),
            VerificationError::MissingCallerRegistry
        );
    }

    #[test]
    fn production_runtime_stamps_authenticated_caller_into_context() {
        let registry = registry_with_active_caller(1);
        let packet =
            signed_packet_for_opcode(&caller_signing_key(1), "caller:alpha", PRODUCTION_OPCODE);

        let context = Verifier::verify_manifest_operation_for_runtime_with_caller(
            &packet,
            &production_manifest(),
            AUDIENCE,
            NOW,
            RuntimeMode::ProductionVerified,
            Some(&registry),
        )
        .unwrap();

        assert_eq!(context.subject.subject_id, "did:example:alpha");
        assert_eq!(context.subject.key_id, "caller:alpha");
    }

    #[test]
    fn production_runtime_rejects_forged_proof_with_typed_reason() {
        let registry = registry_with_active_caller(1);
        let packet =
            signed_packet_for_opcode(&caller_signing_key(2), "caller:alpha", PRODUCTION_OPCODE);

        let result = Verifier::verify_manifest_operation_for_runtime_with_caller(
            &packet,
            &production_manifest(),
            AUDIENCE,
            NOW,
            RuntimeMode::ProductionVerified,
            Some(&registry),
        );

        assert_eq!(result.unwrap_err(), VerificationError::BadCallerProof);
    }

    #[test]
    fn descriptor_production_gates_fire_before_caller_checks() {
        // Dev descriptor in production rejects on the descriptor gate even
        // with no registry installed — descriptor rejects keep their reasons.
        let dev_packet = signed_packet_for_opcode(&caller_signing_key(1), "caller:alpha", 0x10);
        let result = Verifier::verify_manifest_operation_for_runtime_with_caller(
            &dev_packet,
            &ReceiverManifest::default_v0(),
            AUDIENCE,
            NOW,
            RuntimeMode::ProductionVerified,
            None,
        );
        assert_eq!(
            result.unwrap_err(),
            VerificationError::PrototypeOperationNotProductionAuthorized
        );

        // A valid caller proof never unlocks the 0x44 descriptor-only
        // evidence gap: caller auth is necessary, never sufficient.
        let registry = registry_with_active_caller(1);
        let membership_packet =
            signed_packet_for_opcode(&caller_signing_key(1), "caller:alpha", 0x44);
        let result = Verifier::verify_manifest_operation_for_runtime_with_caller(
            &membership_packet,
            &ReceiverManifest::default_v0(),
            AUDIENCE,
            NOW,
            RuntimeMode::ProductionVerified,
            Some(&registry),
        );
        assert_eq!(result.unwrap_err(), VerificationError::InsufficientEvidence);
    }

    #[test]
    fn local_dev_without_registry_keeps_prototype_subject() {
        let packet = ZenithPacket {
            session_id: [0xAA; 16],
            nonce: [0xBB; 12],
            opcode: 0x10,
            proof: vec![1],
            claim_ttl: 300,
            encrypted_payload: b"payload".to_vec(),
            mac: [0u8; 16],
        };

        let context = Verifier::verify_manifest_operation_for_runtime_with_caller(
            &packet,
            &ReceiverManifest::default_v0(),
            "secS://receiver-a",
            NOW,
            RuntimeMode::LocalDevPlaintext,
            None,
        )
        .unwrap();

        assert_eq!(context.subject.subject_id, "prototype.local-dev.subject");
    }

    #[test]
    fn local_dev_with_fixture_registry_verifies_and_stamps_caller() {
        let registry = registry_with_active_caller(1);
        let packet = signed_packet_for_opcode(&caller_signing_key(1), "caller:alpha", 0x10);

        let context = Verifier::verify_manifest_operation_for_runtime_with_caller(
            &packet,
            &ReceiverManifest::default_v0(),
            "secS://receiver-a",
            NOW,
            RuntimeMode::LocalDevPlaintext,
            Some(&registry),
        )
        .unwrap();

        assert_eq!(context.subject.subject_id, "did:example:alpha");

        // And a bad proof under a fixture registry still rejects.
        let forged = signed_packet_for_opcode(&caller_signing_key(2), "caller:alpha", 0x10);
        let result = Verifier::verify_manifest_operation_for_runtime_with_caller(
            &forged,
            &ReceiverManifest::default_v0(),
            "secS://receiver-a",
            NOW,
            RuntimeMode::LocalDevPlaintext,
            Some(&registry),
        );
        assert_eq!(result.unwrap_err(), VerificationError::BadCallerProof);
    }
}
