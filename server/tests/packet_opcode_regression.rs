use libsec_core::{ZenithPacket, OPCODE_GENERATE};
use server::verifier::{VerificationError, Verifier};

fn packet_with(proof: Vec<u8>, ttl: u64, opcode: u8) -> ZenithPacket {
    ZenithPacket {
        session_id: [0xAA; 16],
        nonce: [0xBB; 12],
        opcode,
        proof,
        claim_ttl: ttl,
        encrypted_payload: b"payload".to_vec(),
        mac: [0xCC; 16],
    }
}

#[test]
fn packet_v0_regression_round_trips_non_empty_envelope() {
    let packet = packet_with(vec![0x01, 0x02, 0x03], 3600, OPCODE_GENERATE);

    let bytes = bincode::serialize(&packet).unwrap();
    let deserialized: ZenithPacket = bincode::deserialize(&bytes).unwrap();

    assert_eq!(deserialized.session_id, [0xAA; 16]);
    assert_eq!(deserialized.nonce, [0xBB; 12]);
    assert_eq!(deserialized.opcode, OPCODE_GENERATE);
    assert_eq!(deserialized.proof, vec![0x01, 0x02, 0x03]);
    assert_eq!(deserialized.claim_ttl, 3600);
    assert_eq!(deserialized.encrypted_payload, b"payload".to_vec());
    assert_eq!(deserialized.mac, [0xCC; 16]);
}

#[test]
fn packet_v0_regression_round_trips_maximum_u8_opcode() {
    let packet = packet_with(vec![0x01], 3600, u8::MAX);

    let bytes = bincode::serialize(&packet).unwrap();
    let deserialized: ZenithPacket = bincode::deserialize(&bytes).unwrap();

    assert_eq!(deserialized.opcode, u8::MAX);
}

#[test]
fn packet_v0_regression_serialization_allows_empty_proof_but_verifier_rejects_it() {
    let packet = packet_with(vec![], 3600, 0x10);

    let bytes = bincode::serialize(&packet).unwrap();
    let deserialized: ZenithPacket = bincode::deserialize(&bytes).unwrap();

    assert!(deserialized.proof.is_empty());
    assert_eq!(
        Verifier::verify_prototype_envelope(&deserialized).unwrap_err(),
        VerificationError::MissingPrototypeProofEnvelope
    );
}

#[test]
fn packet_v0_regression_serialization_allows_zero_ttl_but_verifier_rejects_it() {
    let packet = packet_with(vec![0x01], 0, 0x10);

    let bytes = bincode::serialize(&packet).unwrap();
    let deserialized: ZenithPacket = bincode::deserialize(&bytes).unwrap();

    assert_eq!(deserialized.claim_ttl, 0);
    assert_eq!(
        Verifier::verify_prototype_envelope(&deserialized).unwrap_err(),
        VerificationError::ExpiredClaim
    );
}
