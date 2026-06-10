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
