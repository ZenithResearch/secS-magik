//! Versioned sealed envelope for bounded provider intake.
//!
//! The public relay sees only the recipient key identifier, expiry and opaque
//! ciphertext. Requester evidence remains inside the authenticated ciphertext.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::tunnel::{
    decrypt_payload, derive_tunnel_key_hkdf, encrypt_payload, tunnel_public_key_id,
};

pub const INTAKE_ENVELOPE_V1_MAGIC: &[u8; 8] = b"SECSI01\0";
const INTAKE_PAYLOAD_V1_MAGIC: &[u8; 8] = b"SECSIP1\0";
pub const MAX_INTAKE_BYTES: usize = 65_536;
pub const MAX_REQUESTER_EVIDENCE_BYTES: usize = 262_144;
pub const MAX_INTAKE_CIPHERTEXT_BYTES: usize = MAX_INTAKE_BYTES + MAX_REQUESTER_EVIDENCE_BYTES + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntakeEnvelopeError {
    Malformed,
    UnsupportedVersion,
    WrongRecipient,
    Expired,
    InvalidKeyAgreement,
    AuthenticationFailed,
    IntakeTooLarge,
    EvidenceTooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedIntakeEnvelope {
    pub intake: Vec<u8>,
    pub requester_evidence: Vec<u8>,
    pub recipient_key_id: String,
    pub expires_at_ms: u64,
}

fn session_id(
    recipient_public: &[u8; 32],
    ephemeral_public: &[u8; 32],
    expires_at_ms: u64,
) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"service.intake-envelope.v1/session\0");
    digest.update(recipient_public);
    digest.update(ephemeral_public);
    digest.update(expires_at_ms.to_be_bytes());
    let digest = digest.finalize();
    let mut session = [0u8; 16];
    session.copy_from_slice(&digest[..16]);
    session
}

fn header(
    recipient_key_id: &str,
    ephemeral_public: &[u8; 32],
    nonce: &[u8; 12],
    expires_at_ms: u64,
) -> Result<Vec<u8>, IntakeEnvelopeError> {
    let key_id = recipient_key_id.as_bytes();
    if key_id.is_empty()
        || key_id.len() > u8::MAX as usize
        || key_id.iter().any(|byte| !byte.is_ascii_graphic())
    {
        return Err(IntakeEnvelopeError::Malformed);
    }
    let mut value = Vec::with_capacity(8 + 8 + 1 + key_id.len() + 32 + 12);
    value.extend_from_slice(INTAKE_ENVELOPE_V1_MAGIC);
    value.extend_from_slice(&expires_at_ms.to_be_bytes());
    value.push(key_id.len() as u8);
    value.extend_from_slice(key_id);
    value.extend_from_slice(ephemeral_public);
    value.extend_from_slice(nonce);
    Ok(value)
}

fn payload(intake: &[u8], evidence: &[u8]) -> Result<Vec<u8>, IntakeEnvelopeError> {
    if intake.is_empty() || intake.len() > MAX_INTAKE_BYTES {
        return Err(IntakeEnvelopeError::IntakeTooLarge);
    }
    if evidence.is_empty() || evidence.len() > MAX_REQUESTER_EVIDENCE_BYTES {
        return Err(IntakeEnvelopeError::EvidenceTooLarge);
    }
    let mut value = Vec::with_capacity(16 + intake.len() + evidence.len());
    value.extend_from_slice(INTAKE_PAYLOAD_V1_MAGIC);
    value.extend_from_slice(&(intake.len() as u32).to_be_bytes());
    value.extend_from_slice(&(evidence.len() as u32).to_be_bytes());
    value.extend_from_slice(intake);
    value.extend_from_slice(evidence);
    Ok(value)
}

pub fn seal_intake_envelope_v1(
    recipient_public: &[u8; 32],
    ephemeral_secret: &[u8; 32],
    nonce: &[u8; 12],
    intake: &[u8],
    requester_evidence: &[u8],
    expires_at_ms: u64,
) -> Result<Vec<u8>, IntakeEnvelopeError> {
    if expires_at_ms == 0 {
        return Err(IntakeEnvelopeError::Malformed);
    }
    let secret = StaticSecret::from(*ephemeral_secret);
    let ephemeral_public = PublicKey::from(&secret).to_bytes();
    let recipient = PublicKey::from(*recipient_public);
    let shared = secret.diffie_hellman(&recipient);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(IntakeEnvelopeError::InvalidKeyAgreement);
    }
    let key_id = tunnel_public_key_id(recipient_public);
    let aad = header(&key_id, &ephemeral_public, nonce, expires_at_ms)?;
    let session = session_id(recipient_public, &ephemeral_public, expires_at_ms);
    let key = derive_tunnel_key_hkdf(
        shared.as_bytes(),
        &session,
        &ephemeral_public,
        recipient_public,
    );
    let ciphertext = encrypt_payload(&key, nonce, &payload(intake, requester_evidence)?, &aad);
    if ciphertext.len() > MAX_INTAKE_CIPHERTEXT_BYTES {
        return Err(IntakeEnvelopeError::Malformed);
    }
    let mut envelope = aad;
    envelope.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub fn open_intake_envelope_v1(
    recipient_secret: &[u8; 32],
    expected_recipient_key_id: &str,
    envelope: &[u8],
    now_ms: u64,
) -> Result<OpenedIntakeEnvelope, IntakeEnvelopeError> {
    if envelope.len() < 8 + 8 + 1 + 32 + 12 + 4 + 16 {
        return Err(IntakeEnvelopeError::Malformed);
    }
    if &envelope[..8] != INTAKE_ENVELOPE_V1_MAGIC {
        return Err(IntakeEnvelopeError::UnsupportedVersion);
    }
    let expires_at_ms = u64::from_be_bytes(
        envelope[8..16]
            .try_into()
            .map_err(|_| IntakeEnvelopeError::Malformed)?,
    );
    if now_ms >= expires_at_ms {
        return Err(IntakeEnvelopeError::Expired);
    }
    let key_id_len = envelope[16] as usize;
    let key_id_end = 17usize
        .checked_add(key_id_len)
        .ok_or(IntakeEnvelopeError::Malformed)?;
    let ephemeral_end = key_id_end
        .checked_add(32)
        .ok_or(IntakeEnvelopeError::Malformed)?;
    let nonce_end = ephemeral_end
        .checked_add(12)
        .ok_or(IntakeEnvelopeError::Malformed)?;
    let length_end = nonce_end
        .checked_add(4)
        .ok_or(IntakeEnvelopeError::Malformed)?;
    if length_end > envelope.len() {
        return Err(IntakeEnvelopeError::Malformed);
    }
    let key_id = core::str::from_utf8(&envelope[17..key_id_end])
        .map_err(|_| IntakeEnvelopeError::Malformed)?;
    let recipient_secret = StaticSecret::from(*recipient_secret);
    let recipient_public = PublicKey::from(&recipient_secret).to_bytes();
    let actual_key_id = tunnel_public_key_id(&recipient_public);
    if key_id != expected_recipient_key_id || key_id != actual_key_id {
        return Err(IntakeEnvelopeError::WrongRecipient);
    }
    let ephemeral_public: [u8; 32] = envelope[key_id_end..ephemeral_end]
        .try_into()
        .map_err(|_| IntakeEnvelopeError::Malformed)?;
    let nonce: [u8; 12] = envelope[ephemeral_end..nonce_end]
        .try_into()
        .map_err(|_| IntakeEnvelopeError::Malformed)?;
    let ciphertext_len = u32::from_be_bytes(
        envelope[nonce_end..length_end]
            .try_into()
            .map_err(|_| IntakeEnvelopeError::Malformed)?,
    ) as usize;
    if ciphertext_len > MAX_INTAKE_CIPHERTEXT_BYTES || envelope.len() != length_end + ciphertext_len
    {
        return Err(IntakeEnvelopeError::Malformed);
    }
    let ephemeral_public_key = PublicKey::from(ephemeral_public);
    let shared = recipient_secret.diffie_hellman(&ephemeral_public_key);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(IntakeEnvelopeError::InvalidKeyAgreement);
    }
    let session = session_id(&recipient_public, &ephemeral_public, expires_at_ms);
    let key = derive_tunnel_key_hkdf(
        shared.as_bytes(),
        &session,
        &ephemeral_public,
        &recipient_public,
    );
    let plaintext = decrypt_payload(
        &key,
        &nonce,
        &envelope[length_end..],
        &envelope[..nonce_end],
    )
    .map_err(|_| IntakeEnvelopeError::AuthenticationFailed)?;
    if plaintext.len() < 16 || &plaintext[..8] != INTAKE_PAYLOAD_V1_MAGIC {
        return Err(IntakeEnvelopeError::Malformed);
    }
    let intake_len = u32::from_be_bytes(
        plaintext[8..12]
            .try_into()
            .map_err(|_| IntakeEnvelopeError::Malformed)?,
    ) as usize;
    let evidence_len = u32::from_be_bytes(
        plaintext[12..16]
            .try_into()
            .map_err(|_| IntakeEnvelopeError::Malformed)?,
    ) as usize;
    if intake_len == 0 || intake_len > MAX_INTAKE_BYTES {
        return Err(IntakeEnvelopeError::IntakeTooLarge);
    }
    if evidence_len == 0 || evidence_len > MAX_REQUESTER_EVIDENCE_BYTES {
        return Err(IntakeEnvelopeError::EvidenceTooLarge);
    }
    if plaintext.len() != 16 + intake_len + evidence_len {
        return Err(IntakeEnvelopeError::Malformed);
    }
    Ok(OpenedIntakeEnvelope {
        intake: plaintext[16..16 + intake_len].to_vec(),
        requester_evidence: plaintext[16 + intake_len..].to_vec(),
        recipient_key_id: actual_key_id,
        expires_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn fixture() -> ([u8; 32], [u8; 32], [u8; 12], Vec<u8>) {
        let recipient_secret = [7u8; 32];
        let recipient_public = PublicKey::from(&StaticSecret::from(recipient_secret)).to_bytes();
        let nonce = [9u8; 12];
        let envelope = seal_intake_envelope_v1(
            &recipient_public,
            &[8u8; 32],
            &nonce,
            br#"{"schema":"service.intake.v1"}"#,
            b"signed-membership-proof",
            2_000,
        )
        .unwrap();
        (recipient_secret, recipient_public, nonce, envelope)
    }

    #[test]
    fn sealed_intake_round_trips_and_exposes_no_plaintext() {
        let (secret, public, _, envelope) = fixture();
        assert!(!envelope.windows(7).any(|value| value == b"service"));
        let opened =
            open_intake_envelope_v1(&secret, &tunnel_public_key_id(&public), &envelope, 1_000)
                .unwrap();
        assert_eq!(opened.intake, br#"{"schema":"service.intake.v1"}"#);
        assert_eq!(opened.requester_evidence, b"signed-membership-proof");
        assert_eq!(opened.expires_at_ms, 2_000);
    }

    #[test]
    fn tampering_wrong_recipient_and_expiry_fail_closed() {
        let (secret, public, _, envelope) = fixture();
        let id = tunnel_public_key_id(&public);
        let mut tampered = envelope.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            open_intake_envelope_v1(&secret, &id, &tampered, 1_000),
            Err(IntakeEnvelopeError::AuthenticationFailed)
        );
        assert_eq!(
            open_intake_envelope_v1(&[6u8; 32], &id, &envelope, 1_000),
            Err(IntakeEnvelopeError::WrongRecipient)
        );
        assert_eq!(
            open_intake_envelope_v1(&secret, &id, &envelope, 2_000),
            Err(IntakeEnvelopeError::Expired)
        );
    }

    #[test]
    fn same_input_uses_nonce_and_ephemeral_secret_for_domain_separation() {
        let (_, public, nonce, a) = fixture();
        let b =
            seal_intake_envelope_v1(&public, &[8u8; 32], &[10u8; 12], b"x", b"y", 2_000).unwrap();
        let c = seal_intake_envelope_v1(&public, &[11u8; 32], &nonce, b"x", b"y", 2_000).unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
    }

    #[test]
    fn bounded_plaintext_and_closed_framing_reject_invalid_inputs() {
        let public = PublicKey::from(&StaticSecret::from([7u8; 32])).to_bytes();
        assert_eq!(
            seal_intake_envelope_v1(&public, &[8u8; 32], &[9u8; 12], b"", b"e", 2_000),
            Err(IntakeEnvelopeError::IntakeTooLarge)
        );
        assert_eq!(
            seal_intake_envelope_v1(&public, &[8u8; 32], &[9u8; 12], b"i", b"", 2_000),
            Err(IntakeEnvelopeError::EvidenceTooLarge)
        );
        let mut envelope = fixture().3;
        envelope.push(0);
        assert_eq!(
            open_intake_envelope_v1(&[7u8; 32], &tunnel_public_key_id(&public), &envelope, 1_000),
            Err(IntakeEnvelopeError::Malformed)
        );
    }

    #[test]
    fn deterministic_interop_fixture_is_stable() {
        let envelope = fixture().3;
        assert_eq!(
            Sha256::digest(&envelope).as_slice(),
            &[
                81, 231, 108, 83, 103, 251, 25, 46, 154, 233, 103, 201, 16, 220, 226, 221, 115,
                151, 151, 37, 61, 52, 191, 118, 43, 83, 241, 173, 40, 114, 25, 228,
            ]
        );
    }
}
