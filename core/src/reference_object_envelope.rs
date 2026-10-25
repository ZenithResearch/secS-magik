//! Versioned sealed envelope for one bounded provider reference object.
//!
//! The public relay sees only the recipient key identifier, expiry and opaque
//! ciphertext. Stable request/object identities, original bytes and the exact
//! requester evidence remain inside the authenticated ciphertext.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::tunnel::{
    decrypt_payload, derive_tunnel_key_hkdf, encrypt_payload, tunnel_public_key_id,
};

pub const REFERENCE_OBJECT_ENVELOPE_V1_MAGIC: &[u8; 8] = b"SECSR01\0";
const REFERENCE_OBJECT_PAYLOAD_V1_MAGIC: &[u8; 8] = b"SECSRP1\0";
pub const MAX_REFERENCE_OBJECT_BYTES: usize = 524_288;
pub const MAX_REFERENCE_EVIDENCE_BYTES: usize = 262_144;
pub const MAX_REFERENCE_IDENTIFIER_BYTES: usize = 128;
const MAX_REFERENCE_PAYLOAD_BYTES: usize = 8
    + 4
    + 4
    + 32
    + (3 * (1 + MAX_REFERENCE_IDENTIFIER_BYTES))
    + MAX_REFERENCE_OBJECT_BYTES
    + MAX_REFERENCE_EVIDENCE_BYTES;
pub const MAX_REFERENCE_OBJECT_CIPHERTEXT_BYTES: usize = MAX_REFERENCE_PAYLOAD_BYTES + 16;
pub const MAX_REFERENCE_OBJECT_ENVELOPE_BYTES: usize =
    8 + 8 + 1 + u8::MAX as usize + 32 + 12 + 4 + MAX_REFERENCE_OBJECT_CIPHERTEXT_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceObjectEnvelopeError {
    Malformed,
    UnsupportedVersion,
    WrongRecipient,
    Expired,
    InvalidKeyAgreement,
    AuthenticationFailed,
    ObjectTooLarge,
    EvidenceTooLarge,
    DigestMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedReferenceObjectEnvelope {
    pub request_id: String,
    pub idempotency_key: String,
    pub artifact_id: String,
    pub content_hash: [u8; 32],
    pub object: Vec<u8>,
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
    digest.update(b"service.reference-object-envelope.v1/session\0");
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
) -> Result<Vec<u8>, ReferenceObjectEnvelopeError> {
    let key_id = recipient_key_id.as_bytes();
    if key_id.is_empty()
        || key_id.len() > u8::MAX as usize
        || key_id.iter().any(|byte| !byte.is_ascii_graphic())
    {
        return Err(ReferenceObjectEnvelopeError::Malformed);
    }
    let mut value = Vec::with_capacity(8 + 8 + 1 + key_id.len() + 32 + 12);
    value.extend_from_slice(REFERENCE_OBJECT_ENVELOPE_V1_MAGIC);
    value.extend_from_slice(&expires_at_ms.to_be_bytes());
    value.push(key_id.len() as u8);
    value.extend_from_slice(key_id);
    value.extend_from_slice(ephemeral_public);
    value.extend_from_slice(nonce);
    Ok(value)
}

fn identifier(value: &str) -> Result<&[u8], ReferenceObjectEnvelopeError> {
    let raw = value.as_bytes();
    if raw.is_empty()
        || raw.len() > MAX_REFERENCE_IDENTIFIER_BYTES
        || raw.iter().any(|byte| !byte.is_ascii_graphic())
    {
        return Err(ReferenceObjectEnvelopeError::Malformed);
    }
    Ok(raw)
}

fn payload(
    request_id: &str,
    idempotency_key: &str,
    artifact_id: &str,
    content_hash: &[u8; 32],
    object: &[u8],
    evidence: &[u8],
) -> Result<Vec<u8>, ReferenceObjectEnvelopeError> {
    if object.is_empty() || object.len() > MAX_REFERENCE_OBJECT_BYTES {
        return Err(ReferenceObjectEnvelopeError::ObjectTooLarge);
    }
    if evidence.is_empty() || evidence.len() > MAX_REFERENCE_EVIDENCE_BYTES {
        return Err(ReferenceObjectEnvelopeError::EvidenceTooLarge);
    }
    if Sha256::digest(object).as_slice() != content_hash {
        return Err(ReferenceObjectEnvelopeError::DigestMismatch);
    }
    let request = identifier(request_id)?;
    let idempotency = identifier(idempotency_key)?;
    let artifact = identifier(artifact_id)?;
    let mut value = Vec::with_capacity(
        8 + 4
            + 4
            + 32
            + 3
            + request.len()
            + idempotency.len()
            + artifact.len()
            + object.len()
            + evidence.len(),
    );
    value.extend_from_slice(REFERENCE_OBJECT_PAYLOAD_V1_MAGIC);
    value.extend_from_slice(&(object.len() as u32).to_be_bytes());
    value.extend_from_slice(&(evidence.len() as u32).to_be_bytes());
    value.extend_from_slice(content_hash);
    for item in [request, idempotency, artifact] {
        value.push(item.len() as u8);
        value.extend_from_slice(item);
    }
    value.extend_from_slice(object);
    value.extend_from_slice(evidence);
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub fn seal_reference_object_envelope_v1(
    recipient_public: &[u8; 32],
    ephemeral_secret: &[u8; 32],
    nonce: &[u8; 12],
    request_id: &str,
    idempotency_key: &str,
    artifact_id: &str,
    content_hash: &[u8; 32],
    object: &[u8],
    requester_evidence: &[u8],
    expires_at_ms: u64,
) -> Result<Vec<u8>, ReferenceObjectEnvelopeError> {
    if expires_at_ms == 0 {
        return Err(ReferenceObjectEnvelopeError::Malformed);
    }
    let secret = StaticSecret::from(*ephemeral_secret);
    let ephemeral_public = PublicKey::from(&secret).to_bytes();
    let recipient = PublicKey::from(*recipient_public);
    let shared = secret.diffie_hellman(&recipient);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(ReferenceObjectEnvelopeError::InvalidKeyAgreement);
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
    let ciphertext = encrypt_payload(
        &key,
        nonce,
        &payload(
            request_id,
            idempotency_key,
            artifact_id,
            content_hash,
            object,
            requester_evidence,
        )?,
        &aad,
    );
    if ciphertext.len() > MAX_REFERENCE_OBJECT_CIPHERTEXT_BYTES {
        return Err(ReferenceObjectEnvelopeError::Malformed);
    }
    let mut envelope = aad;
    envelope.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub fn open_reference_object_envelope_v1(
    recipient_secret: &[u8; 32],
    expected_recipient_key_id: &str,
    envelope: &[u8],
    now_ms: u64,
) -> Result<OpenedReferenceObjectEnvelope, ReferenceObjectEnvelopeError> {
    if envelope.len() < 8 + 8 + 1 + 32 + 12 + 4 + 16 {
        return Err(ReferenceObjectEnvelopeError::Malformed);
    }
    if &envelope[..8] != REFERENCE_OBJECT_ENVELOPE_V1_MAGIC {
        return Err(ReferenceObjectEnvelopeError::UnsupportedVersion);
    }
    let expires_at_ms = u64::from_be_bytes(
        envelope[8..16]
            .try_into()
            .map_err(|_| ReferenceObjectEnvelopeError::Malformed)?,
    );
    if now_ms >= expires_at_ms {
        return Err(ReferenceObjectEnvelopeError::Expired);
    }
    let key_id_len = envelope[16] as usize;
    let key_id_end = 17usize
        .checked_add(key_id_len)
        .ok_or(ReferenceObjectEnvelopeError::Malformed)?;
    let ephemeral_end = key_id_end
        .checked_add(32)
        .ok_or(ReferenceObjectEnvelopeError::Malformed)?;
    let nonce_end = ephemeral_end
        .checked_add(12)
        .ok_or(ReferenceObjectEnvelopeError::Malformed)?;
    let length_end = nonce_end
        .checked_add(4)
        .ok_or(ReferenceObjectEnvelopeError::Malformed)?;
    if length_end > envelope.len() {
        return Err(ReferenceObjectEnvelopeError::Malformed);
    }
    let key_id = core::str::from_utf8(&envelope[17..key_id_end])
        .map_err(|_| ReferenceObjectEnvelopeError::Malformed)?;
    let recipient_secret = StaticSecret::from(*recipient_secret);
    let recipient_public = PublicKey::from(&recipient_secret).to_bytes();
    let actual_key_id = tunnel_public_key_id(&recipient_public);
    if key_id != expected_recipient_key_id || key_id != actual_key_id {
        return Err(ReferenceObjectEnvelopeError::WrongRecipient);
    }
    let ephemeral_public: [u8; 32] = envelope[key_id_end..ephemeral_end]
        .try_into()
        .map_err(|_| ReferenceObjectEnvelopeError::Malformed)?;
    let nonce: [u8; 12] = envelope[ephemeral_end..nonce_end]
        .try_into()
        .map_err(|_| ReferenceObjectEnvelopeError::Malformed)?;
    let ciphertext_len = u32::from_be_bytes(
        envelope[nonce_end..length_end]
            .try_into()
            .map_err(|_| ReferenceObjectEnvelopeError::Malformed)?,
    ) as usize;
    if ciphertext_len > MAX_REFERENCE_OBJECT_CIPHERTEXT_BYTES
        || envelope.len() != length_end + ciphertext_len
    {
        return Err(ReferenceObjectEnvelopeError::Malformed);
    }
    let ephemeral_public_key = PublicKey::from(ephemeral_public);
    let shared = recipient_secret.diffie_hellman(&ephemeral_public_key);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(ReferenceObjectEnvelopeError::InvalidKeyAgreement);
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
    .map_err(|_| ReferenceObjectEnvelopeError::AuthenticationFailed)?;
    if plaintext.len() < 8 + 4 + 4 + 32 + 3 || &plaintext[..8] != REFERENCE_OBJECT_PAYLOAD_V1_MAGIC
    {
        return Err(ReferenceObjectEnvelopeError::Malformed);
    }
    let object_len = u32::from_be_bytes(
        plaintext[8..12]
            .try_into()
            .map_err(|_| ReferenceObjectEnvelopeError::Malformed)?,
    ) as usize;
    let evidence_len = u32::from_be_bytes(
        plaintext[12..16]
            .try_into()
            .map_err(|_| ReferenceObjectEnvelopeError::Malformed)?,
    ) as usize;
    let content_hash: [u8; 32] = plaintext[16..48]
        .try_into()
        .map_err(|_| ReferenceObjectEnvelopeError::Malformed)?;
    if object_len == 0 || object_len > MAX_REFERENCE_OBJECT_BYTES {
        return Err(ReferenceObjectEnvelopeError::ObjectTooLarge);
    }
    if evidence_len == 0 || evidence_len > MAX_REFERENCE_EVIDENCE_BYTES {
        return Err(ReferenceObjectEnvelopeError::EvidenceTooLarge);
    }
    let mut cursor = 48usize;
    let mut identifiers = Vec::with_capacity(3);
    for _ in 0..3 {
        let length = *plaintext
            .get(cursor)
            .ok_or(ReferenceObjectEnvelopeError::Malformed)? as usize;
        cursor = cursor
            .checked_add(1)
            .ok_or(ReferenceObjectEnvelopeError::Malformed)?;
        let end = cursor
            .checked_add(length)
            .ok_or(ReferenceObjectEnvelopeError::Malformed)?;
        let raw = plaintext
            .get(cursor..end)
            .ok_or(ReferenceObjectEnvelopeError::Malformed)?;
        let value =
            core::str::from_utf8(raw).map_err(|_| ReferenceObjectEnvelopeError::Malformed)?;
        identifier(value)?;
        identifiers.push(value.to_string());
        cursor = end;
    }
    let object_end = cursor
        .checked_add(object_len)
        .ok_or(ReferenceObjectEnvelopeError::Malformed)?;
    let evidence_end = object_end
        .checked_add(evidence_len)
        .ok_or(ReferenceObjectEnvelopeError::Malformed)?;
    if evidence_end != plaintext.len() {
        return Err(ReferenceObjectEnvelopeError::Malformed);
    }
    let object = plaintext[cursor..object_end].to_vec();
    if Sha256::digest(&object).as_slice() != content_hash {
        return Err(ReferenceObjectEnvelopeError::DigestMismatch);
    }
    Ok(OpenedReferenceObjectEnvelope {
        request_id: identifiers.remove(0),
        idempotency_key: identifiers.remove(0),
        artifact_id: identifiers.remove(0),
        content_hash,
        object,
        requester_evidence: plaintext[object_end..].to_vec(),
        recipient_key_id: actual_key_id,
        expires_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn fixture() -> ([u8; 32], [u8; 32], Vec<u8>) {
        let recipient_secret = [7u8; 32];
        let recipient_public = PublicKey::from(&StaticSecret::from(recipient_secret)).to_bytes();
        let object = b"original visual reference";
        let content_hash = Sha256::digest(object).into();
        let envelope = seal_reference_object_envelope_v1(
            &recipient_public,
            &[8u8; 32],
            &[9u8; 12],
            "request-1",
            "submit-1",
            "reference-1",
            &content_hash,
            object,
            b"signed-requester-evidence",
            2_000,
        )
        .unwrap();
        (recipient_secret, recipient_public, envelope)
    }

    #[test]
    fn sealed_reference_round_trips_and_exposes_no_plaintext() {
        let (secret, public, envelope) = fixture();
        assert!(!envelope.windows(8).any(|value| value == b"original"));
        let opened = open_reference_object_envelope_v1(
            &secret,
            &tunnel_public_key_id(&public),
            &envelope,
            1_000,
        )
        .unwrap();
        assert_eq!(opened.request_id, "request-1");
        assert_eq!(opened.idempotency_key, "submit-1");
        assert_eq!(opened.artifact_id, "reference-1");
        assert_eq!(opened.object, b"original visual reference");
        assert_eq!(opened.requester_evidence, b"signed-requester-evidence");
    }

    #[test]
    fn wrong_digest_tampering_recipient_and_expiry_fail_closed() {
        let (secret, public, envelope) = fixture();
        let id = tunnel_public_key_id(&public);
        let object = b"original visual reference";
        assert_eq!(
            seal_reference_object_envelope_v1(
                &public,
                &[8; 32],
                &[9; 12],
                "request-1",
                "submit-1",
                "reference-1",
                &[0; 32],
                object,
                b"evidence",
                2_000,
            ),
            Err(ReferenceObjectEnvelopeError::DigestMismatch)
        );
        let mut tampered = envelope.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            open_reference_object_envelope_v1(&secret, &id, &tampered, 1_000),
            Err(ReferenceObjectEnvelopeError::AuthenticationFailed)
        );
        assert_eq!(
            open_reference_object_envelope_v1(&[6; 32], &id, &envelope, 1_000),
            Err(ReferenceObjectEnvelopeError::WrongRecipient)
        );
        assert_eq!(
            open_reference_object_envelope_v1(&secret, &id, &envelope, 2_000),
            Err(ReferenceObjectEnvelopeError::Expired)
        );
    }

    #[test]
    fn deterministic_interop_fixture_is_stable() {
        let envelope = fixture().2;
        assert_eq!(
            Sha256::digest(&envelope).as_slice(),
            &[
                187, 126, 107, 21, 157, 36, 76, 255, 238, 47, 21, 0, 92, 216, 128, 213, 58, 160,
                90, 207, 55, 128, 191, 220, 3, 84, 140, 242, 114, 83, 21, 124,
            ]
        );
    }
}
