//! Caller proof-of-origin contract (M12.1).
//!
//! Defines the canonical bytes a caller signs and the versioned envelope the
//! `ZenithPacket.proof` field carries. The proof binds the entire envelope —
//! session, nonce, opcode, TTL, and encrypted payload — so a captured proof
//! cannot be re-bound to a different packet. The receiver verifies the
//! signature against a receiver-held caller key registry; the key id carried
//! in the proof is only a lookup reference, never trusted key material.
//!
//! Boundary: caller proof-of-origin is necessary but never sufficient
//! authority. It proves who sent the packet — not membership, issuer, root,
//! or Dregg authority.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

/// Version tag for the canonical signed bytes and the proof envelope. Bump on
/// any change to either construction.
pub const CALLER_PROOF_VERSION: &str = "secs-caller-proof-v1";

/// Ed25519 signature length in bytes.
pub const CALLER_SIGNATURE_LEN: usize = 64;

/// Maximum accepted caller key id length in bytes (defensive bound).
pub const MAX_CALLER_KEY_ID_LEN: usize = 256;

fn append_field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    out.push(b':');
    out.extend_from_slice(itoa(value.len()).as_bytes());
    out.push(b':');
    out.extend_from_slice(value);
    out.push(b'\n');
}

fn itoa(value: usize) -> String {
    use alloc::string::ToString;
    value.to_string()
}

/// Canonical, length-prefixed, newline-delimited bytes the caller signs.
/// Field order is fixed; every envelope field that must not be reattributable
/// is included (session_id, nonce, opcode, claim_ttl, encrypted_payload).
pub fn caller_canonical_bytes(
    session_id: &[u8; 16],
    nonce: &[u8; 12],
    opcode: u8,
    claim_ttl: u64,
    encrypted_payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(96 + encrypted_payload.len());
    out.extend_from_slice(CALLER_PROOF_VERSION.as_bytes());
    out.push(b'\n');
    append_field(&mut out, "session_id", session_id);
    append_field(&mut out, "nonce", nonce);
    append_field(&mut out, "opcode", &[opcode]);
    append_field(&mut out, "claim_ttl", &claim_ttl.to_be_bytes());
    append_field(&mut out, "encrypted_payload", encrypted_payload);
    out
}

/// Decoded contents of a caller proof envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerProofParts {
    /// Receiver-registry lookup reference. Never key material.
    pub key_id: String,
    pub signature: [u8; CALLER_SIGNATURE_LEN],
}

/// Encode the proof envelope carried in `ZenithPacket.proof`:
/// version tag, `\n`, u16-BE key id length, key id bytes, 64-byte signature.
pub fn encode_caller_proof(key_id: &str, signature: &[u8; CALLER_SIGNATURE_LEN]) -> Vec<u8> {
    let key_id_bytes = key_id.as_bytes();
    debug_assert!(key_id_bytes.len() <= MAX_CALLER_KEY_ID_LEN);
    let mut out =
        Vec::with_capacity(CALLER_PROOF_VERSION.len() + 3 + key_id_bytes.len() + signature.len());
    out.extend_from_slice(CALLER_PROOF_VERSION.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(&(key_id_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(key_id_bytes);
    out.extend_from_slice(signature);
    out
}

/// Decode a proof envelope. Returns `None` for anything malformed: wrong or
/// missing version tag, truncated fields, oversized or non-UTF-8 key id,
/// or trailing bytes after the signature.
pub fn decode_caller_proof(proof: &[u8]) -> Option<CallerProofParts> {
    let version = CALLER_PROOF_VERSION.as_bytes();
    let rest = proof.strip_prefix(version)?;
    let rest = rest.strip_prefix(b"\n")?;
    if rest.len() < 2 {
        return None;
    }
    let (len_bytes, rest) = rest.split_at(2);
    let key_id_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
    if key_id_len == 0 || key_id_len > MAX_CALLER_KEY_ID_LEN {
        return None;
    }
    if rest.len() != key_id_len + CALLER_SIGNATURE_LEN {
        return None;
    }
    let (key_id_bytes, signature_bytes) = rest.split_at(key_id_len);
    let key_id = core::str::from_utf8(key_id_bytes).ok()?;
    let mut signature = [0u8; CALLER_SIGNATURE_LEN];
    signature.copy_from_slice(signature_bytes);
    Some(CallerProofParts {
        key_id: String::from(key_id),
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn canonical_bytes_carry_version_and_fixed_field_order() {
        let bytes = caller_canonical_bytes(&[0xAA; 16], &[0xBB; 12], 0x10, 300, b"payload");
        let text_prefix = b"secs-caller-proof-v1\nsession_id:16:";

        assert!(bytes.starts_with(text_prefix));
        let session_pos = 21 + 14; // after version line + "session_id:16:"
        assert_eq!(&bytes[session_pos..session_pos + 16], &[0xAA; 16]);
        // claim_ttl is big-endian 8 bytes
        let ttl_marker = b"claim_ttl:8:";
        let ttl_pos = bytes
            .windows(ttl_marker.len())
            .position(|window| window == ttl_marker)
            .unwrap()
            + ttl_marker.len();
        assert_eq!(&bytes[ttl_pos..ttl_pos + 8], &300u64.to_be_bytes());
    }

    #[test]
    fn canonical_bytes_differ_when_any_envelope_field_differs() {
        let base = caller_canonical_bytes(&[1; 16], &[2; 12], 0x10, 300, b"payload");

        assert_ne!(
            base,
            caller_canonical_bytes(&[9; 16], &[2; 12], 0x10, 300, b"payload")
        );
        assert_ne!(
            base,
            caller_canonical_bytes(&[1; 16], &[9; 12], 0x10, 300, b"payload")
        );
        assert_ne!(
            base,
            caller_canonical_bytes(&[1; 16], &[2; 12], 0x20, 300, b"payload")
        );
        assert_ne!(
            base,
            caller_canonical_bytes(&[1; 16], &[2; 12], 0x10, 301, b"payload")
        );
        assert_ne!(
            base,
            caller_canonical_bytes(&[1; 16], &[2; 12], 0x10, 300, b"payloae")
        );
    }

    #[test]
    fn proof_envelope_round_trips() {
        let signature = [7u8; CALLER_SIGNATURE_LEN];
        let proof = encode_caller_proof("caller:alpha", &signature);

        let parts = decode_caller_proof(&proof).unwrap();
        assert_eq!(parts.key_id, "caller:alpha");
        assert_eq!(parts.signature, signature);
    }

    #[test]
    fn decode_rejects_wrong_version_tag() {
        let signature = [7u8; CALLER_SIGNATURE_LEN];
        let mut proof = encode_caller_proof("caller:alpha", &signature);
        proof[0] ^= 0x01;

        assert!(decode_caller_proof(&proof).is_none());
    }

    #[test]
    fn decode_rejects_truncated_and_extended_envelopes() {
        let signature = [7u8; CALLER_SIGNATURE_LEN];
        let proof = encode_caller_proof("caller:alpha", &signature);

        assert!(decode_caller_proof(&proof[..proof.len() - 1]).is_none());
        let mut extended = proof.clone();
        extended.push(0);
        assert!(decode_caller_proof(&extended).is_none());
        assert!(decode_caller_proof(b"").is_none());
        assert!(decode_caller_proof(b"secs-caller-proof-v1\n").is_none());
    }

    #[test]
    fn decode_rejects_empty_oversized_or_non_utf8_key_id() {
        let signature = [7u8; CALLER_SIGNATURE_LEN];

        // Empty key id.
        let mut proof = Vec::new();
        proof.extend_from_slice(CALLER_PROOF_VERSION.as_bytes());
        proof.push(b'\n');
        proof.extend_from_slice(&0u16.to_be_bytes());
        proof.extend_from_slice(&signature);
        assert!(decode_caller_proof(&proof).is_none());

        // Non-UTF-8 key id.
        let mut proof = Vec::new();
        proof.extend_from_slice(CALLER_PROOF_VERSION.as_bytes());
        proof.push(b'\n');
        proof.extend_from_slice(&2u16.to_be_bytes());
        proof.extend_from_slice(&[0xFF, 0xFE]);
        proof.extend_from_slice(&signature);
        assert!(decode_caller_proof(&proof).is_none());

        // Declared length larger than the bound.
        let mut proof = Vec::new();
        proof.extend_from_slice(CALLER_PROOF_VERSION.as_bytes());
        proof.push(b'\n');
        proof.extend_from_slice(&((MAX_CALLER_KEY_ID_LEN + 1) as u16).to_be_bytes());
        proof.extend_from_slice(&vec![b'a'; MAX_CALLER_KEY_ID_LEN + 1]);
        proof.extend_from_slice(&signature);
        assert!(decode_caller_proof(&proof).is_none());
    }
}
