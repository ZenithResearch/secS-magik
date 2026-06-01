use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as SignatureVerifier, VerifyingKey};
use libsec_core::ZenithPacket;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    MalformedPacket,
    ExpiredClaim,
    MissingPrototypeProofEnvelope,
    BadPrototypeProofEnvelope,
    MissingTunnelKey,
    BadMac,
    UnknownOperation,
    HandlerUnavailable,
    WrongAudience,
    InvalidSignature,
    InternalError,
}

impl VerificationError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::MalformedPacket => "malformed_packet",
            Self::ExpiredClaim => "expired_claim",
            Self::MissingPrototypeProofEnvelope => "missing_prototype_proof_envelope",
            Self::BadPrototypeProofEnvelope => "bad_prototype_proof_envelope",
            Self::MissingTunnelKey => "missing_tunnel_key",
            Self::BadMac => "bad_mac",
            Self::UnknownOperation => "unknown_operation",
            Self::HandlerUnavailable => "handler_unavailable",
            Self::WrongAudience => "wrong_audience",
            Self::InvalidSignature => "invalid_signature",
            Self::InternalError => "internal_error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedSubject {
    pub subject_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCallContext {
    pub schema_version: u16,
    pub context_id: String,
    pub packet_hash: [u8; 32],
    pub session_id: [u8; 16],
    pub nonce: [u8; 12],
    pub opcode: u8,
    pub operation: String,
    pub subject: VerifiedSubject,
    pub audience: String,
    pub evidence_summary: Vec<String>,
    pub capability_result: String,
    pub credential_result: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub replay_scope: String,
    pub handler_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticatorKind {
    LocalDevUntrusted,
    LocalMac,
    Ed25519Node,
    Ed25519Verifier,
    Ed25519NodeAndVerifier,
    ExternalAnchor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVerifiedCallContext {
    pub context: VerifiedCallContext,
    pub signer_key_id: String,
    pub authenticator_kind: AuthenticatorKind,
    pub signature: Vec<u8>,
}

pub enum VerificationDecision {
    Verified(VerifiedCallContext),
    Rejected(VerificationError),
}

pub struct Verifier;

impl Verifier {
    pub fn verify_prototype_envelope(packet: &ZenithPacket) -> Result<(), VerificationError> {
        if packet.proof.is_empty() {
            return Err(VerificationError::MissingPrototypeProofEnvelope);
        }
        if packet.claim_ttl == 0 {
            return Err(VerificationError::ExpiredClaim);
        }
        Ok(())
    }
}

impl VerifiedCallContext {
    pub fn sign_ed25519(
        self,
        signer_key_id: &str,
        secret_key: &[u8; 32],
        authenticator_kind: AuthenticatorKind,
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        let signing_key = SigningKey::from_bytes(secret_key);
        let bytes = bincode::serialize(&self).map_err(|_| VerificationError::InternalError)?;
        let signature = signing_key.sign(&bytes);

        Ok(SignedVerifiedCallContext {
            context: self,
            signer_key_id: signer_key_id.to_string(),
            authenticator_kind,
            signature: signature.to_bytes().to_vec(),
        })
    }
}

impl SignedVerifiedCallContext {
    pub fn verify_ed25519(
        &self,
        secret_key: &[u8; 32],
        expected_audience: &str,
        now: u64,
    ) -> Result<(), VerificationError> {
        if self.context.audience != expected_audience {
            return Err(VerificationError::WrongAudience);
        }
        if now > self.context.expires_at {
            return Err(VerificationError::ExpiredClaim);
        }

        let signing_key = SigningKey::from_bytes(secret_key);
        let verifying_key = VerifyingKey::from(&signing_key);
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| VerificationError::InvalidSignature)?;
        let bytes =
            bincode::serialize(&self.context).map_err(|_| VerificationError::InternalError)?;

        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| VerificationError::InvalidSignature)
    }
}
