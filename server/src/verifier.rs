use crate::evidence::{EvidenceAdapter, EvidenceRequest, EvidenceResult};
use crate::identity::NodeVerifierIdentity;
use crate::manifest::{ReceiverManifest, ReplayScope};
pub use crate::receipt::AuthenticatorKind;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as SignatureVerifier, VerifyingKey};
use libsec_core::ZenithPacket;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    WrongSubject,
    WrongOrigin,
    InsufficientEvidence,
    InvalidPresentation,
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
            Self::WrongSubject => "wrong_subject",
            Self::WrongOrigin => "wrong_origin",
            Self::InsufficientEvidence => "insufficient_evidence",
            Self::InvalidPresentation => "invalid_presentation",
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
pub struct SignedVerifiedCallContext {
    pub context: VerifiedCallContext,
    pub signer_key_id: String,
    pub authenticator_kind: AuthenticatorKind,
    pub signature: Vec<u8>,
}

pub enum VerificationDecision {
    Verified(Box<VerifiedCallContext>),
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

    pub fn verify_manifest_operation_and_sign(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        now: u64,
        signer_key_id: &str,
        secret_key: &[u8; 32],
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        Self::verify_manifest_operation_and_sign_with_kind(
            packet,
            manifest,
            audience,
            now,
            signer_key_id,
            secret_key,
            AuthenticatorKind::Ed25519Verifier,
        )
    }

    pub fn verify_manifest_operation_and_sign_with_identity(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        now: u64,
        identity: &NodeVerifierIdentity,
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        let context = Self::verify_manifest_operation(packet, manifest, audience, now)?;
        identity.sign_context(context)
    }

    pub fn verify_manifest_operation(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        now: u64,
    ) -> Result<VerifiedCallContext, VerificationError> {
        Self::verify_prototype_envelope(packet)?;
        let descriptor = manifest.lookup(packet.opcode)?;
        verified_context_for_descriptor(
            packet,
            descriptor,
            audience,
            "prototype.local-dev.subject",
            descriptor_evidence_summary(descriptor),
            now,
        )
    }

    pub fn verify_manifest_operation_and_sign_with_kind(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        now: u64,
        signer_key_id: &str,
        secret_key: &[u8; 32],
        authenticator_kind: AuthenticatorKind,
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        let context = Self::verify_manifest_operation(packet, manifest, audience, now)?;
        context.sign_ed25519(signer_key_id, secret_key, authenticator_kind)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_manifest_operation_with_evidence_and_sign(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        subject: &str,
        evidence_ref: Option<&str>,
        adapter: &dyn EvidenceAdapter,
        now: u64,
        signer_key_id: &str,
        secret_key: &[u8; 32],
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        Self::verify_prototype_envelope(packet)?;
        let descriptor = manifest.lookup(packet.opcode)?;
        let request = EvidenceRequest::from_descriptor(descriptor, subject, audience, evidence_ref);
        let evidence_summary = match adapter.verify(&request) {
            EvidenceResult::Satisfied(summary) => summary.to_context_fields(),
            EvidenceResult::Rejected(error) => return Err(error),
        };
        let context = verified_context_for_descriptor(
            packet,
            descriptor,
            audience,
            subject,
            evidence_summary,
            now,
        )?;

        context.sign_ed25519(
            signer_key_id,
            secret_key,
            AuthenticatorKind::Ed25519Verifier,
        )
    }
}

fn verified_context_for_descriptor(
    packet: &ZenithPacket,
    descriptor: &crate::manifest::OperationDescriptor,
    audience: &str,
    subject: &str,
    evidence_summary: Vec<String>,
    now: u64,
) -> Result<VerifiedCallContext, VerificationError> {
    let max_ttl = packet.claim_ttl.min(descriptor.max_ttl_seconds);
    Ok(VerifiedCallContext {
        schema_version: 1,
        context_id: format!("ctx-v1-{now}-{:02x}", packet.opcode),
        packet_hash: packet_hash(packet)?,
        session_id: packet.session_id,
        nonce: packet.nonce,
        opcode: packet.opcode,
        operation: descriptor.name.as_str().to_string(),
        subject: VerifiedSubject {
            subject_id: subject.to_string(),
            key_id: format!("{subject}#key"),
        },
        audience: audience.to_string(),
        evidence_summary,
        capability_result: descriptor.required_capabilities.join(","),
        credential_result: descriptor.required_credentials.join(","),
        issued_at: now,
        expires_at: now.saturating_add(max_ttl),
        replay_scope: replay_scope_name(descriptor.replay_scope).to_string(),
        handler_id: Some(descriptor.handler_id.clone()),
    })
}

fn packet_hash(packet: &ZenithPacket) -> Result<[u8; 32], VerificationError> {
    let bytes = bincode::serialize(packet).map_err(|_| VerificationError::InternalError)?;
    Ok(Sha256::digest(bytes).into())
}

fn descriptor_evidence_summary(descriptor: &crate::manifest::OperationDescriptor) -> Vec<String> {
    let mut evidence = descriptor.accepted_evidence.clone();
    evidence.push(format!("opcode_range:{:?}", descriptor.range));
    evidence.push(format!("dev_binding:{}", descriptor.dev_binding));
    evidence
}

fn replay_scope_name(scope: ReplayScope) -> &'static str {
    match scope {
        ReplayScope::SessionOpcodeNonce => "session:opcode:nonce",
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
        let signing_key = SigningKey::from_bytes(secret_key);
        let verifying_key = VerifyingKey::from(&signing_key);
        self.verify_ed25519_with_key(&verifying_key, expected_audience, now)
    }

    pub fn verify_ed25519_with_key(
        &self,
        verifying_key: &VerifyingKey,
        expected_audience: &str,
        now: u64,
    ) -> Result<(), VerificationError> {
        if self.context.audience != expected_audience {
            return Err(VerificationError::WrongAudience);
        }
        if now > self.context.expires_at {
            return Err(VerificationError::ExpiredClaim);
        }

        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| VerificationError::InvalidSignature)?;
        let bytes =
            bincode::serialize(&self.context).map_err(|_| VerificationError::InternalError)?;

        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| VerificationError::InvalidSignature)
    }
}
