use crate::evidence::{EvidenceAdapter, EvidenceKind, EvidenceRequest, EvidenceResult};
use crate::identity::NodeVerifierIdentity;
use crate::manifest::{OperationDescriptor, ReceiverManifest, ReplayScope, TargetKind};
use crate::ontology::PROTOTYPE_LOCAL_SUBJECT;
pub use crate::receipt::AuthenticatorKind;
use crate::runtime_mode::RuntimeMode;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as SignatureVerifier, VerifyingKey};

use libsec_core::ZenithPacket;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    MalformedPacket,
    ExpiredClaim,
    ClaimTtlExceedsDescriptorMax,
    InvalidSession,
    MissingPrototypeProofEnvelope,
    BadPrototypeProofEnvelope,
    MissingTunnelKey,
    BadMac,
    UnknownOperation,
    HandlerUnavailable,
    PrototypeOperationNotProductionAuthorized,
    WrongAudience,
    WrongSubject,
    WrongOrigin,
    WrongOperation,
    WrongResource,
    InsufficientEvidence,
    InvalidPresentation,
    InvalidSignature,
    NotYetValidClaim,
    UnsupportedSignatureSuite,
    UnknownIssuer,
    WrongIssuerKey,
    WrongTrustRoot,
    WrongRegistryRoot,
    RevokedIssuer,
    RevokedCredential,
    StaleRegistryStatus,
    UnknownVerifierKey,
    RevokedVerifierKey,
    ExpiredVerifierKey,
    NotYetValidVerifierKey,
    UntrustedVerifierKey,
    BadCallerProof,
    UnknownCallerKey,
    RevokedCallerKey,
    ExpiredCallerKey,
    NotYetValidCallerKey,
    MissingCallerRegistry,
    InternalError,
}

impl VerificationError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::MalformedPacket => "malformed_packet",
            Self::ExpiredClaim => "expired_claim",
            Self::ClaimTtlExceedsDescriptorMax => "claim_ttl_exceeds_descriptor_max",
            Self::InvalidSession => "invalid_session",
            Self::MissingPrototypeProofEnvelope => "missing_prototype_proof_envelope",
            Self::BadPrototypeProofEnvelope => "bad_prototype_proof_envelope",
            Self::MissingTunnelKey => "missing_tunnel_key",
            Self::BadMac => "bad_mac",
            Self::UnknownOperation => "unknown_operation",
            Self::HandlerUnavailable => "handler_unavailable",
            Self::PrototypeOperationNotProductionAuthorized => {
                "prototype_operation_not_production_authorized"
            }
            Self::WrongAudience => "wrong_audience",
            Self::WrongSubject => "wrong_subject",
            Self::WrongOrigin => "wrong_origin",
            Self::WrongOperation => "wrong_operation",
            Self::WrongResource => "wrong_resource",
            Self::InsufficientEvidence => "insufficient_evidence",
            Self::InvalidPresentation => "invalid_presentation",
            Self::InvalidSignature => "invalid_signature",
            Self::NotYetValidClaim => "not_yet_valid_claim",
            Self::UnsupportedSignatureSuite => "unsupported_signature_suite",
            Self::UnknownIssuer => "unknown_issuer",
            Self::WrongIssuerKey => "wrong_issuer_key",
            Self::WrongTrustRoot => "wrong_trust_root",
            Self::WrongRegistryRoot => "wrong_registry_root",
            Self::RevokedIssuer => "revoked_issuer",
            Self::RevokedCredential => "revoked_credential",
            Self::StaleRegistryStatus => "stale_registry_status",
            Self::UnknownVerifierKey => "unknown_verifier_key",
            Self::RevokedVerifierKey => "revoked_verifier_key",
            Self::ExpiredVerifierKey => "expired_verifier_key",
            Self::NotYetValidVerifierKey => "not_yet_valid_verifier_key",
            Self::UntrustedVerifierKey => "untrusted_verifier_key",
            Self::BadCallerProof => "bad_caller_proof",
            Self::UnknownCallerKey => "unknown_caller_key",
            Self::RevokedCallerKey => "revoked_caller_key",
            Self::ExpiredCallerKey => "expired_caller_key",
            Self::NotYetValidCallerKey => "not_yet_valid_caller_key",
            Self::MissingCallerRegistry => "missing_caller_registry",
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

    pub fn verify_manifest_operation_and_sign_for_runtime_with_identity(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        now: u64,
        identity: &NodeVerifierIdentity,
        runtime_mode: RuntimeMode,
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        let context = Self::verify_manifest_operation_for_runtime(
            packet,
            manifest,
            audience,
            now,
            runtime_mode,
        )?;
        identity.sign_context(context)
    }

    pub fn verify_manifest_operation(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        now: u64,
    ) -> Result<VerifiedCallContext, VerificationError> {
        // A clock-read failure must reject before any signed context exists;
        // a saturated expires_at would otherwise pass plain expiry comparisons.
        if crate::clock::is_clock_read_failure(now) {
            return Err(VerificationError::ExpiredClaim);
        }
        Self::verify_prototype_envelope(packet)?;
        let descriptor = manifest.lookup(packet.opcode)?;
        verified_context_for_descriptor(
            packet,
            descriptor,
            audience,
            PROTOTYPE_LOCAL_SUBJECT,
            descriptor_evidence_summary(descriptor),
            now,
        )
    }

    pub fn verify_manifest_operation_for_runtime(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        now: u64,
        runtime_mode: RuntimeMode,
    ) -> Result<VerifiedCallContext, VerificationError> {
        if crate::clock::is_clock_read_failure(now) {
            return Err(VerificationError::ExpiredClaim);
        }
        Self::verify_prototype_envelope(packet)?;
        let descriptor = manifest.lookup(packet.opcode)?;
        reject_non_production_descriptor(descriptor, runtime_mode)?;
        verified_context_for_descriptor(
            packet,
            descriptor,
            audience,
            PROTOTYPE_LOCAL_SUBJECT,
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
        Self::verify_manifest_operation_with_evidence_inputs_and_sign(
            packet,
            manifest,
            audience,
            subject,
            evidence_ref,
            [],
            adapter,
            now,
            signer_key_id,
            secret_key,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_manifest_operation_with_evidence_inputs_and_sign(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        subject: &str,
        evidence_ref: Option<&str>,
        public_inputs: impl IntoIterator<Item = String>,
        adapter: &dyn EvidenceAdapter,
        now: u64,
        signer_key_id: &str,
        secret_key: &[u8; 32],
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        Self::verify_prototype_envelope(packet)?;
        let descriptor = manifest.lookup(packet.opcode)?;
        let mut request =
            EvidenceRequest::from_descriptor(descriptor, subject, audience, evidence_ref);
        request.public_inputs.extend(public_inputs);
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

fn reject_non_production_descriptor(
    descriptor: &OperationDescriptor,
    runtime_mode: RuntimeMode,
) -> Result<(), VerificationError> {
    if runtime_mode != RuntimeMode::ProductionVerified {
        return Ok(());
    }
    if descriptor.dev_binding
        || descriptor.handler_id.starts_with("dev/")
        || descriptor.name.as_str().starts_with("candidate.dev")
        || (descriptor.target_kind == TargetKind::LegacyCoreExample
            && descriptor
                .accepted_evidence
                .iter()
                .any(|evidence| evidence == "prototype-proof-envelope"))
    {
        return Err(VerificationError::PrototypeOperationNotProductionAuthorized);
    }
    reject_descriptor_only_runtime_evidence_gap(descriptor)?;
    Ok(())
}

fn reject_descriptor_only_runtime_evidence_gap(
    descriptor: &OperationDescriptor,
) -> Result<(), VerificationError> {
    if descriptor.opcode == 0x44
        && descriptor.name.as_str() == "membership.provision"
        && descriptor
            .accepted_evidence
            .iter()
            .any(|evidence| evidence == EvidenceKind::WalletPresentation.as_str())
        && descriptor
            .accepted_evidence
            .iter()
            .any(|evidence| evidence == EvidenceKind::MembershipCredential.as_str())
    {
        return Err(VerificationError::InsufficientEvidence);
    }
    Ok(())
}

fn verified_context_for_descriptor(
    packet: &ZenithPacket,
    descriptor: &crate::manifest::OperationDescriptor,
    audience: &str,
    subject: &str,
    evidence_summary: Vec<String>,
    now: u64,
) -> Result<VerifiedCallContext, VerificationError> {
    if packet.claim_ttl > descriptor.max_ttl_seconds {
        return Err(VerificationError::ClaimTtlExceedsDescriptorMax);
    }
    if packet.session_id == [0u8; 16] {
        return Err(VerificationError::InvalidSession);
    }

    let packet_hash = packet_hash(packet)?;
    let packet_hash_suffix = packet_hash[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    Ok(VerifiedCallContext {
        schema_version: 1,
        context_id: format!("ctx-v1-{now}-{:02x}-{packet_hash_suffix}", packet.opcode),
        packet_hash,
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
        expires_at: now.saturating_add(packet.claim_ttl),
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
        // Reject the clock-read failure sentinel explicitly: a context created
        // under a failed clock saturates expires_at to u64::MAX, so the plain
        // comparison below would treat sentinel-now as not expired.
        if crate::clock::is_clock_read_failure(now) {
            return Err(VerificationError::ExpiredClaim);
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
