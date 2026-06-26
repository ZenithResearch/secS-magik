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
    ResourceLockViolation,
    AuthorityAmplification,
    InsufficientEvidence,
    InvalidPresentation,
    InvalidSignature,
    NotYetValidClaim,
    UnsupportedSignatureSuite,
    UnknownIssuer,
    WrongIssuerKey,
    WrongTrustRoot,
    WrongRegistryRoot,
    WrongRoot,
    WrongEpoch,
    Stale,
    Revoked,
    NotFinal,
    Equivocated,
    MalformedDreggAuthority,
    UnsupportedSuite,
    WrongBinding,
    MissingStatus,
    MissingRevocationRoot,
    WrongRevocationRoot,
    UnsupportedRevocationVerifier,
    UnsupportedBlsThresholdFinality,
    UnsupportedRotatedReplayVerifier,
    MissingLiveDreggVerifier,
    MissingLiveDreggRevocationVerifier,
    MissingLiveDreggBlsThresholdVerifier,
    MissingLiveDreggRotatedReplayVerifier,
    StaleDreggRevocationRoot,
    InvalidDreggRevocationProof,
    InvalidDreggFinalityQc,
    InvalidDreggRotatedProof,
    InvalidAdmission,
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
            Self::ResourceLockViolation => "resource_lock_violation",
            Self::AuthorityAmplification => "authority_amplification",
            Self::InsufficientEvidence => "insufficient_evidence",
            Self::InvalidPresentation => "invalid_presentation",
            Self::InvalidSignature => "invalid_signature",
            Self::NotYetValidClaim => "not_yet_valid_claim",
            Self::UnsupportedSignatureSuite => "unsupported_signature_suite",
            Self::UnknownIssuer => "unknown_issuer",
            Self::WrongIssuerKey => "wrong_issuer_key",
            Self::WrongTrustRoot => "wrong_trust_root",
            Self::WrongRegistryRoot => "wrong_registry_root",
            Self::WrongRoot => "wrong_root",
            Self::WrongEpoch => "wrong_epoch",
            Self::Stale => "stale",
            Self::Revoked => "revoked",
            Self::NotFinal => "not_final",
            Self::Equivocated => "equivocated",
            Self::MalformedDreggAuthority => "malformed",
            Self::UnsupportedSuite => "unsupported_suite",
            Self::WrongBinding => "wrong_binding",
            Self::MissingStatus => "missing_status",
            Self::MissingRevocationRoot => "missing_revocation_root",
            Self::WrongRevocationRoot => "wrong_revocation_root",
            Self::UnsupportedRevocationVerifier => "unsupported_revocation_verifier",
            Self::UnsupportedBlsThresholdFinality => "unsupported_bls_threshold_finality",
            Self::UnsupportedRotatedReplayVerifier => "unsupported_rotated_replay_verifier",
            Self::MissingLiveDreggVerifier => "missing_live_dregg_verifier",
            Self::MissingLiveDreggRevocationVerifier => "missing_live_dregg_revocation_verifier",
            Self::MissingLiveDreggBlsThresholdVerifier => {
                "missing_live_dregg_bls_threshold_verifier"
            }
            Self::MissingLiveDreggRotatedReplayVerifier => {
                "missing_live_dregg_rotated_replay_verifier"
            }
            Self::StaleDreggRevocationRoot => "stale_dregg_revocation_root",
            Self::InvalidDreggRevocationProof => "invalid_dregg_revocation_proof",
            Self::InvalidDreggFinalityQc => "invalid_dregg_finality_qc",
            Self::InvalidDreggRotatedProof => "invalid_dregg_rotated_proof",
            Self::InvalidAdmission => "invalid_admission",
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

/// Bumped to 3 by M13.3: contexts now carry the bound `resource` the operation
/// acts on, so receiver-local permission policy can be evaluated against it.
/// (v2 added the #81 descriptor authorization fingerprint.)
pub const VERIFIED_CALL_CONTEXT_SCHEMA_VERSION: u16 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCallContext {
    pub schema_version: u16,
    pub context_id: String,
    pub packet_hash: [u8; 32],
    pub session_id: [u8; 16],
    pub nonce: [u8; 12],
    pub opcode: u8,
    pub operation: String,
    /// Resource the operation acts on (M13.3), bound into the signed context so
    /// receiver-local permission policy can be evaluated against it. `None` for
    /// operations that carry no resource. Signing covers this field, so a
    /// tampered resource breaks context verification.
    pub resource: Option<String>,
    pub subject: VerifiedSubject,
    pub audience: String,
    pub evidence_summary: Vec<String>,
    pub capability_result: String,
    pub credential_result: String,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Canonical authorization fingerprint of the descriptor this context
    /// was verified against (#81); re-checked against the active manifest
    /// before any route side effects. Empty fingerprints never route.
    pub descriptor_fingerprint: String,
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

    /// M13.3: verify a (dev/prototype) operation and bind a `resource` into the
    /// signed context before signing, so receiver-local permission policy can be
    /// evaluated against it. The resource is signed, so it cannot be altered
    /// after verification.
    pub fn verify_manifest_operation_with_resource_and_sign_with_identity(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        resource: Option<&str>,
        now: u64,
        identity: &NodeVerifierIdentity,
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        let mut context = Self::verify_manifest_operation(packet, manifest, audience, now)?;
        context.resource = resource.map(ToString::to_string);
        identity.sign_context(context)
    }

    /// Raw-key variant of [`Self::verify_manifest_operation_with_resource_and_sign_with_identity`].
    pub fn verify_manifest_operation_with_resource_and_sign(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        resource: Option<&str>,
        now: u64,
        signer_key_id: &str,
        secret_key: &[u8; 32],
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        let mut context = Self::verify_manifest_operation(packet, manifest, audience, now)?;
        context.resource = resource.map(ToString::to_string);
        context.sign_ed25519(
            signer_key_id,
            secret_key,
            AuthenticatorKind::Ed25519Verifier,
        )
    }

    pub fn verify_manifest_operation_and_sign_for_runtime_with_identity(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        now: u64,
        identity: &NodeVerifierIdentity,
        runtime_mode: RuntimeMode,
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        Self::verify_manifest_operation_and_sign_for_runtime_with_identity_and_caller(
            packet,
            manifest,
            audience,
            now,
            identity,
            runtime_mode,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_manifest_operation_and_sign_for_runtime_with_identity_and_caller(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        now: u64,
        identity: &NodeVerifierIdentity,
        runtime_mode: RuntimeMode,
        caller_keys: Option<&crate::caller::CallerKeyRegistry>,
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        let context = Self::verify_manifest_operation_for_runtime_with_caller(
            packet,
            manifest,
            audience,
            now,
            runtime_mode,
            caller_keys,
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
            prototype_subject(),
            descriptor_evidence_summary(descriptor),
            None,
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
        Self::verify_manifest_operation_for_runtime_with_caller(
            packet,
            manifest,
            audience,
            now,
            runtime_mode,
            None,
        )
    }

    /// Runtime verification with the receiver-held caller key seam (M12.1).
    ///
    /// Caller authentication runs after the descriptor production gates so
    /// existing descriptor rejects keep their typed reasons, and before
    /// signed-context creation so the context subject reflects the
    /// authenticated caller. In `production_verified` a registry is required
    /// and the proof must verify; local/dev modes verify when a fixture
    /// registry is supplied and otherwise keep the prototype subject (those
    /// contexts are already marked LocalDevUntrusted by the dev identity).
    /// Caller proof-of-origin is necessary, never sufficient: it does not
    /// satisfy wallet/issuer/Dregg evidence requirements.
    pub fn verify_manifest_operation_for_runtime_with_caller(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        now: u64,
        runtime_mode: RuntimeMode,
        caller_keys: Option<&crate::caller::CallerKeyRegistry>,
    ) -> Result<VerifiedCallContext, VerificationError> {
        if crate::clock::is_clock_read_failure(now) {
            return Err(VerificationError::ExpiredClaim);
        }
        Self::verify_prototype_envelope(packet)?;
        let descriptor = manifest.lookup(packet.opcode)?;
        reject_non_production_descriptor(descriptor, runtime_mode)?;
        let subject = match (runtime_mode, caller_keys) {
            (_, Some(registry)) => {
                let caller = crate::caller::verify_caller_proof(packet, registry, now)?;
                VerifiedSubject {
                    subject_id: caller.subject_id,
                    key_id: caller.key_id,
                }
            }
            (RuntimeMode::ProductionVerified, None) => {
                return Err(VerificationError::MissingCallerRegistry);
            }
            (_, None) => prototype_subject(),
        };
        verified_context_for_descriptor(
            packet,
            descriptor,
            audience,
            subject,
            descriptor_evidence_summary(descriptor),
            None,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_manifest_operation_with_live_evidence_and_sign_for_runtime_with_identity_and_caller(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        inputs: &crate::evidence::EvidenceInputs,
        trusted_payload: &[u8],
        adapter: &dyn EvidenceAdapter,
        now: u64,
        identity: &NodeVerifierIdentity,
        runtime_mode: RuntimeMode,
        caller_keys: Option<&crate::caller::CallerKeyRegistry>,
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        if crate::clock::is_clock_read_failure(now) {
            return Err(VerificationError::ExpiredClaim);
        }
        Self::verify_prototype_envelope(packet)?;
        let descriptor = manifest.lookup(packet.opcode)?;
        reject_non_production_descriptor(descriptor, runtime_mode)?;
        let subject = match (runtime_mode, caller_keys) {
            (_, Some(registry)) => {
                let caller = crate::caller::verify_caller_proof(packet, registry, now)?;
                VerifiedSubject {
                    subject_id: caller.subject_id,
                    key_id: caller.key_id,
                }
            }
            (RuntimeMode::ProductionVerified, None) => {
                return Err(VerificationError::MissingCallerRegistry);
            }
            (_, None) => prototype_subject(),
        };
        let mut request = EvidenceRequest::from_descriptor_with_refs(
            descriptor,
            &subject.subject_id,
            audience,
            inputs.evidence_refs().iter().map(String::as_str),
        );
        request
            .public_inputs
            .extend(inputs.public_inputs().iter().cloned());
        request.trusted_requested_resource =
            trusted_requested_resource_from_payload(trusted_payload)?;
        let evidence_summary = match adapter.verify(&request) {
            EvidenceResult::Satisfied(summary) => summary.to_context_fields(),
            EvidenceResult::Rejected(error) => return Err(error),
        };
        let context_resource = context_resource_from_evidence_summary(&evidence_summary)?;
        let context = verified_context_for_descriptor(
            packet,
            descriptor,
            audience,
            subject,
            evidence_summary,
            context_resource,
            now,
        )?;
        identity.sign_context(context)
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
    /// Canonical multi-evidence-ref verification API (#79): all evidence
    /// refs and public inputs arrive as explicit [`EvidenceInputs`] from the
    /// caller/runtime, never via adapter mutation. Enforces the same
    /// envelope, descriptor, TTL, session, binding, and Ed25519
    /// context-signing checks as the single-ref helpers, which now delegate
    /// here.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(
        packet: &ZenithPacket,
        manifest: &ReceiverManifest,
        audience: &str,
        subject: &str,
        inputs: &crate::evidence::EvidenceInputs,
        adapter: &dyn EvidenceAdapter,
        now: u64,
        signer_key_id: &str,
        secret_key: &[u8; 32],
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        if crate::clock::is_clock_read_failure(now) {
            return Err(VerificationError::ExpiredClaim);
        }
        Self::verify_prototype_envelope(packet)?;
        let descriptor = manifest.lookup(packet.opcode)?;
        let mut request = EvidenceRequest::from_descriptor_with_refs(
            descriptor,
            subject,
            audience,
            inputs.evidence_refs().iter().map(String::as_str),
        );
        request
            .public_inputs
            .extend(inputs.public_inputs().iter().cloned());
        request.trusted_requested_resource =
            trusted_requested_resource_from_payload(&packet.encrypted_payload)?;
        let evidence_summary = match adapter.verify(&request) {
            EvidenceResult::Satisfied(summary) => summary.to_context_fields(),
            EvidenceResult::Rejected(error) => return Err(error),
        };
        let context_resource = context_resource_from_evidence_summary(&evidence_summary)?;
        let context = verified_context_for_descriptor(
            packet,
            descriptor,
            audience,
            VerifiedSubject {
                subject_id: subject.to_string(),
                key_id: format!("{subject}#key"),
            },
            evidence_summary,
            context_resource,
            now,
        )?;

        context.sign_ed25519(
            signer_key_id,
            secret_key,
            AuthenticatorKind::Ed25519Verifier,
        )
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
        // Compatibility wrapper: single optional ref + loose public inputs
        // normalize into the canonical EvidenceInputs path (#79).
        let inputs = crate::evidence::EvidenceInputs::new(evidence_ref, public_inputs);
        Self::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(
            packet,
            manifest,
            audience,
            subject,
            &inputs,
            adapter,
            now,
            signer_key_id,
            secret_key,
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
    // #151 lockstep guard: canonical `membership.provision` advertises the
    // evidence-backed helper/API contract, but live TCP ingress is still
    // descriptor-only and carries no evidence refs/public inputs. Keep this
    // fail-closed branch until ingress routes on-wire evidence into the
    // evidence-backed verifier path.
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

fn prototype_subject() -> VerifiedSubject {
    VerifiedSubject {
        subject_id: PROTOTYPE_LOCAL_SUBJECT.to_string(),
        key_id: format!("{PROTOTYPE_LOCAL_SUBJECT}#key"),
    }
}

fn context_resource_from_evidence_summary(
    evidence_summary: &[String],
) -> Result<Option<String>, VerificationError> {
    if !evidence_summary
        .iter()
        .any(|field| field == "resource_lock:verified")
    {
        return Ok(None);
    }

    let Some(value) = evidence_summary
        .iter()
        .find_map(|field| field.strip_prefix("resource:"))
    else {
        return Err(VerificationError::ResourceLockViolation);
    };
    if value.is_empty() {
        return Err(VerificationError::WrongResource);
    }
    Ok(Some(value.to_string()))
}

fn trusted_requested_resource_from_payload(
    payload: &[u8],
) -> Result<Option<String>, VerificationError> {
    if payload.is_empty() {
        return Ok(None);
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return Ok(None);
    };
    let Some(resource) = value
        .as_object()
        .and_then(|object| object.get("requested_resource"))
    else {
        return Ok(None);
    };
    let Some(resource) = resource.as_str() else {
        return Err(VerificationError::AuthorityAmplification);
    };
    if resource.is_empty() {
        return Err(VerificationError::AuthorityAmplification);
    }
    Ok(Some(resource.to_string()))
}

fn verified_context_for_descriptor(
    packet: &ZenithPacket,
    descriptor: &crate::manifest::OperationDescriptor,
    audience: &str,
    subject: VerifiedSubject,
    evidence_summary: Vec<String>,
    resource: Option<String>,
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
        schema_version: VERIFIED_CALL_CONTEXT_SCHEMA_VERSION,
        context_id: format!("ctx-v1-{now}-{:02x}-{packet_hash_suffix}", packet.opcode),
        packet_hash,
        session_id: packet.session_id,
        nonce: packet.nonce,
        opcode: packet.opcode,
        operation: descriptor.name.as_str().to_string(),
        // Evidence-backed sign paths promote a verifier-derived resource only
        // after the evidence adapter has accepted it (M15.8/#144). Descriptor-only
        // verification continues to bind no resource.
        resource,
        subject,
        audience: audience.to_string(),
        evidence_summary,
        capability_result: descriptor.required_capabilities.join(","),
        credential_result: descriptor.required_credentials.join(","),
        issued_at: now,
        expires_at: now.saturating_add(packet.claim_ttl),
        replay_scope: replay_scope_name(descriptor.replay_scope).to_string(),
        descriptor_fingerprint: descriptor.authorization_fingerprint(),
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
