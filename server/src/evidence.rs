//! Evidence adapter boundary for verifier inputs.
//!
//! External proof, federation, and settlement systems should enter secS through
//! adapters rooted here rather than becoming hard dependencies of packet parsing
//! or gateway execution.

use crate::dregg_authority::{
    DreggAuthorityFinalityMode, DreggAuthorityFinalityStatus, DreggAuthorityLookup,
    DreggAuthorityRegistry, DreggAuthorityRevocationStatus, DreggAuthorityRevocationVerifierMode,
};
use crate::manifest::OperationDescriptor;
use crate::verifier::VerificationError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    #[serde(rename = "prototype-proof-envelope")]
    PrototypeProofEnvelope,
    #[serde(rename = "local_static")]
    LocalStatic,
    #[serde(rename = "wallet_presentation")]
    WalletPresentation,
    #[serde(rename = "membership_credential")]
    MembershipCredential,
    #[serde(rename = "provisioning_credential")]
    ProvisioningCredential,
    #[serde(rename = "midnight_proof")]
    MidnightProof,
    #[serde(rename = "dregg_receipt")]
    DreggReceipt,
    #[serde(rename = "dregg_authority")]
    DreggAuthority,
    #[serde(rename = "cardano_settlement")]
    CardanoSettlement,
}

impl EvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrototypeProofEnvelope => "prototype-proof-envelope",
            Self::LocalStatic => "local_static",
            Self::WalletPresentation => "wallet_presentation",
            Self::MembershipCredential => "membership_credential",
            Self::ProvisioningCredential => "provisioning_credential",
            Self::MidnightProof => "midnight_proof",
            Self::DreggReceipt => "dregg_receipt",
            Self::DreggAuthority => "dregg_authority",
            Self::CardanoSettlement => "cardano_settlement",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveDreggProofKind {
    Revocation,
    BlsThresholdFinality,
    RotatedReplay,
}

impl LiveDreggProofKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Revocation => "revocation",
            Self::BlsThresholdFinality => "bls_threshold_finality",
            Self::RotatedReplay => "rotated_replay",
        }
    }
}

/// Versioned contract envelope for future live Dregg verifier adapters (#177).
///
/// This is a typed, redaction-safe contract only. It deliberately does not
/// verify revocation, BLS finality, or rotated replay proofs; later #178/#179/#180
/// adapters plug real verifiers into the trait seam using this shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveDreggEvidenceEnvelope {
    pub version: &'static str,
    pub proof_kind: LiveDreggProofKind,
    pub evidence_ref: String,
    pub federation_id: String,
    pub issuer_id: String,
    pub root_ref: String,
    pub root_fingerprint: String,
    pub epoch_id: String,
    pub proof_ref: String,
    pub verifier_mode: String,
}

impl LiveDreggEvidenceEnvelope {
    pub const VERSION: &'static str = "secs-dregg-live-evidence-v1";

    pub fn evidence_kind(&self) -> EvidenceKind {
        EvidenceKind::DreggAuthority
    }

    pub fn redacted_summary_fields(&self) -> Vec<String> {
        vec![
            format!("live_dregg_contract:{}", self.version),
            format!("live_dregg_proof_kind:{}", self.proof_kind.as_str()),
            redacted_reference_field("evidence_ref", &self.evidence_ref),
            redacted_reference_field("federation_id", &self.federation_id),
            redacted_reference_field("issuer_id", &self.issuer_id),
            redacted_reference_field("root_ref", &self.root_ref),
            format!("root_fingerprint:{}", self.root_fingerprint),
            redacted_reference_field("epoch_id", &self.epoch_id),
            redacted_reference_field("proof_ref", &self.proof_ref),
            format!("verifier_mode:{}", self.verifier_mode),
        ]
    }
}

/// Canonical caller/runtime evidence inputs (#79).
///
/// The explicit, ordered, validated representation of what a caller or
/// runtime ingress supplies for evidence-backed verification: zero or more
/// evidence references plus zero or more public inputs. This replaces the
/// test-only adapter-mutation pattern — evidence refs are direct inputs to
/// the verifier API, never hidden inside adapter clones.
///
/// Refs are deduplicated at construction (first occurrence wins, order
/// preserved) so duplicates can never escalate evidence. Empty refs are a
/// valid input that fails closed downstream — never an implicit fallback to
/// local/static evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceInputs {
    evidence_refs: Vec<String>,
    public_inputs: Vec<String>,
}

impl EvidenceInputs {
    pub fn new(
        evidence_refs: impl IntoIterator<Item = impl Into<String>>,
        public_inputs: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let mut deduped: Vec<String> = Vec::new();
        for evidence_ref in evidence_refs {
            let evidence_ref = evidence_ref.into();
            if !deduped.contains(&evidence_ref) {
                deduped.push(evidence_ref);
            }
        }
        Self {
            evidence_refs: deduped,
            public_inputs: public_inputs.into_iter().map(Into::into).collect(),
        }
    }

    pub fn evidence_refs(&self) -> &[String] {
        &self.evidence_refs
    }

    pub fn public_inputs(&self) -> &[String] {
        &self.public_inputs
    }

    pub fn is_empty(&self) -> bool {
        self.evidence_refs.is_empty() && self.public_inputs.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRequest {
    pub accepted_evidence: Vec<String>,
    pub subject: String,
    pub audience: String,
    pub operation: String,
    pub resource: Option<String>,
    pub evidence_refs: Vec<String>,
    pub public_inputs: Vec<String>,
    pub trusted_requested_resource: Option<String>,
}

impl EvidenceRequest {
    pub fn from_descriptor(
        descriptor: &OperationDescriptor,
        subject: &str,
        audience: &str,
        evidence_ref: Option<&str>,
    ) -> Self {
        Self::from_descriptor_with_refs(descriptor, subject, audience, evidence_ref)
    }

    pub fn from_descriptor_with_refs<'a>(
        descriptor: &OperationDescriptor,
        subject: &str,
        audience: &str,
        evidence_refs: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        Self {
            accepted_evidence: descriptor.accepted_evidence.clone(),
            subject: subject.to_string(),
            audience: audience.to_string(),
            operation: descriptor.name.as_str().to_string(),
            resource: descriptor.payload_schema.clone(),
            evidence_refs: evidence_refs.into_iter().map(ToString::to_string).collect(),
            public_inputs: vec![
                format!("opcode:{:02x}", descriptor.opcode),
                format!("handler_id:{}", descriptor.handler_id),
            ],
            trusted_requested_resource: None,
        }
    }

    pub fn accepts(&self, kind: EvidenceKind) -> bool {
        self.accepted_evidence
            .iter()
            .any(|accepted| accepted == kind.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSummary {
    pub kind: EvidenceKind,
    pub subject: String,
    pub audience: String,
    pub operation: String,
    pub resource: Option<String>,
    pub local_dev_test_only: bool,
    pub public_proof: bool,
    pub summary_fields: Vec<String>,
}

impl EvidenceSummary {
    pub fn to_context_fields(&self) -> Vec<String> {
        let mut fields = vec![
            format!("evidence_kind:{}", self.kind.as_str()),
            format!("subject:{}", self.subject),
            format!("audience:{}", self.audience),
            format!("operation:{}", self.operation),
            format!("local_dev_test_only:{}", self.local_dev_test_only),
            format!("public_proof:{}", self.public_proof),
        ];
        if let Some(resource) = &self.resource {
            fields.push(format!("resource:{resource}"));
        }
        fields.extend(self.summary_fields.clone());
        fields
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceResult {
    Satisfied(EvidenceSummary),
    Rejected(VerificationError),
}

pub trait EvidenceAdapter: Send + Sync {
    fn kind(&self) -> EvidenceKind;
    fn verify(&self, request: &EvidenceRequest) -> EvidenceResult;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedIssuerStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedIssuerEntry {
    pub issuer_id: String,
    pub issuer_key_id: String,
    pub public_key_bytes: Vec<u8>,
    pub trust_root_ref: String,
    pub registry_root_ref: String,
    pub accepted_evidence: Vec<EvidenceKind>,
    pub accepted_audiences: Vec<String>,
    pub accepted_operations: Vec<String>,
    pub accepted_resources: Vec<String>,
    pub status: TrustedIssuerStatus,
    pub not_before: u64,
    pub not_after: u64,
    pub registry_status_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIssuerRegistry {
    entries: Vec<TrustedIssuerEntry>,
}

impl TrustedIssuerRegistry {
    pub fn from_json_str(json: &str) -> Result<Self, VerificationError> {
        if json.trim().is_empty() {
            return Err(VerificationError::InvalidPresentation);
        }
        let entries: Vec<TrustedIssuerEntry> =
            serde_json::from_str(json).map_err(|_| VerificationError::InvalidPresentation)?;
        Self::new(entries)
    }

    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, VerificationError> {
        let json = fs::read_to_string(path).map_err(|_| VerificationError::InvalidPresentation)?;
        Self::from_json_str(&json)
    }

    pub fn new(
        entries: impl IntoIterator<Item = TrustedIssuerEntry>,
    ) -> Result<Self, VerificationError> {
        let entries: Vec<_> = entries.into_iter().collect();
        let mut ids = BTreeSet::new();
        let mut key_ids = BTreeSet::new();
        for entry in &entries {
            if entry.issuer_id.is_empty()
                || entry.issuer_key_id.is_empty()
                || entry.public_key_bytes.len() != 32
                || entry.trust_root_ref.is_empty()
                || entry.registry_root_ref.is_empty()
                || !ids.insert(entry.issuer_id.clone())
                || !key_ids.insert(entry.issuer_key_id.clone())
            {
                return Err(VerificationError::InvalidPresentation);
            }
        }
        Ok(Self { entries })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn lookup_active(
        &self,
        issuer_id: &str,
        issuer_key_id: &str,
        trust_root_ref: &str,
        registry_root_ref: &str,
        evidence_kind: EvidenceKind,
        audience: &str,
        operation: &str,
        resource: &str,
        validation_time: u64,
    ) -> Result<&TrustedIssuerEntry, VerificationError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.issuer_id == issuer_id)
            .ok_or(VerificationError::UnknownIssuer)?;
        if entry.issuer_key_id != issuer_key_id {
            return Err(VerificationError::WrongIssuerKey);
        }
        if entry.trust_root_ref != trust_root_ref {
            return Err(VerificationError::WrongTrustRoot);
        }
        if entry.registry_root_ref != registry_root_ref {
            return Err(VerificationError::WrongRegistryRoot);
        }
        if entry.status != TrustedIssuerStatus::Active {
            return Err(VerificationError::RevokedIssuer);
        }
        if validation_time < entry.not_before {
            return Err(VerificationError::NotYetValidVerifierKey);
        }
        if validation_time > entry.not_after {
            return Err(VerificationError::ExpiredVerifierKey);
        }
        if !entry.accepted_evidence.contains(&evidence_kind)
            || !entry
                .accepted_audiences
                .iter()
                .any(|accepted| accepted == audience)
            || !entry
                .accepted_operations
                .iter()
                .any(|accepted| accepted == operation)
            || !entry
                .accepted_resources
                .iter()
                .any(|accepted| accepted == resource)
        {
            return Err(VerificationError::InsufficientEvidence);
        }
        Ok(entry)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederatedCredentialStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecsFederatedCredential {
    pub credential_id: String,
    pub kind: EvidenceKind,
    pub subject: String,
    pub audience: String,
    pub origin: Option<String>,
    pub operation: String,
    pub resource: String,
    pub issuer_id: String,
    pub issuer_key_id: String,
    pub trust_root_ref: String,
    pub registry_root_ref: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub status: FederatedCredentialStatus,
    pub status_ref: String,
    pub signature_suite: String,
}

impl SecsFederatedCredential {
    pub const VERSION: &'static str = "secs-federated-credential-v1";
    pub const ED25519_SIGNATURE_SUITE: &'static str = "Ed25519";

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_line(&mut bytes, Self::VERSION);
        append_field(&mut bytes, "credential_id", &self.credential_id);
        append_field(&mut bytes, "kind", self.kind.as_str());
        append_field(&mut bytes, "subject", &self.subject);
        append_field(&mut bytes, "audience", &self.audience);
        append_field(&mut bytes, "origin", self.origin.as_deref().unwrap_or(""));
        append_field(&mut bytes, "operation", &self.operation);
        append_field(&mut bytes, "resource", &self.resource);
        append_field(&mut bytes, "issuer_id", &self.issuer_id);
        append_field(&mut bytes, "issuer_key_id", &self.issuer_key_id);
        append_field(&mut bytes, "trust_root_ref", &self.trust_root_ref);
        append_field(&mut bytes, "registry_root_ref", &self.registry_root_ref);
        append_field(&mut bytes, "issued_at", &self.issued_at.to_string());
        append_field(&mut bytes, "expires_at", &self.expires_at.to_string());
        append_field(&mut bytes, "status", credential_status_name(self.status));
        append_field(&mut bytes, "status_ref", &self.status_ref);
        append_field(&mut bytes, "signature_suite", &self.signature_suite);
        bytes
    }
}

fn credential_status_name(status: FederatedCredentialStatus) -> &'static str {
    match status {
        FederatedCredentialStatus::Active => "active",
        FederatedCredentialStatus::Revoked => "revoked",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedCredentialFixture {
    pub evidence_ref: String,
    pub credential: Option<SecsFederatedCredential>,
    pub embedded_issuer_public_key_bytes: Vec<u8>,
    pub signature_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedCredentialAdapter {
    credentials: Vec<FederatedCredentialFixture>,
    registry: TrustedIssuerRegistry,
    validation_time: u64,
}

impl FederatedCredentialAdapter {
    pub fn new(
        credentials: impl IntoIterator<Item = FederatedCredentialFixture>,
        registry: TrustedIssuerRegistry,
        validation_time: u64,
    ) -> Self {
        Self {
            credentials: credentials.into_iter().collect(),
            registry,
            validation_time,
        }
    }
}

impl EvidenceAdapter for FederatedCredentialAdapter {
    fn kind(&self) -> EvidenceKind {
        EvidenceKind::MembershipCredential
    }

    fn verify(&self, request: &EvidenceRequest) -> EvidenceResult {
        let Some((evidence_ref, fixture)) = request.evidence_refs.iter().find_map(|evidence_ref| {
            self.credentials
                .iter()
                .find(|fixture| &fixture.evidence_ref == evidence_ref)
                .map(|fixture| (evidence_ref, fixture))
        }) else {
            return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
        };
        let Some(credential) = &fixture.credential else {
            return EvidenceResult::Rejected(VerificationError::InvalidPresentation);
        };
        if !request.accepts(credential.kind) {
            return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
        }
        if credential.kind != EvidenceKind::MembershipCredential
            && credential.kind != EvidenceKind::ProvisioningCredential
        {
            return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
        }
        if credential.subject != request.subject {
            return EvidenceResult::Rejected(VerificationError::WrongSubject);
        }
        if credential.audience != request.audience {
            return EvidenceResult::Rejected(VerificationError::WrongAudience);
        }
        if credential.operation != request.operation {
            return EvidenceResult::Rejected(VerificationError::WrongOperation);
        }
        if request.resource.as_deref().unwrap_or_default() != credential.resource {
            return EvidenceResult::Rejected(VerificationError::WrongResource);
        }
        if let Some(request_origin) = requested_origin(request) {
            if credential.origin.as_deref() != Some(request_origin) {
                return EvidenceResult::Rejected(VerificationError::WrongOrigin);
            }
        }
        if credential.signature_suite != SecsFederatedCredential::ED25519_SIGNATURE_SUITE {
            return EvidenceResult::Rejected(VerificationError::UnsupportedSignatureSuite);
        }
        if credential.issued_at > self.validation_time {
            return EvidenceResult::Rejected(VerificationError::NotYetValidClaim);
        }
        if credential.expires_at <= self.validation_time {
            return EvidenceResult::Rejected(VerificationError::ExpiredClaim);
        }
        if credential.status != FederatedCredentialStatus::Active {
            return EvidenceResult::Rejected(VerificationError::RevokedCredential);
        }
        let entry = match self.registry.lookup_active(
            &credential.issuer_id,
            &credential.issuer_key_id,
            &credential.trust_root_ref,
            &credential.registry_root_ref,
            credential.kind,
            &credential.audience,
            &credential.operation,
            &credential.resource,
            self.validation_time,
        ) {
            Ok(entry) => entry,
            Err(err) => return EvidenceResult::Rejected(err),
        };
        if fixture.embedded_issuer_public_key_bytes != entry.public_key_bytes {
            return EvidenceResult::Rejected(VerificationError::WrongIssuerKey);
        }
        if !verify_ed25519_signature(
            &entry.public_key_bytes,
            &fixture.signature_bytes,
            &credential.canonical_bytes(),
        ) {
            return EvidenceResult::Rejected(VerificationError::InvalidSignature);
        }

        EvidenceResult::Satisfied(EvidenceSummary {
            kind: credential.kind,
            subject: credential.subject.clone(),
            audience: credential.audience.clone(),
            operation: credential.operation.clone(),
            resource: Some(credential.resource.clone()),
            local_dev_test_only: false,
            public_proof: true,
            // #83 credential-summary disclosure boundary. Every field here is
            // an explicit local/operator-inspection disclosure decision — this
            // is NOT public auditability (#37) or deployment proof (#33). See
            // `docs/issues/secs-magik-phases/credential-summary-disclosure-boundary.md`.
            //
            //   digest (sha256, deterministic, correlatable, never raw):
            //     evidence_ref, credential_id, status_ref, issuer_key_id —
            //     externally-linkable opaque handles/pointers.
            //   cleartext authority-layer metadata (receiver already holds it):
            //     credential_kind, issuer_id, trust_root_ref, registry_root_ref,
            //     status, signature_suite, and the validity window issued_at/
            //     expires_at.
            //   redacted marker: proof.
            //   absent: raw refs/paths/tokens, raw signatures, private seeds/
            //     keys, raw credential bodies (never constructed here).
            summary_fields: vec![
                redacted_reference_field("evidence_ref", evidence_ref),
                redacted_reference_field("credential_id", &credential.credential_id),
                format!("credential_kind:{}", credential.kind.as_str()),
                format!("issuer_id:{}", credential.issuer_id),
                format!("issuer_key_id:{}", credential.issuer_key_id),
                format!("trust_root_ref:{}", credential.trust_root_ref),
                format!("registry_root_ref:{}", credential.registry_root_ref),
                format!("status:{}", credential_status_name(credential.status)),
                redacted_reference_field("status_ref", &credential.status_ref),
                format!("issued_at:{}", credential.issued_at),
                format!("expires_at:{}", credential.expires_at),
                format!("signature_suite:{}", credential.signature_suite),
                "proof:redacted_ed25519_signature".to_string(),
            ],
        })
    }
}

pub struct CompositeEvidenceAdapter<'a> {
    adapters: Vec<&'a dyn EvidenceAdapter>,
}

impl<'a> CompositeEvidenceAdapter<'a> {
    pub fn new(adapters: impl IntoIterator<Item = &'a dyn EvidenceAdapter>) -> Self {
        Self {
            adapters: adapters.into_iter().collect(),
        }
    }
}

impl EvidenceAdapter for CompositeEvidenceAdapter<'_> {
    fn kind(&self) -> EvidenceKind {
        EvidenceKind::MembershipCredential
    }

    fn verify(&self, request: &EvidenceRequest) -> EvidenceResult {
        let mut summaries = Vec::new();
        for adapter in &self.adapters {
            match adapter.verify(request) {
                EvidenceResult::Satisfied(summary) => summaries.push(summary),
                EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
                | EvidenceResult::Rejected(VerificationError::InvalidPresentation) => {}
                EvidenceResult::Rejected(error) => return EvidenceResult::Rejected(error),
            }
        }

        for required in &request.accepted_evidence {
            if !summaries
                .iter()
                .any(|summary| summary.kind.as_str() == required)
            {
                return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
            }
        }

        let locked_resource = summaries.iter().find_map(|summary| {
            if summary.kind == EvidenceKind::DreggAuthority
                && summary
                    .summary_fields
                    .iter()
                    .any(|field| field == "resource_lock:verified")
            {
                summary.resource.clone()
            } else {
                None
            }
        });
        let mut summary_fields = Vec::new();
        for summary in &summaries {
            summary_fields.extend(summary.to_context_fields());
        }

        EvidenceResult::Satisfied(EvidenceSummary {
            kind: summaries
                .last()
                .map(|summary| summary.kind)
                .unwrap_or(EvidenceKind::MembershipCredential),
            subject: request.subject.clone(),
            audience: request.audience.clone(),
            operation: request.operation.clone(),
            resource: locked_resource,
            local_dev_test_only: summaries.iter().any(|summary| summary.local_dev_test_only),
            public_proof: summaries.iter().all(|summary| summary.public_proof),
            summary_fields,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalStaticGrant {
    pub subject: String,
    pub audience: String,
    pub operation: String,
    pub resource: Option<String>,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalStaticEvidenceAdapter {
    grants: Vec<LocalStaticGrant>,
}

impl LocalStaticEvidenceAdapter {
    pub fn new(grants: impl IntoIterator<Item = LocalStaticGrant>) -> Self {
        Self {
            grants: grants.into_iter().collect(),
        }
    }
}

impl EvidenceAdapter for LocalStaticEvidenceAdapter {
    fn kind(&self) -> EvidenceKind {
        EvidenceKind::LocalStatic
    }

    fn verify(&self, request: &EvidenceRequest) -> EvidenceResult {
        if !request.accepts(self.kind()) {
            return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
        }
        let Some(evidence_ref) = request.evidence_refs.first() else {
            return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
        };
        let Some(grant) = self
            .grants
            .iter()
            .find(|grant| &grant.evidence_ref == evidence_ref)
        else {
            return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
        };
        if grant.subject != request.subject {
            return EvidenceResult::Rejected(VerificationError::WrongSubject);
        }
        if grant.audience != request.audience {
            return EvidenceResult::Rejected(VerificationError::WrongAudience);
        }
        if grant.operation != request.operation {
            return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
        }
        if grant.resource != request.resource {
            return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
        }

        EvidenceResult::Satisfied(EvidenceSummary {
            kind: self.kind(),
            subject: request.subject.clone(),
            audience: request.audience.clone(),
            operation: request.operation.clone(),
            resource: request.resource.clone(),
            local_dev_test_only: true,
            public_proof: false,
            summary_fields: vec![
                "authority:local_dev_test_only".to_string(),
                redacted_reference_field("evidence_ref", evidence_ref),
            ],
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPresentationFixture {
    pub evidence_ref: String,
    pub subject: String,
    pub audience: String,
    pub origin: String,
    pub operation: String,
    pub resource: String,
    pub challenge_ref: String,
    pub signature_ref: String,
    pub public_key_ref: String,
    pub replay_nonce_ref: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature_suite: String,
    pub public_key_bytes: Vec<u8>,
    pub signature_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletPresentationShellStatus {
    ShapeValidatedSignatureUnsupported,
}

impl WalletPresentationShellStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ShapeValidatedSignatureUnsupported => "shape_validated_signature_unsupported",
        }
    }

    pub fn as_summary_field(&self) -> &'static str {
        match self {
            Self::ShapeValidatedSignatureUnsupported => {
                "adapter_status:shape_validated_signature_unsupported"
            }
        }
    }
}

impl WalletPresentationFixture {
    fn has_required_shape(&self) -> bool {
        !self.evidence_ref.is_empty()
            && !self.subject.is_empty()
            && !self.audience.is_empty()
            && !self.origin.is_empty()
            && !self.operation.is_empty()
            && !self.resource.is_empty()
            && !self.challenge_ref.is_empty()
            && !self.signature_ref.is_empty()
            && !self.public_key_ref.is_empty()
            && !self.replay_nonce_ref.is_empty()
            && self.issued_at < self.expires_at
            && !self.signature_suite.is_empty()
            && self.public_key_bytes.len() == 32
            && self.signature_bytes.len() == 64
    }
}

/// Temporary secS wallet challenge contract for Track D D1.
///
/// This is intentionally a minimal-equivalent secS contract, not a claim that
/// Castalia Wallet `wallet-core` currently binds every secS-required field.
/// It exists only until wallet-core canonical challenge parity binds subject,
/// resource/payload schema, and the wallet public-key reference/id alongside
/// the existing audience/origin/operation/nonce/time fields.
///
/// Canonical bytes are UTF-8, newline-delimited, length-prefixed fields in the
/// exact order implemented by [`SecsWalletChallenge::canonical_bytes`]. Lengths
/// are decimal byte lengths of each value, preventing delimiter ambiguity while
/// keeping the fixture contract inspectable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecsWalletChallenge {
    pub subject: String,
    pub audience: String,
    pub origin: String,
    pub operation: String,
    pub resource: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature_suite: String,
    pub public_key_ref: String,
}

impl SecsWalletChallenge {
    pub const VERSION: &'static str = "secs-wallet-challenge-v1";
    pub const ED25519_SIGNATURE_SUITE: &'static str = "Ed25519";

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_line(&mut bytes, Self::VERSION);
        append_field(&mut bytes, "subject", &self.subject);
        append_field(&mut bytes, "audience", &self.audience);
        append_field(&mut bytes, "origin", &self.origin);
        append_field(&mut bytes, "operation", &self.operation);
        append_field(&mut bytes, "resource", &self.resource);
        append_field(&mut bytes, "nonce", &self.nonce);
        append_field(&mut bytes, "issued_at", &self.issued_at.to_string());
        append_field(&mut bytes, "expires_at", &self.expires_at.to_string());
        append_field(&mut bytes, "signature_suite", &self.signature_suite);
        append_field(&mut bytes, "public_key_ref", &self.public_key_ref);
        bytes
    }
}

fn append_line(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(b'\n');
}

fn append_field(bytes: &mut Vec<u8>, name: &str, value: &str) {
    append_line(bytes, &format!("{name}:{}:{value}", value.len()));
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPresentationAdapter {
    fixtures: Vec<WalletPresentationFixture>,
    validation_time: Option<u64>,
}

impl WalletPresentationAdapter {
    pub fn new(fixtures: impl IntoIterator<Item = WalletPresentationFixture>) -> Self {
        Self {
            fixtures: fixtures.into_iter().collect(),
            validation_time: Some(current_unix_time()),
        }
    }

    pub fn with_validation_time(
        fixtures: impl IntoIterator<Item = WalletPresentationFixture>,
        validation_time: u64,
    ) -> Self {
        Self {
            fixtures: fixtures.into_iter().collect(),
            validation_time: Some(validation_time),
        }
    }
}

impl EvidenceAdapter for WalletPresentationAdapter {
    fn kind(&self) -> EvidenceKind {
        EvidenceKind::WalletPresentation
    }

    fn verify(&self, request: &EvidenceRequest) -> EvidenceResult {
        if !request.accepts(self.kind()) {
            return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
        }
        let Some((evidence_ref, presentation)) =
            request.evidence_refs.iter().find_map(|evidence_ref| {
                self.fixtures
                    .iter()
                    .find(|fixture| &fixture.evidence_ref == evidence_ref)
                    .map(|fixture| (evidence_ref, fixture))
            })
        else {
            return EvidenceResult::Rejected(VerificationError::InvalidPresentation);
        };
        if presentation.subject != request.subject {
            return EvidenceResult::Rejected(VerificationError::WrongSubject);
        }
        if presentation.audience != request.audience {
            return EvidenceResult::Rejected(VerificationError::WrongAudience);
        }
        if presentation.operation != request.operation {
            return EvidenceResult::Rejected(VerificationError::WrongOperation);
        }
        let resource = request.resource.as_deref().unwrap_or_default();
        if presentation.resource != resource {
            return EvidenceResult::Rejected(VerificationError::WrongResource);
        }
        if let Some(request_origin) = requested_origin(request) {
            if request_origin != presentation.origin {
                return EvidenceResult::Rejected(VerificationError::WrongOrigin);
            }
        } else {
            return EvidenceResult::Rejected(VerificationError::InvalidPresentation);
        }
        if !presentation.has_required_shape() {
            return EvidenceResult::Rejected(VerificationError::InvalidPresentation);
        }
        if presentation.public_key_ref != public_key_ref_for_bytes(&presentation.public_key_bytes) {
            return EvidenceResult::Rejected(VerificationError::InvalidPresentation);
        }
        if presentation.signature_suite != SecsWalletChallenge::ED25519_SIGNATURE_SUITE {
            return EvidenceResult::Rejected(VerificationError::UnsupportedSignatureSuite);
        }
        if let Some(validation_time) = self.validation_time {
            if presentation.issued_at > validation_time {
                return EvidenceResult::Rejected(VerificationError::NotYetValidClaim);
            }
            if presentation.expires_at <= validation_time {
                return EvidenceResult::Rejected(VerificationError::ExpiredClaim);
            }
        }
        let challenge = SecsWalletChallenge {
            subject: request.subject.clone(),
            audience: request.audience.clone(),
            origin: presentation.origin.clone(),
            operation: request.operation.clone(),
            resource: presentation.resource.clone(),
            nonce: presentation.replay_nonce_ref.clone(),
            issued_at: presentation.issued_at,
            expires_at: presentation.expires_at,
            signature_suite: presentation.signature_suite.clone(),
            public_key_ref: presentation.public_key_ref.clone(),
        };
        if !verify_ed25519_signature(
            &presentation.public_key_bytes,
            &presentation.signature_bytes,
            &challenge.canonical_bytes(),
        ) {
            return EvidenceResult::Rejected(VerificationError::InvalidSignature);
        }

        EvidenceResult::Satisfied(EvidenceSummary {
            kind: self.kind(),
            subject: request.subject.clone(),
            audience: request.audience.clone(),
            operation: request.operation.clone(),
            resource: request.resource.clone(),
            local_dev_test_only: false,
            public_proof: true,
            summary_fields: vec![
                redacted_reference_field("evidence_ref", evidence_ref),
                format!("origin:{}", presentation.origin),
                format!("challenge_ref:{}", presentation.challenge_ref),
                format!("signature_ref:{}", presentation.signature_ref),
                format!("public_key_ref:{}", presentation.public_key_ref),
                format!("replay_nonce_ref:{}", presentation.replay_nonce_ref),
                format!("issued_at:{}", presentation.issued_at),
                format!("expires_at:{}", presentation.expires_at),
                format!("signature_suite:{}", presentation.signature_suite),
            ],
        })
    }
}

/// Temporary minimal-equivalent **Dregg-shaped** receipt/capability evidence
/// contract (M12.3).
///
/// Mirrors how Track D landed the wallet challenge: a real cryptographic
/// check over a bounded, inspectable, versioned shape, explicitly labeled as
/// not the full upstream system. The adapter verifies envelope shape and the
/// author Ed25519 signature over canonical bytes — and nothing more. It does
/// **not** reconstruct or verify the Dregg blocklace DAG, `tau` finality,
/// capability non-amplification, nullifier/no-double-spend, CapTP handoff, or
/// revocation authority; those remain the #73 authority rail, which this
/// seam does not close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreggReceiptFixture {
    pub evidence_ref: String,
    pub subject: String,
    pub audience: String,
    pub origin: String,
    pub operation: String,
    pub resource: String,
    /// "receipt" or "capability_ref" — the two demo-scope presentation kinds.
    pub receipt_kind: String,
    /// Opaque reference to the author's strand/entry; never raw Dregg data.
    pub strand_ref: String,
    /// Author sequence number (shape only; monotonicity is #73's concern).
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature_suite: String,
    /// Fingerprint reference that must match `author_public_key_bytes`.
    pub public_key_ref: String,
    pub author_public_key_bytes: Vec<u8>,
    pub signature_bytes: Vec<u8>,
}

impl DreggReceiptFixture {
    /// Version tag for the canonical signed bytes. The temporary contract is
    /// explicit and replaceable: bump on any change, retire when #73 lands.
    pub const VERSION: &'static str = "secs-dregg-receipt-shape-v1";
    pub const RECEIPT_KIND: &'static str = "receipt";
    pub const CAPABILITY_REF_KIND: &'static str = "capability_ref";

    /// Canonical, length-prefixed, newline-delimited bytes the author signs —
    /// same construction style as [`SecsWalletChallenge::canonical_bytes`].
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_line(&mut bytes, Self::VERSION);
        append_field(&mut bytes, "subject", &self.subject);
        append_field(&mut bytes, "audience", &self.audience);
        append_field(&mut bytes, "origin", &self.origin);
        append_field(&mut bytes, "operation", &self.operation);
        append_field(&mut bytes, "resource", &self.resource);
        append_field(&mut bytes, "receipt_kind", &self.receipt_kind);
        append_field(&mut bytes, "strand_ref", &self.strand_ref);
        append_field(&mut bytes, "sequence", &self.sequence.to_string());
        append_field(&mut bytes, "issued_at", &self.issued_at.to_string());
        append_field(&mut bytes, "expires_at", &self.expires_at.to_string());
        append_field(&mut bytes, "signature_suite", &self.signature_suite);
        append_field(&mut bytes, "public_key_ref", &self.public_key_ref);
        bytes
    }

    fn has_required_shape(&self) -> bool {
        !self.evidence_ref.is_empty()
            && !self.subject.is_empty()
            && !self.audience.is_empty()
            && !self.origin.is_empty()
            && !self.operation.is_empty()
            && !self.resource.is_empty()
            && (self.receipt_kind == Self::RECEIPT_KIND
                || self.receipt_kind == Self::CAPABILITY_REF_KIND)
            && !self.strand_ref.is_empty()
            && self.issued_at < self.expires_at
            && !self.signature_suite.is_empty()
            && !self.public_key_ref.is_empty()
            && self.author_public_key_bytes.len() == 32
            && self.signature_bytes.len() == 64
    }
}

/// Fixture-level authority grant token accepted by the M15.3 Dregg authority
/// verifier seam. This intentionally models the productized `dregg-auth` policy
/// admission contract (subject + tool + expiry) without treating M12.3
/// `dregg_receipt` shape/signature evidence as production authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreggAuthorityGrantFixture {
    pub evidence_ref: String,
    pub token: String,
    pub issuer_id: String,
    pub issuer_key_id: String,
    pub root_ref: String,
    pub root_fingerprint: String,
    pub epoch_id: String,
    pub suite: String,
    pub status_checked_at: Option<u64>,
    pub revocation_status: Option<crate::dregg_authority::DreggAuthorityRevocationStatus>,
    pub finality_status: Option<crate::dregg_authority::DreggAuthorityFinalityStatus>,
    pub attested_revocation_root_ref: Option<String>,
}

impl DreggAuthorityGrantFixture {
    pub const TOKEN_PREFIX: &'static str = "dga1_";

    pub fn fixture_token(subject: &str, tool: &str, until: u64) -> String {
        format!("{}{subject}|{tool}|{until}", Self::TOKEN_PREFIX)
    }

    pub fn fixture_token_with_resource_prefix(
        subject: &str,
        tool: &str,
        delegated_resource_prefix: &str,
        until: u64,
    ) -> String {
        format!(
            "{}{subject}|{tool}|resource_prefix:{delegated_resource_prefix}|{until}",
            Self::TOKEN_PREFIX
        )
    }

    pub fn fixture_token_with_resource_lock(
        subject: &str,
        tool: &str,
        locked_resource: &str,
        until: u64,
    ) -> String {
        format!(
            "{}{subject}|{tool}|resource_lock:{locked_resource}|{until}",
            Self::TOKEN_PREFIX
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedDreggAuthorityToken<'a> {
    subject: &'a str,
    tool: &'a str,
    delegated_resource_prefix: Option<&'a str>,
    resource_lock: Option<&'a str>,
    until: u64,
}

fn parse_dregg_authority_token(
    token: &str,
) -> Result<ParsedDreggAuthorityToken<'_>, VerificationError> {
    let Some(rest) = token.strip_prefix(DreggAuthorityGrantFixture::TOKEN_PREFIX) else {
        return Err(VerificationError::MalformedDreggAuthority);
    };
    let mut parts = rest.split('|');
    let subject = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(VerificationError::MalformedDreggAuthority)?;
    let tool = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(VerificationError::MalformedDreggAuthority)?;
    let third = parts
        .next()
        .ok_or(VerificationError::MalformedDreggAuthority)?;
    let (delegated_resource_prefix, resource_lock, until) =
        if let Some(prefix) = third.strip_prefix("resource_prefix:") {
            let until = parts
                .next()
                .ok_or(VerificationError::MalformedDreggAuthority)?
                .parse::<u64>()
                .map_err(|_| VerificationError::MalformedDreggAuthority)?;
            if prefix.is_empty() {
                return Err(VerificationError::MalformedDreggAuthority);
            }
            (Some(prefix), None, until)
        } else if let Some(locked_resource) = third.strip_prefix("resource_lock:") {
            let until = parts
                .next()
                .ok_or(VerificationError::MalformedDreggAuthority)?
                .parse::<u64>()
                .map_err(|_| VerificationError::MalformedDreggAuthority)?;
            if locked_resource.is_empty() {
                return Err(VerificationError::MalformedDreggAuthority);
            }
            (None, Some(locked_resource), until)
        } else {
            (
                None,
                None,
                third
                    .parse::<u64>()
                    .map_err(|_| VerificationError::MalformedDreggAuthority)?,
            )
        };
    if parts.next().is_some() {
        return Err(VerificationError::MalformedDreggAuthority);
    }
    Ok(ParsedDreggAuthorityToken {
        subject,
        tool,
        delegated_resource_prefix,
        resource_lock,
        until,
    })
}

/// Production Dregg authority verifier seam for M15.3.
///
/// The receiver-held registry is consulted before any token admission result is
/// accepted. The fixture token here is deliberately `dga1_`-shaped and separate
/// from M12.3 `dregg_receipt` fixtures so shape + author signature can never be
/// confused with production authority. Full revocation proof/finality semantics
/// remain M15.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreggAuthorityEvidenceAdapter {
    grants: Vec<DreggAuthorityGrantFixture>,
    registry: DreggAuthorityRegistry,
    validation_time: u64,
}

impl DreggAuthorityEvidenceAdapter {
    pub fn new(
        grants: impl IntoIterator<Item = DreggAuthorityGrantFixture>,
        registry: DreggAuthorityRegistry,
        validation_time: u64,
    ) -> Self {
        Self {
            grants: grants.into_iter().collect(),
            registry,
            validation_time,
        }
    }
}

impl EvidenceAdapter for DreggAuthorityEvidenceAdapter {
    fn kind(&self) -> EvidenceKind {
        EvidenceKind::DreggAuthority
    }

    fn verify(&self, request: &EvidenceRequest) -> EvidenceResult {
        if !request.accepts(self.kind()) {
            return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
        }
        let Some((evidence_ref, grant)) = request.evidence_refs.iter().find_map(|evidence_ref| {
            self.grants
                .iter()
                .find(|grant| &grant.evidence_ref == evidence_ref)
                .map(|grant| (evidence_ref, grant))
        }) else {
            return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
        };
        let resource = request.resource.as_deref().unwrap_or_default();
        let lookup = DreggAuthorityLookup {
            issuer_id: grant.issuer_id.clone(),
            issuer_key_id: grant.issuer_key_id.clone(),
            root_ref: grant.root_ref.clone(),
            root_fingerprint: grant.root_fingerprint.clone(),
            epoch_id: grant.epoch_id.clone(),
            audience: request.audience.clone(),
            operation: request.operation.clone(),
            resource: resource.to_string(),
            suite: grant.suite.clone(),
            validation_time: self.validation_time,
            status_checked_at: grant.status_checked_at,
            revocation_status: grant.revocation_status,
            finality_status: grant.finality_status,
            attested_revocation_root_ref: grant.attested_revocation_root_ref.clone(),
        };
        let entry = match self.registry.lookup_active_policy(&lookup) {
            Ok(entry) => entry,
            Err(error) => return EvidenceResult::Rejected(error),
        };
        let parsed = match parse_dregg_authority_token(&grant.token) {
            Ok(parsed) => parsed,
            Err(error) => return EvidenceResult::Rejected(error),
        };
        if parsed.subject != request.subject {
            return EvidenceResult::Rejected(VerificationError::WrongSubject);
        }
        if parsed.tool != request.operation {
            return EvidenceResult::Rejected(VerificationError::WrongOperation);
        }
        if parsed.until <= self.validation_time {
            return EvidenceResult::Rejected(VerificationError::InvalidAdmission);
        }
        let requested_resource = request.trusted_requested_resource.as_deref();
        let mut verified_resource_lock = None;
        if let Some(delegated_prefix) = parsed.delegated_resource_prefix {
            let Some(requested_resource) = requested_resource else {
                return EvidenceResult::Rejected(VerificationError::AuthorityAmplification);
            };
            if !requested_resource.starts_with(delegated_prefix) {
                return EvidenceResult::Rejected(VerificationError::AuthorityAmplification);
            }
        }
        if let Some(locked_resource) = parsed.resource_lock {
            let Some(requested_resource) = requested_resource else {
                return EvidenceResult::Rejected(VerificationError::ResourceLockViolation);
            };
            if requested_resource != locked_resource {
                return EvidenceResult::Rejected(VerificationError::ResourceLockViolation);
            }
            verified_resource_lock = Some(requested_resource.to_string());
        }

        let mut summary_fields = vec![
            "admission:admitted".to_string(),
            "authority_class:dregg_authority".to_string(),
            "tier:m15_production_shaped".to_string(),
            redacted_reference_field("evidence_ref", evidence_ref),
            "token:dga1_[redacted]".to_string(),
            format!("issuer_id:{}", grant.issuer_id),
            redacted_reference_field("issuer_key_id", &grant.issuer_key_id),
            redacted_reference_field("root_ref", &grant.root_ref),
            format!("root_fingerprint:{}", grant.root_fingerprint),
            redacted_reference_field("epoch_id", &grant.epoch_id),
            format!("suite:{}", grant.suite),
            format!(
                "revocation_verifier_mode:{}",
                revocation_verifier_mode_name(entry.status_policy.revocation_verifier_mode)
            ),
            entry
                .status_policy
                .expected_revocation_root_ref
                .as_ref()
                .map(|root| redacted_reference_field("revocation_root_ref", root))
                .unwrap_or_else(|| "revocation_root_ref:not_required".to_string()),
            grant
                .revocation_status
                .map(|status| format!("revocation_status:{}", revocation_status_name(status)))
                .unwrap_or_else(|| "revocation_status:named_blocker_missing".to_string()),
            format!(
                "finality_mode:{}",
                finality_mode_name(entry.status_policy.finality_mode)
            ),
            grant
                .finality_status
                .map(|status| format!("finality_status:{}", finality_status_name(status)))
                .unwrap_or_else(|| "finality_status:not_required".to_string()),
            redacted_reference_field("federation_id", &entry.federation_id),
            format!(
                "issuer_public_key_ref:{}",
                public_key_ref_for_hex(&entry.issuer_public_key_hex)
            ),
        ];
        if let Some(delegated_prefix) = parsed.delegated_resource_prefix {
            summary_fields.push("attenuation:non_amplifying".to_string());
            summary_fields.push(redacted_reference_field(
                "delegated_resource_prefix",
                delegated_prefix,
            ));
            if let Some(requested_resource) = requested_resource {
                summary_fields.push(redacted_reference_field(
                    "requested_resource",
                    requested_resource,
                ));
            }
        }
        if let Some(locked_resource) = parsed.resource_lock {
            summary_fields.push("resource_lock:verified".to_string());
            summary_fields.push(redacted_reference_field("resource_lock", locked_resource));
            if let Some(requested_resource) = requested_resource {
                summary_fields.push(redacted_reference_field(
                    "locked_resource",
                    requested_resource,
                ));
            }
        }

        EvidenceResult::Satisfied(EvidenceSummary {
            kind: self.kind(),
            subject: request.subject.clone(),
            audience: request.audience.clone(),
            operation: request.operation.clone(),
            resource: verified_resource_lock,
            local_dev_test_only: false,
            // M15.3 admits against receiver-held Dregg policy, but M15.4 still
            // owns revocation proofs/finality/public auditability.
            public_proof: false,
            summary_fields,
        })
    }
}

fn revocation_verifier_mode_name(mode: DreggAuthorityRevocationVerifierMode) -> &'static str {
    match mode {
        DreggAuthorityRevocationVerifierMode::FixtureStatusOnly => "fixture_status_only",
        DreggAuthorityRevocationVerifierMode::ExpectedRootBinding => "expected_root_binding",
        DreggAuthorityRevocationVerifierMode::LiveRevocationVerifierRequired => {
            "live_revocation_verifier_required"
        }
    }
}

fn finality_mode_name(mode: DreggAuthorityFinalityMode) -> &'static str {
    match mode {
        DreggAuthorityFinalityMode::NotRequired => "not_required",
        DreggAuthorityFinalityMode::FixtureStatusOnly => "fixture_status_only",
        DreggAuthorityFinalityMode::BlsThresholdRequired => "bls_threshold_required",
        DreggAuthorityFinalityMode::RotatedReplayRequired => "rotated_replay_required",
    }
}

fn revocation_status_name(status: DreggAuthorityRevocationStatus) -> &'static str {
    match status {
        DreggAuthorityRevocationStatus::Active => "active",
        DreggAuthorityRevocationStatus::Revoked => "revoked",
    }
}

fn finality_status_name(status: DreggAuthorityFinalityStatus) -> &'static str {
    match status {
        DreggAuthorityFinalityStatus::Final => "final",
        DreggAuthorityFinalityStatus::NotFinal => "not_final",
        DreggAuthorityFinalityStatus::Equivocated => "equivocated",
    }
}

fn public_key_ref_for_hex(hex: &str) -> String {
    let digest = Sha256::digest(hex.as_bytes());
    let hash: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("dregg-issuer-pubkey:sha256:{hash}")
}

/// Adapter for [`EvidenceKind::DreggReceipt`]: shape + author-signature only.
/// Receiver-held trust — accepted author keys are whatever the receiver
/// configured as fixtures; bytes the caller embeds are never implicitly
/// trusted. Dregg-shaped evidence is necessary-where-required, never
/// sufficient authority on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreggShapedEvidenceAdapter {
    fixtures: Vec<DreggReceiptFixture>,
    validation_time: Option<u64>,
}

impl DreggShapedEvidenceAdapter {
    pub fn new(fixtures: impl IntoIterator<Item = DreggReceiptFixture>) -> Self {
        Self {
            fixtures: fixtures.into_iter().collect(),
            validation_time: Some(current_unix_time()),
        }
    }

    pub fn with_validation_time(
        fixtures: impl IntoIterator<Item = DreggReceiptFixture>,
        validation_time: u64,
    ) -> Self {
        Self {
            fixtures: fixtures.into_iter().collect(),
            validation_time: Some(validation_time),
        }
    }
}

impl EvidenceAdapter for DreggShapedEvidenceAdapter {
    fn kind(&self) -> EvidenceKind {
        EvidenceKind::DreggReceipt
    }

    fn verify(&self, request: &EvidenceRequest) -> EvidenceResult {
        if !request.accepts(self.kind()) {
            return EvidenceResult::Rejected(VerificationError::InsufficientEvidence);
        }
        let Some((evidence_ref, receipt)) = request.evidence_refs.iter().find_map(|evidence_ref| {
            self.fixtures
                .iter()
                .find(|fixture| &fixture.evidence_ref == evidence_ref)
                .map(|fixture| (evidence_ref, fixture))
        }) else {
            return EvidenceResult::Rejected(VerificationError::InvalidPresentation);
        };
        if receipt.subject != request.subject {
            return EvidenceResult::Rejected(VerificationError::WrongSubject);
        }
        if receipt.audience != request.audience {
            return EvidenceResult::Rejected(VerificationError::WrongAudience);
        }
        if receipt.operation != request.operation {
            return EvidenceResult::Rejected(VerificationError::WrongOperation);
        }
        let resource = request.resource.as_deref().unwrap_or_default();
        if receipt.resource != resource {
            return EvidenceResult::Rejected(VerificationError::WrongResource);
        }
        if let Some(request_origin) = requested_origin(request) {
            if request_origin != receipt.origin {
                return EvidenceResult::Rejected(VerificationError::WrongOrigin);
            }
        } else {
            return EvidenceResult::Rejected(VerificationError::InvalidPresentation);
        }
        if !receipt.has_required_shape() {
            return EvidenceResult::Rejected(VerificationError::InvalidPresentation);
        }
        if receipt.public_key_ref != public_key_ref_for_bytes(&receipt.author_public_key_bytes) {
            return EvidenceResult::Rejected(VerificationError::InvalidPresentation);
        }
        if receipt.signature_suite != SecsWalletChallenge::ED25519_SIGNATURE_SUITE {
            return EvidenceResult::Rejected(VerificationError::UnsupportedSignatureSuite);
        }
        if let Some(validation_time) = self.validation_time {
            if receipt.issued_at > validation_time {
                return EvidenceResult::Rejected(VerificationError::NotYetValidClaim);
            }
            if receipt.expires_at <= validation_time {
                return EvidenceResult::Rejected(VerificationError::ExpiredClaim);
            }
        }
        if !verify_ed25519_signature(
            &receipt.author_public_key_bytes,
            &receipt.signature_bytes,
            &receipt.canonical_bytes(),
        ) {
            return EvidenceResult::Rejected(VerificationError::InvalidSignature);
        }

        EvidenceResult::Satisfied(EvidenceSummary {
            kind: self.kind(),
            subject: request.subject.clone(),
            audience: request.audience.clone(),
            operation: request.operation.clone(),
            resource: request.resource.clone(),
            local_dev_test_only: false,
            // Shape + author-signature only: never a public/consensus proof
            // claim — Dregg finality/authority remains #73.
            public_proof: false,
            summary_fields: vec![
                format!("shape_contract:{}", DreggReceiptFixture::VERSION),
                redacted_reference_field("evidence_ref", evidence_ref),
                redacted_reference_field("strand_ref", &receipt.strand_ref),
                format!("origin:{}", receipt.origin),
                format!("receipt_kind:{}", receipt.receipt_kind),
                format!("sequence:{}", receipt.sequence),
                format!("public_key_ref:{}", receipt.public_key_ref),
                format!("issued_at:{}", receipt.issued_at),
                format!("expires_at:{}", receipt.expires_at),
                format!("signature_suite:{}", receipt.signature_suite),
            ],
        })
    }
}

pub fn public_key_ref_for_bytes(public_key_bytes: &[u8]) -> String {
    let digest = Sha256::digest(public_key_bytes);
    format!("pubkey:sha256:{}", hex_lower(&digest))
}

fn redacted_reference_field(name: &str, value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{name}_sha256:{}", hex_lower(&digest))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn current_unix_time() -> u64 {
    // Shared fail-closed policy (M12.5): an unreadable clock yields the
    // sentinel, under which every time-windowed evidence check rejects.
    crate::clock::failclosed_unix_seconds()
}

fn verify_ed25519_signature(
    public_key_bytes: &[u8],
    signature_bytes: &[u8],
    message: &[u8],
) -> bool {
    let Ok(public_key_bytes) = <&[u8; 32]>::try_from(public_key_bytes) else {
        return false;
    };
    let Ok(public_key) = VerifyingKey::from_bytes(public_key_bytes) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature_bytes) else {
        return false;
    };

    public_key.verify(message, &signature).is_ok()
}

fn requested_origin(request: &EvidenceRequest) -> Option<&str> {
    request
        .public_inputs
        .iter()
        .find_map(|input| input.strip_prefix("origin:"))
}
