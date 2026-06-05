//! Evidence adapter boundary for verifier inputs.
//!
//! External proof, federation, and settlement systems should enter secS through
//! adapters rooted here rather than becoming hard dependencies of packet parsing
//! or gateway execution.

use crate::manifest::OperationDescriptor;
use crate::verifier::VerificationError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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
            Self::CardanoSettlement => "cardano_settlement",
        }
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
}

impl EvidenceRequest {
    pub fn from_descriptor(
        descriptor: &OperationDescriptor,
        subject: &str,
        audience: &str,
        evidence_ref: Option<&str>,
    ) -> Self {
        Self::from_descriptor_with_refs(descriptor, subject, audience, evidence_ref.into_iter())
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

pub trait EvidenceAdapter {
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
            summary_fields: vec![
                format!("evidence_ref:{evidence_ref}"),
                format!("credential_id:{}", credential.credential_id),
                format!("credential_kind:{}", credential.kind.as_str()),
                format!("issuer_id:{}", credential.issuer_id),
                format!("issuer_key_id:{}", credential.issuer_key_id),
                format!("trust_root_ref:{}", credential.trust_root_ref),
                format!("registry_root_ref:{}", credential.registry_root_ref),
                format!("status:{}", credential_status_name(credential.status)),
                format!("status_ref:{}", credential.status_ref),
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
            resource: request.resource.clone(),
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
                format!("evidence_ref:{evidence_ref}"),
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
                format!("evidence_ref:{evidence_ref}"),
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

pub fn public_key_ref_for_bytes(public_key_bytes: &[u8]) -> String {
    let digest = Sha256::digest(public_key_bytes);
    let fingerprint = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("pubkey:sha256:{fingerprint}")
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX)
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
