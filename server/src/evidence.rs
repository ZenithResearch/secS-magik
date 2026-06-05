//! Evidence adapter boundary for verifier inputs.
//!
//! External proof, federation, and settlement systems should enter secS through
//! adapters rooted here rather than becoming hard dependencies of packet parsing
//! or gateway execution.

use crate::manifest::OperationDescriptor;
use crate::verifier::VerificationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    PrototypeProofEnvelope,
    LocalStatic,
    WalletPresentation,
    MidnightProof,
    DreggReceipt,
    CardanoSettlement,
}

impl EvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrototypeProofEnvelope => "prototype-proof-envelope",
            Self::LocalStatic => "local_static",
            Self::WalletPresentation => "wallet_presentation",
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
        Self {
            accepted_evidence: descriptor.accepted_evidence.clone(),
            subject: subject.to_string(),
            audience: audience.to_string(),
            operation: descriptor.name.as_str().to_string(),
            resource: descriptor.payload_schema.clone(),
            evidence_refs: evidence_ref.into_iter().map(ToString::to_string).collect(),
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
    pub challenge_ref: String,
    pub signature_ref: String,
    pub public_key_ref: String,
    pub replay_nonce_ref: String,
    pub issued_at: u64,
    pub expires_at: u64,
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
            && !self.challenge_ref.is_empty()
            && !self.signature_ref.is_empty()
            && !self.public_key_ref.is_empty()
            && !self.replay_nonce_ref.is_empty()
            && self.issued_at < self.expires_at
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
}

impl WalletPresentationAdapter {
    pub fn new(fixtures: impl IntoIterator<Item = WalletPresentationFixture>) -> Self {
        Self {
            fixtures: fixtures.into_iter().collect(),
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
        let Some(evidence_ref) = request.evidence_refs.first() else {
            return EvidenceResult::Rejected(VerificationError::InvalidPresentation);
        };
        let Some(presentation) = self
            .fixtures
            .iter()
            .find(|fixture| &fixture.evidence_ref == evidence_ref)
        else {
            return EvidenceResult::Rejected(VerificationError::InvalidPresentation);
        };
        if presentation.subject != request.subject {
            return EvidenceResult::Rejected(VerificationError::WrongSubject);
        }
        if presentation.audience != request.audience {
            return EvidenceResult::Rejected(VerificationError::WrongAudience);
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

        EvidenceResult::Satisfied(EvidenceSummary {
            kind: self.kind(),
            subject: request.subject.clone(),
            audience: request.audience.clone(),
            operation: request.operation.clone(),
            resource: request.resource.clone(),
            local_dev_test_only: false,
            public_proof: false,
            summary_fields: vec![
                WalletPresentationShellStatus::ShapeValidatedSignatureUnsupported
                    .as_summary_field()
                    .to_string(),
                format!("evidence_ref:{evidence_ref}"),
                format!("origin:{}", presentation.origin),
                format!("challenge_ref:{}", presentation.challenge_ref),
                format!("signature_ref:{}", presentation.signature_ref),
                format!("public_key_ref:{}", presentation.public_key_ref),
                format!("replay_nonce_ref:{}", presentation.replay_nonce_ref),
                format!("issued_at:{}", presentation.issued_at),
                format!("expires_at:{}", presentation.expires_at),
            ],
        })
    }
}

fn requested_origin(request: &EvidenceRequest) -> Option<&str> {
    request
        .public_inputs
        .iter()
        .find_map(|input| input.strip_prefix("origin:"))
}
