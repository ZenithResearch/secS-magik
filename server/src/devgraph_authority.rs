//! Exact producer for the ratified `devgraph.issue.create.v1` authority projection.
//!
//! This module deliberately does not expose a generic operation, route, handler,
//! transport, or Work API. It verifies one Wallet Ed25519 presentation against
//! one receiver-held policy, emits one portable signed JSON projection, and
//! reserves the exact operation-scoped replay key before returning it. Devgraph
//! remains the sole owner of Work mutation, idempotency, audit, and EventReceipt.

use crate::identity::{NodeVerifierIdentity, PublicVerifierKeyRegistry};
use crate::ledger::{DevgraphReplayReservationOutcome, Ledger};
use crate::receipt::AuthenticatorKind;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const DEVGRAPH_ISSUE_CREATE_OPERATION_V1: &str = "devgraph.issue.create.v1";
pub const DEVGRAPH_AUTHORITY_SCHEMA_V1: &str = "secs-devgraph-authority.v1";
pub const DEVGRAPH_AUTHORITY_SCHEMA_VERSION_V1: u64 = 1;
pub const DEVGRAPH_AUTHORITY_REPLAY_SCOPE_V1: &str = "session:operation:nonce";
pub const DEVGRAPH_AUTHORITY_SIGNATURE_SUITE_V1: &str = "Ed25519";
pub const DEVGRAPH_ISSUE_CREATE_POLICY_SCHEMA_V1: &str = "secs-devgraph-issue-create-policy.v1";
pub const DEVGRAPH_WALLET_PRESENTATION_SCHEMA_V1: &str =
    "devgraph.issue.create.wallet-presentation.v1";
pub const DEVGRAPH_AUTHORITY_MAX_TTL_SECONDS_V1: u64 = 60;
pub const DEVGRAPH_ISSUE_CREATE_MAX_REQUEST_JSON_BYTES_V1: usize = 131_072;
pub const DEVGRAPH_ISSUE_CREATE_MAX_CANONICAL_REQUEST_BYTES_V1: usize = 65_536;
pub const DEVGRAPH_WALLET_PRESENTATION_MAX_JSON_BYTES_V1: usize = 16_384;
pub const DEVGRAPH_ISSUE_CREATE_POLICY_MAX_JSON_BYTES_V1: usize = 262_144;
pub const DEVGRAPH_AUTHORITY_PROJECTION_MAX_JSON_BYTES_V1: usize = 16_384;
pub const DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1: u64 = 9_007_199_254_740_991;

pub(crate) const DEVGRAPH_AUTHORITY_SIGNATURE_DOMAIN_V1: &[u8] =
    b"secs-devgraph-authority.v1/signature\0";
const DEVGRAPH_AUTHORITY_PROJECTION_DOMAIN_V1: &[u8] = b"secs-devgraph-authority.v1/projection\0";
const DEVGRAPH_REQUEST_DOMAIN_V1: &[u8] = b"devgraph.issue.create.request.v1\0";
const DEVGRAPH_WALLET_SIGNATURE_DOMAIN_V1: &[u8] =
    b"devgraph.issue.create.wallet-presentation.v1/signature\0";
const DEVGRAPH_WALLET_PRESENTATION_DOMAIN_V1: &[u8] =
    b"devgraph.issue.create.wallet-presentation.v1/presentation\0";
const DEVGRAPH_POLICY_DOMAIN_V1: &[u8] = b"secs-devgraph-issue-create-policy.v1\0";
const DEVGRAPH_CONTEXT_DOMAIN_V1: &[u8] = b"secs-devgraph-authority.v1/context\0";

const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevgraphAuthorityError {
    MalformedRequest,
    RequestTooLarge,
    InvalidIdentifier,
    EmptyTitle,
    InvalidRequest,
    InvalidIdempotencyKey,
    MalformedWalletPresentation,
    WalletPresentationTooLarge,
    InvalidWalletPresentation,
    UnsupportedSignatureSuite,
    InvalidWalletSignature,
    WrongActor,
    WrongAudience,
    WrongOperation,
    WrongResource,
    WrongRequestDigest,
    WrongIdempotencyDigest,
    InvalidSession,
    InvalidValidityWindow,
    NotYetValid,
    Expired,
    ClockFailure,
    InvalidReceiverPolicy,
    ReceiverPolicyTooLarge,
    ReceiverPolicyDenied,
    UntrustedVerifierIdentity,
    MalformedProjection,
    ProjectionTooLarge,
    WrongProjectionBinding,
    InvalidVerifierSignature,
    ReplayConflict,
    ReplayStorageFailed,
    Internal,
}

impl DevgraphAuthorityError {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::MalformedRequest => "devgraph_request_malformed",
            Self::RequestTooLarge => "devgraph_request_too_large",
            Self::InvalidIdentifier => "devgraph_identifier_invalid",
            Self::EmptyTitle => "devgraph_title_empty",
            Self::InvalidRequest => "devgraph_request_invalid",
            Self::InvalidIdempotencyKey => "devgraph_idempotency_key_invalid",
            Self::MalformedWalletPresentation => "devgraph_wallet_presentation_malformed",
            Self::WalletPresentationTooLarge => "devgraph_wallet_presentation_too_large",
            Self::InvalidWalletPresentation => "devgraph_wallet_presentation_invalid",
            Self::UnsupportedSignatureSuite => "devgraph_signature_suite_unsupported",
            Self::InvalidWalletSignature => "devgraph_wallet_signature_invalid",
            Self::WrongActor => "devgraph_actor_mismatch",
            Self::WrongAudience => "devgraph_audience_mismatch",
            Self::WrongOperation => "devgraph_operation_mismatch",
            Self::WrongResource => "devgraph_resource_mismatch",
            Self::WrongRequestDigest => "devgraph_request_digest_mismatch",
            Self::WrongIdempotencyDigest => "devgraph_idempotency_digest_mismatch",
            Self::InvalidSession => "devgraph_session_invalid",
            Self::InvalidValidityWindow => "devgraph_validity_window_invalid",
            Self::NotYetValid => "devgraph_authority_not_yet_valid",
            Self::Expired => "devgraph_authority_expired",
            Self::ClockFailure => "devgraph_clock_unavailable",
            Self::InvalidReceiverPolicy => "devgraph_receiver_policy_invalid",
            Self::ReceiverPolicyTooLarge => "devgraph_receiver_policy_too_large",
            Self::ReceiverPolicyDenied => "devgraph_receiver_policy_denied",
            Self::UntrustedVerifierIdentity => "devgraph_verifier_identity_untrusted",
            Self::MalformedProjection => "devgraph_authority_projection_malformed",
            Self::ProjectionTooLarge => "devgraph_authority_projection_too_large",
            Self::WrongProjectionBinding => "devgraph_authority_projection_mismatch",
            Self::InvalidVerifierSignature => "devgraph_verifier_signature_invalid",
            Self::ReplayConflict => "devgraph_replay_scope_conflict",
            Self::ReplayStorageFailed => "devgraph_replay_storage_failed",
            Self::Internal => "devgraph_authority_internal",
        }
    }
}

impl fmt::Display for DevgraphAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for DevgraphAuthorityError {}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevgraphIssueCreateRequestV1 {
    #[serde(default)]
    pub artifact_ids: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub external_link_ids: Vec<String>,
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub priority: i64,
    pub title: String,
}

impl fmt::Debug for DevgraphIssueCreateRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevgraphIssueCreateRequestV1")
            .field("artifact_id_count", &self.artifact_ids.len())
            .field("description", &"[redacted]")
            .field("external_link_id_count", &self.external_link_ids.len())
            .field("id", &"[redacted]")
            .field("kind", &self.kind)
            .field("priority", &self.priority)
            .field("title", &"[redacted]")
            .finish()
    }
}

impl DevgraphIssueCreateRequestV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, DevgraphAuthorityError> {
        if bytes.len() > DEVGRAPH_ISSUE_CREATE_MAX_REQUEST_JSON_BYTES_V1 {
            return Err(DevgraphAuthorityError::RequestTooLarge);
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| DevgraphAuthorityError::MalformedRequest)?;
        request.validate()?;
        if request.canonical_json()?.len() > DEVGRAPH_ISSUE_CREATE_MAX_CANONICAL_REQUEST_BYTES_V1 {
            return Err(DevgraphAuthorityError::RequestTooLarge);
        }
        Ok(request)
    }

    pub fn resource(&self) -> String {
        format!("Issue/{}", self.id)
    }

    pub fn canonical_json(&self) -> Result<String, DevgraphAuthorityError> {
        let artifact_ids = serde_json::to_string(&self.artifact_ids)
            .map_err(|_| DevgraphAuthorityError::Internal)?;
        let description = json_string(&self.description)?;
        let external_link_ids = serde_json::to_string(&self.external_link_ids)
            .map_err(|_| DevgraphAuthorityError::Internal)?;
        let id = json_string(&self.id)?;
        let kind = json_string(&self.kind)?;
        let priority = self.priority.to_string();
        let title = json_string(&self.title)?;
        canonical_object(&[
            ("artifact_ids", artifact_ids),
            ("description", description),
            ("external_link_ids", external_link_ids),
            ("id", id),
            ("kind", kind),
            ("priority", priority),
            ("title", title),
        ])
    }

    pub fn request_digest_sha256(&self) -> Result<String, DevgraphAuthorityError> {
        Ok(domain_digest_hex(
            DEVGRAPH_REQUEST_DOMAIN_V1,
            self.canonical_json()?.as_bytes(),
        ))
    }

    fn validate(&self) -> Result<(), DevgraphAuthorityError> {
        if self.kind != "Issue" {
            return Err(DevgraphAuthorityError::InvalidRequest);
        }
        if self.priority < -(DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1 as i64)
            || self.priority > DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1 as i64
        {
            return Err(DevgraphAuthorityError::InvalidRequest);
        }
        if !is_canonical_identifier(&self.id)
            || self
                .artifact_ids
                .iter()
                .any(|id| !is_canonical_identifier(id))
            || self
                .external_link_ids
                .iter()
                .any(|id| !is_canonical_identifier(id))
        {
            return Err(DevgraphAuthorityError::InvalidIdentifier);
        }
        if self.title.is_empty() {
            return Err(DevgraphAuthorityError::EmptyTitle);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevgraphIssueCreateWalletPresentationV1 {
    pub actor_public_key: String,
    pub actor_signature_suite: String,
    pub audience: String,
    pub expires_at: u64,
    pub idempotency_key_digest_sha256: String,
    pub issued_at: u64,
    pub nonce: String,
    pub operation: String,
    pub request_digest_sha256: String,
    pub resource: String,
    pub schema: String,
    pub schema_version: u64,
    pub session_id: String,
    pub signature: String,
}

impl fmt::Debug for DevgraphIssueCreateWalletPresentationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevgraphIssueCreateWalletPresentationV1")
            .field("actor_public_key", &"[redacted]")
            .field("actor_signature_suite", &self.actor_signature_suite)
            .field("audience", &"[redacted]")
            .field("expires_at", &"[redacted]")
            .field(
                "idempotency_key_digest_sha256",
                &self.idempotency_key_digest_sha256,
            )
            .field("issued_at", &"[redacted]")
            .field("nonce", &"[redacted]")
            .field("operation", &self.operation)
            .field("request_digest_sha256", &self.request_digest_sha256)
            .field("resource", &self.resource)
            .field("schema", &self.schema)
            .field("schema_version", &self.schema_version)
            .field("session_id", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

impl DevgraphIssueCreateWalletPresentationV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, DevgraphAuthorityError> {
        if bytes.len() > DEVGRAPH_WALLET_PRESENTATION_MAX_JSON_BYTES_V1 {
            return Err(DevgraphAuthorityError::WalletPresentationTooLarge);
        }
        serde_json::from_slice(bytes)
            .map_err(|_| DevgraphAuthorityError::MalformedWalletPresentation)
    }

    pub fn canonical_unsigned_json(&self) -> Result<String, DevgraphAuthorityError> {
        self.validate_canonical_numbers()?;
        canonical_object(&[
            ("actor_public_key", json_string(&self.actor_public_key)?),
            (
                "actor_signature_suite",
                json_string(&self.actor_signature_suite)?,
            ),
            ("audience", json_string(&self.audience)?),
            ("expires_at", self.expires_at.to_string()),
            (
                "idempotency_key_digest_sha256",
                json_string(&self.idempotency_key_digest_sha256)?,
            ),
            ("issued_at", self.issued_at.to_string()),
            ("nonce", json_string(&self.nonce)?),
            ("operation", json_string(&self.operation)?),
            (
                "request_digest_sha256",
                json_string(&self.request_digest_sha256)?,
            ),
            ("resource", json_string(&self.resource)?),
            ("schema", json_string(&self.schema)?),
            ("schema_version", self.schema_version.to_string()),
            ("session_id", json_string(&self.session_id)?),
        ])
    }

    pub fn canonical_json(&self) -> Result<String, DevgraphAuthorityError> {
        self.validate_canonical_numbers()?;
        canonical_object(&[
            ("actor_public_key", json_string(&self.actor_public_key)?),
            (
                "actor_signature_suite",
                json_string(&self.actor_signature_suite)?,
            ),
            ("audience", json_string(&self.audience)?),
            ("expires_at", self.expires_at.to_string()),
            (
                "idempotency_key_digest_sha256",
                json_string(&self.idempotency_key_digest_sha256)?,
            ),
            ("issued_at", self.issued_at.to_string()),
            ("nonce", json_string(&self.nonce)?),
            ("operation", json_string(&self.operation)?),
            (
                "request_digest_sha256",
                json_string(&self.request_digest_sha256)?,
            ),
            ("resource", json_string(&self.resource)?),
            ("schema", json_string(&self.schema)?),
            ("schema_version", self.schema_version.to_string()),
            ("session_id", json_string(&self.session_id)?),
            ("signature", json_string(&self.signature)?),
        ])
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, DevgraphAuthorityError> {
        let mut preimage = DEVGRAPH_WALLET_SIGNATURE_DOMAIN_V1.to_vec();
        preimage.extend_from_slice(self.canonical_unsigned_json()?.as_bytes());
        Ok(preimage)
    }

    pub fn presentation_digest_sha256(&self) -> Result<String, DevgraphAuthorityError> {
        Ok(domain_digest_hex(
            DEVGRAPH_WALLET_PRESENTATION_DOMAIN_V1,
            self.canonical_json()?.as_bytes(),
        ))
    }

    fn verify(
        &self,
        audience: &str,
        resource: &str,
        request_digest_sha256: &str,
        idempotency_key_digest_sha256: &str,
        now: u64,
    ) -> Result<VerifiedWalletPresentationV1, DevgraphAuthorityError> {
        self.validate_canonical_numbers()?;
        validate_time_window(self.issued_at, self.expires_at, now)?;
        if self.schema != DEVGRAPH_WALLET_PRESENTATION_SCHEMA_V1 || self.schema_version != 1 {
            return Err(DevgraphAuthorityError::InvalidWalletPresentation);
        }
        if self.actor_signature_suite != DEVGRAPH_AUTHORITY_SIGNATURE_SUITE_V1 {
            return Err(DevgraphAuthorityError::UnsupportedSignatureSuite);
        }
        if self.audience != audience {
            return Err(DevgraphAuthorityError::WrongAudience);
        }
        if self.operation != DEVGRAPH_ISSUE_CREATE_OPERATION_V1 {
            return Err(DevgraphAuthorityError::WrongOperation);
        }
        if self.resource != resource {
            return Err(DevgraphAuthorityError::WrongResource);
        }
        if self.request_digest_sha256 != request_digest_sha256 {
            return Err(DevgraphAuthorityError::WrongRequestDigest);
        }
        if self.idempotency_key_digest_sha256 != idempotency_key_digest_sha256 {
            return Err(DevgraphAuthorityError::WrongIdempotencyDigest);
        }
        validate_digest(&self.request_digest_sha256)?;
        validate_digest(&self.idempotency_key_digest_sha256)?;
        let session_id = decode_base64url_exact::<16>(&self.session_id)
            .map_err(|_| DevgraphAuthorityError::InvalidSession)?;
        let nonce = decode_base64url_exact::<12>(&self.nonce)
            .map_err(|_| DevgraphAuthorityError::InvalidWalletPresentation)?;
        let public_key_bytes = decode_base64url_exact::<32>(&self.actor_public_key)
            .map_err(|_| DevgraphAuthorityError::InvalidWalletPresentation)?;
        let signature_bytes = decode_base64url_exact::<64>(&self.signature)
            .map_err(|_| DevgraphAuthorityError::InvalidWalletSignature)?;
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|_| DevgraphAuthorityError::InvalidWalletPresentation)?;
        let signature = Signature::from_bytes(&signature_bytes);
        public_key
            .verify_strict(&self.signature_preimage()?, &signature)
            .map_err(|_| DevgraphAuthorityError::InvalidWalletSignature)?;
        let actor_id = actor_id_for_public_key(&public_key_bytes);
        Ok(VerifiedWalletPresentationV1 {
            actor_id,
            session_id,
            nonce,
            presentation_digest_sha256: self.presentation_digest_sha256()?,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        })
    }

    fn validate_canonical_numbers(&self) -> Result<(), DevgraphAuthorityError> {
        if !is_json_safe_u64(self.schema_version)
            || !is_json_safe_u64(self.issued_at)
            || !is_json_safe_u64(self.expires_at)
        {
            return Err(DevgraphAuthorityError::InvalidWalletPresentation);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct VerifiedWalletPresentationV1 {
    actor_id: String,
    session_id: [u8; 16],
    nonce: [u8; 12],
    presentation_digest_sha256: String,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevgraphPolicyEffectV1 {
    Allow,
    Deny,
}

impl DevgraphPolicyEffectV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevgraphPolicyStatusV1 {
    Active,
    Revoked,
}

impl DevgraphPolicyStatusV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevgraphResourceMatchV1 {
    Exact,
    Prefix,
}

impl DevgraphResourceMatchV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Prefix => "prefix",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevgraphIssueCreatePolicyRuleV1 {
    pub actor_id: String,
    pub effect: DevgraphPolicyEffectV1,
    pub not_after: u64,
    pub not_before: u64,
    pub resource: String,
    pub resource_match: DevgraphResourceMatchV1,
    pub status: DevgraphPolicyStatusV1,
}

impl fmt::Debug for DevgraphIssueCreatePolicyRuleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevgraphIssueCreatePolicyRuleV1")
            .field("actor_id", &"[redacted]")
            .field("effect", &self.effect)
            .field("not_after", &"[redacted]")
            .field("not_before", &"[redacted]")
            .field("resource", &"[redacted]")
            .field("resource_match", &self.resource_match)
            .field("status", &self.status)
            .finish()
    }
}

impl DevgraphIssueCreatePolicyRuleV1 {
    fn canonical_json(&self) -> Result<String, DevgraphAuthorityError> {
        canonical_object(&[
            ("actor_id", json_string(&self.actor_id)?),
            ("effect", json_string(self.effect.as_str())?),
            ("not_after", self.not_after.to_string()),
            ("not_before", self.not_before.to_string()),
            ("resource", json_string(&self.resource)?),
            ("resource_match", json_string(self.resource_match.as_str())?),
            ("status", json_string(self.status.as_str())?),
        ])
    }

    fn validate(&self) -> Result<(), DevgraphAuthorityError> {
        if !is_actor_id(&self.actor_id)
            || self.not_before >= self.not_after
            || !is_json_safe_u64(self.not_before)
            || !is_json_safe_u64(self.not_after)
        {
            return Err(DevgraphAuthorityError::InvalidReceiverPolicy);
        }
        match self.resource_match {
            DevgraphResourceMatchV1::Exact if !is_canonical_issue_resource(&self.resource) => {
                Err(DevgraphAuthorityError::InvalidReceiverPolicy)
            }
            DevgraphResourceMatchV1::Prefix
                if !self.resource.starts_with("Issue/") || self.resource.len() > 262 =>
            {
                Err(DevgraphAuthorityError::InvalidReceiverPolicy)
            }
            _ => Ok(()),
        }
    }

    fn matches(&self, actor_id: &str, resource: &str, now: u64) -> bool {
        self.actor_id == actor_id
            && self.status == DevgraphPolicyStatusV1::Active
            && self.not_before <= now
            && now < self.not_after
            && match self.resource_match {
                DevgraphResourceMatchV1::Exact => self.resource == resource,
                DevgraphResourceMatchV1::Prefix => resource.starts_with(&self.resource),
            }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevgraphIssueCreatePolicyV1 {
    pub audience: String,
    pub operation: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub rules: Vec<DevgraphIssueCreatePolicyRuleV1>,
    pub schema: String,
}

impl fmt::Debug for DevgraphIssueCreatePolicyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevgraphIssueCreatePolicyV1")
            .field("audience", &self.audience)
            .field("operation", &self.operation)
            .field("policy_id", &self.policy_id)
            .field("policy_version", &self.policy_version)
            .field("rule_count", &self.rules.len())
            .field("schema", &self.schema)
            .finish()
    }
}

impl DevgraphIssueCreatePolicyV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, DevgraphAuthorityError> {
        if bytes.len() > DEVGRAPH_ISSUE_CREATE_POLICY_MAX_JSON_BYTES_V1 {
            return Err(DevgraphAuthorityError::ReceiverPolicyTooLarge);
        }
        let policy: Self = serde_json::from_slice(bytes)
            .map_err(|_| DevgraphAuthorityError::InvalidReceiverPolicy)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn canonical_json(&self) -> Result<String, DevgraphAuthorityError> {
        let rules = self
            .rules
            .iter()
            .map(DevgraphIssueCreatePolicyRuleV1::canonical_json)
            .collect::<Result<Vec<_>, _>>()?
            .join(",");
        canonical_object(&[
            ("audience", json_string(&self.audience)?),
            ("operation", json_string(&self.operation)?),
            ("policy_id", json_string(&self.policy_id)?),
            ("policy_version", self.policy_version.to_string()),
            ("rules", format!("[{rules}]")),
            ("schema", json_string(&self.schema)?),
        ])
    }

    pub fn binding(&self) -> Result<DevgraphReceiverPolicyBindingV1, DevgraphAuthorityError> {
        self.validate()?;
        Ok(DevgraphReceiverPolicyBindingV1 {
            policy_id: self.policy_id.clone(),
            policy_version: self.policy_version,
            policy_digest_sha256: domain_digest_hex(
                DEVGRAPH_POLICY_DOMAIN_V1,
                self.canonical_json()?.as_bytes(),
            ),
        })
    }

    fn validate(&self) -> Result<(), DevgraphAuthorityError> {
        if self.schema != DEVGRAPH_ISSUE_CREATE_POLICY_SCHEMA_V1
            || self.operation != DEVGRAPH_ISSUE_CREATE_OPERATION_V1
            || self.policy_version == 0
            || !is_json_safe_u64(self.policy_version)
            || !is_safe_label(&self.policy_id, 128)
            || !is_safe_receiver_value(&self.audience, 256)
            || self.rules.is_empty()
            || self.rules.len() > 256
        {
            return Err(DevgraphAuthorityError::InvalidReceiverPolicy);
        }
        for rule in &self.rules {
            rule.validate()?;
        }
        Ok(())
    }

    fn authorize(
        &self,
        actor_id: &str,
        resource: &str,
        now: u64,
    ) -> Result<(), DevgraphAuthorityError> {
        self.validate()?;
        let mut allowed = false;
        for rule in &self.rules {
            if rule.matches(actor_id, resource, now) {
                match rule.effect {
                    DevgraphPolicyEffectV1::Deny => {
                        return Err(DevgraphAuthorityError::ReceiverPolicyDenied)
                    }
                    DevgraphPolicyEffectV1::Allow => allowed = true,
                }
            }
        }
        if allowed {
            Ok(())
        } else {
            Err(DevgraphAuthorityError::ReceiverPolicyDenied)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevgraphReceiverPolicyBindingV1 {
    pub policy_id: String,
    pub policy_version: u64,
    pub policy_digest_sha256: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevgraphAuthorityProjectionV1 {
    pub actor_id: String,
    pub actor_signature_suite: String,
    pub audience: String,
    pub expires_at: u64,
    pub idempotency_key_digest_sha256: String,
    pub issued_at: u64,
    pub nonce: String,
    pub operation: String,
    pub receiver_policy_digest_sha256: String,
    pub receiver_policy_id: String,
    pub receiver_policy_version: u64,
    pub replay_scope: String,
    pub request_digest_sha256: String,
    pub resource: String,
    pub schema: String,
    pub schema_version: u64,
    pub secs_context_id: String,
    pub secs_verifier_key_id: String,
    pub secs_verifier_signature: String,
    pub secs_verifier_signature_suite: String,
    pub session_id: String,
    pub wallet_presentation_digest_sha256: String,
}

impl fmt::Debug for DevgraphAuthorityProjectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevgraphAuthorityProjectionV1")
            .field("actor_id", &self.actor_id)
            .field("audience", &"[redacted]")
            .field("expires_at", &"[redacted]")
            .field(
                "idempotency_key_digest_sha256",
                &self.idempotency_key_digest_sha256,
            )
            .field("issued_at", &"[redacted]")
            .field("nonce", &"[redacted]")
            .field("operation", &self.operation)
            .field("receiver_policy_id", &self.receiver_policy_id)
            .field("receiver_policy_version", &self.receiver_policy_version)
            .field("request_digest_sha256", &self.request_digest_sha256)
            .field("resource", &self.resource)
            .field("secs_context_id", &self.secs_context_id)
            .field("secs_verifier_key_id", &self.secs_verifier_key_id)
            .field("secs_verifier_signature", &"[redacted]")
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl DevgraphAuthorityProjectionV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, DevgraphAuthorityError> {
        if bytes.len() > DEVGRAPH_AUTHORITY_PROJECTION_MAX_JSON_BYTES_V1 {
            return Err(DevgraphAuthorityError::ProjectionTooLarge);
        }
        serde_json::from_slice(bytes).map_err(|_| DevgraphAuthorityError::MalformedProjection)
    }

    pub fn canonical_unsigned_json(&self) -> Result<String, DevgraphAuthorityError> {
        self.canonical_json_with_signature(false)
    }

    pub fn canonical_json(&self) -> Result<String, DevgraphAuthorityError> {
        self.canonical_json_with_signature(true)
    }

    fn signature_preimage(
        &self,
    ) -> Result<DevgraphAuthoritySignaturePreimageV1, DevgraphAuthorityError> {
        let mut preimage = DEVGRAPH_AUTHORITY_SIGNATURE_DOMAIN_V1.to_vec();
        preimage.extend_from_slice(self.canonical_unsigned_json()?.as_bytes());
        Ok(DevgraphAuthoritySignaturePreimageV1(preimage))
    }

    pub fn correlation_digest_sha256(&self) -> Result<String, DevgraphAuthorityError> {
        Ok(domain_digest_hex(
            DEVGRAPH_AUTHORITY_PROJECTION_DOMAIN_V1,
            self.canonical_json()?.as_bytes(),
        ))
    }

    pub fn redacted_telemetry_fields(&self) -> Result<Vec<String>, DevgraphAuthorityError> {
        Ok(vec![
            format!("operation:{}", self.operation),
            format!("actor_id:{}", self.actor_id),
            format!("resource:{}", self.resource),
            format!("session_id:{}", self.session_id),
            format!("secs_context_id:{}", self.secs_context_id),
            format!("receiver_policy_id:{}", self.receiver_policy_id),
            format!("receiver_policy_version:{}", self.receiver_policy_version),
            format!(
                "receiver_policy_digest_sha256:{}",
                self.receiver_policy_digest_sha256
            ),
            format!("request_digest_sha256:{}", self.request_digest_sha256),
            format!(
                "idempotency_key_digest_sha256:{}",
                self.idempotency_key_digest_sha256
            ),
            format!("secs_verifier_key_id:{}", self.secs_verifier_key_id),
            format!(
                "authority_projection_digest_sha256:{}",
                self.correlation_digest_sha256()?
            ),
        ])
    }

    pub fn verify_with_registry(
        &self,
        registry: &PublicVerifierKeyRegistry,
        expected: &DevgraphAuthorityExpectationsV1,
        now: u64,
    ) -> Result<String, DevgraphAuthorityError> {
        validate_time_window(self.issued_at, self.expires_at, now)?;
        if !is_safe_receiver_value(&expected.audience, 256)
            || !is_safe_label(&expected.policy.policy_id, 128)
            || expected.policy.policy_version == 0
            || !is_json_safe_u64(expected.policy.policy_version)
            || validate_digest(&expected.policy.policy_digest_sha256).is_err()
        {
            return Err(DevgraphAuthorityError::WrongProjectionBinding);
        }
        if self.schema != DEVGRAPH_AUTHORITY_SCHEMA_V1
            || self.schema_version != DEVGRAPH_AUTHORITY_SCHEMA_VERSION_V1
            || self.actor_signature_suite != DEVGRAPH_AUTHORITY_SIGNATURE_SUITE_V1
            || self.secs_verifier_signature_suite != DEVGRAPH_AUTHORITY_SIGNATURE_SUITE_V1
            || self.operation != DEVGRAPH_ISSUE_CREATE_OPERATION_V1
            || self.replay_scope != DEVGRAPH_AUTHORITY_REPLAY_SCOPE_V1
            || !is_actor_id(&self.actor_id)
            || !is_canonical_issue_resource(&self.resource)
            || !is_context_id(&self.secs_context_id)
            || !is_safe_label(&self.secs_verifier_key_id, 256)
            || !is_json_safe_u64(self.schema_version)
            || !is_json_safe_u64(self.issued_at)
            || !is_json_safe_u64(self.expires_at)
            || !is_json_safe_u64(self.receiver_policy_version)
        {
            return Err(DevgraphAuthorityError::MalformedProjection);
        }
        for digest in [
            &self.idempotency_key_digest_sha256,
            &self.receiver_policy_digest_sha256,
            &self.request_digest_sha256,
            &self.wallet_presentation_digest_sha256,
        ] {
            validate_digest(digest)?;
        }
        let session_id = decode_base64url_exact::<16>(&self.session_id)
            .map_err(|_| DevgraphAuthorityError::MalformedProjection)?;
        let nonce = decode_base64url_exact::<12>(&self.nonce)
            .map_err(|_| DevgraphAuthorityError::MalformedProjection)?;
        let signature = decode_base64url_exact::<64>(&self.secs_verifier_signature)
            .map_err(|_| DevgraphAuthorityError::InvalidVerifierSignature)?;
        if self.actor_id != expected.actor_id
            || self.audience != expected.audience
            || self.resource != expected.resource
            || self.request_digest_sha256 != expected.request_digest_sha256
            || self.idempotency_key_digest_sha256 != expected.idempotency_key_digest_sha256
            || session_id != expected.session_id
            || nonce != expected.nonce
            || self.issued_at != expected.issued_at
            || self.expires_at != expected.expires_at
            || self.receiver_policy_id != expected.policy.policy_id
            || self.receiver_policy_version != expected.policy.policy_version
            || self.receiver_policy_digest_sha256 != expected.policy.policy_digest_sha256
            || self.wallet_presentation_digest_sha256 != expected.wallet_presentation_digest_sha256
        {
            return Err(DevgraphAuthorityError::WrongProjectionBinding);
        }
        registry
            .verify_devgraph_authority_v1_signature(
                &self.secs_verifier_key_id,
                &self.signature_preimage()?,
                &signature,
                now,
            )
            .map_err(|_| DevgraphAuthorityError::InvalidVerifierSignature)?;
        self.correlation_digest_sha256()
    }

    fn canonical_json_with_signature(
        &self,
        include_signature: bool,
    ) -> Result<String, DevgraphAuthorityError> {
        if !is_json_safe_u64(self.schema_version)
            || !is_json_safe_u64(self.issued_at)
            || !is_json_safe_u64(self.expires_at)
            || !is_json_safe_u64(self.receiver_policy_version)
        {
            return Err(DevgraphAuthorityError::MalformedProjection);
        }
        let mut fields = vec![
            ("actor_id", json_string(&self.actor_id)?),
            (
                "actor_signature_suite",
                json_string(&self.actor_signature_suite)?,
            ),
            ("audience", json_string(&self.audience)?),
            ("expires_at", self.expires_at.to_string()),
            (
                "idempotency_key_digest_sha256",
                json_string(&self.idempotency_key_digest_sha256)?,
            ),
            ("issued_at", self.issued_at.to_string()),
            ("nonce", json_string(&self.nonce)?),
            ("operation", json_string(&self.operation)?),
            (
                "receiver_policy_digest_sha256",
                json_string(&self.receiver_policy_digest_sha256)?,
            ),
            ("receiver_policy_id", json_string(&self.receiver_policy_id)?),
            (
                "receiver_policy_version",
                self.receiver_policy_version.to_string(),
            ),
            ("replay_scope", json_string(&self.replay_scope)?),
            (
                "request_digest_sha256",
                json_string(&self.request_digest_sha256)?,
            ),
            ("resource", json_string(&self.resource)?),
            ("schema", json_string(&self.schema)?),
            ("schema_version", self.schema_version.to_string()),
            ("secs_context_id", json_string(&self.secs_context_id)?),
            (
                "secs_verifier_key_id",
                json_string(&self.secs_verifier_key_id)?,
            ),
        ];
        if include_signature {
            fields.push((
                "secs_verifier_signature",
                json_string(&self.secs_verifier_signature)?,
            ));
        }
        fields.push((
            "secs_verifier_signature_suite",
            json_string(&self.secs_verifier_signature_suite)?,
        ));
        fields.push(("session_id", json_string(&self.session_id)?));
        fields.push((
            "wallet_presentation_digest_sha256",
            json_string(&self.wallet_presentation_digest_sha256)?,
        ));
        canonical_object(&fields)
    }
}

/// Opaque, domain-separated signing input for the one fixed DG-P projection.
/// Its tuple field and constructor remain private to this module, so sibling
/// modules cannot turn the authority signer into an arbitrary-byte oracle.
pub(crate) struct DevgraphAuthoritySignaturePreimageV1(Vec<u8>);

impl DevgraphAuthoritySignaturePreimageV1 {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DevgraphAuthorityExpectationsV1 {
    pub actor_id: String,
    pub audience: String,
    pub resource: String,
    pub request_digest_sha256: String,
    pub idempotency_key_digest_sha256: String,
    pub session_id: [u8; 16],
    pub nonce: [u8; 12],
    pub issued_at: u64,
    pub expires_at: u64,
    pub policy: DevgraphReceiverPolicyBindingV1,
    pub wallet_presentation_digest_sha256: String,
}

impl fmt::Debug for DevgraphAuthorityExpectationsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevgraphAuthorityExpectationsV1")
            .field("actor_id", &self.actor_id)
            .field("audience", &"[redacted]")
            .field("resource", &self.resource)
            .field("request_digest_sha256", &self.request_digest_sha256)
            .field(
                "idempotency_key_digest_sha256",
                &self.idempotency_key_digest_sha256,
            )
            .field("session_id", &"[redacted]")
            .field("nonce", &"[redacted]")
            .field("issued_at", &"[redacted]")
            .field("expires_at", &"[redacted]")
            .field("policy", &self.policy)
            .field(
                "wallet_presentation_digest_sha256",
                &self.wallet_presentation_digest_sha256,
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum DevgraphAuthorityIssueOutcomeV1 {
    Fresh(DevgraphAuthorityProjectionV1),
    ExactRetry(DevgraphAuthorityProjectionV1),
}

impl fmt::Debug for DevgraphAuthorityIssueOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fresh(projection) => formatter.debug_tuple("Fresh").field(projection).finish(),
            Self::ExactRetry(projection) => formatter
                .debug_tuple("ExactRetry")
                .field(projection)
                .finish(),
        }
    }
}

impl DevgraphAuthorityIssueOutcomeV1 {
    pub fn projection(&self) -> &DevgraphAuthorityProjectionV1 {
        match self {
            Self::Fresh(projection) | Self::ExactRetry(projection) => projection,
        }
    }

    pub fn is_exact_retry(&self) -> bool {
        matches!(self, Self::ExactRetry(_))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DevgraphAuthorityReplayBindingV1 {
    pub actor_id: String,
    pub audience: String,
    pub expires_at: u64,
    pub idempotency_key_digest_sha256: String,
    pub issued_at: u64,
    pub nonce: [u8; 12],
    pub operation: String,
    pub replay_scope: String,
    pub receiver_policy_id: String,
    pub receiver_policy_version: u64,
    pub receiver_policy_digest_sha256: String,
    pub request_digest_sha256: String,
    pub resource: String,
    pub secs_context_id: String,
    pub secs_verifier_key_id: String,
    pub session_id: [u8; 16],
    pub wallet_presentation_digest_sha256: String,
}

/// Borrowed, bounded inputs for one fixed DG-P issuance attempt. The producer
/// takes this typed aggregate instead of an extensible route/options bag.
pub struct DevgraphIssueCreateAuthorityInputV1<'a> {
    pub request_json: &'a [u8],
    pub idempotency_key: &'a str,
    pub wallet_presentation_json: &'a [u8],
    pub now: u64,
}

pub async fn issue_devgraph_issue_create_authority_v1(
    ledger: &Ledger,
    verifier_identity: &NodeVerifierIdentity,
    verifier_registry: &PublicVerifierKeyRegistry,
    receiver_policy: &DevgraphIssueCreatePolicyV1,
    input: DevgraphIssueCreateAuthorityInputV1<'_>,
) -> Result<DevgraphAuthorityIssueOutcomeV1, DevgraphAuthorityError> {
    let DevgraphIssueCreateAuthorityInputV1 {
        request_json,
        idempotency_key,
        wallet_presentation_json,
        now,
    } = input;
    if crate::clock::is_clock_read_failure(now) {
        return Err(DevgraphAuthorityError::ClockFailure);
    }
    if verifier_identity.authenticator_kind() != AuthenticatorKind::Ed25519NodeAndVerifier {
        return Err(DevgraphAuthorityError::UntrustedVerifierIdentity);
    }
    verifier_registry
        .require_devgraph_authority_signer_v1(
            verifier_identity.signer_key_id(),
            verifier_identity.public_key(),
            now,
        )
        .map_err(|_| DevgraphAuthorityError::UntrustedVerifierIdentity)?;
    let request = DevgraphIssueCreateRequestV1::from_json(request_json)?;
    let request_digest_sha256 = request.request_digest_sha256()?;
    let idempotency_key_digest_sha256 = idempotency_key_digest_sha256(idempotency_key)?;
    let resource = request.resource();
    let presentation =
        DevgraphIssueCreateWalletPresentationV1::from_json(wallet_presentation_json)?;
    receiver_policy.validate()?;
    let verified_presentation = presentation.verify(
        &receiver_policy.audience,
        &resource,
        &request_digest_sha256,
        &idempotency_key_digest_sha256,
        now,
    )?;
    receiver_policy.authorize(&verified_presentation.actor_id, &resource, now)?;
    let policy = receiver_policy.binding()?;
    let context_id = context_id(
        &verified_presentation.presentation_digest_sha256,
        &policy.policy_digest_sha256,
        verifier_identity.signer_key_id(),
    );
    let mut projection = DevgraphAuthorityProjectionV1 {
        actor_id: verified_presentation.actor_id.clone(),
        actor_signature_suite: DEVGRAPH_AUTHORITY_SIGNATURE_SUITE_V1.to_string(),
        audience: receiver_policy.audience.clone(),
        expires_at: verified_presentation.expires_at,
        idempotency_key_digest_sha256: idempotency_key_digest_sha256.clone(),
        issued_at: verified_presentation.issued_at,
        nonce: encode_base64url(&verified_presentation.nonce),
        operation: DEVGRAPH_ISSUE_CREATE_OPERATION_V1.to_string(),
        receiver_policy_digest_sha256: policy.policy_digest_sha256.clone(),
        receiver_policy_id: policy.policy_id.clone(),
        receiver_policy_version: policy.policy_version,
        replay_scope: DEVGRAPH_AUTHORITY_REPLAY_SCOPE_V1.to_string(),
        request_digest_sha256: request_digest_sha256.clone(),
        resource: resource.clone(),
        schema: DEVGRAPH_AUTHORITY_SCHEMA_V1.to_string(),
        schema_version: DEVGRAPH_AUTHORITY_SCHEMA_VERSION_V1,
        secs_context_id: context_id,
        secs_verifier_key_id: verifier_identity.signer_key_id().to_string(),
        secs_verifier_signature: String::new(),
        secs_verifier_signature_suite: DEVGRAPH_AUTHORITY_SIGNATURE_SUITE_V1.to_string(),
        session_id: encode_base64url(&verified_presentation.session_id),
        wallet_presentation_digest_sha256: verified_presentation.presentation_digest_sha256.clone(),
    };
    let signature = verifier_identity
        .sign_devgraph_authority_v1(&projection.signature_preimage()?)
        .map_err(|_| DevgraphAuthorityError::UntrustedVerifierIdentity)?;
    projection.secs_verifier_signature = encode_base64url(&signature);
    let expected = DevgraphAuthorityExpectationsV1 {
        actor_id: verified_presentation.actor_id.clone(),
        audience: receiver_policy.audience.clone(),
        resource: resource.clone(),
        request_digest_sha256: request_digest_sha256.clone(),
        idempotency_key_digest_sha256: idempotency_key_digest_sha256.clone(),
        session_id: verified_presentation.session_id,
        nonce: verified_presentation.nonce,
        issued_at: verified_presentation.issued_at,
        expires_at: verified_presentation.expires_at,
        policy: policy.clone(),
        wallet_presentation_digest_sha256: verified_presentation.presentation_digest_sha256.clone(),
    };
    projection.verify_with_registry(verifier_registry, &expected, now)?;
    let replay = DevgraphAuthorityReplayBindingV1 {
        actor_id: verified_presentation.actor_id,
        audience: receiver_policy.audience.clone(),
        expires_at: verified_presentation.expires_at,
        idempotency_key_digest_sha256,
        issued_at: verified_presentation.issued_at,
        nonce: verified_presentation.nonce,
        operation: DEVGRAPH_ISSUE_CREATE_OPERATION_V1.to_string(),
        replay_scope: DEVGRAPH_AUTHORITY_REPLAY_SCOPE_V1.to_string(),
        receiver_policy_id: policy.policy_id,
        receiver_policy_version: policy.policy_version,
        receiver_policy_digest_sha256: policy.policy_digest_sha256,
        request_digest_sha256,
        resource,
        secs_context_id: projection.secs_context_id.clone(),
        secs_verifier_key_id: projection.secs_verifier_key_id.clone(),
        session_id: verified_presentation.session_id,
        wallet_presentation_digest_sha256: verified_presentation.presentation_digest_sha256,
    };
    match ledger
        .reserve_devgraph_authority_replay(&replay, now)
        .await
        .map_err(|_| DevgraphAuthorityError::ReplayStorageFailed)?
    {
        DevgraphReplayReservationOutcome::Reserved => {
            Ok(DevgraphAuthorityIssueOutcomeV1::Fresh(projection))
        }
        DevgraphReplayReservationOutcome::ExactDuplicate => {
            Ok(DevgraphAuthorityIssueOutcomeV1::ExactRetry(projection))
        }
        DevgraphReplayReservationOutcome::ScopeConflict => {
            Err(DevgraphAuthorityError::ReplayConflict)
        }
    }
}

pub fn idempotency_key_digest_sha256(
    idempotency_key: &str,
) -> Result<String, DevgraphAuthorityError> {
    if !(16..=128).contains(&idempotency_key.len())
        || !idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
    {
        return Err(DevgraphAuthorityError::InvalidIdempotencyKey);
    }
    Ok(lower_hex(&Sha256::digest(idempotency_key.as_bytes())))
}

pub fn actor_id_for_public_key(public_key: &[u8; 32]) -> String {
    format!("pubkey:sha256:{}", lower_hex(&Sha256::digest(public_key)))
}

pub fn encode_base64url(bytes: &[u8]) -> String {
    let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(BASE64URL_ALPHABET[(first >> 2) as usize] as char);
        output.push(BASE64URL_ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() >= 2 {
            output
                .push(BASE64URL_ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        }
        if chunk.len() == 3 {
            output.push(BASE64URL_ALPHABET[(third & 0x3f) as usize] as char);
        }
    }
    output
}

fn decode_base64url_exact<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    let encoded_len = N.div_ceil(3) * 4 - ((3 - (N % 3)) % 3);
    if value.len() != encoded_len || value.contains('=') {
        return Err(());
    }
    let mut decoded = Vec::with_capacity(value.len() * 3 / 4);
    let encoded = value.as_bytes();
    let mut index = 0;
    while index < encoded.len() {
        let remaining = encoded.len() - index;
        let take = remaining.min(4);
        if take == 1 {
            return Err(());
        }
        let mut sextets = [0u8; 4];
        for offset in 0..take {
            sextets[offset] = base64url_value(encoded[index + offset]).ok_or(())?;
        }
        decoded.push((sextets[0] << 2) | (sextets[1] >> 4));
        if take >= 3 {
            decoded.push((sextets[1] << 4) | (sextets[2] >> 2));
        } else if sextets[1] & 0x0f != 0 {
            return Err(());
        }
        if take == 4 {
            decoded.push((sextets[2] << 6) | sextets[3]);
        } else if take == 3 && sextets[2] & 0x03 != 0 {
            return Err(());
        }
        index += take;
    }
    if decoded.len() != N || encode_base64url(&decoded) != value {
        return Err(());
    }
    decoded.try_into().map_err(|_| ())
}

fn is_json_safe_u64(value: u64) -> bool {
    value <= DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1
}

fn base64url_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn canonical_object(fields: &[(&str, String)]) -> Result<String, DevgraphAuthorityError> {
    if fields
        .windows(2)
        .any(|pair| pair[0].0.as_bytes() >= pair[1].0.as_bytes())
    {
        return Err(DevgraphAuthorityError::Internal);
    }
    let mut output = String::from("{");
    for (index, (name, value)) in fields.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&json_string(name)?);
        output.push(':');
        output.push_str(value);
    }
    output.push('}');
    Ok(output)
}

fn json_string(value: &str) -> Result<String, DevgraphAuthorityError> {
    serde_json::to_string(value).map_err(|_| DevgraphAuthorityError::Internal)
}

fn context_id(
    wallet_presentation_digest: &str,
    policy_digest: &str,
    verifier_key_id: &str,
) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(wallet_presentation_digest.as_bytes());
    payload.push(0);
    payload.extend_from_slice(policy_digest.as_bytes());
    payload.push(0);
    payload.extend_from_slice(verifier_key_id.as_bytes());
    format!(
        "ctx:sha256:{}",
        domain_digest_hex(DEVGRAPH_CONTEXT_DOMAIN_V1, &payload)
    )
}

fn domain_digest_hex(domain: &[u8], payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(payload);
    lower_hex(&hasher.finalize())
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_digest(value: &str) -> Result<(), DevgraphAuthorityError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(DevgraphAuthorityError::MalformedProjection)
    }
}

fn validate_time_window(
    issued_at: u64,
    expires_at: u64,
    now: u64,
) -> Result<(), DevgraphAuthorityError> {
    if crate::clock::is_clock_read_failure(now) {
        return Err(DevgraphAuthorityError::ClockFailure);
    }
    if issued_at >= expires_at
        || expires_at.saturating_sub(issued_at) > DEVGRAPH_AUTHORITY_MAX_TTL_SECONDS_V1
    {
        return Err(DevgraphAuthorityError::InvalidValidityWindow);
    }
    if now < issued_at {
        return Err(DevgraphAuthorityError::NotYetValid);
    }
    if now >= expires_at {
        return Err(DevgraphAuthorityError::Expired);
    }
    Ok(())
}

fn is_canonical_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > 256 {
        return false;
    }
    let bytes = value.as_bytes();
    let endpoint = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    endpoint(bytes[0])
        && endpoint(bytes[bytes.len() - 1])
        && bytes.iter().all(|byte| endpoint(*byte) || *byte == b'-')
}

fn is_canonical_issue_resource(value: &str) -> bool {
    value
        .strip_prefix("Issue/")
        .is_some_and(is_canonical_identifier)
}

fn is_actor_id(value: &str) -> bool {
    value
        .strip_prefix("pubkey:sha256:")
        .is_some_and(|digest| validate_digest(digest).is_ok())
}

fn is_context_id(value: &str) -> bool {
    value
        .strip_prefix("ctx:sha256:")
        .is_some_and(|digest| validate_digest(digest).is_ok())
}

fn is_safe_receiver_value(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.chars().any(char::is_control)
        && !value.trim().is_empty()
}

fn is_safe_label(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}
