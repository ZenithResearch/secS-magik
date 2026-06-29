//! No-network decision helpers for the `secs-dregg-live-source-client-v1`
//! contract.
//!
//! This module intentionally stops before HTTP/signed-request transport. It
//! pins request/response/cache semantics so future transport wiring cannot turn
//! stale, degraded, duplicate, or wrong-binding live source material into
//! receiver-held authority.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::time::Duration;

pub const DREGG_LIVE_SOURCE_CONTRACT_VERSION: &str = "secs-dregg-live-source-client-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DreggLiveSourceRequest {
    pub contract_version: String,
    pub receiver_audience: String,
    pub entity_ref: String,
    pub resource_ref: String,
    pub operation: String,
    pub opcode: u8,
    pub subject: String,
    pub issuer_key_id: Option<String>,
    pub authority_root_ref: Option<String>,
    pub validation_time: u64,
    pub request_nonce: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DreggLiveSourceStatus {
    Active,
    Degraded,
    Unavailable,
    Revoked,
    Inactive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DreggLiveSourceDuplicatePolicy {
    Unique,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DreggLiveSourceResponse {
    pub contract_version: String,
    pub source_id: String,
    pub source_key_id: String,
    pub source_status: DreggLiveSourceStatus,
    pub entity_ref: String,
    pub resource_ref: String,
    pub issuer_key_id: String,
    pub issuer_status: DreggLiveSourceStatus,
    pub authority_root_ref: String,
    pub root_fingerprint: String,
    pub root_status: DreggLiveSourceStatus,
    pub namespace_status: DreggLiveSourceStatus,
    pub resource_status: DreggLiveSourceStatus,
    pub status_observed_at: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub snapshot_generation: String,
    pub duplicate_policy: DreggLiveSourceDuplicatePolicy,
    pub redacted_summary: String,
    pub response_signature: Vec<u8>,
}

impl DreggLiveSourceResponse {
    pub fn signature_payload(&self, request: &DreggLiveSourceRequest) -> Vec<u8> {
        let mut payload = Vec::new();
        for value in [
            DREGG_LIVE_SOURCE_CONTRACT_VERSION,
            &request.contract_version,
            &request.receiver_audience,
            &request.operation,
            &request.opcode.to_string(),
            &request.entity_ref,
            &request.resource_ref,
            &request.subject,
            request.issuer_key_id.as_deref().unwrap_or(""),
            request.authority_root_ref.as_deref().unwrap_or(""),
            &request.validation_time.to_string(),
            &request.request_nonce,
            &self.contract_version,
            &self.source_id,
            &self.source_key_id,
            &format!("{:?}", self.source_status),
            &self.entity_ref,
            &self.resource_ref,
            &self.issuer_key_id,
            &format!("{:?}", self.issuer_status),
            &self.authority_root_ref,
            &self.root_fingerprint,
            &format!("{:?}", self.root_status),
            &format!("{:?}", self.namespace_status),
            &format!("{:?}", self.resource_status),
            &self.status_observed_at.to_string(),
            &self.valid_from.to_string(),
            &self.valid_until.to_string(),
            &self.snapshot_generation,
            &format!("{:?}", self.duplicate_policy),
            &self.redacted_summary,
        ] {
            payload.extend_from_slice(&(value.len() as u64).to_be_bytes());
            payload.extend_from_slice(value.as_bytes());
        }
        payload
    }
}

#[derive(Debug, Clone)]
pub struct DreggLiveSourceTrustedKey {
    pub source_id: String,
    pub source_key_id: String,
    pub public_key: VerifyingKey,
    pub active: bool,
}

impl DreggLiveSourceTrustedKey {
    pub fn active(
        source_id: impl Into<String>,
        source_key_id: impl Into<String>,
        public_key: VerifyingKey,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            source_key_id: source_key_id.into(),
            public_key,
            active: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreggLiveSourceDecision {
    pub source_id: String,
    pub issuer_key_id: String,
    pub authority_root_ref: String,
    pub root_fingerprint: String,
    pub cache_generation: String,
    pub redacted_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreggLiveSourceCacheEntry {
    pub request: DreggLiveSourceRequest,
    pub response: DreggLiveSourceResponse,
    pub cached_at: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct DreggLiveSourceAuthMaterial {
    token: String,
}

impl fmt::Debug for DreggLiveSourceAuthMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DreggLiveSourceAuthMaterial")
            .field("token", &"<redacted>")
            .finish()
    }
}

impl DreggLiveSourceAuthMaterial {
    pub fn redacted_summary(&self) -> String {
        "auth_token:<redacted>".to_string()
    }

    pub fn bearer_token(&self) -> &str {
        &self.token
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreggLiveSourceLookupPolicy {
    pub timeout: Duration,
    pub retry_max: u64,
    pub stale_max_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreggLiveSourceTransportError {
    Timeout,
    SourceUnavailable,
    Unauthorized,
    MalformedResponse,
}

pub trait DreggLiveSourceTransport {
    fn fetch_authority(
        &mut self,
        request: &DreggLiveSourceRequest,
        auth: &DreggLiveSourceAuthMaterial,
        timeout: Duration,
    ) -> Result<DreggLiveSourceResponse, DreggLiveSourceTransportError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreggLiveSourceClientError {
    UnsupportedContractVersion,
    MalformedResponse,
    SourceUnavailable,
    TransportDisabled,
    MissingAuthMaterial,
    MissingSourceTrust,
    TransportTimeout,
    UnauthorizedSource,
    WrongBinding,
    WrongRoot,
    RevokedOrInactive,
    DuplicateAuthorityConflict,
    UnredactedSummary,
    FutureStatus,
    StaleStatus,
}

pub fn load_live_source_auth_token(
    path: &Path,
) -> Result<DreggLiveSourceAuthMaterial, DreggLiveSourceClientError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| DreggLiveSourceClientError::MissingAuthMaterial)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(DreggLiveSourceClientError::MissingAuthMaterial);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(DreggLiveSourceClientError::MissingAuthMaterial);
        }
    }
    let token = std::fs::read_to_string(path)
        .map_err(|_| DreggLiveSourceClientError::MissingAuthMaterial)?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(DreggLiveSourceClientError::MissingAuthMaterial);
    }
    Ok(DreggLiveSourceAuthMaterial { token })
}

pub fn execute_live_source_lookup<T: DreggLiveSourceTransport>(
    mut transport: Option<&mut T>,
    auth: Option<&DreggLiveSourceAuthMaterial>,
    trusted_key: Option<&DreggLiveSourceTrustedKey>,
    request: &DreggLiveSourceRequest,
    policy: DreggLiveSourceLookupPolicy,
) -> Result<DreggLiveSourceDecision, DreggLiveSourceClientError> {
    let transport = transport
        .as_mut()
        .ok_or(DreggLiveSourceClientError::TransportDisabled)?;
    let auth = auth.ok_or(DreggLiveSourceClientError::MissingAuthMaterial)?;
    let trusted_key = trusted_key.ok_or(DreggLiveSourceClientError::MissingSourceTrust)?;
    let mut attempts = 0_u64;
    loop {
        attempts += 1;
        match transport.fetch_authority(request, auth, policy.timeout) {
            Ok(response) => {
                return validate_live_source_response(
                    request,
                    &response,
                    policy.stale_max_seconds,
                    Some(trusted_key),
                );
            }
            Err(DreggLiveSourceTransportError::Timeout) => {
                if attempts > policy.retry_max {
                    return Err(DreggLiveSourceClientError::TransportTimeout);
                }
            }
            Err(DreggLiveSourceTransportError::SourceUnavailable) => {
                return Err(DreggLiveSourceClientError::SourceUnavailable);
            }
            Err(DreggLiveSourceTransportError::Unauthorized) => {
                return Err(DreggLiveSourceClientError::UnauthorizedSource);
            }
            Err(DreggLiveSourceTransportError::MalformedResponse) => {
                return Err(DreggLiveSourceClientError::MalformedResponse);
            }
        }
    }
}

pub fn validate_live_source_response(
    request: &DreggLiveSourceRequest,
    response: &DreggLiveSourceResponse,
    max_status_age_seconds: u64,
    trusted_key: Option<&DreggLiveSourceTrustedKey>,
) -> Result<DreggLiveSourceDecision, DreggLiveSourceClientError> {
    let trusted_key = trusted_key.ok_or(DreggLiveSourceClientError::MissingSourceTrust)?;
    if request.contract_version != DREGG_LIVE_SOURCE_CONTRACT_VERSION
        || response.contract_version != DREGG_LIVE_SOURCE_CONTRACT_VERSION
    {
        return Err(DreggLiveSourceClientError::UnsupportedContractVersion);
    }
    validate_required_response_fields(response)?;
    verify_live_source_signature(request, response, trusted_key)?;
    validate_live_source_response_semantics(request, response, max_status_age_seconds)
}

fn validate_live_source_response_semantics(
    request: &DreggLiveSourceRequest,
    response: &DreggLiveSourceResponse,
    max_status_age_seconds: u64,
) -> Result<DreggLiveSourceDecision, DreggLiveSourceClientError> {
    if response.source_status != DreggLiveSourceStatus::Active {
        return Err(DreggLiveSourceClientError::SourceUnavailable);
    }
    if response.entity_ref != request.entity_ref || response.resource_ref != request.resource_ref {
        return Err(DreggLiveSourceClientError::WrongBinding);
    }
    if let Some(expected_issuer_key_id) = &request.issuer_key_id {
        if response.issuer_key_id != *expected_issuer_key_id {
            return Err(DreggLiveSourceClientError::WrongBinding);
        }
    }
    if let Some(expected_root_ref) = &request.authority_root_ref {
        if response.authority_root_ref != *expected_root_ref {
            return Err(DreggLiveSourceClientError::WrongRoot);
        }
    }
    if response.duplicate_policy != DreggLiveSourceDuplicatePolicy::Unique {
        return Err(DreggLiveSourceClientError::DuplicateAuthorityConflict);
    }
    if response.status_observed_at > request.validation_time {
        return Err(DreggLiveSourceClientError::FutureStatus);
    }
    if request
        .validation_time
        .saturating_sub(response.status_observed_at)
        > max_status_age_seconds
    {
        return Err(DreggLiveSourceClientError::StaleStatus);
    }
    if request.validation_time < response.valid_from
        || request.validation_time > response.valid_until
    {
        return Err(DreggLiveSourceClientError::StaleStatus);
    }
    if !all_authority_statuses_active(response) {
        return Err(DreggLiveSourceClientError::RevokedOrInactive);
    }
    Ok(DreggLiveSourceDecision {
        source_id: response.source_id.clone(),
        issuer_key_id: response.issuer_key_id.clone(),
        authority_root_ref: response.authority_root_ref.clone(),
        root_fingerprint: response.root_fingerprint.clone(),
        cache_generation: response.snapshot_generation.clone(),
        redacted_summary: response.redacted_summary.clone(),
    })
}

pub fn cache_entry_is_fresh_for_request(
    entry: &DreggLiveSourceCacheEntry,
    request: &DreggLiveSourceRequest,
    now: u64,
    cache_ttl_seconds: u64,
) -> bool {
    cache_key_matches(&entry.request, request)
        && now >= entry.cached_at
        && now - entry.cached_at <= cache_ttl_seconds
}

pub fn should_replace_cache_entry(
    old_entry: &DreggLiveSourceCacheEntry,
    candidate_request: &DreggLiveSourceRequest,
    candidate_response: &DreggLiveSourceResponse,
    trusted_key: &DreggLiveSourceTrustedKey,
) -> bool {
    if !cache_key_matches(&old_entry.request, candidate_request) {
        return false;
    }
    if validate_live_source_response(
        candidate_request,
        candidate_response,
        u64::MAX,
        Some(trusted_key),
    )
    .is_err()
    {
        return false;
    }
    candidate_response.status_observed_at > old_entry.response.status_observed_at
        || (candidate_response.status_observed_at == old_entry.response.status_observed_at
            && candidate_response.snapshot_generation > old_entry.response.snapshot_generation)
}

fn cache_key_matches(left: &DreggLiveSourceRequest, right: &DreggLiveSourceRequest) -> bool {
    left.contract_version == right.contract_version
        && left.receiver_audience == right.receiver_audience
        && left.entity_ref == right.entity_ref
        && left.resource_ref == right.resource_ref
        && left.operation == right.operation
        && left.opcode == right.opcode
        && left.subject == right.subject
        && left.issuer_key_id == right.issuer_key_id
        && left.authority_root_ref == right.authority_root_ref
}

fn all_authority_statuses_active(response: &DreggLiveSourceResponse) -> bool {
    response.issuer_status == DreggLiveSourceStatus::Active
        && response.root_status == DreggLiveSourceStatus::Active
        && response.namespace_status == DreggLiveSourceStatus::Active
        && response.resource_status == DreggLiveSourceStatus::Active
}

fn validate_required_response_fields(
    response: &DreggLiveSourceResponse,
) -> Result<(), DreggLiveSourceClientError> {
    for value in [
        &response.source_id,
        &response.source_key_id,
        &response.entity_ref,
        &response.resource_ref,
        &response.issuer_key_id,
        &response.authority_root_ref,
        &response.root_fingerprint,
        &response.snapshot_generation,
        &response.redacted_summary,
    ] {
        if value.trim().is_empty() {
            return Err(DreggLiveSourceClientError::MalformedResponse);
        }
    }
    if response.valid_from >= response.valid_until {
        return Err(DreggLiveSourceClientError::MalformedResponse);
    }
    let lower_summary = response.redacted_summary.to_ascii_lowercase();
    for forbidden in [
        "bearer ",
        "authorization:",
        "token=",
        "access_token",
        "private_key",
        "secret",
        "raw_proof",
        "signature:",
    ] {
        if lower_summary.contains(forbidden) {
            return Err(DreggLiveSourceClientError::UnredactedSummary);
        }
    }
    Ok(())
}

fn verify_live_source_signature(
    request: &DreggLiveSourceRequest,
    response: &DreggLiveSourceResponse,
    trusted_key: &DreggLiveSourceTrustedKey,
) -> Result<(), DreggLiveSourceClientError> {
    if !trusted_key.active
        || trusted_key.source_id != response.source_id
        || trusted_key.source_key_id != response.source_key_id
        || response.response_signature.len() != 64
    {
        return Err(DreggLiveSourceClientError::UnauthorizedSource);
    }
    let signature = Signature::from_slice(&response.response_signature)
        .map_err(|_| DreggLiveSourceClientError::UnauthorizedSource)?;
    trusted_key
        .public_key
        .verify(&response.signature_payload(request), &signature)
        .map_err(|_| DreggLiveSourceClientError::UnauthorizedSource)
}
