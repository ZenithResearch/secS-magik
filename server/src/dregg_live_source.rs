//! No-network decision helpers for the `secs-dregg-live-source-client-v1`
//! contract.
//!
//! This module intentionally stops before HTTP/signed-request transport. It
//! pins request/response/cache semantics so future transport wiring cannot turn
//! stale, degraded, duplicate, or wrong-binding live source material into
//! receiver-held authority.

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreggLiveSourceClientError {
    UnsupportedContractVersion,
    MalformedResponse,
    SourceUnavailable,
    WrongBinding,
    WrongRoot,
    RevokedOrInactive,
    DuplicateAuthorityConflict,
    UnredactedSummary,
    FutureStatus,
    StaleStatus,
}

pub fn validate_live_source_response(
    request: &DreggLiveSourceRequest,
    response: &DreggLiveSourceResponse,
    max_status_age_seconds: u64,
) -> Result<DreggLiveSourceDecision, DreggLiveSourceClientError> {
    if request.contract_version != DREGG_LIVE_SOURCE_CONTRACT_VERSION
        || response.contract_version != DREGG_LIVE_SOURCE_CONTRACT_VERSION
    {
        return Err(DreggLiveSourceClientError::UnsupportedContractVersion);
    }
    validate_required_response_fields(response)?;
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
    candidate_response: &DreggLiveSourceResponse,
) -> bool {
    if validate_live_source_response(&old_entry.request, candidate_response, u64::MAX).is_err() {
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
