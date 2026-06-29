use server::dregg_live_source::{
    cache_entry_is_fresh_for_request, should_replace_cache_entry, validate_live_source_response,
    DreggLiveSourceCacheEntry, DreggLiveSourceClientError, DreggLiveSourceDuplicatePolicy,
    DreggLiveSourceRequest, DreggLiveSourceResponse, DreggLiveSourceStatus,
    DREGG_LIVE_SOURCE_CONTRACT_VERSION,
};

const NOW: u64 = 1_770_000_300;

fn request() -> DreggLiveSourceRequest {
    DreggLiveSourceRequest {
        contract_version: DREGG_LIVE_SOURCE_CONTRACT_VERSION.to_string(),
        receiver_audience: "secS://operator-receiver".to_string(),
        entity_ref: "castalia:entity:example".to_string(),
        resource_ref: "application/json".to_string(),
        operation: "membership.provision".to_string(),
        opcode: 16,
        subject: "did:example:alice".to_string(),
        issuer_key_id: Some("issuer-key:1".to_string()),
        authority_root_ref: Some("dregg-root:2026q2".to_string()),
        validation_time: NOW,
        request_nonce: "nonce-1".to_string(),
    }
}

fn response() -> DreggLiveSourceResponse {
    DreggLiveSourceResponse {
        contract_version: DREGG_LIVE_SOURCE_CONTRACT_VERSION.to_string(),
        source_id: "dregg-source:operator".to_string(),
        source_status: DreggLiveSourceStatus::Active,
        entity_ref: "castalia:entity:example".to_string(),
        resource_ref: "application/json".to_string(),
        issuer_key_id: "issuer-key:1".to_string(),
        issuer_status: DreggLiveSourceStatus::Active,
        authority_root_ref: "dregg-root:2026q2".to_string(),
        root_fingerprint: "root:sha256:fixture".to_string(),
        root_status: DreggLiveSourceStatus::Active,
        namespace_status: DreggLiveSourceStatus::Active,
        resource_status: DreggLiveSourceStatus::Active,
        status_observed_at: NOW - 30,
        valid_from: NOW - 60,
        valid_until: NOW + 60,
        snapshot_generation: "generation:42".to_string(),
        duplicate_policy: DreggLiveSourceDuplicatePolicy::Unique,
        redacted_summary: "source=dregg-source:operator root=root:sha256:fixture".to_string(),
    }
}

#[test]
fn live_source_response_must_match_request_binding_and_freshness() {
    let decision = validate_live_source_response(&request(), &response(), 300)
        .expect("active matching response should validate");

    assert_eq!(decision.source_id, "dregg-source:operator");
    assert_eq!(decision.cache_generation, "generation:42");
    assert_eq!(
        decision.redacted_summary,
        "source=dregg-source:operator root=root:sha256:fixture"
    );
}

#[test]
fn live_source_response_rejects_wrong_contract_wrong_binding_and_status() {
    let mut wrong_contract = response();
    wrong_contract.contract_version = "secs-dregg-live-source-client-v0".to_string();
    assert_eq!(
        validate_live_source_response(&request(), &wrong_contract, 300),
        Err(DreggLiveSourceClientError::UnsupportedContractVersion)
    );

    let mut wrong_resource = response();
    wrong_resource.resource_ref = "text/plain".to_string();
    assert_eq!(
        validate_live_source_response(&request(), &wrong_resource, 300),
        Err(DreggLiveSourceClientError::WrongBinding)
    );

    let mut degraded_source = response();
    degraded_source.source_status = DreggLiveSourceStatus::Degraded;
    assert_eq!(
        validate_live_source_response(&request(), &degraded_source, 300),
        Err(DreggLiveSourceClientError::SourceUnavailable)
    );

    let mut duplicate_conflict = response();
    duplicate_conflict.duplicate_policy = DreggLiveSourceDuplicatePolicy::Conflict;
    assert_eq!(
        validate_live_source_response(&request(), &duplicate_conflict, 300),
        Err(DreggLiveSourceClientError::DuplicateAuthorityConflict)
    );
}

#[test]
fn live_source_response_rejects_stale_future_or_invalid_windows() {
    let mut stale = response();
    stale.status_observed_at = NOW - 301;
    assert_eq!(
        validate_live_source_response(&request(), &stale, 300),
        Err(DreggLiveSourceClientError::StaleStatus)
    );

    let mut future = response();
    future.status_observed_at = NOW + 1;
    assert_eq!(
        validate_live_source_response(&request(), &future, 300),
        Err(DreggLiveSourceClientError::FutureStatus)
    );

    let mut expired = response();
    expired.valid_until = NOW - 1;
    assert_eq!(
        validate_live_source_response(&request(), &expired, 300),
        Err(DreggLiveSourceClientError::StaleStatus)
    );
}

#[test]
fn live_source_response_rejects_malformed_or_unredacted_operator_summary() {
    let mut missing_source_id = response();
    missing_source_id.source_id = "".to_string();
    assert_eq!(
        validate_live_source_response(&request(), &missing_source_id, 300),
        Err(DreggLiveSourceClientError::MalformedResponse)
    );

    let mut invalid_window = response();
    invalid_window.valid_from = NOW + 10;
    invalid_window.valid_until = NOW + 10;
    assert_eq!(
        validate_live_source_response(&request(), &invalid_window, 300),
        Err(DreggLiveSourceClientError::MalformedResponse)
    );

    let mut unredacted = response();
    unredacted.redacted_summary = "Authorization: Bearer live-source-secret".to_string();
    assert_eq!(
        validate_live_source_response(&request(), &unredacted, 300),
        Err(DreggLiveSourceClientError::UnredactedSummary)
    );
}

#[test]
fn cache_reuse_requires_same_binding_and_fresh_ttl() {
    let req = request();
    let entry = DreggLiveSourceCacheEntry {
        request: req.clone(),
        response: response(),
        cached_at: NOW - 20,
    };
    assert!(cache_entry_is_fresh_for_request(&entry, &req, NOW, 30));

    let mut different_subject = req.clone();
    different_subject.subject = "did:example:bob".to_string();
    assert!(!cache_entry_is_fresh_for_request(
        &entry,
        &different_subject,
        NOW,
        30
    ));
    assert!(!cache_entry_is_fresh_for_request(&entry, &req, NOW, 19));
}

#[test]
fn cache_replacement_prefers_newer_observed_status_or_generation() {
    let old_entry = DreggLiveSourceCacheEntry {
        request: request(),
        response: response(),
        cached_at: NOW - 20,
    };
    let mut newer = response();
    newer.status_observed_at = NOW - 10;
    assert!(should_replace_cache_entry(&old_entry, &newer));

    let mut older = response();
    older.status_observed_at = NOW - 40;
    older.snapshot_generation = "generation:99".to_string();
    assert!(!should_replace_cache_entry(&old_entry, &older));

    let mut wrong_binding = response();
    wrong_binding.status_observed_at = NOW - 10;
    wrong_binding.resource_ref = "text/plain".to_string();
    assert!(!should_replace_cache_entry(&old_entry, &wrong_binding));

    let mut duplicate_conflict = response();
    duplicate_conflict.status_observed_at = NOW - 10;
    duplicate_conflict.duplicate_policy = DreggLiveSourceDuplicatePolicy::Conflict;
    assert!(!should_replace_cache_entry(&old_entry, &duplicate_conflict));
}
