use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use server::dregg_live_source::{
    build_live_source_http_request, cache_entry_is_fresh_for_request, execute_live_source_lookup,
    load_live_source_auth_token, should_replace_cache_entry, validate_live_source_response,
    DreggLiveSourceAuthMaterial, DreggLiveSourceCacheEntry, DreggLiveSourceClientError,
    DreggLiveSourceDuplicatePolicy, DreggLiveSourceLookupPolicy, DreggLiveSourceRequest,
    DreggLiveSourceResponse, DreggLiveSourceStatus, DreggLiveSourceTransport,
    DreggLiveSourceTransportError, DreggLiveSourceTrustedKey, DREGG_LIVE_SOURCE_CONTRACT_VERSION,
};
use std::collections::VecDeque;
use std::path::Path;
use std::time::Duration;

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
        source_key_id: "dregg-source-key:1".to_string(),
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
        response_signature: Vec::new(),
    }
}

fn source_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7_u8; 32])
}

fn source_trusted_key() -> DreggLiveSourceTrustedKey {
    DreggLiveSourceTrustedKey::active(
        "dregg-source:operator",
        "dregg-source-key:1",
        VerifyingKey::from(&source_signing_key()),
    )
}

fn signed_response() -> DreggLiveSourceResponse {
    sign_response_for_request(&request(), response())
}

fn sign_response_for_request(
    request: &DreggLiveSourceRequest,
    mut response: DreggLiveSourceResponse,
) -> DreggLiveSourceResponse {
    let signature_payload = response.signature_payload(request);
    response.response_signature = source_signing_key()
        .sign(&signature_payload)
        .to_bytes()
        .to_vec();
    response
}

struct FixtureTransport {
    outcomes: VecDeque<Result<DreggLiveSourceResponse, DreggLiveSourceTransportError>>,
    calls: usize,
    observed_auth_summary: Option<String>,
    observed_timeout: Option<Duration>,
}

impl FixtureTransport {
    fn new(outcomes: Vec<Result<DreggLiveSourceResponse, DreggLiveSourceTransportError>>) -> Self {
        Self {
            outcomes: outcomes.into(),
            calls: 0,
            observed_auth_summary: None,
            observed_timeout: None,
        }
    }
}

impl DreggLiveSourceTransport for FixtureTransport {
    fn fetch_authority(
        &mut self,
        _request: &DreggLiveSourceRequest,
        auth: &DreggLiveSourceAuthMaterial,
        timeout: Duration,
    ) -> Result<DreggLiveSourceResponse, DreggLiveSourceTransportError> {
        self.calls += 1;
        self.observed_auth_summary = Some(auth.redacted_summary());
        self.observed_timeout = Some(timeout);
        self.outcomes
            .pop_front()
            .expect("fixture transport outcome should be queued")
    }
}

fn token_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("secs-magik-{name}-{}-{}", std::process::id(), NOW))
}

fn write_owner_private_token(path: &Path, token: &str) {
    std::fs::write(path, token).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn auth_material(name: &str) -> DreggLiveSourceAuthMaterial {
    let path = token_path(name);
    write_owner_private_token(&path, "live-secret-token\n");
    let auth = load_live_source_auth_token(Path::new(&path)).unwrap();
    let _ = std::fs::remove_file(&path);
    auth
}

#[test]
fn live_source_http_request_builder_serializes_signed_no_network_contract() {
    let auth = auth_material("http-request-builder");

    let http_request = build_live_source_http_request(
        "https://dregg.example.test/api/v1/authority?ignored=true#fragment",
        &request(),
        &auth,
    )
    .expect("valid HTTPS base URL should build a deterministic no-network HTTP request");

    assert_eq!(http_request.method, "POST");
    assert_eq!(
        http_request.url,
        "https://dregg.example.test/api/v1/authority/lookup"
    );
    assert_eq!(
        http_request.headers,
        vec![
            (
                "authorization".to_string(),
                "Bearer live-secret-token".to_string()
            ),
            ("content-type".to_string(), "application/json".to_string()),
            (
                "x-secs-contract".to_string(),
                DREGG_LIVE_SOURCE_CONTRACT_VERSION.to_string()
            ),
        ]
    );
    assert!(http_request
        .body_json
        .contains("\"request_nonce\":\"nonce-1\""));
    assert!(http_request
        .body_json
        .contains("\"receiver_audience\":\"secS://operator-receiver\""));
    assert!(!http_request.body_json.contains("live-secret-token"));
    assert!(!format!("{http_request:?}").contains("live-secret-token"));
}

#[test]
fn live_source_http_request_builder_rejects_non_https_or_secret_bearing_urls() {
    let auth = auth_material("http-request-builder-rejects");

    for source_url in [
        "http://dregg.example.test/api",
        "https://user:secret@dregg.example.test/api",
        "https://dregg.example.test/api?token=secret",
        "https://dregg.example.test/api?api_key=secret",
        "https://dregg.example.test/api?client_secret=secret",
        "https://dregg.example.test/api?refresh_token=secret",
        "https://dregg.example.test/api?x-api-key=secret",
        "https://dregg.example.test/api?api%5Fkey=secret",
        "https://dregg.example.test/api?password=secret",
        "https://dregg.example.test/api?signature=secret",
        " https://dregg.example.test/api",
        "https://dregg.example.test/api\r\nX-Injected: yes",
    ] {
        assert_eq!(
            build_live_source_http_request(source_url, &request(), &auth),
            Err(DreggLiveSourceClientError::InsecureSourceUrl),
            "source URL should fail closed: {source_url:?}"
        );
    }
}

#[test]
fn live_source_auth_material_rejects_header_control_characters() {
    let newline = token_path("newline-auth-material");
    write_owner_private_token(&newline, "live-secret-token\nX-Injected: yes\n");
    assert_eq!(
        load_live_source_auth_token(Path::new(&newline)),
        Err(DreggLiveSourceClientError::MissingAuthMaterial)
    );
    let _ = std::fs::remove_file(&newline);

    let carriage_return = token_path("carriage-return-auth-material");
    write_owner_private_token(&carriage_return, "live-secret-token\rX-Injected: yes\n");
    assert_eq!(
        load_live_source_auth_token(Path::new(&carriage_return)),
        Err(DreggLiveSourceClientError::MissingAuthMaterial)
    );
    let _ = std::fs::remove_file(&carriage_return);
}

#[test]
fn live_source_response_must_match_request_binding_and_freshness() {
    let decision = validate_live_source_response(
        &request(),
        &signed_response(),
        300,
        Some(&source_trusted_key()),
    )
    .expect("active matching response should validate");

    assert_eq!(decision.source_id, "dregg-source:operator");
    assert_eq!(decision.cache_generation, "generation:42");
    assert_eq!(
        decision.redacted_summary,
        "source=dregg-source:operator root=root:sha256:fixture"
    );
}

#[test]
fn live_source_response_signature_binds_nonce_contract_audience_operation_resource_and_subject() {
    let trusted_key = source_trusted_key();
    let signed = signed_response();

    validate_live_source_response(&request(), &signed, 300, Some(&trusted_key))
        .expect("matching trusted source signature should verify");
    assert_eq!(
        validate_live_source_response(&request(), &signed, 300, None),
        Err(DreggLiveSourceClientError::MissingSourceTrust)
    );

    let mut bad_signature = signed.clone();
    bad_signature.response_signature[0] ^= 0x01;
    assert_eq!(
        validate_live_source_response(&request(), &bad_signature, 300, Some(&trusted_key)),
        Err(DreggLiveSourceClientError::UnauthorizedSource)
    );

    let mut tampered_nonce = request();
    tampered_nonce.request_nonce = "nonce-2".to_string();
    assert_eq!(
        validate_live_source_response(&tampered_nonce, &signed, 300, Some(&trusted_key)),
        Err(DreggLiveSourceClientError::UnauthorizedSource)
    );

    let mut tampered_subject = request();
    tampered_subject.subject = "did:example:bob".to_string();
    assert_eq!(
        validate_live_source_response(&tampered_subject, &signed, 300, Some(&trusted_key)),
        Err(DreggLiveSourceClientError::UnauthorizedSource)
    );

    let wrong_key = DreggLiveSourceTrustedKey::active(
        "dregg-source:operator",
        "dregg-source-key:other",
        VerifyingKey::from(&SigningKey::from_bytes(&[8_u8; 32])),
    );
    assert_eq!(
        validate_live_source_response(&request(), &signed, 300, Some(&wrong_key)),
        Err(DreggLiveSourceClientError::UnauthorizedSource)
    );
}

#[test]
fn live_source_response_rejects_wrong_contract_wrong_binding_and_status() {
    let mut wrong_contract = response();
    wrong_contract.contract_version = "secs-dregg-live-source-client-v0".to_string();
    assert_eq!(
        validate_live_source_response(
            &request(),
            &wrong_contract,
            300,
            Some(&source_trusted_key())
        ),
        Err(DreggLiveSourceClientError::UnsupportedContractVersion)
    );

    let mut wrong_resource = response();
    wrong_resource.resource_ref = "text/plain".to_string();
    let wrong_resource = sign_response_for_request(&request(), wrong_resource);
    assert_eq!(
        validate_live_source_response(
            &request(),
            &wrong_resource,
            300,
            Some(&source_trusted_key())
        ),
        Err(DreggLiveSourceClientError::WrongBinding)
    );

    let mut degraded_source = response();
    degraded_source.source_status = DreggLiveSourceStatus::Degraded;
    let degraded_source = sign_response_for_request(&request(), degraded_source);
    assert_eq!(
        validate_live_source_response(
            &request(),
            &degraded_source,
            300,
            Some(&source_trusted_key())
        ),
        Err(DreggLiveSourceClientError::SourceUnavailable)
    );

    let mut duplicate_conflict = response();
    duplicate_conflict.duplicate_policy = DreggLiveSourceDuplicatePolicy::Conflict;
    let duplicate_conflict = sign_response_for_request(&request(), duplicate_conflict);
    assert_eq!(
        validate_live_source_response(
            &request(),
            &duplicate_conflict,
            300,
            Some(&source_trusted_key())
        ),
        Err(DreggLiveSourceClientError::DuplicateAuthorityConflict)
    );
}

#[test]
fn live_source_response_rejects_stale_future_or_invalid_windows() {
    let mut stale = response();
    stale.status_observed_at = NOW - 301;
    let stale = sign_response_for_request(&request(), stale);
    assert_eq!(
        validate_live_source_response(&request(), &stale, 300, Some(&source_trusted_key())),
        Err(DreggLiveSourceClientError::StaleStatus)
    );

    let mut future = response();
    future.status_observed_at = NOW + 1;
    let future = sign_response_for_request(&request(), future);
    assert_eq!(
        validate_live_source_response(&request(), &future, 300, Some(&source_trusted_key())),
        Err(DreggLiveSourceClientError::FutureStatus)
    );

    let mut expired = response();
    expired.valid_until = NOW - 1;
    let expired = sign_response_for_request(&request(), expired);
    assert_eq!(
        validate_live_source_response(&request(), &expired, 300, Some(&source_trusted_key())),
        Err(DreggLiveSourceClientError::StaleStatus)
    );
}

#[test]
fn live_source_response_rejects_malformed_or_unredacted_operator_summary() {
    let mut missing_source_id = response();
    missing_source_id.source_id = "".to_string();
    assert_eq!(
        validate_live_source_response(
            &request(),
            &missing_source_id,
            300,
            Some(&source_trusted_key())
        ),
        Err(DreggLiveSourceClientError::MalformedResponse)
    );

    let mut invalid_window = response();
    invalid_window.valid_from = NOW + 10;
    invalid_window.valid_until = NOW + 10;
    assert_eq!(
        validate_live_source_response(
            &request(),
            &invalid_window,
            300,
            Some(&source_trusted_key())
        ),
        Err(DreggLiveSourceClientError::MalformedResponse)
    );

    let mut unredacted = response();
    unredacted.redacted_summary = "Authorization: Bearer live-source-secret".to_string();
    assert_eq!(
        validate_live_source_response(&request(), &unredacted, 300, Some(&source_trusted_key())),
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
        response: signed_response(),
        cached_at: NOW - 20,
    };
    let trusted_key = source_trusted_key();
    let mut candidate_request = request();
    candidate_request.request_nonce = "nonce-2".to_string();
    let mut newer = response();
    newer.status_observed_at = NOW - 10;
    let newer = sign_response_for_request(&candidate_request, newer);
    assert!(should_replace_cache_entry(
        &old_entry,
        &candidate_request,
        &newer,
        &trusted_key
    ));

    let mut unsigned_newer = response();
    unsigned_newer.status_observed_at = NOW - 5;
    assert!(!should_replace_cache_entry(
        &old_entry,
        &candidate_request,
        &unsigned_newer,
        &trusted_key
    ));

    let mut different_subject_request = candidate_request.clone();
    different_subject_request.subject = "did:example:bob".to_string();
    let different_subject_response =
        sign_response_for_request(&different_subject_request, response());
    assert!(!should_replace_cache_entry(
        &old_entry,
        &different_subject_request,
        &different_subject_response,
        &trusted_key
    ));

    let mut older = response();
    older.status_observed_at = NOW - 40;
    older.snapshot_generation = "generation:99".to_string();
    let older = sign_response_for_request(&candidate_request, older);
    assert!(!should_replace_cache_entry(
        &old_entry,
        &candidate_request,
        &older,
        &trusted_key
    ));

    let mut wrong_binding = response();
    wrong_binding.status_observed_at = NOW - 10;
    wrong_binding.resource_ref = "text/plain".to_string();
    let wrong_binding = sign_response_for_request(&candidate_request, wrong_binding);
    assert!(!should_replace_cache_entry(
        &old_entry,
        &candidate_request,
        &wrong_binding,
        &trusted_key
    ));

    let mut duplicate_conflict = response();
    duplicate_conflict.status_observed_at = NOW - 10;
    duplicate_conflict.duplicate_policy = DreggLiveSourceDuplicatePolicy::Conflict;
    let duplicate_conflict = sign_response_for_request(&candidate_request, duplicate_conflict);
    assert!(!should_replace_cache_entry(
        &old_entry,
        &candidate_request,
        &duplicate_conflict,
        &trusted_key
    ));
}

#[test]
fn live_source_auth_material_loads_without_exposing_token_contents() {
    let path = token_path("auth-material");
    write_owner_private_token(&path, "live-secret-token\n");

    let auth = load_live_source_auth_token(Path::new(&path)).unwrap();
    let _ = std::fs::remove_file(&path);

    assert_eq!(auth.redacted_summary(), "auth_token:<redacted>");
    assert!(!auth.redacted_summary().contains("live-secret-token"));
    assert!(!format!("{auth:?}").contains("live-secret-token"));
}

#[test]
fn live_source_auth_material_rejects_missing_or_empty_token_files() {
    let missing = token_path("missing-auth-material");
    let _ = std::fs::remove_file(&missing);
    assert_eq!(
        load_live_source_auth_token(Path::new(&missing)),
        Err(DreggLiveSourceClientError::MissingAuthMaterial)
    );

    let empty = token_path("empty-auth-material");
    write_owner_private_token(&empty, "  \n");
    assert_eq!(
        load_live_source_auth_token(Path::new(&empty)),
        Err(DreggLiveSourceClientError::MissingAuthMaterial)
    );
    let _ = std::fs::remove_file(&empty);
}

#[test]
fn live_source_lookup_does_not_call_transport_when_adapter_disabled_auth_missing_or_trust_missing()
{
    let policy = DreggLiveSourceLookupPolicy {
        timeout: Duration::from_millis(250),
        retry_max: 2,
        stale_max_seconds: 300,
    };
    let mut transport = FixtureTransport::new(vec![Ok(signed_response())]);
    let auth = auth_material("lookup-preflight");

    let disabled_result = execute_live_source_lookup(
        None::<&mut FixtureTransport>,
        None,
        None,
        &request(),
        policy,
    );
    assert_eq!(
        disabled_result,
        Err(DreggLiveSourceClientError::TransportDisabled)
    );
    assert_eq!(transport.calls, 0);

    let missing_auth_result =
        execute_live_source_lookup(Some(&mut transport), None, None, &request(), policy);
    assert_eq!(
        missing_auth_result,
        Err(DreggLiveSourceClientError::MissingAuthMaterial)
    );
    assert_eq!(transport.calls, 0);

    let missing_trust_result =
        execute_live_source_lookup(Some(&mut transport), Some(&auth), None, &request(), policy);
    assert_eq!(
        missing_trust_result,
        Err(DreggLiveSourceClientError::MissingSourceTrust)
    );
    assert_eq!(transport.calls, 0);
}

#[test]
fn live_source_lookup_retries_transport_timeouts_then_validates_response() {
    let policy = DreggLiveSourceLookupPolicy {
        timeout: Duration::from_millis(250),
        retry_max: 2,
        stale_max_seconds: 300,
    };
    let auth = auth_material("lookup-timeout-success");
    let mut transport = FixtureTransport::new(vec![
        Err(DreggLiveSourceTransportError::Timeout),
        Err(DreggLiveSourceTransportError::Timeout),
        Ok(signed_response()),
    ]);

    let decision = execute_live_source_lookup(
        Some(&mut transport),
        Some(&auth),
        Some(&source_trusted_key()),
        &request(),
        policy,
    )
    .expect("lookup should retry transport timeouts then validate the successful response");

    assert_eq!(decision.source_id, "dregg-source:operator");
    assert_eq!(transport.calls, 3);
    assert_eq!(transport.observed_timeout, Some(Duration::from_millis(250)));
    assert_eq!(
        transport.observed_auth_summary.as_deref(),
        Some("auth_token:<redacted>")
    );
}

#[test]
fn live_source_lookup_returns_transport_timeout_after_bounded_retry_exhaustion() {
    let policy = DreggLiveSourceLookupPolicy {
        timeout: Duration::from_millis(250),
        retry_max: 2,
        stale_max_seconds: 300,
    };
    let auth = auth_material("lookup-timeout-exhausted");
    let mut transport = FixtureTransport::new(vec![
        Err(DreggLiveSourceTransportError::Timeout),
        Err(DreggLiveSourceTransportError::Timeout),
        Err(DreggLiveSourceTransportError::Timeout),
    ]);

    let result = execute_live_source_lookup(
        Some(&mut transport),
        Some(&auth),
        Some(&source_trusted_key()),
        &request(),
        policy,
    );

    assert_eq!(result, Err(DreggLiveSourceClientError::TransportTimeout));
    assert_eq!(transport.calls, 3);
}

#[test]
fn live_source_lookup_does_not_retry_source_unavailable_transport_failure() {
    let policy = DreggLiveSourceLookupPolicy {
        timeout: Duration::from_millis(250),
        retry_max: 2,
        stale_max_seconds: 300,
    };
    let auth = auth_material("lookup-source-unavailable");
    let mut transport = FixtureTransport::new(vec![
        Err(DreggLiveSourceTransportError::SourceUnavailable),
        Ok(response()),
    ]);

    let result = execute_live_source_lookup(
        Some(&mut transport),
        Some(&auth),
        Some(&source_trusted_key()),
        &request(),
        policy,
    );

    assert_eq!(result, Err(DreggLiveSourceClientError::SourceUnavailable));
    assert_eq!(transport.calls, 1);
}

#[test]
fn live_source_lookup_does_not_retry_semantic_rejects() {
    let policy = DreggLiveSourceLookupPolicy {
        timeout: Duration::from_millis(250),
        retry_max: 2,
        stale_max_seconds: 300,
    };
    let auth = auth_material("lookup-semantic-reject");
    let mut malformed = response();
    malformed.source_id = "".to_string();
    let mut transport = FixtureTransport::new(vec![Ok(malformed), Ok(response())]);

    let result = execute_live_source_lookup(
        Some(&mut transport),
        Some(&auth),
        Some(&source_trusted_key()),
        &request(),
        policy,
    );

    assert_eq!(result, Err(DreggLiveSourceClientError::MalformedResponse));
    assert_eq!(transport.calls, 1);
}
