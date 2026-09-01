use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::Deserialize;
use server::devgraph_authority::{
    actor_id_for_public_key, encode_base64url, idempotency_key_digest_sha256,
    issue_devgraph_issue_create_authority_v1 as issue_devgraph_issue_create_authority_v1_with_registry,
    DevgraphAuthorityError, DevgraphAuthorityExpectationsV1, DevgraphAuthorityProjectionV1,
    DevgraphIssueCreateAuthorityInputV1, DevgraphIssueCreatePolicyRuleV1,
    DevgraphIssueCreatePolicyV1, DevgraphIssueCreateRequestV1,
    DevgraphIssueCreateWalletPresentationV1, DevgraphPolicyEffectV1, DevgraphPolicyStatusV1,
    DevgraphResourceMatchV1, DEVGRAPH_AUTHORITY_PROJECTION_MAX_JSON_BYTES_V1,
    DEVGRAPH_AUTHORITY_REPLAY_SCOPE_V1, DEVGRAPH_AUTHORITY_SCHEMA_V1,
    DEVGRAPH_AUTHORITY_SIGNATURE_SUITE_V1, DEVGRAPH_ISSUE_CREATE_MAX_REQUEST_JSON_BYTES_V1,
    DEVGRAPH_ISSUE_CREATE_OPERATION_V1, DEVGRAPH_ISSUE_CREATE_POLICY_MAX_JSON_BYTES_V1,
    DEVGRAPH_ISSUE_CREATE_POLICY_SCHEMA_V1, DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1,
    DEVGRAPH_WALLET_PRESENTATION_MAX_JSON_BYTES_V1, DEVGRAPH_WALLET_PRESENTATION_SCHEMA_V1,
};
use server::identity::{
    explicit_test_fixture_identity, load_node_verifier_identity, NodeVerifierIdentity,
    PublicVerifierKey, PublicVerifierKeyRegistry, VerificationKeyStatus, VerifierIdentityConfig,
};
use server::ledger::Ledger;
use server::runtime_mode::RuntimeMode;
use server::schema::{DEVGRAPH_AUTHORITY_REPLAY_RESERVATIONS_TABLE, LEDGER_TABLES};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::Row;
use std::collections::BTreeSet;
use std::fs;
use tempfile::TempDir;

const REQUEST_JSON: &[u8] = include_bytes!("fixtures/devgraph_issue_create_v1/request.json");
const CANONICAL_REQUEST_JSON: &[u8] =
    include_bytes!("fixtures/devgraph_issue_create_v1/canonical-request.json");
const GOLDEN_WALLET_PRESENTATION_JSON: &[u8] =
    include_bytes!("fixtures/devgraph_issue_create_v1/wallet-presentation.json");
const GOLDEN_UNSIGNED_PROJECTION_JSON: &[u8] =
    include_bytes!("fixtures/devgraph_issue_create_v1/unsigned-projection.json");
const GOLDEN_SIGNED_PROJECTION_JSON: &[u8] =
    include_bytes!("fixtures/devgraph_issue_create_v1/signed-projection.json");
const GOLDEN_CORRELATION_DIGEST: &[u8] =
    include_bytes!("fixtures/devgraph_issue_create_v1/correlation-digest.txt");
const NONDEFAULT_REQUEST_JSON: &[u8] =
    include_bytes!("fixtures/devgraph_issue_create_v1/request-nondefault.json");
const NONDEFAULT_CANONICAL_REQUEST_JSON: &[u8] =
    include_bytes!("fixtures/devgraph_issue_create_v1/canonical-request-nondefault.json");
const NONDEFAULT_REQUEST_DIGEST: &[u8] =
    include_bytes!("fixtures/devgraph_issue_create_v1/request-nondefault-digest.txt");
const AUDIENCE: &str = "devgraph://receiver-local";
const IDEMPOTENCY_KEY: &str = "dg-issue-create-golden-0001";
const ISSUED_AT: u64 = 1_800_000_000;
const EXPIRES_AT: u64 = ISSUED_AT + 60;
const SESSION_ID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const NONCE: [u8; 12] = [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27];
const WALLET_SECRET: [u8; 32] = [7; 32];
const SECS_SECRET: [u8; 32] = [11; 32];

fn canonical_json_line(value: &str) -> Vec<u8> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(b'\n');
    bytes
}

fn digest_line(value: &str) -> Vec<u8> {
    canonical_json_line(value)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureManifest {
    schema: String,
    schema_version: u64,
    operation: String,
    expected_now: u64,
    json_transport_contract: String,
    idempotency_key: FixtureIdempotencyKey,
    receiver_policy: FixtureReceiverPolicy,
    secs_public_key_registry_path: String,
    files: Vec<FixtureDigest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureIdempotencyKey {
    path: String,
    encoding: String,
    non_secret: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureReceiverPolicy {
    path: String,
    binding_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureDigest {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureKeyRegistry {
    keys: Vec<FixturePublicKey>,
    schema: String,
    schema_version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixturePublicKey {
    algorithm: String,
    key_id: String,
    production_authority: bool,
    public_key_base64url: String,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixturePolicyBinding {
    policy_digest_sha256: String,
    policy_id: String,
    policy_version: u64,
}

async fn memory_ledger() -> Ledger {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let ledger = Ledger::new(pool);
    ledger.init_schema().await.unwrap();
    ledger
}

async fn file_ledger(path: &std::path::Path, create: bool) -> Ledger {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(create);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    Ledger::new(pool)
}

fn production_identity() -> (TempDir, NodeVerifierIdentity) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secs-verifier.key");
    let encoded: String = SECS_SECRET
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    fs::write(&path, encoded).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let identity = load_node_verifier_identity(&VerifierIdentityConfig {
        runtime_mode: RuntimeMode::ProductionVerified,
        verifier_key_path: Some(path),
        verifier_key_id: Some("secs-devgraph-authority-v1".to_string()),
    })
    .unwrap();
    (directory, identity)
}

async fn issue_devgraph_issue_create_authority_v1(
    ledger: &Ledger,
    verifier_identity: &NodeVerifierIdentity,
    receiver_policy: &DevgraphIssueCreatePolicyV1,
    request_json: &[u8],
    idempotency_key: &str,
    wallet_presentation_json: &[u8],
    now: u64,
) -> Result<server::devgraph_authority::DevgraphAuthorityIssueOutcomeV1, DevgraphAuthorityError> {
    let registry = PublicVerifierKeyRegistry::from_keys([verifier_identity.public_verifier_key()]);
    issue_devgraph_issue_create_authority_v1_with_registry(
        ledger,
        verifier_identity,
        &registry,
        receiver_policy,
        DevgraphIssueCreateAuthorityInputV1 {
            request_json,
            idempotency_key,
            wallet_presentation_json,
            now,
        },
    )
    .await
}

fn request() -> DevgraphIssueCreateRequestV1 {
    DevgraphIssueCreateRequestV1::from_json(REQUEST_JSON).unwrap()
}

fn wallet_presentation(
    request: &DevgraphIssueCreateRequestV1,
    idempotency_key: &str,
    session_id: [u8; 16],
    nonce: [u8; 12],
    issued_at: u64,
    expires_at: u64,
) -> DevgraphIssueCreateWalletPresentationV1 {
    let signing_key = SigningKey::from_bytes(&WALLET_SECRET);
    let public_key = VerifyingKey::from(&signing_key).to_bytes();
    let mut presentation = DevgraphIssueCreateWalletPresentationV1 {
        actor_public_key: encode_base64url(&public_key),
        actor_signature_suite: DEVGRAPH_AUTHORITY_SIGNATURE_SUITE_V1.to_string(),
        audience: AUDIENCE.to_string(),
        expires_at,
        idempotency_key_digest_sha256: idempotency_key_digest_sha256(idempotency_key).unwrap(),
        issued_at,
        nonce: encode_base64url(&nonce),
        operation: DEVGRAPH_ISSUE_CREATE_OPERATION_V1.to_string(),
        request_digest_sha256: request.request_digest_sha256().unwrap(),
        resource: request.resource(),
        schema: DEVGRAPH_WALLET_PRESENTATION_SCHEMA_V1.to_string(),
        schema_version: 1,
        session_id: encode_base64url(&session_id),
        signature: String::new(),
    };
    presentation.signature = encode_base64url(
        &signing_key
            .sign(&presentation.signature_preimage().unwrap())
            .to_bytes(),
    );
    presentation
}

fn resign_wallet_presentation(
    mut presentation: DevgraphIssueCreateWalletPresentationV1,
) -> DevgraphIssueCreateWalletPresentationV1 {
    let signing_key = SigningKey::from_bytes(&WALLET_SECRET);
    presentation.signature.clear();
    presentation.signature = encode_base64url(
        &signing_key
            .sign(&presentation.signature_preimage().unwrap())
            .to_bytes(),
    );
    presentation
}

fn policy(
    request: &DevgraphIssueCreateRequestV1,
    effects: &[DevgraphPolicyEffectV1],
) -> DevgraphIssueCreatePolicyV1 {
    let public_key = VerifyingKey::from(&SigningKey::from_bytes(&WALLET_SECRET)).to_bytes();
    let actor_id = actor_id_for_public_key(&public_key);
    DevgraphIssueCreatePolicyV1 {
        audience: AUDIENCE.to_string(),
        operation: DEVGRAPH_ISSUE_CREATE_OPERATION_V1.to_string(),
        policy_id: "receiver-local-policy".to_string(),
        policy_version: 3,
        rules: effects
            .iter()
            .map(|effect| DevgraphIssueCreatePolicyRuleV1 {
                actor_id: actor_id.clone(),
                effect: *effect,
                not_after: EXPIRES_AT + 600,
                not_before: ISSUED_AT - 600,
                resource: request.resource(),
                resource_match: DevgraphResourceMatchV1::Exact,
                status: DevgraphPolicyStatusV1::Active,
            })
            .collect(),
        schema: DEVGRAPH_ISSUE_CREATE_POLICY_SCHEMA_V1.to_string(),
    }
}

fn expectations(
    projection: &DevgraphAuthorityProjectionV1,
    policy: &DevgraphIssueCreatePolicyV1,
    presentation: &DevgraphIssueCreateWalletPresentationV1,
    session_id: [u8; 16],
    nonce: [u8; 12],
) -> DevgraphAuthorityExpectationsV1 {
    DevgraphAuthorityExpectationsV1 {
        actor_id: projection.actor_id.clone(),
        audience: projection.audience.clone(),
        resource: projection.resource.clone(),
        request_digest_sha256: projection.request_digest_sha256.clone(),
        idempotency_key_digest_sha256: projection.idempotency_key_digest_sha256.clone(),
        session_id,
        nonce,
        issued_at: projection.issued_at,
        expires_at: projection.expires_at,
        policy: policy.binding().unwrap(),
        wallet_presentation_digest_sha256: presentation.presentation_digest_sha256().unwrap(),
    }
}

#[tokio::test]
async fn producer_emits_golden_portable_projection_and_exact_retry() {
    let ledger = memory_ledger().await;
    let (_directory, identity) = production_identity();
    let request = request();
    assert_eq!(
        canonical_json_line(&request.canonical_json().unwrap()),
        CANONICAL_REQUEST_JSON
    );
    let presentation = wallet_presentation(
        &request,
        IDEMPOTENCY_KEY,
        SESSION_ID,
        NONCE,
        ISSUED_AT,
        EXPIRES_AT,
    );
    let policy = policy(&request, &[DevgraphPolicyEffectV1::Allow]);
    let presentation_json = serde_json::to_vec(&presentation).unwrap();

    let fresh = issue_devgraph_issue_create_authority_v1(
        &ledger,
        &identity,
        &policy,
        REQUEST_JSON,
        IDEMPOTENCY_KEY,
        &presentation_json,
        ISSUED_AT,
    )
    .await
    .unwrap();
    assert!(!fresh.is_exact_retry());
    let projection = fresh.projection();
    assert_eq!(
        canonical_json_line(&presentation.canonical_json().unwrap()),
        GOLDEN_WALLET_PRESENTATION_JSON
    );
    assert_eq!(
        canonical_json_line(&projection.canonical_unsigned_json().unwrap()),
        GOLDEN_UNSIGNED_PROJECTION_JSON
    );
    assert_eq!(
        canonical_json_line(&projection.canonical_json().unwrap()),
        GOLDEN_SIGNED_PROJECTION_JSON
    );
    assert_eq!(
        digest_line(&projection.correlation_digest_sha256().unwrap()),
        GOLDEN_CORRELATION_DIGEST
    );
    assert_eq!(projection.schema, DEVGRAPH_AUTHORITY_SCHEMA_V1);
    assert_eq!(projection.operation, DEVGRAPH_ISSUE_CREATE_OPERATION_V1);
    assert_eq!(projection.replay_scope, DEVGRAPH_AUTHORITY_REPLAY_SCOPE_V1);
    assert_eq!(projection.resource, "Issue/issue-golden");

    let expected = expectations(projection, &policy, &presentation, SESSION_ID, NONCE);
    let registry = PublicVerifierKeyRegistry::from_keys([identity.public_verifier_key()]);
    let digest = projection
        .verify_with_registry(&registry, &expected, ISSUED_AT)
        .unwrap();
    assert_eq!(digest.len(), 64);

    let retry = issue_devgraph_issue_create_authority_v1(
        &ledger,
        &identity,
        &policy,
        REQUEST_JSON,
        IDEMPOTENCY_KEY,
        &presentation_json,
        ISSUED_AT + 1,
    )
    .await
    .unwrap();
    assert!(retry.is_exact_retry());
    assert_eq!(retry.projection(), projection);
}

#[tokio::test]
async fn cross_language_fixture_bundle_is_versioned_complete_and_byte_exact() {
    let fixture_directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/devgraph_issue_create_v1");
    let manifest: FixtureManifest =
        serde_json::from_slice(&fs::read(fixture_directory.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(
        manifest.schema,
        "secs-devgraph-issue-create-fixture-bundle.v1"
    );
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.operation, DEVGRAPH_ISSUE_CREATE_OPERATION_V1);
    assert_eq!(manifest.expected_now, ISSUED_AT);
    assert!(manifest.json_transport_contract.contains("recanonicalized"));
    assert!(manifest
        .json_transport_contract
        .contains("without trimming"));
    assert!(manifest
        .json_transport_contract
        .contains("without normalization"));
    assert!(manifest.json_transport_contract.contains("array order"));
    assert_eq!(manifest.idempotency_key.path, "idempotency-key.txt");
    assert_eq!(manifest.idempotency_key.encoding, "utf8-single-line-lf");
    assert!(manifest.idempotency_key.non_secret);
    assert_eq!(manifest.receiver_policy.path, "receiver-policy.json");
    assert_eq!(
        manifest.receiver_policy.binding_path,
        "receiver-policy-binding.json"
    );
    assert_eq!(
        manifest.secs_public_key_registry_path,
        "secs-public-key-registry.json"
    );

    let declared: BTreeSet<_> = manifest
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    let present: BTreeSet<_> = fs::read_dir(&fixture_directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != "manifest.json")
        .collect();
    assert_eq!(
        declared,
        present.iter().map(String::as_str).collect::<BTreeSet<_>>()
    );
    for file in &manifest.files {
        let bytes = fs::read(fixture_directory.join(&file.path)).unwrap();
        assert_eq!(sha256_hex(&bytes), file.sha256, "{}", file.path);
    }

    assert_eq!(
        fs::read(fixture_directory.join(&manifest.idempotency_key.path)).unwrap(),
        format!("{IDEMPOTENCY_KEY}\n").as_bytes()
    );
    let receiver_policy_bytes =
        fs::read(fixture_directory.join(&manifest.receiver_policy.path)).unwrap();
    let receiver_policy = DevgraphIssueCreatePolicyV1::from_json(&receiver_policy_bytes).unwrap();
    assert_eq!(
        canonical_json_line(&receiver_policy.canonical_json().unwrap()),
        receiver_policy_bytes
    );
    let fixture_binding: FixturePolicyBinding = serde_json::from_slice(
        &fs::read(fixture_directory.join(&manifest.receiver_policy.binding_path)).unwrap(),
    )
    .unwrap();
    let actual_binding = receiver_policy.binding().unwrap();
    assert_eq!(fixture_binding.policy_id, actual_binding.policy_id);
    assert_eq!(
        fixture_binding.policy_version,
        actual_binding.policy_version
    );
    assert_eq!(
        fixture_binding.policy_digest_sha256,
        actual_binding.policy_digest_sha256
    );

    let key_registry: FixtureKeyRegistry = serde_json::from_slice(
        &fs::read(fixture_directory.join(&manifest.secs_public_key_registry_path)).unwrap(),
    )
    .unwrap();
    assert_eq!(key_registry.schema, "secs-public-verifier-key-registry.v1");
    assert_eq!(key_registry.schema_version, 1);
    assert_eq!(key_registry.keys.len(), 1);
    let fixture_key = &key_registry.keys[0];
    let (_directory, identity) = production_identity();
    assert_eq!(fixture_key.algorithm, "ed25519");
    assert_eq!(fixture_key.key_id, identity.signer_key_id());
    assert!(fixture_key.production_authority);
    assert_eq!(fixture_key.status, "active");
    assert_eq!(
        fixture_key.public_key_base64url,
        encode_base64url(identity.public_key().as_bytes())
    );
    let fixture_registry =
        PublicVerifierKeyRegistry::from_keys([PublicVerifierKey::configured_production_authority(
            fixture_key.key_id.clone(),
            fixture_key.algorithm.clone(),
            *identity.public_key(),
        )]);
    let fixture_wallet = fs::read(fixture_directory.join("wallet-presentation.json")).unwrap();
    assert!(issue_devgraph_issue_create_authority_v1_with_registry(
        &memory_ledger().await,
        &identity,
        &fixture_registry,
        &receiver_policy,
        DevgraphIssueCreateAuthorityInputV1 {
            request_json: REQUEST_JSON,
            idempotency_key: IDEMPOTENCY_KEY,
            wallet_presentation_json: &fixture_wallet,
            now: manifest.expected_now,
        },
    )
    .await
    .is_ok());

    let nondefault = DevgraphIssueCreateRequestV1::from_json(NONDEFAULT_REQUEST_JSON).unwrap();
    assert_eq!(
        canonical_json_line(&nondefault.canonical_json().unwrap()),
        NONDEFAULT_CANONICAL_REQUEST_JSON
    );
    assert_eq!(
        digest_line(&nondefault.request_digest_sha256().unwrap()),
        NONDEFAULT_REQUEST_DIGEST
    );
    assert_eq!(nondefault.priority, -7);
    assert_eq!(nondefault.artifact_ids, ["artifact-z", "artifact-a"]);
    assert_eq!(nondefault.external_link_ids, ["external-2", "external-1"]);

    let decomposed = String::from_utf8(
        NONDEFAULT_REQUEST_JSON
            .windows("Café".len())
            .position(|window| window == "Café".as_bytes())
            .map(|index| {
                let mut bytes = NONDEFAULT_REQUEST_JSON.to_vec();
                bytes.splice(index..index + "Café".len(), "Cafe\u{301}".bytes());
                bytes
            })
            .unwrap(),
    )
    .unwrap();
    let decomposed = DevgraphIssueCreateRequestV1::from_json(decomposed.as_bytes()).unwrap();
    assert!(decomposed.canonical_json().unwrap().contains("Cafe\u{301}"));
    assert_ne!(
        decomposed.request_digest_sha256().unwrap(),
        nondefault.request_digest_sha256().unwrap()
    );
}

#[tokio::test]
async fn strict_json_base64_and_expiry_boundaries_fail_closed() {
    let request = request();
    let duplicate_request = br#"{"artifact_ids":[],"description":"","external_link_ids":[],"id":"issue-golden","id":"issue-other","kind":"Issue","priority":0,"title":"Golden issue"}"#;
    assert_eq!(
        DevgraphIssueCreateRequestV1::from_json(duplicate_request),
        Err(DevgraphAuthorityError::MalformedRequest)
    );
    let trailing = [REQUEST_JSON, b" trailing"].concat();
    assert_eq!(
        DevgraphIssueCreateRequestV1::from_json(&trailing),
        Err(DevgraphAuthorityError::MalformedRequest)
    );

    let ledger = memory_ledger().await;
    let (_directory, identity) = production_identity();
    let policy = policy(&request, &[DevgraphPolicyEffectV1::Allow]);
    let presentation = wallet_presentation(
        &request,
        IDEMPOTENCY_KEY,
        [0; 16],
        NONCE,
        ISSUED_AT,
        EXPIRES_AT,
    );
    let zero_session = serde_json::to_vec(&presentation).unwrap();
    assert!(issue_devgraph_issue_create_authority_v1(
        &ledger,
        &identity,
        &policy,
        REQUEST_JSON,
        IDEMPOTENCY_KEY,
        &zero_session,
        ISSUED_AT,
    )
    .await
    .is_ok());

    let duplicate_presentation = serde_json::to_string(&presentation).unwrap().replacen(
        '{',
        &format!("{{\"audience\":\"{AUDIENCE}\","),
        1,
    );
    assert_eq!(
        issue_devgraph_issue_create_authority_v1(
            &memory_ledger().await,
            &identity,
            &policy,
            REQUEST_JSON,
            IDEMPOTENCY_KEY,
            duplicate_presentation.as_bytes(),
            ISSUED_AT,
        )
        .await,
        Err(DevgraphAuthorityError::MalformedWalletPresentation)
    );

    let mut padded = presentation.clone();
    padded.session_id.push('=');
    assert_eq!(
        issue_devgraph_issue_create_authority_v1(
            &memory_ledger().await,
            &identity,
            &policy,
            REQUEST_JSON,
            IDEMPOTENCY_KEY,
            &serde_json::to_vec(&padded).unwrap(),
            ISSUED_AT,
        )
        .await,
        Err(DevgraphAuthorityError::InvalidSession)
    );

    assert_eq!(
        issue_devgraph_issue_create_authority_v1(
            &memory_ledger().await,
            &identity,
            &policy,
            REQUEST_JSON,
            IDEMPOTENCY_KEY,
            &serde_json::to_vec(&presentation).unwrap(),
            EXPIRES_AT,
        )
        .await,
        Err(DevgraphAuthorityError::Expired)
    );
}

#[tokio::test]
async fn bounded_decoding_safe_integers_and_strict_signatures_fail_closed() {
    assert_eq!(
        DevgraphIssueCreateRequestV1::from_json(&vec![
            b' ';
            DEVGRAPH_ISSUE_CREATE_MAX_REQUEST_JSON_BYTES_V1
                + 1
        ]),
        Err(DevgraphAuthorityError::RequestTooLarge)
    );
    let oversized_wallet = format!(
        "{{\"signature\":\"{}\"}}",
        "x".repeat(DEVGRAPH_WALLET_PRESENTATION_MAX_JSON_BYTES_V1)
    );
    assert_eq!(
        DevgraphIssueCreateWalletPresentationV1::from_json(oversized_wallet.as_bytes()),
        Err(DevgraphAuthorityError::WalletPresentationTooLarge)
    );
    let oversized_policy = format!(
        "{{\"policy_id\":\"{}\"}}",
        "x".repeat(DEVGRAPH_ISSUE_CREATE_POLICY_MAX_JSON_BYTES_V1)
    );
    assert_eq!(
        DevgraphIssueCreatePolicyV1::from_json(oversized_policy.as_bytes()),
        Err(DevgraphAuthorityError::ReceiverPolicyTooLarge)
    );
    assert_eq!(
        DevgraphAuthorityProjectionV1::from_json(&vec![
            b' ';
            DEVGRAPH_AUTHORITY_PROJECTION_MAX_JSON_BYTES_V1
                + 1
        ]),
        Err(DevgraphAuthorityError::ProjectionTooLarge)
    );

    for priority in [
        -(DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1 as i64),
        DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1 as i64,
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(REQUEST_JSON).unwrap();
        value["priority"] = priority.into();
        assert_eq!(
            DevgraphIssueCreateRequestV1::from_json(&serde_json::to_vec(&value).unwrap())
                .unwrap()
                .priority,
            priority
        );
    }
    for priority in [
        -(DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1 as i64) - 1,
        DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1 as i64 + 1,
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(REQUEST_JSON).unwrap();
        value["priority"] = priority.into();
        assert_eq!(
            DevgraphIssueCreateRequestV1::from_json(&serde_json::to_vec(&value).unwrap()),
            Err(DevgraphAuthorityError::InvalidRequest)
        );
    }

    let request = request();
    let (_directory, identity) = production_identity();
    let receiver_policy = policy(&request, &[DevgraphPolicyEffectV1::Allow]);
    let base = wallet_presentation(
        &request,
        IDEMPOTENCY_KEY,
        SESSION_ID,
        NONCE,
        ISSUED_AT,
        EXPIRES_AT,
    );
    let mut overlong_session = base.clone();
    overlong_session.session_id = "A".repeat(4_096);
    assert_eq!(
        issue_devgraph_issue_create_authority_v1(
            &memory_ledger().await,
            &identity,
            &receiver_policy,
            REQUEST_JSON,
            IDEMPOTENCY_KEY,
            &serde_json::to_vec(&overlong_session).unwrap(),
            ISSUED_AT,
        )
        .await,
        Err(DevgraphAuthorityError::InvalidSession)
    );
    let mut weak_key = base.clone();
    let mut identity_encoding = [0_u8; 32];
    identity_encoding[0] = 1;
    weak_key.actor_public_key = encode_base64url(&identity_encoding);
    weak_key.signature = encode_base64url(&[0_u8; 64]);
    assert_eq!(
        issue_devgraph_issue_create_authority_v1(
            &memory_ledger().await,
            &identity,
            &receiver_policy,
            REQUEST_JSON,
            IDEMPOTENCY_KEY,
            &serde_json::to_vec(&weak_key).unwrap(),
            ISSUED_AT,
        )
        .await,
        Err(DevgraphAuthorityError::InvalidWalletSignature)
    );

    let mut safe_wallet = base.clone();
    safe_wallet.issued_at = DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1 - 60;
    safe_wallet.expires_at = DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1;
    assert!(safe_wallet.canonical_json().is_ok());
    safe_wallet.expires_at = DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1 + 1;
    assert_eq!(
        safe_wallet.canonical_json(),
        Err(DevgraphAuthorityError::InvalidWalletPresentation)
    );
    let mut safe_policy = receiver_policy.clone();
    safe_policy.policy_version = DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1;
    safe_policy.rules[0].not_before = DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1 - 100;
    safe_policy.rules[0].not_after = DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1;
    assert!(safe_policy.binding().is_ok());
    safe_policy.policy_version = DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1 + 1;
    assert_eq!(
        safe_policy.binding(),
        Err(DevgraphAuthorityError::InvalidReceiverPolicy)
    );
}

#[tokio::test]
async fn deny_wins_and_invalid_wallet_signature_never_reserve_replay() {
    let request = request();
    let ledger = memory_ledger().await;
    let (_directory, identity) = production_identity();
    let presentation = wallet_presentation(
        &request,
        IDEMPOTENCY_KEY,
        SESSION_ID,
        NONCE,
        ISSUED_AT,
        EXPIRES_AT,
    );
    let deny_policy = policy(
        &request,
        &[DevgraphPolicyEffectV1::Allow, DevgraphPolicyEffectV1::Deny],
    );
    assert_eq!(
        issue_devgraph_issue_create_authority_v1(
            &ledger,
            &identity,
            &deny_policy,
            REQUEST_JSON,
            IDEMPOTENCY_KEY,
            &serde_json::to_vec(&presentation).unwrap(),
            ISSUED_AT,
        )
        .await,
        Err(DevgraphAuthorityError::ReceiverPolicyDenied)
    );

    let mut invalid_signature = presentation;
    invalid_signature.signature.replace_range(0..1, "A");
    assert_eq!(
        issue_devgraph_issue_create_authority_v1(
            &ledger,
            &identity,
            &policy(&request, &[DevgraphPolicyEffectV1::Allow]),
            REQUEST_JSON,
            IDEMPOTENCY_KEY,
            &serde_json::to_vec(&invalid_signature).unwrap(),
            ISSUED_AT,
        )
        .await,
        Err(DevgraphAuthorityError::InvalidWalletSignature)
    );
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM devgraph_authority_replay_reservations")
            .fetch_one(ledger.pool())
            .await
            .unwrap();
    assert_eq!(count.0, 0);
}

#[tokio::test]
async fn wallet_request_and_receiver_policy_denial_matrix_is_exact() {
    let request = request();
    let (_directory, identity) = production_identity();
    let allow = policy(&request, &[DevgraphPolicyEffectV1::Allow]);
    let base = wallet_presentation(
        &request,
        IDEMPOTENCY_KEY,
        SESSION_ID,
        NONCE,
        ISSUED_AT,
        EXPIRES_AT,
    );

    let presentation_cases = vec![
        (
            "wrong schema",
            {
                let mut value = base.clone();
                value.schema = "other.wallet.v1".to_string();
                value
            },
            DevgraphAuthorityError::InvalidWalletPresentation,
        ),
        (
            "wrong schema version",
            {
                let mut value = base.clone();
                value.schema_version = 2;
                value
            },
            DevgraphAuthorityError::InvalidWalletPresentation,
        ),
        (
            "wrong suite",
            {
                let mut value = base.clone();
                value.actor_signature_suite = "ML-DSA-65".to_string();
                value
            },
            DevgraphAuthorityError::UnsupportedSignatureSuite,
        ),
        (
            "wrong audience",
            {
                let mut value = base.clone();
                value.audience = "devgraph://other".to_string();
                value
            },
            DevgraphAuthorityError::WrongAudience,
        ),
        (
            "wrong operation",
            {
                let mut value = base.clone();
                value.operation = "devgraph.issue.update.v1".to_string();
                value
            },
            DevgraphAuthorityError::WrongOperation,
        ),
        (
            "wrong resource",
            {
                let mut value = base.clone();
                value.resource = "Issue/issue-other".to_string();
                value
            },
            DevgraphAuthorityError::WrongResource,
        ),
        (
            "wrong request digest",
            {
                let mut value = base.clone();
                value.request_digest_sha256 = "0".repeat(64);
                value
            },
            DevgraphAuthorityError::WrongRequestDigest,
        ),
        (
            "wrong idempotency digest",
            {
                let mut value = base.clone();
                value.idempotency_key_digest_sha256 = "0".repeat(64);
                value
            },
            DevgraphAuthorityError::WrongIdempotencyDigest,
        ),
        (
            "wrong actor public key",
            {
                let mut value = base.clone();
                let other = VerifyingKey::from(&SigningKey::from_bytes(&[8; 32])).to_bytes();
                value.actor_public_key = encode_base64url(&other);
                value
            },
            DevgraphAuthorityError::InvalidWalletSignature,
        ),
        (
            "short session",
            {
                let mut value = base.clone();
                value.session_id = encode_base64url(&[1; 15]);
                value
            },
            DevgraphAuthorityError::InvalidSession,
        ),
        (
            "short nonce",
            {
                let mut value = base.clone();
                value.nonce = encode_base64url(&[1; 11]);
                value
            },
            DevgraphAuthorityError::InvalidWalletPresentation,
        ),
        (
            "future issued",
            resign_wallet_presentation({
                let mut value = base.clone();
                value.issued_at = ISSUED_AT + 1;
                value.expires_at = EXPIRES_AT + 1;
                value
            }),
            DevgraphAuthorityError::NotYetValid,
        ),
        (
            "inverted validity",
            resign_wallet_presentation({
                let mut value = base.clone();
                value.expires_at = value.issued_at;
                value
            }),
            DevgraphAuthorityError::InvalidValidityWindow,
        ),
        (
            "overlong validity",
            resign_wallet_presentation({
                let mut value = base.clone();
                value.expires_at = value.issued_at + 61;
                value
            }),
            DevgraphAuthorityError::InvalidValidityWindow,
        ),
    ];
    for (name, presentation, expected) in presentation_cases {
        let actual = issue_devgraph_issue_create_authority_v1(
            &memory_ledger().await,
            &identity,
            &allow,
            REQUEST_JSON,
            IDEMPOTENCY_KEY,
            &serde_json::to_vec(&presentation).unwrap(),
            ISSUED_AT,
        )
        .await;
        assert_eq!(actual, Err(expected), "{name}");
    }

    let unknown_presentation =
        base.canonical_json()
            .unwrap()
            .replacen('{', "{\"unknown\":true,", 1);
    assert_eq!(
        issue_devgraph_issue_create_authority_v1(
            &memory_ledger().await,
            &identity,
            &allow,
            REQUEST_JSON,
            IDEMPOTENCY_KEY,
            unknown_presentation.as_bytes(),
            ISSUED_AT,
        )
        .await,
        Err(DevgraphAuthorityError::MalformedWalletPresentation)
    );

    for (name, raw, expected) in [
        (
            "wrong kind",
            br#"{"id":"issue-golden","kind":"Task","title":"Golden issue"}"#.as_slice(),
            DevgraphAuthorityError::InvalidRequest,
        ),
        (
            "unknown request field",
            br#"{"id":"issue-golden","kind":"Issue","title":"Golden issue","route":"/arbitrary"}"#.as_slice(),
            DevgraphAuthorityError::MalformedRequest,
        ),
        (
            "invalid priority",
            br#"{"id":"issue-golden","kind":"Issue","title":"Golden issue","priority":1.5}"#.as_slice(),
            DevgraphAuthorityError::MalformedRequest,
        ),
        (
            "exponent priority",
            br#"{"id":"issue-golden","kind":"Issue","title":"Golden issue","priority":1e0}"#.as_slice(),
            DevgraphAuthorityError::MalformedRequest,
        ),
        (
            "quoted priority",
            br#"{"id":"issue-golden","kind":"Issue","title":"Golden issue","priority":"1"}"#.as_slice(),
            DevgraphAuthorityError::MalformedRequest,
        ),
        (
            "empty title",
            br#"{"id":"issue-golden","kind":"Issue","title":""}"#.as_slice(),
            DevgraphAuthorityError::EmptyTitle,
        ),
        (
            "invalid id",
            br#"{"id":"Issue_Golden","kind":"Issue","title":"Golden issue"}"#.as_slice(),
            DevgraphAuthorityError::InvalidIdentifier,
        ),
        (
            "invalid reference",
            br#"{"artifact_ids":["Invalid"],"id":"issue-golden","kind":"Issue","title":"Golden issue"}"#.as_slice(),
            DevgraphAuthorityError::InvalidIdentifier,
        ),
    ] {
        assert_eq!(
            issue_devgraph_issue_create_authority_v1(
                &memory_ledger().await,
                &identity,
                &allow,
                raw,
                IDEMPOTENCY_KEY,
                &serde_json::to_vec(&base).unwrap(),
                ISSUED_AT,
            )
            .await,
            Err(expected),
            "{name}"
        );
    }

    let mut oversized = request.clone();
    oversized.description = "x".repeat(70_000);
    assert_eq!(
        DevgraphIssueCreateRequestV1::from_json(&serde_json::to_vec(&oversized).unwrap()),
        Err(DevgraphAuthorityError::RequestTooLarge)
    );
    assert_eq!(
        idempotency_key_digest_sha256("too-short"),
        Err(DevgraphAuthorityError::InvalidIdempotencyKey)
    );
    assert_eq!(
        idempotency_key_digest_sha256("invalid/key/characters"),
        Err(DevgraphAuthorityError::InvalidIdempotencyKey)
    );

    let mut revoked = allow.clone();
    revoked.rules[0].status = DevgraphPolicyStatusV1::Revoked;
    let mut outside_window = allow.clone();
    outside_window.rules[0].not_before = ISSUED_AT + 1;
    let mut no_actor_match = allow.clone();
    no_actor_match.rules[0].actor_id = format!("pubkey:sha256:{}", "0".repeat(64));
    let mut bad_id = allow.clone();
    bad_id.policy_id = "unsafe policy id".to_string();
    let mut zero_version = allow.clone();
    zero_version.policy_version = 0;
    let mut wrong_policy_schema = allow.clone();
    wrong_policy_schema.schema = "generic-policy.v1".to_string();
    for (name, receiver_policy, expected) in [
        (
            "revoked policy rule",
            revoked,
            DevgraphAuthorityError::ReceiverPolicyDenied,
        ),
        (
            "policy outside window",
            outside_window,
            DevgraphAuthorityError::ReceiverPolicyDenied,
        ),
        (
            "policy actor no match",
            no_actor_match,
            DevgraphAuthorityError::ReceiverPolicyDenied,
        ),
        (
            "invalid policy id",
            bad_id,
            DevgraphAuthorityError::InvalidReceiverPolicy,
        ),
        (
            "zero policy version",
            zero_version,
            DevgraphAuthorityError::InvalidReceiverPolicy,
        ),
        (
            "wrong policy schema",
            wrong_policy_schema,
            DevgraphAuthorityError::InvalidReceiverPolicy,
        ),
    ] {
        assert_eq!(
            issue_devgraph_issue_create_authority_v1(
                &memory_ledger().await,
                &identity,
                &receiver_policy,
                REQUEST_JSON,
                IDEMPOTENCY_KEY,
                &serde_json::to_vec(&base).unwrap(),
                ISSUED_AT,
            )
            .await,
            Err(expected),
            "{name}"
        );
    }
}

#[tokio::test]
async fn replay_conflicts_storage_failures_and_unsafe_integer_fail_closed() {
    let request = request();
    let ledger = memory_ledger().await;
    let (_directory, identity) = production_identity();
    let policy = policy(&request, &[DevgraphPolicyEffectV1::Allow]);
    let first = wallet_presentation(
        &request,
        IDEMPOTENCY_KEY,
        SESSION_ID,
        NONCE,
        ISSUED_AT,
        EXPIRES_AT,
    );
    issue_devgraph_issue_create_authority_v1(
        &ledger,
        &identity,
        &policy,
        REQUEST_JSON,
        IDEMPOTENCY_KEY,
        &serde_json::to_vec(&first).unwrap(),
        ISSUED_AT,
    )
    .await
    .unwrap();
    let other_key = "dg-issue-create-other-0002";
    let conflicting = wallet_presentation(
        &request, other_key, SESSION_ID, NONCE, ISSUED_AT, EXPIRES_AT,
    );
    assert_eq!(
        issue_devgraph_issue_create_authority_v1(
            &ledger,
            &identity,
            &policy,
            REQUEST_JSON,
            other_key,
            &serde_json::to_vec(&conflicting).unwrap(),
            ISSUED_AT,
        )
        .await,
        Err(DevgraphAuthorityError::ReplayConflict)
    );
    assert_eq!(
        ledger
            .prune_expired_devgraph_authority_replay_reservations(EXPIRES_AT - 1)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        ledger
            .prune_expired_devgraph_authority_replay_reservations(EXPIRES_AT)
            .await
            .unwrap(),
        1
    );

    let broken_ledger = memory_ledger().await;
    sqlx::query("DROP TABLE devgraph_authority_replay_reservations")
        .execute(broken_ledger.pool())
        .await
        .unwrap();
    assert_eq!(
        issue_devgraph_issue_create_authority_v1(
            &broken_ledger,
            &identity,
            &policy,
            REQUEST_JSON,
            IDEMPOTENCY_KEY,
            &serde_json::to_vec(&first).unwrap(),
            ISSUED_AT,
        )
        .await,
        Err(DevgraphAuthorityError::ReplayStorageFailed)
    );

    let issued_at = DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1 + 1;
    let mut overflowing = first.clone();
    overflowing.issued_at = issued_at;
    overflowing.expires_at = issued_at + 60;
    assert_eq!(
        issue_devgraph_issue_create_authority_v1(
            &memory_ledger().await,
            &identity,
            &policy,
            REQUEST_JSON,
            IDEMPOTENCY_KEY,
            &serde_json::to_vec(&overflowing).unwrap(),
            issued_at,
        )
        .await,
        Err(DevgraphAuthorityError::InvalidWalletPresentation)
    );
}

#[tokio::test]
async fn file_backed_replay_survives_reopen_for_exact_retry_and_conflict() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("dg-p-replay.sqlite3");
    let pre_dg_p = file_ledger(&database, true).await;
    for table in LEDGER_TABLES
        .iter()
        .filter(|table| table.name != DEVGRAPH_AUTHORITY_REPLAY_RESERVATIONS_TABLE.name)
    {
        sqlx::query(table.ddl)
            .execute(pre_dg_p.pool())
            .await
            .unwrap();
    }
    sqlx::query(
        "INSERT INTO events (timestamp, event_kind, reason)
         VALUES (7, 'sentinel', 'preserve-me')",
    )
    .execute(pre_dg_p.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO replay_reservations (
            reserved_at, expires_at, replay_scope, session_id, opcode, nonce,
            packet_hash, context_id, signer_key_id
         ) VALUES (7, ?, 'legacy:scope', ?, 3, ?, ?, 'legacy-context', 'legacy-key')",
    )
    .bind(i64::MAX)
    .bind(vec![1_u8; 16])
    .bind(vec![2_u8; 12])
    .bind(vec![3_u8; 32])
    .execute(pre_dg_p.pool())
    .await
    .unwrap();
    drop(pre_dg_p);

    let ledger = file_ledger(&database, false).await;
    ledger.init_schema().await.unwrap();
    ledger.init_schema().await.unwrap();
    let event: (String, String) =
        sqlx::query_as("SELECT event_kind, reason FROM events WHERE timestamp = 7")
            .fetch_one(ledger.pool())
            .await
            .unwrap();
    assert_eq!(event, ("sentinel".to_string(), "preserve-me".to_string()));
    let legacy_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM replay_reservations WHERE context_id = 'legacy-context'",
    )
    .fetch_one(ledger.pool())
    .await
    .unwrap();
    assert_eq!(legacy_count.0, 1);
    let table_sql: (String,) =
        sqlx::query_as("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind(DEVGRAPH_AUTHORITY_REPLAY_RESERVATIONS_TABLE.name)
            .fetch_one(ledger.pool())
            .await
            .unwrap();
    assert!(table_sql
        .0
        .contains("CHECK(replay_scope = 'session:operation:nonce')"));
    let indexes = sqlx::query("PRAGMA index_list('devgraph_authority_replay_reservations')")
        .fetch_all(ledger.pool())
        .await
        .unwrap();
    let unique_index = indexes
        .iter()
        .find(|row| row.get::<i64, _>("unique") == 1)
        .unwrap()
        .get::<String, _>("name");
    let index_columns = sqlx::query(&format!("PRAGMA index_info('{unique_index}')"))
        .fetch_all(ledger.pool())
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<String, _>("name"))
        .collect::<Vec<_>>();
    assert_eq!(index_columns, ["session_id", "operation", "nonce"]);
    let (_key_directory, identity) = production_identity();
    let request = request();
    let policy = policy(&request, &[DevgraphPolicyEffectV1::Allow]);
    let presentation = wallet_presentation(
        &request,
        IDEMPOTENCY_KEY,
        SESSION_ID,
        NONCE,
        ISSUED_AT,
        EXPIRES_AT,
    );
    issue_devgraph_issue_create_authority_v1(
        &ledger,
        &identity,
        &policy,
        REQUEST_JSON,
        IDEMPOTENCY_KEY,
        &serde_json::to_vec(&presentation).unwrap(),
        ISSUED_AT,
    )
    .await
    .unwrap();
    drop(ledger);

    let reopened = file_ledger(&database, false).await;
    let retry = issue_devgraph_issue_create_authority_v1(
        &reopened,
        &identity,
        &policy,
        REQUEST_JSON,
        IDEMPOTENCY_KEY,
        &serde_json::to_vec(&presentation).unwrap(),
        ISSUED_AT + 1,
    )
    .await
    .unwrap();
    assert!(retry.is_exact_retry());

    let other_key = "dg-issue-create-reopen-0002";
    let conflicting = wallet_presentation(
        &request, other_key, SESSION_ID, NONCE, ISSUED_AT, EXPIRES_AT,
    );
    assert_eq!(
        issue_devgraph_issue_create_authority_v1(
            &reopened,
            &identity,
            &policy,
            REQUEST_JSON,
            other_key,
            &serde_json::to_vec(&conflicting).unwrap(),
            ISSUED_AT + 1,
        )
        .await,
        Err(DevgraphAuthorityError::ReplayConflict)
    );
}

#[tokio::test]
async fn projection_is_strict_signature_bound_and_uses_exclusive_key_expiry() {
    let request = request();
    let ledger = memory_ledger().await;
    let (_directory, identity) = production_identity();
    let policy = policy(&request, &[DevgraphPolicyEffectV1::Allow]);
    let presentation = wallet_presentation(
        &request,
        IDEMPOTENCY_KEY,
        SESSION_ID,
        NONCE,
        ISSUED_AT,
        EXPIRES_AT,
    );
    let output = issue_devgraph_issue_create_authority_v1(
        &ledger,
        &identity,
        &policy,
        REQUEST_JSON,
        IDEMPOTENCY_KEY,
        &serde_json::to_vec(&presentation).unwrap(),
        ISSUED_AT,
    )
    .await
    .unwrap();
    let projection = output.projection();
    let expected = expectations(projection, &policy, &presentation, SESSION_ID, NONCE);
    let canonical = projection.canonical_json().unwrap();
    let duplicate = canonical.replacen(
        '{',
        &format!("{{\"operation\":\"{DEVGRAPH_ISSUE_CREATE_OPERATION_V1}\","),
        1,
    );
    assert_eq!(
        DevgraphAuthorityProjectionV1::from_json(duplicate.as_bytes()),
        Err(DevgraphAuthorityError::MalformedProjection)
    );
    assert_eq!(
        DevgraphAuthorityProjectionV1::from_json(format!("{canonical} x").as_bytes()),
        Err(DevgraphAuthorityError::MalformedProjection)
    );
    let unknown = canonical.replacen('{', "{\"unknown\":true,", 1);
    assert_eq!(
        DevgraphAuthorityProjectionV1::from_json(unknown.as_bytes()),
        Err(DevgraphAuthorityError::MalformedProjection)
    );

    let projection_cases = vec![
        (
            "wrong schema",
            {
                let mut value = projection.clone();
                value.schema = "other.v1".to_string();
                value
            },
            DevgraphAuthorityError::MalformedProjection,
        ),
        (
            "wrong schema version",
            {
                let mut value = projection.clone();
                value.schema_version = 2;
                value
            },
            DevgraphAuthorityError::MalformedProjection,
        ),
        (
            "wrong actor suite",
            {
                let mut value = projection.clone();
                value.actor_signature_suite = "ML-DSA-65".to_string();
                value
            },
            DevgraphAuthorityError::MalformedProjection,
        ),
        (
            "wrong audience",
            {
                let mut value = projection.clone();
                value.audience = "devgraph://other".to_string();
                value
            },
            DevgraphAuthorityError::WrongProjectionBinding,
        ),
        (
            "wrong operation",
            {
                let mut value = projection.clone();
                value.operation = "devgraph.issue.update.v1".to_string();
                value
            },
            DevgraphAuthorityError::MalformedProjection,
        ),
        (
            "wrong resource",
            {
                let mut value = projection.clone();
                value.resource = "Issue/issue-other".to_string();
                value
            },
            DevgraphAuthorityError::WrongProjectionBinding,
        ),
        (
            "wrong request digest",
            {
                let mut value = projection.clone();
                value.request_digest_sha256 = "0".repeat(64);
                value
            },
            DevgraphAuthorityError::WrongProjectionBinding,
        ),
        (
            "wrong idempotency digest",
            {
                let mut value = projection.clone();
                value.idempotency_key_digest_sha256 = "0".repeat(64);
                value
            },
            DevgraphAuthorityError::WrongProjectionBinding,
        ),
        (
            "wrong policy id",
            {
                let mut value = projection.clone();
                value.receiver_policy_id = "other-policy".to_string();
                value
            },
            DevgraphAuthorityError::WrongProjectionBinding,
        ),
        (
            "wrong policy version",
            {
                let mut value = projection.clone();
                value.receiver_policy_version += 1;
                value
            },
            DevgraphAuthorityError::WrongProjectionBinding,
        ),
        (
            "wrong policy digest",
            {
                let mut value = projection.clone();
                value.receiver_policy_digest_sha256 = "0".repeat(64);
                value
            },
            DevgraphAuthorityError::WrongProjectionBinding,
        ),
        (
            "wrong replay scope",
            {
                let mut value = projection.clone();
                value.replay_scope = "generic".to_string();
                value
            },
            DevgraphAuthorityError::MalformedProjection,
        ),
        (
            "short session",
            {
                let mut value = projection.clone();
                value.session_id = encode_base64url(&[1; 15]);
                value
            },
            DevgraphAuthorityError::MalformedProjection,
        ),
        (
            "short nonce",
            {
                let mut value = projection.clone();
                value.nonce = encode_base64url(&[1; 11]);
                value
            },
            DevgraphAuthorityError::MalformedProjection,
        ),
        (
            "wrong verifier suite",
            {
                let mut value = projection.clone();
                value.secs_verifier_signature_suite = "ML-DSA-65".to_string();
                value
            },
            DevgraphAuthorityError::MalformedProjection,
        ),
        (
            "wrong wallet digest",
            {
                let mut value = projection.clone();
                value.wallet_presentation_digest_sha256 = "0".repeat(64);
                value
            },
            DevgraphAuthorityError::WrongProjectionBinding,
        ),
        (
            "future issued",
            {
                let mut value = projection.clone();
                value.issued_at += 1;
                value.expires_at += 1;
                value
            },
            DevgraphAuthorityError::NotYetValid,
        ),
        (
            "inverted validity",
            {
                let mut value = projection.clone();
                value.expires_at = value.issued_at;
                value
            },
            DevgraphAuthorityError::InvalidValidityWindow,
        ),
        (
            "overlong validity",
            {
                let mut value = projection.clone();
                value.expires_at = value.issued_at + 61;
                value
            },
            DevgraphAuthorityError::InvalidValidityWindow,
        ),
    ];
    let registry = PublicVerifierKeyRegistry::from_keys([identity.public_verifier_key()]);
    for (name, candidate, error) in projection_cases {
        assert_eq!(
            candidate.verify_with_registry(&registry, &expected, ISSUED_AT),
            Err(error),
            "{name}"
        );
    }
    assert_eq!(
        projection.verify_with_registry(&registry, &expected, EXPIRES_AT),
        Err(DevgraphAuthorityError::Expired)
    );
    let mut overlong_signature = projection.clone();
    overlong_signature.secs_verifier_signature = "A".repeat(4_096);
    assert_eq!(
        overlong_signature.verify_with_registry(&registry, &expected, ISSUED_AT),
        Err(DevgraphAuthorityError::InvalidVerifierSignature)
    );
    let mut invalid_expected_cases = Vec::new();
    let mut invalid = expected.clone();
    invalid.audience.clear();
    invalid_expected_cases.push(("empty expected audience", invalid));
    let mut invalid = expected.clone();
    invalid.policy.policy_id = "bad policy id".to_string();
    invalid_expected_cases.push(("invalid expected policy id", invalid));
    let mut invalid = expected.clone();
    invalid.policy.policy_version = 0;
    invalid_expected_cases.push(("zero expected policy version", invalid));
    let mut invalid = expected.clone();
    invalid.policy.policy_digest_sha256 = "not-a-digest".to_string();
    invalid_expected_cases.push(("invalid expected policy digest", invalid));
    for (name, invalid_expected) in invalid_expected_cases {
        assert_eq!(
            projection.verify_with_registry(&registry, &invalid_expected, ISSUED_AT),
            Err(DevgraphAuthorityError::WrongProjectionBinding),
            "{name}"
        );
    }

    let mut mutated = projection.clone();
    mutated.actor_id = format!("pubkey:sha256:{}", "0".repeat(64));
    let mut mutated_expected = expected.clone();
    mutated_expected.actor_id = mutated.actor_id.clone();
    assert_eq!(
        mutated.verify_with_registry(&registry, &mutated_expected, ISSUED_AT),
        Err(DevgraphAuthorityError::InvalidVerifierSignature)
    );

    let expiring_key = PublicVerifierKey::configured_production_authority(
        identity.signer_key_id(),
        "ed25519",
        *identity.public_key(),
    )
    .with_validity_window(None, Some(ISSUED_AT));
    let expiring_registry = PublicVerifierKeyRegistry::from_keys([expiring_key]);
    assert_eq!(
        projection.verify_with_registry(&expiring_registry, &expected, ISSUED_AT),
        Err(DevgraphAuthorityError::InvalidVerifierSignature)
    );
    assert_eq!(
        issue_devgraph_issue_create_authority_v1_with_registry(
            &memory_ledger().await,
            &identity,
            &expiring_registry,
            &policy,
            DevgraphIssueCreateAuthorityInputV1 {
                request_json: REQUEST_JSON,
                idempotency_key: IDEMPOTENCY_KEY,
                wallet_presentation_json: &serde_json::to_vec(&presentation).unwrap(),
                now: ISSUED_AT,
            },
        )
        .await,
        Err(DevgraphAuthorityError::UntrustedVerifierIdentity)
    );

    let production_key = identity.public_verifier_key();
    let untrusted =
        PublicVerifierKey::active(identity.signer_key_id(), "ed25519", *identity.public_key());
    let revoked = production_key
        .clone()
        .with_status(VerificationKeyStatus::Revoked);
    let future = production_key
        .clone()
        .with_validity_window(Some(ISSUED_AT + 1), None);
    let wrong_key = PublicVerifierKey::configured_production_authority(
        identity.signer_key_id(),
        "ed25519",
        VerifyingKey::from(&SigningKey::from_bytes(&[12; 32])),
    );
    let signer_registries = vec![
        ("unknown", PublicVerifierKeyRegistry::default()),
        (
            "untrusted",
            PublicVerifierKeyRegistry::from_keys([untrusted]),
        ),
        ("revoked", PublicVerifierKeyRegistry::from_keys([revoked])),
        ("future", PublicVerifierKeyRegistry::from_keys([future])),
        (
            "wrong key",
            PublicVerifierKeyRegistry::from_keys([wrong_key]),
        ),
        (
            "duplicate id",
            PublicVerifierKeyRegistry::from_keys([production_key.clone(), production_key.clone()]),
        ),
    ];
    for (name, signer_registry) in &signer_registries {
        assert_eq!(
            projection.verify_with_registry(signer_registry, &expected, ISSUED_AT),
            Err(DevgraphAuthorityError::InvalidVerifierSignature),
            "{name}"
        );
        let denial_ledger = memory_ledger().await;
        assert_eq!(
            issue_devgraph_issue_create_authority_v1_with_registry(
                &denial_ledger,
                &identity,
                signer_registry,
                &policy,
                DevgraphIssueCreateAuthorityInputV1 {
                    request_json: REQUEST_JSON,
                    idempotency_key: IDEMPOTENCY_KEY,
                    wallet_presentation_json: &serde_json::to_vec(&presentation).unwrap(),
                    now: ISSUED_AT,
                },
            )
            .await,
            Err(DevgraphAuthorityError::UntrustedVerifierIdentity),
            "issuance: {name}"
        );
        let reservation_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM devgraph_authority_replay_reservations")
                .fetch_one(denial_ledger.pool())
                .await
                .unwrap();
        assert_eq!(reservation_count.0, 0, "issuance side effect: {name}");
    }
}

#[tokio::test]
async fn debug_and_telemetry_are_redaction_safe_and_local_fixture_cannot_issue() {
    let request = request();
    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains("Golden issue"));
    assert!(!request_debug.contains("issue-golden"));

    let presentation = wallet_presentation(
        &request,
        IDEMPOTENCY_KEY,
        SESSION_ID,
        NONCE,
        ISSUED_AT,
        EXPIRES_AT,
    );
    let presentation_debug = format!("{presentation:?}");
    assert!(!presentation_debug.contains(&presentation.signature));
    assert!(!presentation_debug.contains(&presentation.actor_public_key));
    assert!(!presentation_debug.contains(AUDIENCE));
    assert!(!presentation_debug.contains(&presentation.nonce));
    assert!(!presentation_debug.contains(&presentation.session_id));
    assert!(!presentation_debug.contains(&presentation.issued_at.to_string()));
    assert!(!presentation_debug.contains(&presentation.expires_at.to_string()));

    let policy = policy(&request, &[DevgraphPolicyEffectV1::Allow]);
    let local = explicit_test_fixture_identity("local-only", SECS_SECRET);
    assert_eq!(
        issue_devgraph_issue_create_authority_v1(
            &memory_ledger().await,
            &local,
            &policy,
            REQUEST_JSON,
            IDEMPOTENCY_KEY,
            &serde_json::to_vec(&presentation).unwrap(),
            ISSUED_AT,
        )
        .await,
        Err(DevgraphAuthorityError::UntrustedVerifierIdentity)
    );

    let (_directory, identity) = production_identity();
    let output = issue_devgraph_issue_create_authority_v1(
        &memory_ledger().await,
        &identity,
        &policy,
        REQUEST_JSON,
        IDEMPOTENCY_KEY,
        &serde_json::to_vec(&presentation).unwrap(),
        ISSUED_AT,
    )
    .await
    .unwrap();
    let projection = output.projection();
    let debug = format!("{projection:?}");
    assert!(!debug.contains(&projection.secs_verifier_signature));
    assert!(!debug.contains(IDEMPOTENCY_KEY));
    assert!(!debug.contains("Golden issue"));
    assert!(!debug.contains(AUDIENCE));
    assert!(!debug.contains(&projection.nonce));
    assert!(!debug.contains(&projection.issued_at.to_string()));
    assert!(!debug.contains(&projection.expires_at.to_string()));
    let expected = expectations(projection, &policy, &presentation, SESSION_ID, NONCE);
    let expected_debug = format!("{expected:?}");
    assert!(!expected_debug.contains(AUDIENCE));
    assert!(!expected_debug.contains(&projection.session_id));
    assert!(!expected_debug.contains(&projection.nonce));
    assert!(!expected_debug.contains(&projection.issued_at.to_string()));
    assert!(!expected_debug.contains(&projection.expires_at.to_string()));
    let telemetry = projection.redacted_telemetry_fields().unwrap().join("\n");
    for required in [
        "receiver_policy_id:",
        "receiver_policy_version:",
        "receiver_policy_digest_sha256:",
        "authority_projection_digest_sha256:",
    ] {
        assert!(telemetry.contains(required), "missing {required}");
    }
    for forbidden in [
        IDEMPOTENCY_KEY,
        "Golden issue",
        &presentation.signature,
        &projection.secs_verifier_signature,
        &presentation.actor_public_key,
    ] {
        assert!(!telemetry.contains(forbidden), "leaked {forbidden}");
    }
}
