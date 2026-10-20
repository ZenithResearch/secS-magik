use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use server::devgraph_authority::{
    actor_id_for_public_key, encode_base64url, idempotency_key_digest_sha256,
};
use server::devgraph_work_authority::{
    digest, issue_work_authority, WorkAuthorityInput, WorkPolicy, WorkRule,
};
use server::devgraph_work_request::WorkRequest;
use server::identity::{
    load_node_verifier_identity, NodeVerifierIdentity, PublicVerifierKeyRegistry,
    VerifierIdentityConfig,
};
use server::ledger::Ledger;
use server::runtime_mode::RuntimeMode;
use sqlx::sqlite::SqlitePoolOptions;

const NOW: u64 = 1_800_000_000;
const KEY: &str = "named-work-native-test-0001";
fn bytes(value: &Value) -> Vec<u8> {
    server::credential_presentation::canonical(value).unwrap()
}
fn wallet(request: &WorkRequest, key: &str, session: u8) -> Value {
    let signer = SigningKey::from_bytes(&[37; 32]);
    let mut value = json!({"actor_public_key":encode_base64url(signer.verifying_key().as_bytes()),
        "actor_signature_suite":"Ed25519", "audience":"devgraph://receiver-local",
        "expires_at": NOW+60, "issued_at": NOW, "idempotency_key_digest_sha256":idempotency_key_digest_sha256(key).unwrap(),
        "nonce":encode_base64url(&[session;12]), "session_id":encode_base64url(&[session;16]),
        "operation":request.operation, "resources":request.resources,
        "request_digest_sha256":digest(request.request_domain(), &request.canonical),
        "schema":"devgraph.work.wallet-presentation.v1", "schema_version":1});
    let mut preimage = b"devgraph.work.wallet-presentation.v1/signature\0".to_vec();
    preimage.extend(bytes(&value));
    value["signature"] = json!(encode_base64url(&signer.sign(&preimage).to_bytes()));
    value
}
fn policy(request: &WorkRequest) -> WorkPolicy {
    WorkPolicy {
        audience: "devgraph://receiver-local".into(),
        policy_id: "named-native-test".into(),
        policy_version: 1,
        schema: "secs-devgraph-work-policy.v1".into(),
        schema_version: 1,
        rules: request
            .resources
            .iter()
            .map(|resource| WorkRule {
                actor_id: actor_id_for_public_key(
                    SigningKey::from_bytes(&[37; 32]).verifying_key().as_bytes(),
                ),
                effect: "allow".into(),
                status: "active".into(),
                validity: server::grant_validity::GrantValidity::dated(NOW - 10, NOW + 600)
                    .unwrap(),
                operation: request.operation.clone(),
                resource: resource.clone(),
                resource_match: "exact".into(),
            })
            .collect(),
    }
}
async fn ledger() -> Ledger {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let ledger = Ledger::new(pool);
    ledger.init_schema().await.unwrap();
    ledger
}
fn identity() -> NodeVerifierIdentity {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("synthetic-verifier.key");
    std::fs::write(&path, "2b".repeat(32)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    load_node_verifier_identity(&VerifierIdentityConfig {
        runtime_mode: RuntimeMode::ProductionVerified,
        verifier_key_path: Some(path),
        verifier_key_id: Some("named-test-secs".into()),
    })
    .unwrap()
}
fn vectors() -> Vec<Value> {
    let mut all: Vec<Value> =
        serde_json::from_slice(include_bytes!("fixtures/named-work-v1/requests.json")).unwrap();
    all.extend(
        serde_json::from_slice::<Vec<Value>>(include_bytes!("fixtures/arena-v1/requests.json"))
            .unwrap(),
    );
    all
}

#[tokio::test]
async fn all_shared_operations_signed_retried_and_verified() {
    let identity = identity();
    let registry = PublicVerifierKeyRegistry::from_keys([identity.public_verifier_key()]);
    let ledger = ledger().await;
    let mut fixtures = Vec::new();
    for (index, vector) in vectors().into_iter().enumerate() {
        let raw = vector["raw"].as_str().unwrap().as_bytes();
        let request = WorkRequest::parse(raw).unwrap();
        let policy = policy(&request);
        let presentation = wallet(&request, KEY, index as u8);
        let raw_presentation = bytes(&presentation);
        let mut first = None;
        for _ in 0..2 {
            let projection = issue_work_authority(
                &ledger,
                &identity,
                &registry,
                &policy,
                WorkAuthorityInput {
                    request_json: raw,
                    wallet_presentation_json: &raw_presentation,
                    idempotency_key: KEY,
                    now: NOW,
                },
            )
            .await
            .unwrap();
            assert_eq!(
                projection.request_digest_sha256,
                vector["digest"].as_str().unwrap()
            );
            let signed = projection.canonical().unwrap();
            let mut unsigned: Value = serde_json::from_slice(&signed).unwrap();
            let signature = unsigned
                .as_object_mut()
                .unwrap()
                .remove("secs_verifier_signature")
                .unwrap();
            let mut preimage = b"secs-devgraph-work-authority.v1/signature\0".to_vec();
            preimage.extend(bytes(&unsigned));
            assert_eq!(
                signature.as_str().unwrap(),
                encode_base64url(&SigningKey::from_bytes(&[43; 32]).sign(&preimage).to_bytes())
            );
            if let Some(ref first) = first {
                assert_eq!(&signed, first);
            } else {
                first = Some(signed);
            }
        }
        fixtures.push(json!({"request":serde_json::from_slice::<Value>(raw).unwrap(), "wallet_presentation":presentation,
            "projection":serde_json::from_slice::<Value>(&first.unwrap()).unwrap(), "policy":policy,
            "public_key":encode_base64url(identity.public_key().as_bytes()), "key":KEY, "now":NOW}));
    }
    // Explicit test-only export contains public proofs and policies, never private keys.
    if let Ok(path) = std::env::var("DEVGRAPH_TEST_VECTOR_OUTPUT") {
        std::fs::write(path, serde_json::to_vec_pretty(&fixtures).unwrap()).unwrap();
    }
}

#[tokio::test]
async fn every_affected_resource_requires_current_permission() {
    let identity = identity();
    let registry = PublicVerifierKeyRegistry::from_keys([identity.public_verifier_key()]);
    for vector in vectors() {
        let raw = vector["raw"].as_str().unwrap().as_bytes();
        let request = WorkRequest::parse(raw).unwrap();
        let presentation = bytes(&wallet(&request, KEY, 1));
        for index in 0..request.resources.len() {
            for state in [
                "missing",
                "revoked",
                "expired",
                "future",
                "deny",
                "wrong-actor",
                "wrong-operation",
                "wrong-resource",
            ] {
                let mut policy = policy(&request);
                let rule = &mut policy.rules[index];
                match state {
                    "revoked" => rule.status = "revoked".into(),
                    "expired" => {
                        rule.validity = server::grant_validity::GrantValidity::dated(
                            rule.validity.not_before(),
                            NOW,
                        )
                        .unwrap()
                    }
                    "future" => {
                        rule.validity = server::grant_validity::GrantValidity::dated(
                            NOW + 1,
                            rule.validity.not_after().unwrap(),
                        )
                        .unwrap()
                    }
                    "deny" => rule.effect = "deny".into(),
                    "wrong-actor" => rule.actor_id = format!("pubkey:sha256:{}", "e".repeat(64)),
                    "wrong-operation" => {
                        rule.operation = if request.operation.ends_with("create.v1") {
                            "devgraph.work.patch.v1"
                        } else {
                            "devgraph.work.create.v1"
                        }
                        .into()
                    }
                    "wrong-resource" => rule.resource = "Issue/other".into(),
                    _ => {
                        policy.rules.remove(index);
                    }
                }
                let result = issue_work_authority(
                    &ledger().await,
                    &identity,
                    &registry,
                    &policy,
                    WorkAuthorityInput {
                        request_json: raw,
                        wallet_presentation_json: &presentation,
                        idempotency_key: KEY,
                        now: NOW,
                    },
                )
                .await;
                assert!(result.is_err(), "{state}");
            }
        }
    }
}

#[tokio::test]
async fn deny_wins_expiry_is_capped_and_replay_conflicts_are_durable() {
    let identity = identity();
    let registry = PublicVerifierKeyRegistry::from_keys([identity.public_verifier_key()]);
    let vector = vectors().remove(0);
    let raw = vector["raw"].as_str().unwrap().as_bytes();
    let request = WorkRequest::parse(raw).unwrap();
    let presentation = bytes(&wallet(&request, KEY, 1));
    let mut policy = policy(&request);
    let mut deny = policy.rules[0].clone();
    deny.effect = "deny".into();
    deny.validity =
        server::grant_validity::GrantValidity::dated(NOW + 5, deny.validity.not_after().unwrap())
            .unwrap();
    policy.rules.push(deny);
    let ledger = ledger().await;
    let projection = issue_work_authority(
        &ledger,
        &identity,
        &registry,
        &policy,
        WorkAuthorityInput {
            request_json: raw,
            wallet_presentation_json: &presentation,
            idempotency_key: KEY,
            now: NOW,
        },
    )
    .await
    .unwrap();
    assert_eq!(projection.expires_at, NOW + 5);
    let other = bytes(&wallet(&request, "named-work-other-key-0001", 1));
    assert!(issue_work_authority(
        &ledger,
        &identity,
        &registry,
        &policy,
        WorkAuthorityInput {
            request_json: raw,
            wallet_presentation_json: &other,
            idempotency_key: "named-work-other-key-0001",
            now: NOW,
        }
    )
    .await
    .is_err());
    policy.rules[1].validity = server::grant_validity::GrantValidity::dated(
        NOW,
        policy.rules[1].validity.not_after().unwrap(),
    )
    .unwrap();
    assert!(issue_work_authority(
        &ledger,
        &identity,
        &registry,
        &policy,
        WorkAuthorityInput {
            request_json: raw,
            wallet_presentation_json: &presentation,
            idempotency_key: KEY,
            now: NOW,
        }
    )
    .await
    .is_err());
}

#[tokio::test]
async fn explicit_until_revoked_policy_issues_only_finite_authority() {
    let vector = vectors().remove(0);
    let raw = vector["raw"].as_str().unwrap().as_bytes();
    let request = WorkRequest::parse(raw).unwrap();
    let old = policy(&request);
    let original = serde_json::to_value(&old).unwrap();
    let mut wire = original.clone();
    wire["schema"] = json!("secs-devgraph-work-policy.v2");
    wire["schema_version"] = json!(2);
    for rule in wire["rules"].as_array_mut().unwrap() {
        let rule = rule.as_object_mut().unwrap();
        let start = rule.remove("not_before").unwrap();
        rule.remove("not_after");
        rule.insert("validity".into(),json!({"schema":"castalia.grant-validity.v1","mode":"until_revoked","not_before":start}));
    }
    let policy = WorkPolicy::parse(&bytes(&wire)).expect("explicit v2 policy");
    assert_eq!(serde_json::to_value(&policy).unwrap(), wire);
    assert_ne!(policy.digest().unwrap(), old.digest().unwrap());
    assert_eq!(
        serde_json::to_value(WorkPolicy::parse(&bytes(&original)).unwrap()).unwrap(),
        original
    );
    let mut legacy = wire.clone();
    legacy["schema"] = json!("secs-devgraph-work-policy.v1");
    legacy["schema_version"] = json!(1);
    assert!(
        WorkPolicy::parse(&bytes(&legacy)).is_err(),
        "Old policy never acquires unbounded rules"
    );
    let identity = identity();
    let registry = PublicVerifierKeyRegistry::from_keys([identity.public_verifier_key()]);
    let ledger = ledger().await;
    let presentation = bytes(&wallet(&request, KEY, 91));
    let issued = issue_work_authority(
        &ledger,
        &identity,
        &registry,
        &policy,
        WorkAuthorityInput {
            request_json: raw,
            wallet_presentation_json: &presentation,
            idempotency_key: KEY,
            now: NOW,
        },
    )
    .await
    .unwrap();
    assert_eq!(issued.expires_at, NOW + 60);
    let mut invalid = wire.clone();
    invalid["rules"][0]["not_after"] = json!(NOW + 999);
    assert!(
        WorkPolicy::parse(&bytes(&invalid)).is_err(),
        "Do not mix old and new validity fields"
    );
}
