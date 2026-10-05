use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use server::credential_presentation::{
    canonical, hex, Caller, Credential, Presentation, PresentationRequest,
};
use server::devgraph_authority::{actor_id_for_public_key, encode_base64url};
use server::devgraph_work_authority::{WorkPolicy, WorkRule};
use server::devgraph_work_request::WorkRequest;
use server::devgraph_work_v2::{
    issue_credential, issue_work_authority_v2, CredentialConfig, CredentialInput,
    WorkAuthorityInputV2,
};
use server::identity::{
    load_node_verifier_identity, NodeVerifierIdentity, PublicVerifierKeyRegistry,
    VerifierIdentityConfig,
};
use server::ledger::Ledger;
use server::runtime_mode::RuntimeMode;
use sqlx::sqlite::SqlitePoolOptions;
const NOW: u64 = 1_800_000_000;
const KEY: &str = "named-work-native-test-0001";
fn identity() -> NodeVerifierIdentity {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("synthetic-key");
    std::fs::write(&path, "2b".repeat(32)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    load_node_verifier_identity(&VerifierIdentityConfig {
        runtime_mode: RuntimeMode::ProductionVerified,
        verifier_key_path: Some(path),
        verifier_key_id: Some("named-test-secs".into()),
    })
    .unwrap()
}
fn caller() -> Caller {
    Caller {
        kind: "terminal".into(),
        id: "devgraph-review".into(),
    }
}
fn config() -> CredentialConfig {
    CredentialConfig {
        schema: "secs-devgraph-credential-config.v2".into(),
        schema_version: 2,
        issuer: "secs://devgraph-work".into(),
        callers: vec![caller()],
    }
}
fn vectors() -> Vec<Value> {
    let mut out: Vec<Value> =
        serde_json::from_slice(include_bytes!("fixtures/named-work-v1/requests.json")).unwrap();
    out.extend(
        serde_json::from_slice::<Vec<Value>>(include_bytes!("fixtures/arena-v1/requests.json"))
            .unwrap(),
    );
    out
}
fn policy(request: &WorkRequest) -> WorkPolicy {
    WorkPolicy {
        audience: "devgraph://receiver-local".into(),
        policy_id: "credential-v2-fixture".into(),
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
                not_after: NOW + 600,
                not_before: NOW - 10,
                operation: request.operation.clone(),
                resource: resource.clone(),
                resource_match: "exact".into(),
                status: "active".into(),
            })
            .collect(),
    }
}
async fn ledger() -> Ledger {
    Ledger::new(
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap(),
    )
}
fn credential(request: &WorkRequest, policy: &WorkPolicy, index: u8) -> PresentationRequest {
    let identity = identity();
    let registry = PublicVerifierKeyRegistry::from_keys([identity.public_verifier_key()]);
    issue_credential(
        &identity,
        &registry,
        policy,
        &config(),
        CredentialInput {
            request_json: &request.canonical,
            idempotency_key: KEY,
            holder_public_key: &hex(SigningKey::from_bytes(&[37; 32]).verifying_key().as_bytes()),
            caller: &caller(),
            nonce: [index; 16],
            now: NOW,
        },
    )
    .unwrap()
}
fn sign(credential: &Credential, index: u8) -> Presentation {
    let c = &credential.claims;
    let mut p = Presentation {
        schema: "castalia.credential-presentation.v2".into(),
        holder_public_key: c.holder_public_key.clone(),
        issuer: c.issuer.clone(),
        key_id: c.key_id.clone(),
        audience: c.audience.clone(),
        caller: c.caller.clone(),
        request_digest_sha256: c.request_digest_sha256.clone(),
        credential_digest_sha256: credential.digest().unwrap(),
        disclosure_digest_sha256: c.disclosure_digest_sha256.clone(),
        nonce: hex(&[index; 16]),
        issued_at: NOW + 1,
        expires_at: NOW + 61,
        signature: String::new(),
    };
    p.signature = hex(&SigningKey::from_bytes(&[37; 32])
        .sign(&p.preimage().unwrap())
        .to_bytes());
    p
}
async fn authorize(
    ledger: &Ledger,
    request: &WorkRequest,
    policy: &WorkPolicy,
    attached: &PresentationRequest,
    presentation: &Presentation,
    key: &str,
    now: u64,
) -> Result<Value, &'static str> {
    let identity = identity();
    let registry = PublicVerifierKeyRegistry::from_keys([identity.public_verifier_key()]);
    let p = issue_work_authority_v2(
        ledger,
        &identity,
        &registry,
        policy,
        &config(),
        WorkAuthorityInputV2 {
            request_json: &request.canonical,
            credential_json: &canonical(&attached.credential).unwrap(),
            disclosure_json: &canonical(&attached.disclosure).unwrap(),
            presentation_json: &canonical(presentation).unwrap(),
            idempotency_key: key,
            now,
        },
    )
    .await?;
    Ok(serde_json::to_value(p).unwrap())
}
#[tokio::test]
async fn all_work_arena_vectors_roundtrip_without_changing_legacy_digests() {
    let ledger = ledger().await;
    let mut shared = Vec::new();
    for (index, vector) in vectors().iter().enumerate() {
        let request = WorkRequest::parse(vector["raw"].as_str().unwrap().as_bytes()).unwrap();
        let policy = policy(&request);
        let attached = credential(&request, &policy, index as u8 + 1);
        let presentation = sign(&attached.credential, index as u8 + 101);
        assert_eq!(attached.credential.claims.expires_at, NOW + 120);
        let projection = authorize(
            &ledger,
            &request,
            &policy,
            &attached,
            &presentation,
            KEY,
            NOW + 1,
        )
        .await
        .unwrap();
        assert_eq!(projection["request_digest_sha256"], vector["digest"]);
        assert_eq!(
            projection,
            authorize(
                &ledger,
                &request,
                &policy,
                &attached,
                &presentation,
                KEY,
                NOW + 2
            )
            .await
            .unwrap()
        );
        let mut unsigned = projection.clone();
        let signature = unsigned
            .as_object_mut()
            .unwrap()
            .remove("secs_verifier_signature")
            .unwrap();
        let mut preimage = b"secs-devgraph-work-authority.v2/signature\0".to_vec();
        preimage.extend(canonical(&unsigned).unwrap());
        assert_eq!(
            signature,
            encode_base64url(&SigningKey::from_bytes(&[43; 32]).sign(&preimage).to_bytes())
        );
        shared.push(json!({"request":request.value,"idempotency_key":KEY,"now":NOW+1,"policy":policy,"presentation_request":attached,"presentation":presentation,"projection":projection}));
    }
    let checked_in: Value =
        serde_json::from_slice(include_bytes!("fixtures/credential-v2/signed-vectors.json"))
            .unwrap();
    assert_eq!(
        checked_in["vectors"],
        serde_json::to_value(&shared).unwrap()
    );
    if let Some(path) = std::env::var_os("SECS_TEST_V2_FIXTURE_OUTPUT") {
        let out = json!({"schema":"secs-devgraph-credential-fixtures.v2","provenance":"Synthetic public test seeds: wallet byte37, authority byte43. No production authority.","issuer_public_key":hex(SigningKey::from_bytes(&[43;32]).verifying_key().as_bytes()),"vectors":shared});
        std::fs::write(path, serde_json::to_vec_pretty(&out).unwrap()).unwrap();
    }
}
#[tokio::test]
async fn substitutions_current_policy_expiry_and_replay_fail_closed() {
    let vector = &vectors()[0];
    let request = WorkRequest::parse(vector["raw"].as_str().unwrap().as_bytes()).unwrap();
    let policy = policy(&request);
    let ledger = ledger().await;
    let attached = credential(&request, &policy, 1);
    let presentation = sign(&attached.credential, 2);
    for field in [
        "holder_public_key",
        "issuer",
        "key_id",
        "audience",
        "request_digest_sha256",
        "disclosure_digest_sha256",
        "credential_digest_sha256",
        "nonce",
        "signature",
    ] {
        let mut bad = serde_json::to_value(&presentation).unwrap();
        bad[field] = json!("00".repeat(32));
        let bad: Presentation = serde_json::from_value(bad).unwrap();
        assert!(
            authorize(&ledger, &request, &policy, &attached, &bad, KEY, NOW + 1)
                .await
                .is_err(),
            "{field}"
        );
    }
    let mut altered = attached.clone();
    altered.disclosure.title = "Harmless login".into();
    assert!(authorize(
        &ledger,
        &request,
        &policy,
        &altered,
        &presentation,
        KEY,
        NOW + 1
    )
    .await
    .is_err());
    let mut revoked = policy.clone();
    revoked.rules[0].status = "revoked".into();
    assert!(authorize(
        &ledger,
        &request,
        &revoked,
        &attached,
        &presentation,
        KEY,
        NOW + 1
    )
    .await
    .is_err());
    assert!(authorize(
        &ledger,
        &request,
        &policy,
        &attached,
        &presentation,
        "different-idempotency-0001",
        NOW + 1
    )
    .await
    .is_err());
    assert!(authorize(
        &ledger,
        &request,
        &policy,
        &attached,
        &presentation,
        KEY,
        NOW + 121
    )
    .await
    .is_err());
    authorize(
        &ledger,
        &request,
        &policy,
        &attached,
        &presentation,
        KEY,
        NOW + 1,
    )
    .await
    .unwrap();
    let mut changed = presentation.clone();
    changed.expires_at -= 1;
    changed.signature = hex(&SigningKey::from_bytes(&[37; 32])
        .sign(&changed.preimage().unwrap())
        .to_bytes());
    assert_eq!(
        authorize(
            &ledger,
            &request,
            &policy,
            &attached,
            &changed,
            KEY,
            NOW + 1
        )
        .await
        .unwrap_err(),
        "replay_conflict"
    );
}
#[test]
fn preflight_denies_missing_grants_untrusted_callers_and_invalid_inputs() {
    let vector = &vectors()[0];
    let request = WorkRequest::parse(vector["raw"].as_str().unwrap().as_bytes()).unwrap();
    let mut policy = policy(&request);
    let identity = identity();
    let registry = PublicVerifierKeyRegistry::from_keys([identity.public_verifier_key()]);
    let holder = hex(SigningKey::from_bytes(&[37; 32]).verifying_key().as_bytes());
    for kind in ["revoked", "wrong_actor", "wrong_operation"] {
        let mut p = policy.clone();
        match kind {
            "revoked" => p.rules[0].status = "revoked".into(),
            "wrong_actor" => p.rules[0].actor_id = format!("pubkey:sha256:{}", "00".repeat(32)),
            _ => p.rules[0].operation = "devgraph.work.patch.v1".into(),
        };
        assert!(issue_credential(
            &identity,
            &registry,
            &p,
            &config(),
            CredentialInput {
                request_json: &request.canonical,
                idempotency_key: KEY,
                holder_public_key: &holder,
                caller: &caller(),
                nonce: [1; 16],
                now: NOW
            }
        )
        .is_err());
    }
    let other = Caller {
        kind: "terminal".into(),
        id: "another-client".into(),
    };
    assert!(issue_credential(
        &identity,
        &registry,
        &policy,
        &config(),
        CredentialInput {
            request_json: &request.canonical,
            idempotency_key: KEY,
            holder_public_key: &holder,
            caller: &other,
            nonce: [1; 16],
            now: NOW
        }
    )
    .is_err());
    policy.rules[0].not_after = NOW + 7;
    assert_eq!(
        credential(&request, &policy, 1)
            .credential
            .claims
            .expires_at,
        NOW + 7
    );
    assert!(Credential::parse(br#"{"claims":{},"claims":{},"signature":""}"#).is_err());
    for id in [
        "https://example.com/",
        "https://EXAMPLE.com",
        "http://example.com",
        "https://user@example.com",
        "https://example.com:443",
        "http://localhost:03000",
        "https://127.1",
        "https://127.00.0.1",
        "https://example.com.",
    ] {
        assert!(
            Caller {
                kind: "browser".into(),
                id: id.into()
            }
            .validate()
            .is_err(),
            "{id}"
        );
    }
    for id in [
        "https://example.com",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://[::1]:3000",
    ] {
        Caller {
            kind: "browser".into(),
            id: id.into(),
        }
        .validate()
        .unwrap();
    }
}

#[test]
fn optional_independent_wallet_fixture_matches_generic_signature_bytes() {
    let Some(path) = std::env::var_os("SECS_TEST_WALLET_GENERIC_FIXTURE") else {
        return;
    };
    let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let request: PresentationRequest = serde_json::from_value(value["request"].clone()).unwrap();
    let presentation: Presentation =
        serde_json::from_value(value["expected_presentation"].clone()).unwrap();
    let pin = &value["trust_config"]["pins"][0];
    let public = ed25519_dalek::VerifyingKey::from_bytes(
        &server::credential_presentation::unhex::<32>(pin["public_key"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    request
        .credential
        .verify(
            pin["issuer"].as_str().unwrap(),
            pin["key_id"].as_str().unwrap(),
            &public,
            pin["audience"].as_str().unwrap(),
            &request.credential.claims.caller,
            value["now"].as_u64().unwrap(),
        )
        .unwrap();
    presentation
        .verify(&request.credential, value["approved_at"].as_u64().unwrap())
        .unwrap();
    assert_eq!(
        hex(&request.credential.preimage().unwrap()),
        value["credential_signing_bytes_hex"]
    );
    assert_eq!(
        hex(&presentation.preimage().unwrap()),
        value["presentation_signing_bytes_hex"]
    );
    assert_eq!(
        String::from_utf8(canonical(&presentation).unwrap()).unwrap(),
        value["canonical_presentation"]
    );
    assert_eq!(
        request.disclosure.digest().unwrap(),
        request.credential.claims.disclosure_digest_sha256
    );
}

#[test]
fn workflow_additions_are_explicitly_unsupported_before_issuance() {
    let vector = &vectors()[0];
    let request = WorkRequest::parse(vector["raw"].as_str().unwrap().as_bytes()).unwrap();
    let policy = policy(&request);
    let mut value = request.value.clone();
    value["operation"] = json!("workflow.transition");
    let identity = identity();
    let registry = PublicVerifierKeyRegistry::from_keys([identity.public_verifier_key()]);
    let result = issue_credential(
        &identity,
        &registry,
        &policy,
        &config(),
        CredentialInput {
            request_json: &canonical(&value).unwrap(),
            idempotency_key: KEY,
            holder_public_key: &hex(SigningKey::from_bytes(&[37; 32]).verifying_key().as_bytes()),
            caller: &caller(),
            nonce: [1; 16],
            now: NOW,
        },
    );
    assert_eq!(result.unwrap_err(), "unsupported_workflow_operation");
}
