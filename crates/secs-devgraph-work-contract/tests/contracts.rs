use castalia_wallet_devgraph_presentation::{decode64, Presentation};
use devgraph_work_protocol::{canonical_json, WorkRequest};
use secs_devgraph_work_contract::{
    verify_presentation, verify_projection, ProjectionExpectation, WorkPolicy,
};
use serde_json::{json, Value};

fn vectors() -> Vec<Value> {
    serde_json::from_slice(include_bytes!(
        "../../../server/tests/fixtures/named-work-v1/signed-vectors.json"
    ))
    .unwrap()
}
fn bytes(v: &impl serde::Serialize) -> Vec<u8> {
    canonical_json(v).unwrap()
}
fn verify(vector: &Value, raw: &[u8], now: u64, public_key: &[u8; 32]) -> bool {
    let request = WorkRequest::parse(&bytes(&vector["request"])).unwrap();
    let presentation = Presentation::parse(&bytes(&vector["wallet_presentation"])).unwrap();
    let policy = WorkPolicy::parse(&bytes(&vector["policy"])).unwrap();
    verify_projection(
        raw,
        ProjectionExpectation {
            request: &request,
            idempotency_key: vector["key"].as_str().unwrap(),
            presentation: &presentation,
            audience: &policy.audience,
            actor_id: vector["projection"]["actor_id"].as_str().unwrap(),
            receiver_policy_id: &policy.policy_id,
            receiver_policy_version: policy.policy_version,
            receiver_policy_digest: &policy.digest().unwrap(),
            verifier_key_id: "named-test-secs",
            verifier_public_key: public_key,
            now,
        },
    )
    .is_ok()
}

#[test]
fn historical_signed_vectors_verify_without_native_issuer_dependencies() {
    for vector in vectors() {
        let public_key = decode64(vector["public_key"].as_str().unwrap()).unwrap();
        let now = vector["now"].as_u64().unwrap();
        let raw = bytes(&vector["projection"]);
        assert!(verify(&vector, &raw, now, &public_key));
        let request = WorkRequest::parse(&bytes(&vector["request"])).unwrap();
        let presentation = Presentation::parse(&bytes(&vector["wallet_presentation"])).unwrap();
        let checked = verify_presentation(
            &request,
            &presentation,
            vector["key"].as_str().unwrap(),
            now,
        )
        .unwrap();
        assert_eq!(
            checked.digest(),
            vector["projection"]["wallet_presentation_digest_sha256"]
        );
        let policy = WorkPolicy::parse(&bytes(&vector["policy"])).unwrap();
        assert_eq!(
            policy.digest().unwrap(),
            vector["projection"]["receiver_policy_digest_sha256"]
        );
        assert_eq!(
            policy
                .authorize_until(checked.actor_id(), &request, now)
                .unwrap(),
            now + 60
        );
    }
}

#[test]
fn every_projection_field_is_authenticated_and_trust_is_supplied() {
    for vector in vectors() {
        let public_key = decode64(vector["public_key"].as_str().unwrap()).unwrap();
        let now = vector["now"].as_u64().unwrap();
        for field in vector["projection"].as_object().unwrap().keys() {
            let mut changed = vector["projection"].clone();
            changed[field] = match &changed[field] {
                Value::String(s) => json!(format!("{s}x")),
                Value::Number(n) => json!(n.as_u64().unwrap() + 1),
                Value::Array(a) => {
                    let mut a = a.clone();
                    a.push(json!("Task/substituted"));
                    json!(a)
                }
                _ => panic!("unexpected fixture field"),
            };
            assert!(
                !verify(&vector, &bytes(&changed), now, &public_key),
                "{field}"
            );
        }
        let raw = bytes(&vector["projection"]);
        assert!(!verify(&vector, &raw, now, &[0; 32]));
        assert!(!verify(&vector, &raw, now - 1, &public_key));
        assert!(!verify(&vector, &raw, now + 60, &public_key));
        assert!(!verify(&vector, &vec![b' '; 16_385], now, &public_key));
        let mut duplicate = raw.clone();
        duplicate.pop();
        duplicate.extend(br#", "schema_version": 1}"#);
        assert!(!verify(&vector, &duplicate, now, &public_key));
    }
}

#[test]
fn all_resources_are_required_and_future_deny_caps_grants() {
    for vector in vectors() {
        let request = WorkRequest::parse(&bytes(&vector["request"])).unwrap();
        let now = vector["now"].as_u64().unwrap();
        let actor = vector["projection"]["actor_id"].as_str().unwrap();
        let policy = WorkPolicy::parse(&bytes(&vector["policy"])).unwrap();
        for index in 0..policy.rules.len() {
            for state in [
                "missing",
                "deny",
                "revoked",
                "expired",
                "future",
                "wrong_actor",
                "wrong_resource",
            ] {
                let mut altered = policy.clone();
                let rule = &mut altered.rules[index];
                match state {
                    "deny" => rule.effect = "deny".into(),
                    "revoked" => rule.status = "revoked".into(),
                    "expired" => rule.not_after = now,
                    "future" => rule.not_before = now + 1,
                    "wrong_actor" => rule.actor_id = format!("pubkey:sha256:{}", "f".repeat(64)),
                    "wrong_resource" => rule.resource = "Task/different".into(),
                    _ => {
                        altered.rules.remove(index);
                    }
                }
                assert!(
                    altered.authorize_until(actor, &request, now).is_err(),
                    "{state}"
                );
            }
        }
        let mut capped = policy.clone();
        let mut deny = capped.rules[0].clone();
        deny.effect = "deny".into();
        deny.not_before = now + 5;
        capped.rules.push(deny);
        assert_eq!(
            capped.authorize_until(actor, &request, now).unwrap(),
            now + 5
        );
    }
}

#[test]
fn semantic_projection_binding_is_checked_even_if_signed_by_trusted_key() {
    use castalia_wallet_devgraph_presentation::base64url;
    use ed25519_dalek::{Signer, SigningKey};
    let vector = vectors().remove(0);
    let key = SigningKey::from_bytes(&[43; 32]);
    let now = vector["now"].as_u64().unwrap();
    for (field, value) in [
        ("nonce", json!(base64url(&[11; 12]))),
        ("session_id", json!(base64url(&[12; 16]))),
        ("issued_at", json!(now - 1)),
        ("expires_at", json!(now + 61)),
        (
            "secs_context_id",
            json!(format!("ctx:sha256:{}", "f".repeat(64))),
        ),
        ("receiver_policy_version", json!(2)),
    ] {
        let mut projection = vector["projection"].clone();
        projection[field] = value;
        projection
            .as_object_mut()
            .unwrap()
            .remove("secs_verifier_signature");
        let mut transcript = b"secs-devgraph-work-authority.v1/signature\0".to_vec();
        transcript.extend(bytes(&projection));
        projection["secs_verifier_signature"] = json!(base64url(&key.sign(&transcript).to_bytes()));
        assert!(
            !verify(
                &vector,
                &bytes(&projection),
                now,
                key.verifying_key().as_bytes()
            ),
            "{field}"
        );
    }
}

#[test]
fn arena_keeps_distinct_digest_and_every_current_and_previous_resource_grant() {
    use castalia_wallet_devgraph_presentation::{actor_id, base64url, complete, prepare};
    use ed25519_dalek::{Signer, SigningKey};
    use secs_devgraph_work_contract::{WorkRule, POLICY_SCHEMA};
    let vectors: Vec<Value> = serde_json::from_slice(include_bytes!(
        "../../../server/tests/fixtures/arena-v1/requests.json"
    ))
    .unwrap();
    let signer = SigningKey::from_bytes(&[37; 32]);
    let actor = actor_id(signer.verifying_key().as_bytes());
    let now = 1_800_000_000;
    let key = "arena-portable-fixture-0001";
    for vector in vectors {
        let request = WorkRequest::parse(vector["raw"].as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(request.request_digest(), vector["digest"].as_str().unwrap());
        let prepared = prepare(
            &request,
            key,
            signer.verifying_key().as_bytes(),
            now,
            &[1; 16],
            &[2; 12],
        )
        .unwrap();
        let signature = signer.sign(prepared.signature_transcript()).to_bytes();
        let presentation = complete(prepared, &signature).unwrap();
        assert!(verify_presentation(&request, &presentation, key, now).is_ok());
        let mut policy = WorkPolicy {
            audience: "devgraph://receiver-local".into(),
            policy_id: "arena-fixture".into(),
            policy_version: 1,
            schema: POLICY_SCHEMA.into(),
            schema_version: 1,
            rules: request
                .resources()
                .iter()
                .map(|resource| WorkRule {
                    actor_id: actor.clone(),
                    effect: "allow".into(),
                    not_after: now + 600,
                    not_before: now - 1,
                    operation: request.operation().into(),
                    resource: resource.clone(),
                    resource_match: "exact".into(),
                    status: "active".into(),
                })
                .collect(),
        };
        assert_eq!(
            policy.authorize_until(&actor, &request, now).unwrap(),
            now + 60
        );
        for index in 0..policy.rules.len() {
            let mut missing = policy.clone();
            missing.rules.remove(index);
            assert!(missing.authorize_until(&actor, &request, now).is_err());
        }
        policy.rules[0].effect = "deny".into();
        assert!(policy.authorize_until(&actor, &request, now).is_err());
        // Even a valid wallet signature cannot substitute the Work digest domain.
        let mut forged: Value = serde_json::from_slice(&presentation.canonical().unwrap()).unwrap();
        forged.as_object_mut().unwrap().remove("signature");
        let wrong_domain: &[u8] = if request.value()["schema"] == "devgraph.arena-request.v1" {
            b"devgraph.work-request.v1\0"
        } else {
            b"devgraph.arena-request.v1\0"
        };
        forged["request_digest_sha256"] = json!(devgraph_work_protocol::digest(
            wrong_domain,
            request.canonical()
        ));
        let mut transcript = b"devgraph.work.wallet-presentation.v1/signature\0".to_vec();
        transcript.extend(bytes(&forged));
        forged["signature"] = json!(base64url(&signer.sign(&transcript).to_bytes()));
        let forged = Presentation::parse(&bytes(&forged)).unwrap();
        assert!(verify_presentation(&request, &forged, key, now).is_err());
    }
}

#[test]
fn workflow_attestations_need_every_declared_evidence_resource() {
    use castalia_wallet_devgraph_presentation::{actor_id, complete, prepare};
    use ed25519_dalek::{Signer, SigningKey};
    use secs_devgraph_work_contract::{WorkRule, POLICY_SCHEMA};
    let vectors: Vec<Value> = serde_json::from_str(include_str!("workflow-requests.json")).unwrap();
    let signer = SigningKey::from_bytes(&[37; 32]);
    let actor = actor_id(signer.verifying_key().as_bytes());
    let now = 1_800_000_000;
    let key = "workflow-portable-fixture-0001";
    for v in vectors {
        let request = WorkRequest::parse(v["raw"].as_str().unwrap().as_bytes()).unwrap();
        let prepared = prepare(
            &request,
            key,
            signer.verifying_key().as_bytes(),
            now,
            &[1; 16],
            &[2; 12],
        )
        .unwrap();
        let signature = signer.sign(prepared.signature_transcript()).to_bytes();
        let presentation = complete(prepared, &signature).unwrap();
        assert!(verify_presentation(&request, &presentation, key, now).is_ok());
        let mut policy = WorkPolicy {
            audience: "devgraph://receiver-local".into(),
            policy_id: "workflow-fixture".into(),
            policy_version: 1,
            schema: POLICY_SCHEMA.into(),
            schema_version: 1,
            rules: request
                .resources()
                .iter()
                .map(|resource| WorkRule {
                    actor_id: actor.clone(),
                    effect: "allow".into(),
                    not_after: now + 600,
                    not_before: now - 1,
                    operation: request.operation().into(),
                    resource: resource.clone(),
                    resource_match: "exact".into(),
                    status: "active".into(),
                })
                .collect(),
        };
        assert!(WorkPolicy::parse(&bytes(&policy)).is_ok());
        assert!(policy.authorize_until(&actor, &request, now).is_ok());
        policy.rules.pop();
        assert!(policy.authorize_until(&actor, &request, now).is_err());
    }
}
