use castalia_wallet_presentation::read_authority::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

fn setup() -> (SigningKey, SigningKey, Policy, Claims, Call) {
    // Disposable fixture keys, never installation keys.
    let issuer = SigningKey::from_bytes(&[71; 32]);
    let holder = SigningKey::from_bytes(&[72; 32]);
    let permission = Permission {
        operation: "example.item.list".into(),
        resource: "https://example.test/items".into(),
        constraints: json!({"arenas":["zenith"],"archived":false}),
    };
    let policy = Policy {
        schema: POLICY.into(),
        issuer: "example".into(),
        key_id: "test-key".into(),
        public_key: hex::encode(issuer.verifying_key().to_bytes()),
        receiver: "https://example.test".into(),
        audience: "example".into(),
        permissions: vec![permission.clone()],
        max_lifetime_seconds: 3600,
    };
    let claims = Claims {
        schema: CREDENTIAL.into(),
        credential_id: "ab".repeat(16),
        holder_public_key: hex::encode(holder.verifying_key().to_bytes()),
        installation_id: "cd".repeat(16),
        issuer: policy.issuer.clone(),
        key_id: policy.key_id.clone(),
        receiver: policy.receiver.clone(),
        audience: policy.audience.clone(),
        policy_digest: policy.digest().unwrap(),
        permissions: vec![permission],
        issued_at: 100,
        expires_at: 3700,
    };
    let call = Call {
        operation: "example.item.list".into(),
        resource: "https://example.test/items".into(),
        parameters: json!({"limit":20}),
    };
    (issuer, holder, policy, claims, call)
}

#[test]
fn issuer_policy_holder_and_exact_read_are_bound() {
    let (issuer, holder, policy, claims, call) = setup();
    let credential = issue(&policy, claims, &issuer, 100).unwrap();
    let proof = Proof::unsigned(&credential, &call, "ef".repeat(16), 101).unwrap();
    let signature = holder.sign(&proof.transcript().unwrap());
    let proof = Proof {
        signature: hex::encode(signature.to_bytes()),
        ..proof
    };
    assert!(verify_call(&policy, &credential, &call, &proof, true, 102).is_ok());
    assert!(verify_call(&policy, &credential, &call, &proof, false, 102).is_err());
    assert!(verify_call(&policy, &credential, &call, &proof, true, 162).is_err());
    let mut changed = call.clone();
    changed.parameters["limit"] = json!(100);
    assert!(verify_call(&policy, &credential, &changed, &proof, true, 102).is_err());
    let mut changed = call.clone();
    changed.operation = "example.item.delete".into();
    assert!(verify_call(&policy, &credential, &changed, &proof, true, 102).is_err());
    let mut changed = credential.clone();
    changed.claims.permissions[0].constraints["arenas"] = json!(["other"]);
    assert!(verify_credential(&policy, &changed, 102).is_err());
    let mut changed = policy.clone();
    changed.permissions[0].constraints["archived"] = json!(true);
    assert!(verify_credential(&changed, &credential, 102).is_err());
}

#[test]
fn factory_cannot_expand_policy_or_change_identity_or_expiry() {
    let (issuer, _, policy, claims, _) = setup();
    let mut changed = claims.clone();
    changed.permissions[0].constraints["arenas"] = json!([]);
    assert!(issue(&policy, changed, &issuer, 100).is_err());
    let mut changed = claims.clone();
    changed.expires_at = 3701;
    assert!(issue(&policy, changed, &issuer, 100).is_err());
    let mut changed = claims.clone();
    changed.holder_public_key = "00".repeat(32);
    assert!(issue(&policy, changed, &issuer, 100).is_err());
    assert!(issue(&policy, claims, &SigningKey::from_bytes(&[73; 32]), 100).is_err());
}
