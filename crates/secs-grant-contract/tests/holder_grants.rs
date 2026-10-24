use ed25519_dalek::SigningKey;
use secs_grant_contract::*;
fn setup() -> (IssuerPin, SigningKey, SigningKey, Grant) {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let holder = SigningKey::from_bytes(&[2; 32]);
    let pin = IssuerPin {
        issuer: "provider:fixture".into(),
        key_id: "issuer:v1".into(),
        public_key: hex::encode(issuer.verifying_key().to_bytes()),
        service: "service:fixture".into(),
    };
    let claims = GrantClaims {
        schema: GRANT.into(),
        grant_id: "11".repeat(16),
        revision: "22".repeat(32),
        issuer: pin.issuer.clone(),
        key_id: pin.key_id.clone(),
        service: pin.service.clone(),
        holder_public_key: hex::encode(holder.verifying_key().to_bytes()),
        installation_id: None,
        validity: Validity::UntilRevoked { not_before: 100 },
        max_credential_lifetime_seconds: 3600,
        onward_delegation: false,
        permissions: vec![Permission {
            operation: "work.read".into(),
            resource: "work".into(),
            scope: Scope::Paths {
                roots: vec![vec![Node {
                    kind: "Arena".into(),
                    id: "a".into(),
                }]],
            },
            constraints: serde_json::json!({"archived":false}),
        }],
    };
    let grant = issue_grant(&pin, claims, &issuer, 100).unwrap();
    (pin, issuer, holder, grant)
}
#[test]
fn same_scope_and_narrower_same_wallet() {
    let (pin, _, holder, g) = setup();
    let c = derive_credential(
        &pin,
        g.clone(),
        g.claims.permissions.clone(),
        None,
        "33".repeat(16),
        101,
        300,
        &holder,
    )
    .unwrap();
    verify_credential(&pin, &c, 102).unwrap();
    let mut narrower = g.claims.permissions.clone();
    if let Scope::Paths { roots } = &mut narrower[0].scope {
        roots[0].push(Node {
            kind: "Project".into(),
            id: "p".into(),
        });
    }
    let c = derive_credential(&pin, g, narrower, None, "44".repeat(16), 101, 300, &holder).unwrap();
    verify_credential(&pin, &c, 102).unwrap();
}
#[test]
fn widening_wrong_holder_and_onward_delegation_denied() {
    let (pin, issuer, holder, g) = setup();
    let mut p = g.claims.permissions.clone();
    p[0].scope = Scope::All;
    assert!(
        derive_credential(&pin, g.clone(), p, None, "33".repeat(16), 101, 300, &holder).is_err()
    );
    let other = SigningKey::from_bytes(&[3; 32]);
    assert!(
        derive_credential(
            &pin,
            g.clone(),
            g.claims.permissions.clone(),
            None,
            "33".repeat(16),
            101,
            300,
            &other
        )
        .is_err()
    );
    let mut claims = g.claims.clone();
    claims.onward_delegation = true;
    assert!(issue_grant(&pin, claims, &issuer, 100).is_err());
}
#[test]
fn expiry_tampering_and_presentation_binding() {
    let (pin, _, holder, g) = setup();
    let c = derive_credential(
        &pin,
        g.clone(),
        g.claims.permissions.clone(),
        None,
        "33".repeat(16),
        101,
        300,
        &holder,
    )
    .unwrap();
    assert!(verify_credential(&pin, &c, 300).is_err());
    let mut bad = c.clone();
    bad.claims.expires_at += 1;
    assert!(verify_credential(&pin, &bad, 102).is_err());
    let call = serde_json::json!({"operation":"work.read","resource":"work","parameters":{"path":"/work"}});
    let proof = present(&pin, &c, &call, "55".repeat(16), 102, &holder).unwrap();
    verify_presentation(&pin, &c, &call, &proof, 103).unwrap();
    assert!(
        verify_presentation(
            &pin,
            &c,
            &serde_json::json!({"operation":"write"}),
            &proof,
            103
        )
        .is_err()
    );
    let mut pin2 = pin.clone();
    pin2.service = "service:other".into();
    assert!(verify_credential(&pin2, &c, 103).is_err());
}
#[test]
fn closed_json_and_finite_parent() {
    assert!(parse::<Grant>(br#"{"claims":{},"claims":{},"signature":"x"}"#).is_err());
    let (pin, issuer, holder, g) = setup();
    let mut claims = g.claims.clone();
    claims.validity = Validity::Dated {
        not_before: 100,
        not_after: 200,
    };
    let g = issue_grant(&pin, claims, &issuer, 100).unwrap();
    assert!(
        derive_credential(
            &pin,
            g.clone(),
            g.claims.permissions.clone(),
            None,
            "33".repeat(16),
            101,
            201,
            &holder
        )
        .is_err()
    );
    assert!(
        derive_credential(
            &pin,
            g.clone(),
            g.claims.permissions.clone(),
            Some("66".repeat(16)),
            "33".repeat(16),
            101,
            200,
            &holder
        )
        .is_ok()
    );
}

#[test]
fn accepted_root_has_room_for_equal_credential_and_transport() {
    let (pin, issuer, holder, grant) = setup();
    let mut claims = grant.claims;
    claims.permissions[0].constraints = serde_json::json!({"padding":"x".repeat(59000)});
    let root = issue_grant(&pin, claims.clone(), &issuer, 100).unwrap();
    let child = derive_credential(
        &pin,
        root.clone(),
        root.claims.permissions.clone(),
        None,
        "33".repeat(16),
        101,
        300,
        &holder,
    )
    .unwrap();
    let call = serde_json::json!({"operation":"work.read","resource":"work","parameters":{}});
    let proof = present(&pin, &child, &call, "44".repeat(16), 102, &holder).unwrap();
    let envelope = serde_json::json!({"credential":child,"call":call,"proof":proof});
    let _: serde_json::Value = parse(&canonical(&envelope).unwrap()).unwrap();
    claims.permissions[0].constraints = serde_json::json!({"padding":"x".repeat(62000)});
    assert!(issue_grant(&pin, claims, &issuer, 100).is_err());
    let mut too_large = call;
    too_large["parameters"] = serde_json::json!({"padding":"x".repeat(20000)});
    assert!(present(&pin, &child, &too_large, "55".repeat(16), 102, &holder).is_err());
}
