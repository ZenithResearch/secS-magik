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

#[test]
fn access_point_binding_authenticates_route_without_changing_grant_scope() {
    let (pin, issuer, _, grant) = setup();
    let claims = AccessPointClaims {
        schema: ACCESS_POINT.into(),
        issuer: pin.issuer.clone(),
        key_id: pin.key_id.clone(),
        service: pin.service.clone(),
        origin: "https://graph.example:9443".into(),
        authority_receiver: "https://127.0.0.1:58754".into(),
        prefix: "/service/v1".into(),
        not_before: 100,
        not_after: 1000,
    };
    let binding = issue_access_point(&pin, claims, &issuer, 101).unwrap();
    verify_access_point(&pin, &binding, "https://graph.example:9443", 102).unwrap();
    assert!(verify_access_point(&pin, &binding, "https://evil.example", 102).is_err());
    let mut other = pin.clone();
    other.service = "service:other".into();
    assert!(verify_access_point(&other, &binding, &binding.claims.origin, 102).is_err());
    let mut changed = binding.clone();
    changed.claims.authority_receiver = "https://evil.example".into();
    assert!(verify_access_point(&pin, &changed, &binding.claims.origin, 102).is_err());
    assert!(verify_access_point(&pin, &binding, &binding.claims.origin, 1000).is_err());
    verify_grant(&pin, &grant, 102).unwrap();
}

#[test]
fn access_point_binding_rejects_ambiguous_origins_and_arbitrary_dispatch_paths() {
    let (pin, issuer, _, _) = setup();
    for origin in [
        "http://graph.example",
        "https://user@graph.example",
        "https://graph.example/path",
        "https://graph.example?x=1",
        "https://graph.example/",
        "https://graph.example#x",
    ] {
        let claims = AccessPointClaims {
            schema: ACCESS_POINT.into(),
            issuer: pin.issuer.clone(),
            key_id: pin.key_id.clone(),
            service: pin.service.clone(),
            origin: origin.into(),
            authority_receiver: "https://127.0.0.1:58754".into(),
            prefix: "/service/v1".into(),
            not_before: 100,
            not_after: 1000,
        };
        assert!(
            issue_access_point(&pin, claims, &issuer, 101).is_err(),
            "{origin}"
        );
    }
}

#[test]
fn access_point_cross_language_golden_vector() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/access-point.json")).unwrap();
    let pin: IssuerPin = serde_json::from_value(v["pin"].clone()).unwrap();
    let binding: AccessPointBinding = serde_json::from_value(v["binding"].clone()).unwrap();
    verify_access_point(&pin, &binding, &binding.claims.origin, 102).unwrap();
    assert_eq!(
        issue_access_point(
            &pin,
            binding.claims.clone(),
            &SigningKey::from_bytes(&[1; 32]),
            102
        )
        .unwrap(),
        binding
    );
}

#[test]
fn independent_action_hierarchies_are_not_a_cartesian_product() {
    let (pin, issuer, holder, original) = setup();
    let mut claims = original.claims;
    let read = claims.permissions[0].clone();
    let mut write = read.clone();
    write.operation = "work.patch".into();
    write.scope = Scope::Paths {
        roots: vec![vec![Node {
            kind: "Arena".into(),
            id: "b".into(),
        }]],
    };
    claims.permissions = vec![read.clone(), write.clone()];
    let grant = issue_grant(&pin, claims, &issuer, 100).unwrap();
    let derive = |permissions| {
        derive_credential(
            &pin,
            grant.clone(),
            permissions,
            None,
            "33".repeat(16),
            101,
            300,
            &holder,
        )
    };
    let equal = derive(vec![read.clone(), write.clone()]).unwrap();
    verify_credential(&pin, &equal, 102).unwrap();
    let mut narrow = write.clone();
    if let Scope::Paths { roots } = &mut narrow.scope {
        roots[0].push(Node {
            kind: "Project".into(),
            id: "p".into(),
        });
    }
    verify_credential(&pin, &derive(vec![narrow]).unwrap(), 102).unwrap();
    let mut mixed = write.clone();
    mixed.scope = read.scope.clone();
    assert!(
        derive(vec![mixed]).is_err(),
        "write-B cannot borrow read-A's scope"
    );
    let mut mixed = read;
    mixed.scope = write.scope;
    assert!(
        derive(vec![mixed]).is_err(),
        "read-A cannot borrow write-B's scope"
    );
    let mut relaxed = grant.claims.permissions.clone();
    relaxed[0].constraints = serde_json::json!({});
    assert!(
        derive(relaxed).is_err(),
        "opaque provider conditions must remain exact"
    );
    let mut delegated = grant.claims.clone();
    delegated.onward_delegation = true;
    assert!(issue_grant(&pin, delegated, &issuer, 100).is_err());
}

#[test]
fn live_collection_scope_is_not_an_issuance_time_inventory() {
    let (pin, issuer, holder, original) = setup();
    let mut claims = original.claims;
    claims.permissions[0].scope = Scope::All;
    claims.permissions[0].operation = "catalog.item.get".into();
    // Generic provider conditions stay opaque and exact; no object IDs are
    // copied into the signed root to simulate collection coverage.
    let root = issue_grant(&pin, claims, &issuer, 100).unwrap();
    let same = derive_credential(
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
    verify_credential(&pin, &same, 102).unwrap();
    let mut narrowed = root.claims.permissions.clone();
    narrowed[0].scope = Scope::Paths {
        roots: vec![vec![Node {
            kind: "CollectionItem".into(),
            id: "created-later".into(),
        }]],
    };
    let fixed = derive_credential(
        &pin,
        root.clone(),
        narrowed.clone(),
        None,
        "44".repeat(16),
        102,
        300,
        &holder,
    )
    .unwrap();
    verify_credential(&pin, &fixed, 103).unwrap();
    assert!(permissions_within(&root.claims.permissions, &narrowed).is_err());
    assert_eq!(same.claims.permissions[0].scope, Scope::All);
    assert!(!root.claims.onward_delegation);
}
