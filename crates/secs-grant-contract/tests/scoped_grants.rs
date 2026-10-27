use ed25519_dalek::SigningKey;
use secs_grant_contract::{
    self as v1, compound_resources::RoleSelection, resource_selector::*, scoped_grants as v2,
};
use serde_json::json;
fn selector(id: &str) -> ResourceSelector {
    ResourceSelector {
        schema: SCHEMA.into(),
        service: "service:graph".into(),
        kinds: vec!["Arena".into()],
        selection: Selection::Objects {
            refs: vec![ResourceRef {
                kind: "Arena".into(),
                id: id.into(),
            }],
            within: None,
        },
    }
}
fn permission(a: &str, b: &str) -> v2::Permission {
    v2::Permission {
        operation: "work.move".into(),
        resource: "graph".into(),
        constraints: json!({}),
        roles: vec![
            RoleSelection {
                role: "source".into(),
                selector: selector(a),
            },
            RoleSelection {
                role: "destination".into(),
                selector: selector(b),
            },
        ],
    }
}
fn fixture() -> (v1::IssuerPin, v2::Grant, SigningKey) {
    let issuer = SigningKey::from_bytes(&[41; 32]);
    let holder = SigningKey::from_bytes(&[42; 32]);
    let pin = v1::IssuerPin {
        issuer: "provider".into(),
        key_id: "key".into(),
        service: "service:graph".into(),
        public_key: hex::encode(issuer.verifying_key().to_bytes()),
    };
    let g = v2::issue_grant(
        &pin,
        v2::GrantClaims {
            schema: v2::GRANT.into(),
            grant_id: "11".repeat(16),
            revision: "22".repeat(32),
            issuer: pin.issuer.clone(),
            key_id: pin.key_id.clone(),
            service: pin.service.clone(),
            holder_public_key: hex::encode(holder.verifying_key().to_bytes()),
            installation_id: None,
            validity: v1::Validity::UntilRevoked { not_before: 100 },
            max_credential_lifetime_seconds: 600,
            onward_delegation: false,
            permissions: vec![permission("A", "B"), permission("C", "D")],
        },
        &issuer,
        100,
    )
    .unwrap();
    (pin, g, holder)
}
#[test]
fn equal_scope_credential_and_presentation_round_trip() {
    let (pin, g, k) = fixture();
    let p = g.claims.permissions.clone();
    let c = v2::derive_credential(
        &pin,
        g,
        p,
        Some("ab".repeat(16)),
        "cd".repeat(16),
        100,
        200,
        &k,
    )
    .unwrap();
    let call = json!({"operation":"work.move","resource":"graph","parameters":{"id":"object"}});
    let proof = v2::present(&pin, &c, &call, "ef".repeat(16), 101, &k).unwrap();
    v2::verify_presentation(&pin, &c, &call, &proof, 102).unwrap();
    assert!(v2::verify_presentation(&pin, &c, &json!({"operation":"other"}), &proof, 102).is_err());
    let mut swapped = c.clone();
    swapped.claims.schema = v1::CREDENTIAL.into();
    assert!(v2::verify_credential(&pin, &swapped, 102).is_err());
    assert!(v1::parse::<v1::Credential>(&serde_json::to_vec(&c).unwrap()).is_err());
}
#[test]
fn derivation_never_mixes_pairs_removes_guard_or_changes_holder() {
    let (pin, g, k) = fixture();
    assert!(
        v2::derive_credential(
            &pin,
            g.clone(),
            vec![permission("A", "D")],
            None,
            "cd".repeat(16),
            100,
            200,
            &k
        )
        .is_err()
    );
    let other = SigningKey::from_bytes(&[43; 32]);
    assert!(
        v2::derive_credential(
            &pin,
            g.clone(),
            g.claims.permissions.clone(),
            None,
            "cd".repeat(16),
            100,
            200,
            &other
        )
        .is_err()
    );
    let mut parent = permission("A", "B");
    parent.roles[0].selector.selection = Selection::Descendants {
        hierarchy: Hierarchy {
            relation: "contains".into(),
            roots: vec![ResourceRef {
                kind: "Arena".into(),
                id: "A".into(),
            }],
            include_self: true,
        },
    };
    let child = permission("A", "B");
    assert!(v2::permissions_within(&[child], &[parent]).is_err());
    let mut wrong = permission("A", "B");
    wrong.roles[0].selector.service = "other".into();
    assert!(v2::permissions_within(&[wrong], &g.claims.permissions).is_err());
}
#[test]
fn closed_roles_and_expiry_fail_closed() {
    let (pin, g, k) = fixture();
    let mut duplicate = permission("A", "B");
    duplicate.roles.push(duplicate.roles[0].clone());
    assert!(duplicate.validate(&pin.service).is_err());
    let c = v2::derive_credential(
        &pin,
        g.clone(),
        vec![permission("A", "B")],
        None,
        "cd".repeat(16),
        100,
        200,
        &k,
    )
    .unwrap();
    assert!(v2::verify_credential(&pin, &c, 200).is_err());
    let raw = serde_json::to_string(&g)
        .unwrap()
        .replace("\"roles\":", "\"scope\":{},\"roles\":");
    assert!(v1::parse::<v2::Grant>(raw.as_bytes()).is_err());
}
