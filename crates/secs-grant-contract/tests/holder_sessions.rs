use ed25519_dalek::SigningKey;
use secs_grant_contract::{
    self as c,
    compound_resources::RoleSelection,
    holder_sessions as s,
    resource_selector::{ResourceRef, ResourceSelector, Selection},
    scoped_grants as v2,
};
use serde_json::json;

fn fixture() -> (
    c::IssuerPin,
    SigningKey,
    SigningKey,
    SigningKey,
    v2::Grant,
    s::Challenge,
    s::Context,
) {
    let issuer = SigningKey::from_bytes(&[61; 32]);
    let holder = SigningKey::from_bytes(&[62; 32]);
    let session = SigningKey::from_bytes(&[63; 32]);
    let pin = c::IssuerPin {
        issuer: "provider:example".into(),
        key_id: "key:one".into(),
        service: "service:example".into(),
        public_key: hex::encode(issuer.verifying_key().to_bytes()),
    };
    let permission = v2::Permission {
        operation: "work.get".into(),
        resource: "example:work".into(),
        constraints: json!({"archived":false}),
        roles: vec![RoleSelection {
            role: "target".into(),
            selector: ResourceSelector {
                schema: "secs.resource-selector.v1".into(),
                service: pin.service.clone(),
                kinds: vec!["Task".into()],
                selection: Selection::Objects {
                    refs: vec![ResourceRef {
                        kind: "Task".into(),
                        id: "example".into(),
                    }],
                    within: None,
                },
            },
        }],
    };
    let grant = v2::issue_grant(
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
            validity: c::Validity::Dated {
                not_before: 90,
                not_after: 1000,
            },
            max_credential_lifetime_seconds: 300,
            onward_delegation: false,
            permissions: vec![permission],
        },
        &issuer,
        100,
    )
    .unwrap();
    let context = s::Context {
        origin: "https://graph.example".into(),
        audience: "example".into(),
    };
    let challenge = s::Challenge {
        schema: s::CHALLENGE.into(),
        challenge_id: "33".repeat(16),
        request_id: "44".repeat(16),
        nonce: "55".repeat(32),
        issuer: pin.issuer.clone(),
        key_id: pin.key_id.clone(),
        service: pin.service.clone(),
        origin: context.origin.clone(),
        audience: context.audience.clone(),
        parent_grant_id: grant.claims.grant_id.clone(),
        parent_grant_digest: c::digest(&grant).unwrap(),
        parent_revision: grant.claims.revision.clone(),
        holder_public_key: grant.claims.holder_public_key.clone(),
        installation_id: "66".repeat(16),
        session_installation_id: "77".repeat(16),
        session_public_key: hex::encode(session.verifying_key().to_bytes()),
        permissions: grant.claims.permissions.clone(),
        issued_at: 100,
        review_deadline: 220,
        expires_at: 400,
    };
    (pin, issuer, holder, session, grant, challenge, context)
}

fn issue() -> (
    c::IssuerPin,
    v2::Grant,
    s::Credential,
    SigningKey,
    s::Context,
) {
    let (pin, issuer, holder, session, grant, challenge, context) = fixture();
    let pop = s::prove_possession(&challenge, &session, 101).unwrap();
    let authorization =
        s::authorize(&pin, grant.clone(), challenge, pop, &context, &holder, 101).unwrap();
    let credential = s::issue(
        &pin,
        &authorization,
        "88".repeat(16),
        &context,
        &issuer,
        102,
    )
    .unwrap();
    (pin, grant, credential, session, context)
}

#[test]
fn finite_session_round_trip_contains_no_parent_grant_and_preserves_parent_bytes() {
    let (pin, grant, credential, session, context) = issue();
    let original = c::canonical(&grant).unwrap();
    s::verify_parent(&pin, &grant, &credential, &context, 103).unwrap();
    let call =
        json!({"operation":"work.get","resource":"example:work","parameters":{"id":"example"}});
    let proof = s::present(
        &pin,
        &credential,
        &call,
        "99".repeat(16),
        &context,
        103,
        &session,
    )
    .unwrap();
    s::verify_presentation(&pin, &grant, &credential, &call, &proof, &context, 104).unwrap();
    assert_eq!(original, c::canonical(&grant).unwrap());
    let value = serde_json::to_value(&credential).unwrap();
    assert_eq!(value["claims"]["challenge"]["expires_at"], 400);
    assert!(value.get("parent_grant").is_none());
    assert!(value["claims"].get("grant").is_none());
    assert!(
        !String::from_utf8(c::canonical(&credential).unwrap())
            .unwrap()
            .contains("max_credential_lifetime_seconds")
    );
}

#[test]
fn session_hard_expiry_is_not_extended_by_late_proof_or_repeated_use() {
    let (pin, grant, credential, key, context) = issue();
    let call = json!({"operation":"work.get","resource":"example:work","parameters":{}});
    let proof = s::present(
        &pin,
        &credential,
        &call,
        "99".repeat(16),
        &context,
        399,
        &key,
    )
    .unwrap();
    assert_eq!(proof.expires_at, 400);
    assert!(
        s::verify_presentation(&pin, &grant, &credential, &call, &proof, &context, 400).is_err()
    );
    assert!(
        s::present(
            &pin,
            &credential,
            &call,
            "99".repeat(16),
            &context,
            400,
            &key
        )
        .is_err()
    );
    assert_eq!(credential.claims.challenge.expires_at, 400);
}

#[test]
fn challenge_cannot_exceed_parent_maximum_or_expiry_or_review_deadline() {
    let (pin, _, holder, session, grant, challenge, context) = fixture();
    for (expiry, review) in [(401, 220), (1001, 220), (400, 221), (100, 100)] {
        let mut changed = challenge.clone();
        changed.expires_at = expiry;
        changed.review_deadline = review;
        let pop = s::prove_possession(&changed, &session, 101);
        assert!(
            pop.is_err()
                || s::authorize(
                    &pin,
                    grant.clone(),
                    changed,
                    pop.unwrap(),
                    &context,
                    &holder,
                    101
                )
                .is_err()
        );
    }
    let pop = s::prove_possession(&challenge, &session, 101).unwrap();
    assert!(s::authorize(&pin, grant, challenge, pop, &context, &holder, 220).is_err());
}

#[test]
fn wrong_key_origin_audience_parent_and_permission_changes_fail() {
    let (pin, issuer, holder, session, grant, challenge, context) = fixture();
    let pop = s::prove_possession(&challenge, &session, 101).unwrap();
    let bad_key = SigningKey::from_bytes(&[64; 32]);
    assert!(
        s::authorize(
            &pin,
            grant.clone(),
            challenge.clone(),
            pop.clone(),
            &context,
            &bad_key,
            101
        )
        .is_err()
    );
    assert!(s::prove_possession(&challenge, &holder, 101).is_err());
    for field in [
        "origin",
        "audience",
        "parent_grant_id",
        "parent_revision",
        "parent_grant_digest",
        "session_installation_id",
    ] {
        let mut changed = serde_json::to_value(&challenge).unwrap();
        changed[field] = json!("different");
        let changed: s::Challenge = serde_json::from_value(changed).unwrap();
        assert!(
            s::authorize(
                &pin,
                grant.clone(),
                changed,
                pop.clone(),
                &context,
                &holder,
                101
            )
            .is_err(),
            "{field}"
        );
    }
    let mut changed = challenge.clone();
    changed.permissions[0].operation = "work.delete".into();
    let changed_pop = s::prove_possession(&changed, &session, 101).unwrap();
    assert!(
        s::authorize(
            &pin,
            grant.clone(),
            changed,
            changed_pop,
            &context,
            &holder,
            101
        )
        .is_err()
    );
    let authorization =
        s::authorize(&pin, grant.clone(), challenge, pop, &context, &holder, 101).unwrap();
    let credential = s::issue(
        &pin,
        &authorization,
        "88".repeat(16),
        &context,
        &issuer,
        102,
    )
    .unwrap();
    let mut parent = grant.clone();
    parent.claims.revision = "aa".repeat(32);
    assert!(s::verify_parent(&pin, &parent, &credential, &context, 103).is_err());
    assert!(
        s::verify_credential(
            &pin,
            &credential,
            &s::Context {
                origin: "https://other.example".into(),
                ..context
            },
            103
        )
        .is_err()
    );
}

#[test]
fn parent_installation_and_session_installation_are_distinct_bindings() {
    let (pin, issuer, holder, session, mut grant, challenge, context) = fixture();
    grant.claims.installation_id = Some("aa".repeat(16));
    grant = v2::issue_grant(&pin, grant.claims, &issuer, 100).unwrap();
    let mut challenge = challenge;
    challenge.parent_grant_digest = c::digest(&grant).unwrap();
    let pop = s::prove_possession(&challenge, &session, 101).unwrap();
    assert!(
        s::authorize(
            &pin,
            grant.clone(),
            challenge.clone(),
            pop,
            &context,
            &holder,
            101
        )
        .is_err()
    );
    challenge.installation_id = "aa".repeat(16);
    let pop = s::prove_possession(&challenge, &session, 101).unwrap();
    assert!(s::authorize(&pin, grant, challenge, pop, &context, &holder, 101).is_ok());
}

#[test]
fn old_wire_decoders_reject_new_session_and_unknown_fields_fail_closed() {
    let (_, _, credential, _, _) = issue();
    assert!(c::parse::<v2::Credential>(&c::canonical(&credential).unwrap()).is_err());
    let mut value = serde_json::to_value(credential).unwrap();
    value["claims"]["renew"] = json!(true);
    assert!(c::parse::<s::Credential>(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn signed_interop_vector_matches_all_transcripts() {
    let (pin, issuer, holder, session, grant, challenge, context) = fixture();
    let pop = s::prove_possession(&challenge, &session, 101).unwrap();
    let authorization = s::authorize(
        &pin,
        grant.clone(),
        challenge.clone(),
        pop,
        &context,
        &holder,
        101,
    )
    .unwrap();
    let credential = s::issue(
        &pin,
        &authorization,
        "88".repeat(16),
        &context,
        &issuer,
        102,
    )
    .unwrap();
    let call =
        json!({"operation":"work.get","resource":"example:work","parameters":{"id":"example"}});
    let proof = s::present(
        &pin,
        &credential,
        &call,
        "99".repeat(16),
        &context,
        103,
        &session,
    )
    .unwrap();
    let status = s::prove_status(&challenge, "ab".repeat(16), 103, &session).unwrap();
    let vector = json!({"schema":"secs.holder-session-interop.v1","now":103,"pin":pin,"context":context,
        "parent_grant":grant,"challenge":challenge,"authorization":authorization,"credential":credential,"call":call,"proof":proof,"status":status});
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/holder-session-v1.json")).unwrap();
    assert_eq!(vector, golden);
}

#[test]
fn status_is_bound_to_original_request_and_cannot_extend_hard_expiry() {
    let (_, _, _, session, _, challenge, context) = fixture();
    let proof = s::prove_status(&challenge, "ab".repeat(16), 399, &session).unwrap();
    assert_eq!(proof.expires_at, 400);
    s::verify_status(&challenge, &proof, &context, 399).unwrap();
    assert!(s::verify_status(&challenge, &proof, &context, 400).is_err());
    let mut changed = proof;
    changed.request_id = "bc".repeat(16);
    assert!(s::verify_status(&challenge, &changed, &context, 399).is_err());
}

#[test]
fn issued_token_and_per_call_proof_tampering_fail_without_parent_reinterpretation() {
    let (pin, parent, credential, session, context) = issue();
    let call =
        json!({"operation":"work.get","resource":"example:work","parameters":{"id":"example"}});
    let proof = s::present(
        &pin,
        &credential,
        &call,
        "99".repeat(16),
        &context,
        103,
        &session,
    )
    .unwrap();
    for field in [
        "nonce",
        "signature",
        "call_digest",
        "credential_digest",
        "schema",
    ] {
        let mut raw = serde_json::to_value(&proof).unwrap();
        raw[field] = json!("00");
        let changed: c::Proof = serde_json::from_value(raw).unwrap();
        assert!(
            s::verify_presentation(&pin, &parent, &credential, &call, &changed, &context, 104)
                .is_err()
        );
    }
    let mut changed = credential.clone();
    changed.claims.challenge.expires_at = 401;
    assert!(s::verify_credential(&pin, &changed, &context, 104).is_err());
    let mut changed_call = call.clone();
    changed_call["parameters"]["id"] = json!("hidden");
    assert!(
        s::verify_presentation(
            &pin,
            &parent,
            &credential,
            &changed_call,
            &proof,
            &context,
            104
        )
        .is_err()
    );
    let mut write = call;
    write["operation"] = json!("work.delete");
    assert!(
        s::present(
            &pin,
            &credential,
            &write,
            "aa".repeat(16),
            &context,
            104,
            &session
        )
        .is_err()
    );
}
