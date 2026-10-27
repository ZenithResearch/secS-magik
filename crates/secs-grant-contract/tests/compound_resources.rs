use secs_grant_contract::{
    Result,
    compound_resources::{
        EffectContract, EffectRule, ResolvedRole, RoleContract, RoleSelection, matching_rule,
    },
    resource_selector::{ResourceRef, ResourceSnapshot, parse_selector},
};
use serde_json::json;
fn reference(kind: &str, id: &str) -> ResourceRef {
    ResourceRef {
        kind: kind.into(),
        id: id.into(),
    }
}
fn contract() -> EffectContract {
    EffectContract {
        service: "media".into(),
        operation: "media:move.v1".into(),
        roles: vec![
            RoleContract {
                name: "subject".into(),
                kinds: vec!["media:Asset".into()],
                minimum: 1,
                maximum: 1,
            },
            RoleContract {
                name: "source".into(),
                kinds: vec!["media:Folder".into()],
                minimum: 1,
                maximum: 1,
            },
            RoleContract {
                name: "destination".into(),
                kinds: vec!["media:Folder".into()],
                minimum: 1,
                maximum: 1,
            },
        ],
    }
}
fn selection(role: &str, kind: &str, id: Option<&str>) -> RoleSelection {
    RoleSelection{role:role.into(),selector:parse_selector(&json!({"schema":"secs.resource-selector.v1","service":"media","kinds":[kind],"selection":match id {Some(id)=>json!({"mode":"objects","refs":[reference(kind,id)]}),None=>json!({"mode":"all"})}}).to_string().into_bytes(),"media").unwrap()}
}
fn rule(from: &str, to: &str) -> EffectRule {
    EffectRule {
        service: "media".into(),
        operation: "media:move.v1".into(),
        roles: vec![
            selection("subject", "media:Asset", None),
            selection("source", "media:Folder", Some(from)),
            selection("destination", "media:Folder", Some(to)),
        ],
    }
}
fn plan(from: &str, to: &str) -> Vec<ResolvedRole> {
    vec![
        ResolvedRole {
            role: "subject".into(),
            resources: vec![reference("media:Asset", "asset-1")],
        },
        ResolvedRole {
            role: "source".into(),
            resources: vec![reference("media:Folder", from)],
        },
        ResolvedRole {
            role: "destination".into(),
            resources: vec![reference("media:Folder", to)],
        },
    ]
}
struct Snapshot;
impl ResourceSnapshot for Snapshot {
    fn exists(&self, _: &str, r: &ResourceRef) -> Result<bool> {
        Ok(r.id != "deleted")
    }
    fn supports_relation(&self, _: &str, _: &str) -> Result<bool> {
        Ok(false)
    }
    fn is_descendant(&self, _: &str, _: &str, _: &ResourceRef, _: &ResourceRef) -> Result<bool> {
        Err("unsupported_relation")
    }
}
#[test]
fn a_to_b_plus_c_to_d_cannot_authorize_a_to_d_or_reverse() {
    let rules = vec![rule("a", "b"), rule("c", "d")];
    assert_eq!(
        matching_rule(&rules, &contract(), &plan("a", "b"), &Snapshot).unwrap(),
        Some(0)
    );
    assert_eq!(
        matching_rule(&rules, &contract(), &plan("c", "d"), &Snapshot).unwrap(),
        Some(1)
    );
    for (from, to) in [("a", "d"), ("c", "b"), ("b", "a")] {
        assert_eq!(
            matching_rule(&rules, &contract(), &plan(from, to), &Snapshot).unwrap(),
            None
        );
    }
    assert!(!rule("a", "d").within(&rules[0], &contract()).unwrap());
    assert!(!rule("a", "d").within(&rules[1], &contract()).unwrap());
    assert!(rules[0].within(&rules[0], &contract()).unwrap());
}
#[test]
fn omitted_duplicate_unknown_or_empty_effects_are_rejected() {
    let rules = vec![rule("a", "b")];
    let c = contract();
    let mut p = plan("a", "b");
    p.pop();
    assert!(matching_rule(&rules, &c, &p, &Snapshot).is_err());
    let mut p = plan("a", "b");
    p.push(p[0].clone());
    assert!(matching_rule(&rules, &c, &p, &Snapshot).is_err());
    let mut p = plan("a", "b");
    p[0].resources.clear();
    assert!(matching_rule(&rules, &c, &p, &Snapshot).is_err());
    let mut p = plan("a", "b");
    p[0].role = "unlisted-effect".into();
    assert!(matching_rule(&rules, &c, &p, &Snapshot).is_err());
    let mut p = plan("a", "b");
    p[0].resources[0].kind = "media:Folder".into();
    assert!(matching_rule(&rules, &c, &p, &Snapshot).is_err());
    let mut r = rule("a", "b");
    r.roles.pop();
    assert!(matching_rule(&[r], &c, &plan("a", "b"), &Snapshot).is_err());
}
#[test]
fn canonical_service_operation_and_live_existence_are_preserved() {
    for field in ["service", "operation"] {
        let mut r = rule("a", "b");
        if field == "service" {
            r.service = "other".into()
        } else {
            r.operation = "media:delete.v1".into()
        };
        assert!(matching_rule(&[r], &contract(), &plan("a", "b"), &Snapshot).is_err());
    }
    assert_eq!(
        matching_rule(
            &[rule("a", "deleted")],
            &contract(),
            &plan("a", "deleted"),
            &Snapshot
        )
        .unwrap(),
        None
    );
}

#[test]
fn postcheck_reuses_one_rule_instead_of_choosing_a_different_parent() {
    let rules = vec![rule("a", "b"), rule("a", "d")];
    let chosen = matching_rule(&rules, &contract(), &plan("a", "b"), &Snapshot)
        .unwrap()
        .unwrap();
    assert!(
        !rules[chosen]
            .permits(&contract(), &plan("a", "d"), &Snapshot)
            .unwrap()
    );
    assert_eq!(
        matching_rule(&rules, &contract(), &plan("a", "d"), &Snapshot).unwrap(),
        Some(1)
    );
}
#[test]
fn every_resource_in_a_multi_target_role_must_match() {
    let mut c = contract();
    c.roles[0].maximum = 4;
    let rules = vec![rule("a", "b")];
    let mut effects = plan("a", "b");
    effects[0]
        .resources
        .push(reference("media:Asset", "asset-2"));
    assert_eq!(
        matching_rule(&rules, &c, &effects, &Snapshot).unwrap(),
        Some(0)
    );
    effects[0]
        .resources
        .push(reference("media:Asset", "deleted"));
    assert_eq!(
        matching_rule(&rules, &c, &effects, &Snapshot).unwrap(),
        None
    );
    effects[0].resources.pop();
    let duplicate = effects[0].resources[0].clone();
    effects[0].resources.push(duplicate);
    assert!(matching_rule(&rules, &c, &effects, &Snapshot).is_err());
}
#[test]
fn selectors_cannot_smuggle_another_service_or_resource_kind_into_an_effect() {
    let mut r = rule("a", "b");
    r.roles[0].selector.service = "other-service".into();
    assert!(matching_rule(&[r], &contract(), &plan("a", "b"), &Snapshot).is_err());
    let mut r = rule("a", "b");
    r.roles[0].selector.kinds.push("secret:Record".into());
    assert!(matching_rule(&[r], &contract(), &plan("a", "b"), &Snapshot).is_err());
    assert_eq!(
        matching_rule(&[], &contract(), &plan("a", "b"), &Snapshot).unwrap(),
        None
    );
}

#[test]
fn effect_contracts_require_a_nonvacuous_bounded_unique_role_set() {
    let mut c = contract();
    for role in &mut c.roles {
        role.minimum = 0;
    }
    assert!(c.validate().is_err());
    let mut c = contract();
    c.roles[0].maximum = 129;
    assert!(c.validate().is_err());
    let mut c = contract();
    c.roles[0].maximum = 0;
    assert!(c.validate().is_err());
    let mut c = contract();
    c.roles.push(c.roles[0].clone());
    assert!(c.validate().is_err());
}
