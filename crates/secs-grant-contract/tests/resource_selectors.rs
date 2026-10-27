use secs_grant_contract::resource_selector::{
    ResourceRef, ResourceSelector, ResourceSnapshot, parse_selector,
};
use secs_grant_contract::{Result, Scope};
use serde_json::{Value, json};

fn read(value: Value) -> ResourceSelector {
    parse_selector(&serde_json::to_vec(&value).unwrap(), "service-a").unwrap()
}
fn selector(selection: Value) -> Value {
    json!({"schema":"secs.resource-selector.v1","service":"service-a","kinds":["work:Task"],"selection":selection})
}
fn object(id: &str) -> ResourceRef {
    ResourceRef {
        kind: "work:Task".into(),
        id: id.into(),
    }
}
fn guard() -> Value {
    json!({"relation":"work:containment.v1","roots":[{"kind":"work:Project","id":"project-a"}],"include_self":false})
}
struct Snapshot {
    moved: bool,
}
impl ResourceSnapshot for Snapshot {
    fn exists(&self, service: &str, resource: &ResourceRef) -> Result<bool> {
        Ok(service == "service-a" && resource.id != "deleted")
    }
    fn supports_relation(&self, _: &str, relation: &str) -> Result<bool> {
        Ok(relation == "work:containment.v1")
    }
    fn is_descendant(
        &self,
        _: &str,
        _: &str,
        resource: &ResourceRef,
        root: &ResourceRef,
    ) -> Result<bool> {
        if resource.id == "ambiguous" {
            return Err("ambiguous_hierarchy");
        }
        Ok(root.id == "project-a" && resource.kind == "work:Task" && !self.moved)
    }
}
#[test]
fn exact_ids_never_include_children_or_other_kinds_or_services() {
    let s = read(selector(
        json!({"mode":"objects","refs":[object("opaque-123")]}),
    ));
    let db = Snapshot { moved: false };
    assert!(s.permits("service-a", &object("opaque-123"), &db).unwrap());
    assert!(!s.permits("service-a", &object("child"), &db).unwrap());
    assert!(
        !s.permits(
            "service-a",
            &ResourceRef {
                kind: "work:Project".into(),
                id: "opaque-123".into()
            },
            &db
        )
        .unwrap()
    );
    assert!(s.permits("service-b", &object("opaque-123"), &db).is_err());
}
#[test]
fn all_matches_future_instances_of_only_the_named_types() {
    let s = read(selector(json!({"mode":"all"})));
    assert!(
        s.permits(
            "service-a",
            &object("created-later"),
            &Snapshot { moved: false }
        )
        .unwrap()
    );
    assert!(
        !s.permits("service-a", &object("deleted"), &Snapshot { moved: false })
            .unwrap()
    );
}
#[test]
fn hierarchy_to_exact_narrowing_keeps_the_guard_after_moving() {
    let parent = read(selector(json!({"mode":"descendants","hierarchy":guard()})));
    let unguarded = read(selector(json!({"mode":"objects","refs":[object("task")]})));
    let guarded = read(selector(
        json!({"mode":"objects","refs":[object("task")],"within":guard()}),
    ));
    assert!(!unguarded.within(&parent).unwrap());
    assert!(guarded.within(&parent).unwrap());
    assert!(
        guarded
            .permits("service-a", &object("task"), &Snapshot { moved: false })
            .unwrap()
    );
    assert!(
        !guarded
            .permits("service-a", &object("task"), &Snapshot { moved: true })
            .unwrap()
    );
    assert!(!parent.within(&guarded).unwrap());
}
#[test]
fn narrowing_cannot_change_service_type_relation_roots_or_include_self() {
    let parent = read(selector(json!({"mode":"descendants","hierarchy":guard()})));
    for field in ["relation", "roots", "include_self"] {
        let mut value = selector(json!({"mode":"descendants","hierarchy":guard()}));
        value["selection"]["hierarchy"][field] = match field {
            "relation" => json!("other:relation"),
            "roots" => json!([{"kind":"work:Project","id":"project-b"}]),
            _ => json!(true),
        };
        assert!(!read(value).within(&parent).unwrap());
    }
    let mut value = selector(json!({"mode":"all"}));
    value["service"] = json!("service-b");
    let other = parse_selector(&serde_json::to_vec(&value).unwrap(), "service-b").unwrap();
    assert!(
        !other
            .within(&read(selector(json!({"mode":"all"}))))
            .unwrap()
    );
}
#[test]
fn objects_can_narrow_but_cannot_become_a_subtree() {
    let parent = read(selector(
        json!({"mode":"objects","refs":[object("a"),object("b")]}),
    ));
    let child = read(selector(json!({"mode":"objects","refs":[object("a")]})));
    assert!(child.within(&parent).unwrap());
    assert!(!parent.within(&child).unwrap());
    assert!(
        !read(selector(json!({"mode":"descendants","hierarchy":guard()})))
            .within(&parent)
            .unwrap()
    );
}
#[test]
fn unsupported_or_ambiguous_relations_fail_closed_even_for_include_self() {
    let mut g = guard();
    g["relation"] = json!("not-installed");
    g["include_self"] = json!(true);
    g["roots"] = json!([object("task")]);
    let s = read(selector(json!({"mode":"descendants","hierarchy":g})));
    assert!(
        s.permits("service-a", &object("task"), &Snapshot { moved: false })
            .is_err()
    );
    let s = read(selector(json!({"mode":"descendants","hierarchy":guard()})));
    assert!(
        s.permits(
            "service-a",
            &object("ambiguous"),
            &Snapshot { moved: false }
        )
        .is_err()
    );
}
#[test]
fn rejects_unknown_fields_duplicates_empty_sets_and_v1_reinterpretation() {
    for mode in [
        json!({"mode":"objects","refs":[]}),
        json!({"mode":"objects","refs":[object("x"),object("x")]}),
        json!({"mode":"all","include_future":true}),
        json!({"mode":"descendants","hierarchy":{"relation":"r","roots":[],"include_self":false}}),
    ] {
        assert!(
            parse_selector(&serde_json::to_vec(&selector(mode)).unwrap(), "service-a").is_err()
        );
    }
    let raw = r#"{"schema":"secs.resource-selector.v1","service":"service-a","service":"service-a","kinds":["work:Task"],"selection":{"mode":"all"}}"#;
    assert!(parse_selector(raw.as_bytes(), "service-a").is_err());
    assert!(
        serde_json::from_value::<Scope>(json!({"mode":"objects","refs":[object("x")]})).is_err()
    );
    let mut value = selector(json!({"mode":"objects","refs":[object("x")]}));
    value["kinds"] = json!(["work:Project"]);
    assert!(parse_selector(&serde_json::to_vec(&value).unwrap(), "service-a").is_err());
}

#[test]
fn structurally_accepted_narrowing_preserves_evaluated_subset_across_moves() {
    let mut cases = vec![read(selector(json!({"mode":"all"})))];
    for refs in [
        vec![object("a")],
        vec![object("b")],
        vec![object("a"), object("b")],
    ] {
        cases.push(read(selector(json!({"mode":"objects","refs":refs}))));
        cases.push(read(selector(
            json!({"mode":"objects","refs":refs,"within":guard()}),
        )));
    }
    cases.push(read(selector(
        json!({"mode":"descendants","hierarchy":guard()}),
    )));
    for child in &cases {
        for parent in &cases {
            if child.within(parent).unwrap() {
                for moved in [false, true] {
                    for target in ["a", "b", "other", "created-later", "deleted"] {
                        let db = Snapshot { moved };
                        if child.permits("service-a", &object(target), &db).unwrap() {
                            assert!(parent.permits("service-a", &object(target), &db).unwrap());
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn bound_sizes_and_kind_sets_are_closed() {
    let mut v = selector(json!({"mode":"all"}));
    for kinds in [vec![], vec!["work:Task"; 2], vec!["x"; 17]] {
        v["kinds"] = json!(kinds);
        assert!(parse_selector(&serde_json::to_vec(&v).unwrap(), "service-a").is_err());
    }
    let refs: Vec<_> = (0..129).map(|i| object(&format!("id-{i}"))).collect();
    assert!(
        parse_selector(
            &serde_json::to_vec(&selector(json!({"mode":"objects","refs":refs}))).unwrap(),
            "service-a"
        )
        .is_err()
    );
    let mut v = selector(json!({"mode":"all"}));
    v["schema"] = json!("secs.resource-selector.v2");
    assert!(parse_selector(&serde_json::to_vec(&v).unwrap(), "service-a").is_err());
}

#[test]
fn media_vectors_use_the_same_service_neutral_narrowing() {
    let vectors: Value =
        serde_json::from_str(include_str!("fixtures/resource-selectors.json")).unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let service = case["service"].as_str().unwrap();
        let child = parse_selector(&serde_json::to_vec(&case["child"]).unwrap(), service).unwrap();
        let parent =
            parse_selector(&serde_json::to_vec(&case["parent"]).unwrap(), service).unwrap();
        assert_eq!(
            child.within(&parent).unwrap(),
            case["within"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}
