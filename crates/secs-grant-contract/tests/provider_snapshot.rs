use secs_grant_contract::{provider_snapshot::*, resource_selector::*};
#[test]
fn provider_witnesses_are_bounded_and_never_cross_services() {
    let root = ResourceRef {
        kind: "Arena".into(),
        id: "a".into(),
    };
    let target = ResourceRef {
        kind: "Task".into(),
        id: "t".into(),
    };
    let mut snapshot = ProviderSnapshot {
        service: "service:a".into(),
        relation: "contains".into(),
        resources: vec![
            ResourceWitness {
                resource: root.clone(),
                ancestors: vec![],
            },
            ResourceWitness {
                resource: target.clone(),
                ancestors: vec![root.clone()],
            },
        ],
    };
    assert!(
        snapshot
            .is_descendant("service:a", "contains", &target, &root)
            .unwrap()
    );
    assert!(
        snapshot
            .is_descendant("service:b", "contains", &target, &root)
            .is_err()
    );
    snapshot.resources.push(snapshot.resources[0].clone());
    assert!(snapshot.validate().is_err());
    snapshot.resources.pop();
    snapshot.resources[1].ancestors.push(target);
    assert!(snapshot.validate().is_err());
}
