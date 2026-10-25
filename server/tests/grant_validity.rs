use serde_json::Value;
use server::grant_validity::GrantValidity;
fn vectors() -> Value {
    serde_json::from_str(include_str!("../../docs/vectors/grant-validity-v1.json")).unwrap()
}
#[test]
fn portable_validity_vectors() {
    let vectors = vectors();
    for case in vectors["valid"].as_array().unwrap() {
        let validity = GrantValidity::parse(case["value"].to_string().as_bytes()).unwrap();
        assert_eq!(serde_json::to_value(&validity).unwrap(), case["value"]);
        for check in case["checks"].as_array().unwrap() {
            assert_eq!(
                validity.contains(check["now"].as_u64().unwrap()),
                check["active"].as_bool().unwrap(),
                "{}",
                case["id"]
            );
        }
        for check in case["deadlines"].as_array().unwrap() {
            let deadline = validity.credential_deadline(
                check["now"].as_u64().unwrap(),
                check["lifetime"].as_u64().unwrap(),
            );
            if check["deadline"].is_null() {
                assert!(deadline.is_err());
            } else {
                assert_eq!(deadline.unwrap(), check["deadline"].as_u64().unwrap());
            }
        }
    }
    for case in vectors["invalid"].as_array().unwrap() {
        assert!(
            GrantValidity::parse(case["raw"].as_str().unwrap().as_bytes()).is_err(),
            "{}",
            case["id"]
        );
        // Embedded serde consumers must be closed too, not only the bounded
        // standalone parser that rejects duplicate JSON globally.
        assert!(
            serde_json::from_str::<GrantValidity>(case["raw"].as_str().unwrap()).is_err(),
            "{}",
            case["id"]
        );
    }
    for case in vectors["subsets"].as_array().unwrap() {
        let child = GrantValidity::parse(case["child"].to_string().as_bytes()).unwrap();
        let parent = GrantValidity::parse(case["parent"].to_string().as_bytes()).unwrap();
        assert_eq!(
            child.contained_by(&parent),
            case["allowed"].as_bool().unwrap()
        );
    }
}
#[test]
fn expired_future_or_unsafe_clock_cannot_mint() {
    let dated = GrantValidity::dated(100, 200).unwrap();
    for (now, lifetime) in [
        (99, 60),
        (200, 60),
        (100, 0),
        (100, 3601),
        (9_007_199_254_740_992, 60),
    ] {
        assert!(dated.credential_deadline(now, lifetime).is_err());
    }
}

#[test]
fn portable_native_policy_digest_matches_python_consumer() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../docs/vectors/standing-native-policy-v2.json"
    ))
    .unwrap();
    let policy = server::devgraph_work_authority::WorkPolicy::parse(
        &serde_json::to_vec(&fixture["policy"]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        policy.digest().unwrap(),
        fixture["digest_sha256"].as_str().unwrap()
    );
}
