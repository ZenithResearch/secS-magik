use std::fs;
use std::path::PathBuf;

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative)
}

#[test]
fn client_surfaces_doc_states_outgoing_surfaces_are_not_verifiers() {
    let docs = fs::read_to_string(repo_path("docs/client-surfaces.md"))
        .expect("docs/client-surfaces.md should document client-side surfaces");

    for required in [
        "local Hermes secS tool/script/skill",
        "secC generic/non-Zenith client form",
        "secZ Zenith-oriented outgoing client surface",
        "client-side ways to call secS",
        "secS-magik / secS remains the verifier and permissioned RPC substrate",
        "none of them replaces secS-magik verification",
    ] {
        assert!(
            docs.contains(required),
            "missing required boundary phrase: {required}"
        );
    }

    assert!(docs.contains("user / local Hermes / app / node intent"));
    assert!(docs.contains("-> ZenithPacket"));
    assert!(docs.contains("-> target secS RPC surface"));
}

#[test]
fn client_surfaces_doc_does_not_regress_secz_into_castalia_interface_or_verifier() {
    let docs = fs::read_to_string(repo_path("docs/client-surfaces.md"))
        .expect("docs/client-surfaces.md should document client-side surfaces");
    let lower = docs.to_lowercase();

    for forbidden in [
        "secz is the generic castalia interface",
        "secz is the verifier",
        "secz replaces secs",
        "secz replaces secs-magik",
    ] {
        assert!(
            !lower.contains(forbidden),
            "forbidden boundary regression: {forbidden}"
        );
    }
}
