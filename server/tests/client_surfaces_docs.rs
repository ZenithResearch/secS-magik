use std::fs;
use std::path::PathBuf;

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative)
}

fn client_surface_docs() -> String {
    fs::read_to_string(repo_path("docs/client-surfaces.md"))
        .expect("docs/client-surfaces.md should document client-side surfaces")
}

#[test]
fn client_surfaces_doc_covers_required_roles_and_flow() {
    let docs = client_surface_docs();
    let lower = docs.to_lowercase();

    for required_concept in [
        "local hermes",
        "secs tool/script/skill",
        "secc",
        "generic/non-zenith client",
        "secz",
        "zenith-oriented",
        "client-side",
        "call secs",
        "secs-magik / secs remains the verifier",
        "none of them replaces secs-magik verification",
        "core/src/packet_builder.rs",
    ] {
        assert!(
            lower.contains(required_concept),
            "missing required client-surface concept: {required_concept}"
        );
    }

    for flow_term in [
        "user / local hermes / app / node intent",
        "operation name / local opcode / target node",
        "capability / credential / evidence refs",
        "zenithpacket",
        "target secs rpc surface",
    ] {
        assert!(lower.contains(flow_term), "missing flow term: {flow_term}");
    }
}

#[test]
fn client_surfaces_doc_keeps_secz_mentions_negated_when_near_verifier_or_castalia_claims() {
    let docs = client_surface_docs();

    for line in docs.lines().map(str::trim).filter(|line| {
        let lower = line.to_lowercase();
        lower.contains("secz") && !lower.starts_with("->")
    }) {
        let lower = line.to_lowercase().replace("verifier-free", "");
        let dangerous_claim = [
            "verifier",
            "verifies",
            "authority",
            "authoritative",
            "generic castalia",
            "castalia interface",
            "replaces secs",
            "replaces secs-magik",
        ]
        .iter()
        .any(|term| lower.contains(term));

        if dangerous_claim {
            let negated = [
                "not",
                "does not",
                "should not",
                "without becoming",
                "none of",
            ]
            .iter()
            .any(|term| lower.contains(term));
            assert!(
                negated,
                "secZ line makes an unnegated verifier/Castalia/authority claim: {line}"
            );
        }
    }
}

#[test]
fn implementation_status_marks_packet_builder_as_present_and_verifier_free() {
    let status = fs::read_to_string(repo_path("docs/implementation-status.md"))
        .expect("implementation status should exist");
    let lower = status.to_lowercase();

    assert!(lower.contains("packet-builder helper"));
    assert!(lower.contains("solid / implemented as verifier-free construction helper"));
    assert!(
        !lower.contains("packet-builder helper | `core/src/packet_builder.rs` | optional planned")
    );
}
