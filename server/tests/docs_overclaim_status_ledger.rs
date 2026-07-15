use serde::Deserialize;

const LEDGER: &str = include_str!("fixtures/dregg_negative_matrix_status_ledger.yaml");
const README: &str = include_str!("../../README.md");
const DOCS_README: &str = include_str!("../../docs/README.md");
const SERVER_README: &str = include_str!("../../server/README.md");
const EXAMPLES_README: &str = include_str!("../../examples/README.md");
const DOCS_SPECS_README: &str = include_str!("../../docs/specs/README.md");
const IMPLEMENTATION_STATUS: &str = include_str!("../../docs/implementation-status.md");
const DREGG_AUTHORITY_SPEC: &str = include_str!("../../docs/specs/dregg-authority-rail.md");
const DREGG_LIVE_SOURCE_SPEC: &str =
    include_str!("../../docs/specs/dregg-live-source-client-contract.md");
const EVIDENCE_ADAPTER_DISCLOSURE_SPEC: &str =
    include_str!("../../docs/specs/evidence-adapter-readiness-disclosure.md");
const M15_DEMO_README: &str = include_str!("../../examples/m15-dregg-authority-demo/README.md");

#[derive(Debug, Deserialize)]
struct Ledger {
    rows: Vec<Row>,
}

#[derive(Debug, Deserialize)]
struct Row {
    row_id: String,
    owner_issue: String,
    docs_wording_allowed: String,
    docs_wording_examples_allowed: Vec<String>,
    docs_wording_examples_forbidden: Vec<String>,
}

fn ledger() -> Ledger {
    serde_yaml::from_str(LEDGER).expect("ledger should parse")
}

fn forbidden_overclaims(text: &str, rows: &[Row]) -> Vec<String> {
    let lowered = text.to_ascii_lowercase();
    let mut violations = Vec::new();
    for row in rows {
        if row.docs_wording_allowed == "implemented" {
            continue;
        }
        for forbidden in &row.docs_wording_examples_forbidden {
            if lowered.contains(&forbidden.to_ascii_lowercase()) {
                violations.push(format!(
                    "{} owned by {} forbids wording stronger than {}: {}",
                    row.row_id, row.owner_issue, row.docs_wording_allowed, forbidden
                ));
            }
        }
    }
    violations
}

#[test]
fn docs_overclaim_status_ledger_rejects_stronger_than_ledger_fixtures() {
    let rows = ledger().rows;
    for (fixture, expected_owner) in [
        (
            "The demo provides implemented federated finality for committee roots.",
            "I17",
        ),
        (
            "Anonymous wallets are not individually identifiable by default.",
            "I06",
        ),
        (
            "The M15 README demonstrates light-client verified Dregg roots using the VK registry.",
            "I18",
        ),
        (
            "Recursive proof-carrying state is implemented for state transitions.",
            "I19",
        ),
        (
            "The system provides audit without surveillance for private holder activity.",
            "I09",
        ),
    ] {
        let violations = forbidden_overclaims(fixture, &rows);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(expected_owner)),
            "fixture should fail with owner {expected_owner}; got {violations:?}"
        );
    }
}

#[test]
fn docs_overclaim_status_ledger_allows_downgraded_fixture_wording() {
    let rows = ledger().rows;
    let allowed = rows
        .iter()
        .flat_map(|row| row.docs_wording_examples_allowed.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    let violations = forbidden_overclaims(&allowed, &rows);
    assert!(
        violations.is_empty(),
        "allowed wording should not trip overclaim checker: {violations:?}"
    );
}

#[test]
fn docs_overclaim_status_ledger_current_docs_do_not_use_forbidden_stronger_claims() {
    let rows = ledger().rows;
    // Scan current-facing public/status/spec surfaces only. Canonical ledger,
    // issue-discovery, broad plans, and test-fixture files intentionally contain
    // forbidden phrases as negative examples and stay excluded until the checker
    // supports row-owned scoped negative-example contexts.
    let docs = [
        ("README.md", README),
        ("docs/README.md", DOCS_README),
        ("server/README.md", SERVER_README),
        ("examples/README.md", EXAMPLES_README),
        ("docs/specs/README.md", DOCS_SPECS_README),
        ("docs/implementation-status.md", IMPLEMENTATION_STATUS),
        ("docs/specs/dregg-authority-rail.md", DREGG_AUTHORITY_SPEC),
        (
            "docs/specs/dregg-live-source-client-contract.md",
            DREGG_LIVE_SOURCE_SPEC,
        ),
        (
            "docs/specs/evidence-adapter-readiness-disclosure.md",
            EVIDENCE_ADAPTER_DISCLOSURE_SPEC,
        ),
        (
            "examples/m15-dregg-authority-demo/README.md",
            M15_DEMO_README,
        ),
    ];
    let mut violations = Vec::new();
    for (name, text) in docs {
        for violation in forbidden_overclaims(text, &rows) {
            violations.push(format!("{name}: {violation}"));
        }
    }
    assert!(
        violations.is_empty(),
        "docs overclaim ledger violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn dregg_claim_surfaces_require_runtime_installation_and_deny_public_proof() {
    let readme = README.to_ascii_lowercase();
    let status = IMPLEMENTATION_STATUS.to_ascii_lowercase();
    let readiness = EVIDENCE_ADAPTER_DISCLOSURE_SPEC.to_ascii_lowercase();

    assert!(readme.contains("public_proof: false"));
    assert!(status.contains("not installed by production gateway"));
    assert!(status.contains("fixture/test-only and non-public-proof"));
    assert!(readiness.contains("concrete runtime adapter instance"));
    assert!(readiness.contains("configuration files alone"));
}
