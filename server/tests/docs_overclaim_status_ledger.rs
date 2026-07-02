use serde::Deserialize;

const LEDGER: &str = include_str!("fixtures/dregg_negative_matrix_status_ledger.yaml");
const README: &str = include_str!("../../README.md");
const IMPLEMENTATION_STATUS: &str = include_str!("../../docs/implementation-status.md");
const DREGG_AUTHORITY_SPEC: &str = include_str!("../../docs/specs/dregg-authority-rail.md");
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
    let docs = [
        ("README.md", README),
        ("docs/implementation-status.md", IMPLEMENTATION_STATUS),
        ("docs/specs/dregg-authority-rail.md", DREGG_AUTHORITY_SPEC),
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
