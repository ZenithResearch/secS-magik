use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const LEDGER: &str = include_str!("fixtures/dregg_negative_matrix_status_ledger.yaml");
const OWNER_ISSUES: &[&str] = &[
    "I01", "I02", "I03", "I04", "I05", "I06", "I07", "I08", "I09", "I10", "I11", "I12", "I13",
    "I14", "I15", "I16", "I17", "I18", "I19", "I20", "I21",
];
const STATUSES: &[&str] = &[
    "implemented",
    "proposed",
    "missing",
    "blocked",
    "provisional",
    "not_applicable",
];
const DOCS_WORDING_ALLOWED: &[&str] = &[
    "implemented",
    "fixture_only",
    "provisional",
    "target",
    "future",
    "blocked",
    "not_mentioned",
];
const NON_IMPLEMENTED_STATUSES: &[&str] = &["proposed", "missing", "blocked", "provisional"];
const PRIVACY_SURFACES: &[&str] = &[
    "receipt",
    "handler_context",
    "logs_traces",
    "readiness_status",
    "demo_ui",
    "public_proof_artifacts",
];
const REQUIRED_SEED_ROWS: &[&str] = &[
    "signed_source_runtime_wireup",
    "federation_checkpoint_not_finality_until_rollback_state",
    "anonymous_unlinkable_membership_blocked_until_i06",
    "light_client_verified_requires_i18_not_i08_metadata",
    "recursive_proof_carrying_state_future",
];

#[derive(Debug, Deserialize)]
struct Ledger {
    schema_version: u64,
    generated_from_issue: String,
    last_schema_reviewed_date: String,
    rows: Vec<Row>,
}

#[derive(Debug, Deserialize)]
struct Row {
    row_id: String,
    claim: String,
    claim_guarded: String,
    claim_terms: Vec<String>,
    current_tier: String,
    owner_issue: String,
    status: String,
    evidence_refs: Vec<String>,
    test_command: String,
    test_name: String,
    expected_reason_code: String,
    is_rejection_row: bool,
    handler_did_not_run_expected: bool,
    docs_wording_allowed: String,
    docs_wording_examples_allowed: Vec<String>,
    docs_wording_examples_forbidden: Vec<String>,
    privacy_guard_expected: PrivacyGuardExpected,
    blocking_dependencies: Vec<String>,
    last_verified_date: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct PrivacyGuardExpected {
    receipt: String,
    handler_context: String,
    logs_traces: String,
    readiness_status: String,
    demo_ui: String,
    public_proof_artifacts: String,
}

fn load_ledger(text: &str) -> Ledger {
    serde_yaml::from_str(text).expect("ledger should parse as YAML")
}

fn validate_ledger(ledger: &Ledger) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if ledger.schema_version != 1 {
        errors.push(format!(
            "schema_version must be 1, got {}",
            ledger.schema_version
        ));
    }
    if ledger.generated_from_issue != "I10" {
        errors.push(format!(
            "generated_from_issue must be I10, got {}",
            ledger.generated_from_issue
        ));
    }
    if !is_iso_date_or_never(&ledger.last_schema_reviewed_date)
        || ledger.last_schema_reviewed_date == "never"
    {
        errors.push("last_schema_reviewed_date must be an ISO date".to_string());
    }
    if ledger.rows.is_empty() {
        errors.push("ledger must contain rows".to_string());
    }

    let mut row_ids = BTreeSet::new();
    for row in &ledger.rows {
        validate_row(row, &mut row_ids, &mut errors);
    }

    for required in REQUIRED_SEED_ROWS {
        if !row_ids.contains(*required) {
            errors.push(format!("missing required seed row {required}"));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_row(row: &Row, row_ids: &mut BTreeSet<String>, errors: &mut Vec<String>) {
    if row.row_id.trim().is_empty() {
        errors.push("row_id must not be empty".to_string());
    } else if !row_ids.insert(row.row_id.clone()) {
        errors.push(format!("{}: duplicate row_id", row.row_id));
    }
    for (field, value) in [
        ("claim", &row.claim),
        ("claim_guarded", &row.claim_guarded),
        ("current_tier", &row.current_tier),
        ("expected_reason_code", &row.expected_reason_code),
        ("docs_wording_allowed", &row.docs_wording_allowed),
    ] {
        if value.trim().is_empty() {
            errors.push(format!("{}: {field} must not be empty", row.row_id));
        }
    }
    if row.claim_terms.is_empty() {
        errors.push(format!("{}: claim_terms must not be empty", row.row_id));
    }
    if !OWNER_ISSUES.contains(&row.owner_issue.as_str()) {
        errors.push(format!(
            "{}: invalid owner_issue {}",
            row.row_id, row.owner_issue
        ));
    }
    if !STATUSES.contains(&row.status.as_str()) {
        errors.push(format!("{}: invalid status {}", row.row_id, row.status));
    }
    if !DOCS_WORDING_ALLOWED.contains(&row.docs_wording_allowed.as_str()) {
        errors.push(format!(
            "{}: invalid docs_wording_allowed {}",
            row.row_id, row.docs_wording_allowed
        ));
    }
    if NON_IMPLEMENTED_STATUSES.contains(&row.status.as_str())
        && row.docs_wording_allowed == "implemented"
    {
        errors.push(format!(
            "{}: non-implemented row cannot allow implemented docs wording",
            row.row_id
        ));
    }
    if row.status == "implemented" {
        if row.evidence_refs.is_empty() {
            errors.push(format!(
                "{}: implemented row requires evidence_refs",
                row.row_id
            ));
        }
        if row.test_command.trim().is_empty() || row.test_name.trim().is_empty() {
            errors.push(format!(
                "{}: implemented row requires test command/name",
                row.row_id
            ));
        }
        if !is_iso_date_or_never(&row.last_verified_date) || row.last_verified_date == "never" {
            errors.push(format!(
                "{}: implemented row requires ISO last_verified_date",
                row.row_id
            ));
        }
    }
    if matches!(row.status.as_str(), "proposed" | "blocked" | "provisional") {
        if row.test_command.trim().is_empty() || row.test_name.trim().is_empty() {
            errors.push(format!(
                "{}: proposed/blocked/provisional row requires proposed command/name",
                row.row_id
            ));
        }
        if row.blocking_dependencies.is_empty() {
            errors.push(format!(
                "{}: proposed/blocked/provisional row requires blocking_dependencies",
                row.row_id
            ));
        }
    }
    if row.is_rejection_row {
        if row.expected_reason_code.trim().is_empty()
            || row.expected_reason_code == "not_applicable"
        {
            errors.push(format!(
                "{}: rejection row requires expected_reason_code",
                row.row_id
            ));
        }
        if !row.handler_did_not_run_expected {
            errors.push(format!(
                "{}: rejection row requires handler_did_not_run_expected",
                row.row_id
            ));
        }
    }
    if row.docs_wording_examples_allowed.is_empty() {
        errors.push(format!(
            "{}: docs_wording_examples_allowed must not be empty",
            row.row_id
        ));
    }
    if row.docs_wording_examples_forbidden.is_empty() && row.docs_wording_allowed != "implemented" {
        errors.push(format!(
            "{}: non-implemented row requires forbidden wording examples",
            row.row_id
        ));
    }
    for dependency in &row.blocking_dependencies {
        if !OWNER_ISSUES.contains(&dependency.as_str()) {
            errors.push(format!(
                "{}: invalid blocking dependency {dependency}",
                row.row_id
            ));
        }
    }
    if !is_iso_date_or_never(&row.last_verified_date) {
        errors.push(format!(
            "{}: invalid last_verified_date {}",
            row.row_id, row.last_verified_date
        ));
    }
    let privacy = [
        ("receipt", &row.privacy_guard_expected.receipt),
        (
            "handler_context",
            &row.privacy_guard_expected.handler_context,
        ),
        ("logs_traces", &row.privacy_guard_expected.logs_traces),
        (
            "readiness_status",
            &row.privacy_guard_expected.readiness_status,
        ),
        ("demo_ui", &row.privacy_guard_expected.demo_ui),
        (
            "public_proof_artifacts",
            &row.privacy_guard_expected.public_proof_artifacts,
        ),
    ];
    for (surface, value) in privacy {
        if value.trim().is_empty() {
            errors.push(format!(
                "{}: privacy_guard_expected.{surface} must not be empty",
                row.row_id
            ));
        }
    }
    for surface in PRIVACY_SURFACES {
        let serialized = serde_yaml::to_string(&row.privacy_guard_expected)
            .expect("privacy surface should serialize for diagnostics");
        if !serialized.contains(surface) {
            errors.push(format!("{}: missing privacy surface {surface}", row.row_id));
        }
    }
}

fn is_iso_date_or_never(value: &str) -> bool {
    if value == "never" {
        return true;
    }
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..].iter().all(u8::is_ascii_digit)
}

#[test]
fn negative_matrix_status_ledger_schema_is_valid() {
    let ledger = load_ledger(LEDGER);
    if let Err(errors) = validate_ledger(&ledger) {
        panic!("ledger schema errors:\n{}", errors.join("\n"));
    }
}

#[test]
fn negative_matrix_status_ledger_rejects_duplicate_row_ids() {
    let invalid = r#"
schema_version: 1
generated_from_issue: I10
last_schema_reviewed_date: "2026-07-02"
rows:
  - &row
    row_id: duplicate
    claim: "First duplicate"
    claim_guarded: "First duplicate"
    claim_terms: ["duplicate"]
    current_tier: blocked
    owner_issue: I10
    status: blocked
    evidence_refs: ["docs/issues/secs-magik-phases/i10-negative-matrix-status-ledger.md"]
    test_command: "cargo test -p server negative_matrix_status_ledger"
    test_name: duplicate_test
    expected_reason_code: duplicate_row
    is_rejection_row: true
    handler_did_not_run_expected: true
    docs_wording_allowed: blocked
    docs_wording_examples_allowed: ["blocked"]
    docs_wording_examples_forbidden: ["implemented"]
    privacy_guard_expected:
      receipt: "redacted only"
      handler_context: "no handler context"
      logs_traces: "redacted only"
      readiness_status: "blocked only"
      demo_ui: "blocked only"
      public_proof_artifacts: "none"
    blocking_dependencies: [I10]
    last_verified_date: never
  - row_id: duplicate
    claim: "Second duplicate"
    claim_guarded: "Second duplicate"
    claim_terms: ["duplicate"]
    current_tier: blocked
    owner_issue: I10
    status: blocked
    evidence_refs: ["docs/issues/secs-magik-phases/i10-negative-matrix-status-ledger.md"]
    test_command: "cargo test -p server negative_matrix_status_ledger"
    test_name: duplicate_test
    expected_reason_code: duplicate_row
    is_rejection_row: true
    handler_did_not_run_expected: true
    docs_wording_allowed: blocked
    docs_wording_examples_allowed: ["blocked"]
    docs_wording_examples_forbidden: ["implemented"]
    privacy_guard_expected:
      receipt: "redacted only"
      handler_context: "no handler context"
      logs_traces: "redacted only"
      readiness_status: "blocked only"
      demo_ui: "blocked only"
      public_proof_artifacts: "none"
    blocking_dependencies: [I10]
    last_verified_date: never
"#;
    let ledger = load_ledger(invalid);
    let errors = validate_ledger(&ledger).expect_err("duplicate row ids should fail");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("duplicate row_id")),
        "{errors:?}"
    );
}

#[test]
fn negative_matrix_status_ledger_rejects_blocked_rows_rendered_as_implemented() {
    let invalid = LEDGER.replace(
        "docs_wording_allowed: target",
        "docs_wording_allowed: implemented",
    );
    let ledger = load_ledger(&invalid);
    let errors =
        validate_ledger(&ledger).expect_err("blocked/proposed rows cannot render as implemented");
    assert!(
        errors.iter().any(
            |error| error.contains("non-implemented row cannot allow implemented docs wording")
        ),
        "{errors:?}"
    );
}
