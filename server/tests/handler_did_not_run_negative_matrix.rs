use serde::Deserialize;

const LEDGER: &str = include_str!("fixtures/dregg_negative_matrix_status_ledger.yaml");

#[derive(Debug, Deserialize)]
struct Ledger {
    rows: Vec<Row>,
}

#[derive(Debug, Deserialize)]
struct Row {
    row_id: String,
    status: String,
    expected_reason_code: String,
    is_rejection_row: bool,
    handler_did_not_run_expected: bool,
    last_verified_date: String,
}

#[test]
fn handler_did_not_run_negative_matrix_rejection_rows_are_explicitly_blocking_execution() {
    let ledger: Ledger = serde_yaml::from_str(LEDGER).expect("ledger should parse");
    let rejection_rows = ledger
        .rows
        .iter()
        .filter(|row| row.is_rejection_row)
        .collect::<Vec<_>>();
    assert!(
        !rejection_rows.is_empty(),
        "negative matrix should include rejection rows"
    );
    for row in rejection_rows {
        assert!(
            row.handler_did_not_run_expected,
            "{} must explicitly assert the handler does not run on rejection",
            row.row_id
        );
        assert!(
            !row.expected_reason_code.trim().is_empty()
                && row.expected_reason_code != "not_applicable",
            "{} must name the rejection reason code or provisional reason label",
            row.row_id
        );
        if row.status != "implemented" {
            assert_eq!(
                row.last_verified_date, "never",
                "{} is not implemented, so it must not record a last_verified_date",
                row.row_id
            );
        }
    }
}
