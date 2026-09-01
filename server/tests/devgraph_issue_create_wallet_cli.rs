use std::process::Command;

#[test]
fn unknown_secret_like_argument_is_bounded_and_never_echoed() {
    let secret = format!("private-wallet-material-{}", "x".repeat(4096));
    let output = Command::new(env!("CARGO_BIN_EXE_secs-devgraph-issue-create-v1-wallet"))
        .arg(format!("--unknown-{secret}"))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"{\"error\":\"invalid_arguments\",\"ok\":false}\n"
    );
    assert!(output.stderr.len() < 128);
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&secret));
}

#[test]
fn help_exposes_only_the_three_file_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_secs-devgraph-issue-create-v1-wallet"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).unwrap();
    for required in [
        "--request-file",
        "--idempotency-key-file",
        "--signed-projection-output",
    ] {
        assert!(help.contains(required), "{required}");
    }
    for forbidden in [
        "--bind",
        "--port",
        "--origin",
        "--browser",
        "--operation",
        "--audience",
        "--policy",
        "--key",
        "--url",
        "--devgraph",
        "--timeout",
    ] {
        assert!(!help.contains(forbidden), "{forbidden}");
    }
}
