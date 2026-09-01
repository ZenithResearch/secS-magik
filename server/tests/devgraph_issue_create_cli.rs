use std::process::Command;

#[test]
fn unknown_secret_like_argument_is_bounded_and_never_echoed() {
    let secret = format!("private-key-material-{}", "x".repeat(4096));
    let output = Command::new(env!("CARGO_BIN_EXE_secs-devgraph-issue-create-v1"))
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
