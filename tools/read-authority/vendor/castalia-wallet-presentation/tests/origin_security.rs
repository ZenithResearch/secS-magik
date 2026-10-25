use castalia_wallet_presentation::Caller;

#[test]
fn browser_callers_reject_delimiter_mapping_and_noncanonical_aliases() {
    // RUSTSEC-2024-0421: URL host processing must not map Unicode delimiters
    // into an authority boundary. Credential callers require exact origins.
    for id in [
        "https://example.com／evil",
        "https://example.com＠evil.test",
        "https://example.com\u{fe13}443",
        "https://example.com%2fevil",
        "https://example.com%40evil.test",
        "https://example.com.",
        "https://EXAMPLE.com",
        "https://example.com:443",
        "https://user@example.com",
        "https://example.com/path",
        "https://example.com?query",
        "https://example.com#fragment",
    ] {
        assert!(
            Caller {
                kind: "browser".into(),
                id: id.into()
            }
            .validate()
            .is_err(),
            "{id}"
        );
    }
    for id in [
        "https://example.com",
        "https://xn--bcher-kva.example",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
    ] {
        assert!(
            Caller {
                kind: "browser".into(),
                id: id.into()
            }
            .validate()
            .is_ok(),
            "{id}"
        );
    }
}
