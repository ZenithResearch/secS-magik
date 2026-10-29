use serde_json::{Value, json};
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Stdio},
};

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../crates/secs-grant-contract/tests/fixtures/holder-session-v1.json"
    ))
    .unwrap()
}
struct Fixture(PathBuf);
static NEXT_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let unique = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "secs-session-cli-{}-{nonce}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, raw) in [
            ("pin", serde_json::to_vec(&vector()["pin"]).unwrap()),
            ("seed", hex::encode([61u8; 32]).into_bytes()),
        ] {
            let f = p.join(name);
            std::fs::write(&f, raw).unwrap();
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self(p)
    }
    fn invoke(&self, input: Value, sign: bool) -> Value {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secs-holder-grant-authority"));
        command.arg("--issuer-pin-file").arg(self.0.join("pin"));
        if sign {
            command.arg("--issuer-key-file").arg(self.0.join("seed"));
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&input).unwrap())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        serde_json::from_slice(&out.stdout).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn native_review_exchange_verify_and_status_match_shared_vector() {
    let f = Fixture::new();
    let v = vector();
    let r=f.invoke(json!({"operation":"review_holder_session","parent_grant":v["parent_grant"],"challenge":v["challenge"],"context":v["context"],"now":101}),false);
    assert_eq!(r["ok"], true);
    let r=f.invoke(json!({"operation":"verify_holder_session_authorization","authorization":v["authorization"],"context":v["context"],"now":102}),false);
    assert_eq!(r["ok"], true);
    let r=f.invoke(json!({"operation":"issue_holder_session","authorization":v["authorization"],"credential_id":"88".repeat(16),"context":v["context"],"now":102}),true);
    assert_eq!(r["value"], v["credential"]);
    let r=f.invoke(json!({"operation":"verify_holder_session","parent_grant":v["parent_grant"],"credential":v["credential"],"call":v["call"],"proof":v["proof"],"context":v["context"],"now":104}),false);
    assert_eq!(r["ok"], true);
    assert_eq!(
        r["value"]["holder_public_key"],
        v["parent_grant"]["claims"]["holder_public_key"]
    );
    assert_eq!(
        r["value"]["session_public_key"],
        v["challenge"]["session_public_key"]
    );
    let r=f.invoke(json!({"operation":"verify_holder_session_status","challenge":v["challenge"],"proof":v["status"],"context":v["context"],"now":104}),false);
    assert_eq!(r["ok"], true);
}

#[test]
fn native_forgery_wrong_context_expiry_and_credential_substitution_fail_closed() {
    let f = Fixture::new();
    let v = vector();
    let original = json!({"operation":"verify_holder_session","parent_grant":v["parent_grant"],"credential":v["credential"],"call":v["call"],"proof":v["proof"],"context":v["context"],"now":104});
    for variant in 0..5 {
        let mut changed = original.clone();
        match variant {
            0 => changed["context"]["origin"] = json!("https://other.example"),
            1 => changed["now"] = json!(400),
            2 => changed["credential"]["claims"]["challenge"]["expires_at"] = json!(401),
            3 => changed["parent_grant"]["claims"]["revision"] = json!("aa".repeat(32)),
            _ => changed["proof"]["signature"] = json!("00".repeat(64)),
        }
        assert_eq!(f.invoke(changed, false)["ok"], false);
    }
    assert_eq!(
        f.invoke(original, true)["ok"],
        false,
        "verification cannot load issuer signing key"
    );
}

#[test]
fn issuance_cannot_use_read_only_configuration_or_rewrite_expiry_after_consent() {
    let f = Fixture::new();
    let v = vector();
    let mut input = json!({"operation":"issue_holder_session","authorization":v["authorization"],"credential_id":"88".repeat(16),"context":v["context"],"now":102});
    assert_eq!(f.invoke(input.clone(), false)["ok"], false);
    input["authorization"]["challenge"]["expires_at"] = json!(399);
    assert_eq!(f.invoke(input, true)["ok"], false);
}
