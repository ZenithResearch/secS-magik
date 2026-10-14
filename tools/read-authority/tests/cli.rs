//! Exercise the actual process with disposable identities and private files.
//! No installed keys, OS authority directories, network or live Wallet are used.
use castalia_wallet_presentation::read_authority::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    policy: Policy,
    claims: Claims,
    holder: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "secs-read-cli-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let issuer = SigningKey::from_bytes(&[71; 32]);
        let holder = SigningKey::from_bytes(&[72; 32]);
        let policy = Policy {
            schema: POLICY.into(),
            issuer: "fixture".into(),
            key_id: "test-read".into(),
            public_key: encode_hex(&issuer.verifying_key().to_bytes()),
            receiver: "https://example.test".into(),
            audience: "example".into(),
            permissions: vec![Permission {
                operation: "example.item.list".into(),
                resource: "https://example.test/items".into(),
                constraints: json!({"arenas":["zenith"],"archived":false}),
            }],
            max_lifetime_seconds: 3600,
        };
        let claims = Claims {
            schema: CREDENTIAL.into(),
            credential_id: "ab".repeat(16),
            installation_id: "cd".repeat(16),
            holder_public_key: encode_hex(&holder.verifying_key().to_bytes()),
            issuer: policy.issuer.clone(),
            key_id: policy.key_id.clone(),
            receiver: policy.receiver.clone(),
            audience: policy.audience.clone(),
            policy_digest: policy.digest().unwrap(),
            permissions: policy.permissions.clone(),
            issued_at: 100,
            expires_at: 3700,
        };
        private_write(
            &root.join("policy.json"),
            &serde_json::to_vec(&policy).unwrap(),
        );
        private_write(&root.join("key"), encode_hex(&[71; 32]).as_bytes());
        Self {
            root,
            policy,
            claims,
            holder,
        }
    }
    fn run(&self, input: &Value, issue: bool) -> Value {
        let policy = self.root.join("policy.json");
        let key = self.root.join("key");
        let mut args = vec!["--policy-file", policy.to_str().unwrap()];
        if issue {
            args.extend(["--issuer-key-file", key.to_str().unwrap()]);
        }
        invoke(&args, &serde_json::to_vec(input).unwrap())
    }
    fn issue(&self) -> Value {
        self.run(
            &json!({"operation":"issue","claims":self.claims,"now":100}),
            true,
        )
    }
    fn verified_request(&self) -> Value {
        let issued = self.issue();
        assert_eq!(issued["ok"], true);
        let credential: Credential = serde_json::from_value(issued["value"].clone()).unwrap();
        let call = Call {
            operation: "example.item.list".into(),
            resource: "https://example.test/items".into(),
            parameters: json!({"limit":20}),
        };
        let mut proof = Proof::unsigned(&credential, &call, "ef".repeat(16), 101).unwrap();
        proof.signature = encode_hex(&self.holder.sign(&proof.transcript().unwrap()).to_bytes());
        json!({"operation":"verify","credential":credential,"call":call,
               "proof":proof,"active":true,"now":102})
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn private_write(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}
fn invoke(args: &[&str], input: &[u8]) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_secs-read-authority-v1"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn process_issues_and_verifies_exact_holder_bound_read() {
    let fixture = Fixture::new();
    let result = fixture.run(&fixture.verified_request(), false);
    assert_eq!(result["ok"], true);
    assert_eq!(
        result["value"]["permissions"],
        json!(fixture.policy.permissions)
    );
    assert!(result["value"].get("signature").is_none());
}

#[test]
fn process_rejects_revocation_expiry_and_call_or_credential_substitution() {
    let fixture = Fixture::new();
    let original = fixture.verified_request();
    for changed in [
        {
            let mut v = original.clone();
            v["active"] = json!(false);
            v
        },
        {
            let mut v = original.clone();
            v["now"] = json!(3700);
            v
        },
        {
            let mut v = original.clone();
            v["call"]["parameters"]["limit"] = json!(100);
            v
        },
        {
            let mut v = original.clone();
            v["call"]["operation"] = json!("example.item.delete");
            v
        },
        {
            let mut v = original.clone();
            v["credential"]["claims"]["permissions"][0]["constraints"]["arenas"] = json!([]);
            v
        },
    ] {
        assert_eq!(fixture.run(&changed, false)["ok"], false);
    }
    assert_eq!(fixture.run(&original, true)["error"], "invalid_arguments");
}

#[test]
fn process_rejects_grant_expansion_wrong_issuer_and_changed_policy() {
    let mut fixture = Fixture::new();
    let original = fixture.verified_request();
    fixture.claims.permissions[0].constraints["arenas"] = json!([]);
    assert_eq!(fixture.issue()["ok"], false);
    fixture.claims.permissions = fixture.policy.permissions.clone();
    fs::write(fixture.root.join("key"), encode_hex(&[73; 32])).unwrap();
    assert_eq!(fixture.issue()["ok"], false);
    fixture.policy.permissions[0].constraints["archived"] = json!(true);
    fs::write(
        fixture.root.join("policy.json"),
        serde_json::to_vec(&fixture.policy).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture.run(&original, false)["ok"], false);
}

#[test]
fn process_rejects_unsafe_configuration_and_missing_key_without_disclosure() {
    let fixture = Fixture::new();
    let key = fixture.root.join("key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        fixture.issue(),
        json!({"ok":false,"error":"unsafe_configuration"})
    );
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&key, fixture.root.join("saved-key")).unwrap();
    symlink(fixture.root.join("saved-key"), &key).unwrap();
    assert_eq!(
        fixture.issue(),
        json!({"ok":false,"error":"setup_required"})
    );
    fs::remove_file(&key).unwrap();
    fs::hard_link(fixture.root.join("saved-key"), &key).unwrap();
    assert_eq!(
        fixture.issue(),
        json!({"ok":false,"error":"unsafe_configuration"})
    );
    fs::remove_file(&key).unwrap();
    assert_eq!(
        fixture.issue(),
        json!({"ok":false,"error":"setup_required"})
    );
}

#[test]
fn process_rejects_unknown_fields_duplicate_keys_and_oversized_input() {
    let fixture = Fixture::new();
    let mut input = fixture.verified_request();
    input["unexpected"] = json!(true);
    assert_eq!(fixture.run(&input, false)["ok"], false);
    let policy = fixture.root.join("policy.json");
    let args = ["--policy-file", policy.to_str().unwrap()];
    assert_eq!(
        invoke(&args, br#"{"operation":"issue","operation":"verify"}"#)["ok"],
        false
    );
    assert_eq!(invoke(&args, &vec![b' '; 131073])["ok"], false);
    assert_eq!(invoke(&[], b"{}")["error"], "invalid_arguments");
}
