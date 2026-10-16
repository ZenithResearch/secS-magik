//! Owner-local issuer/verifier adapter. stdin comes only from a trusted receiver
//! process, never from direct native messaging or an application page.
use castalia_wallet_presentation::{decode_hex, parse, read_authority::*};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Issue {
        claims: Claims,
        now: u64,
    },
    Verify {
        credential: Box<Credential>,
        call: Call,
        proof: Proof,
        active: bool,
        now: u64,
    },
}
fn private(path: &str) -> Result<Vec<u8>, &'static str> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = Path::new(path);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "setup_required")?;
    let info = file.metadata().map_err(|_| "setup_required")?;
    // Files must be owner-private and in the same ownership domain as the
    // executable's invoking account. No symlink/key discovery or auto-creation.
    let owner = unsafe { libc::geteuid() };
    if !path.is_absolute()
        || !info.is_file()
        || info.uid() != owner
        || info.mode() & 0o077 != 0
        || info.nlink() != 1
        || info.len() > 65536
    {
        return Err("unsafe_configuration");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "setup_required")?;
    if bytes.len() > 65536 {
        return Err("unsafe_configuration");
    }
    Ok(bytes)
}
fn run() -> Result<Value, &'static str> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 && args.len() != 5
        || args.get(1).map(String::as_str) != Some("--policy-file")
    {
        return Err("invalid_arguments");
    }
    let policy: Policy = parse(&private(&args[2])?, 65536)?;
    policy.validate()?;
    let mut bytes = Vec::new();
    io::stdin()
        .take(131073)
        .read_to_end(&mut bytes)
        .map_err(|_| "invalid_request")?;
    let command: Command = parse(&bytes, 131072)?;
    match command {
        Command::Issue { claims, now } => {
            if args.len() != 5 || args[3] != "--issuer-key-file" {
                return Err("setup_required");
            }
            let raw = Zeroizing::new(private(&args[4])?);
            let text = std::str::from_utf8(&raw).map_err(|_| "invalid_key")?.trim();
            let seed = Zeroizing::new(decode_hex::<32>(text)?);
            let signer = SigningKey::from_bytes(&seed);
            Ok(json!(issue(&policy, claims, &signer, now)?))
        }
        Command::Verify {
            credential,
            call,
            proof,
            active,
            now,
        } => {
            if args.len() != 3 {
                return Err("invalid_arguments");
            }
            let permissions = verify_call(&policy, &credential, &call, &proof, active, now)?;
            Ok(
                json!({"credential_id":credential.claims.credential_id,"holder_public_key":credential.claims.holder_public_key,"expires_at":credential.claims.expires_at,"permissions":permissions}),
            )
        }
    }
}
fn main() {
    let result = match run() {
        Ok(value) => json!({"ok":true,"value":value}),
        Err(error) => json!({"ok":false,"error":error}),
    };
    println!("{result}");
}
