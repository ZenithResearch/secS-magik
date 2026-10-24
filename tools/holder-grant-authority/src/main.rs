//! Trusted provider-process adapter. No network or policy discovery.
//! Cryptographic verification does not assert current registry status.
use ed25519_dalek::SigningKey;
use secs_grant_contract::*;
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{self, Read};
use zeroize::Zeroizing;
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Issue {
        claims: GrantClaims,
        now: u64,
    },
    Verify {
        credential: Box<Credential>,
        call: Value,
        proof: Proof,
        now: u64,
    },
}
fn private(path: &str) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !std::path::Path::new(path).is_absolute() {
        return Err("unsafe_configuration");
    }
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "setup_required")?;
    let m = f.metadata().map_err(|_| "setup_required")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > 65536
    {
        return Err("unsafe_configuration");
    }
    let mut b = vec![];
    (&mut f)
        .take(65537)
        .read_to_end(&mut b)
        .map_err(|_| "setup_required")?;
    if b.len() > 65536 {
        return Err("unsafe_configuration");
    }
    Ok(b)
}
fn run() -> Result<Value> {
    let a: Vec<_> = std::env::args().collect();
    if (a.len() != 3 && a.len() != 5) || a[1] != "--issuer-pin-file" {
        return Err("invalid_arguments");
    }
    let pin: IssuerPin = parse(&private(&a[2])?)?;
    let mut b = vec![];
    io::stdin()
        .take(131073)
        .read_to_end(&mut b)
        .map_err(|_| "invalid_request")?;
    match parse::<Command>(&b)? {
        Command::Issue { claims, now } => {
            if a.len() != 5 || a[3] != "--issuer-key-file" {
                return Err("invalid_arguments");
            }
            let raw = Zeroizing::new(private(&a[4])?);
            let s = std::str::from_utf8(&raw).map_err(|_| "invalid_key")?.trim();
            if s.len() != 64 {
                return Err("invalid_key");
            }
            let seed = Zeroizing::new(hex::decode(s).map_err(|_| "invalid_key")?);
            let seed: &[u8; 32] = seed.as_slice().try_into().map_err(|_| "invalid_key")?;
            Ok(json!(issue_grant(
                &pin,
                claims,
                &SigningKey::from_bytes(seed),
                now
            )?))
        }
        Command::Verify {
            credential,
            call,
            proof,
            now,
        } => {
            if a.len() != 3 {
                return Err("invalid_arguments");
            }
            verify_presentation(&pin, &credential, &call, &proof, now)?;
            let o = call.as_object().ok_or("invalid_call")?;
            if o.len() != 3 || !o.contains_key("parameters") {
                return Err("invalid_call");
            }
            let p: Vec<_> = credential
                .claims
                .permissions
                .iter()
                .filter(|p| {
                    Some(p.operation.as_str()) == call["operation"].as_str()
                        && Some(p.resource.as_str()) == call["resource"].as_str()
                })
                .collect();
            if p.is_empty() {
                return Err("not_permitted");
            }
            Ok(
                json!({"schema":"secs.verified-holder-credential.v1","grant_id":credential.grant.claims.grant_id,"revision":credential.grant.claims.revision,"grant_digest":digest(&credential.grant)?,"credential_id":credential.claims.credential_id,"holder_public_key":credential.claims.holder_public_key,"installation_id":credential.claims.installation_id,"expires_at":credential.claims.expires_at,"permissions":p}),
            )
        }
    }
}
fn main() {
    let r = match run() {
        Ok(v) => json!({"ok":true,"value":v}),
        Err(e) => json!({"ok":false,"error":e}),
    };
    println!("{r}")
}
