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
    VerifyHolderSessionStatus {
        challenge: Box<holder_sessions::Challenge>,
        proof: holder_sessions::StatusRequest,
        context: holder_sessions::Context,
        now: u64,
    },
    ReviewHolderSession {
        parent_grant: Box<scoped_grants::Grant>,
        challenge: Box<holder_sessions::Challenge>,
        context: holder_sessions::Context,
        now: u64,
    },
    VerifyHolderSessionAuthorization {
        authorization: Box<holder_sessions::Authorization>,
        context: holder_sessions::Context,
        now: u64,
    },
    IssueHolderSession {
        authorization: Box<holder_sessions::Authorization>,
        credential_id: String,
        context: holder_sessions::Context,
        now: u64,
    },
    VerifyHolderSession {
        credential: Box<holder_sessions::Credential>,
        parent_grant: Box<scoped_grants::Grant>,
        call: Value,
        proof: Proof,
        context: holder_sessions::Context,
        now: u64,
    },
    IssueAccessPoint {
        claims: AccessPointClaims,
        now: u64,
    },
    VerifyAccessPoint {
        binding: AccessPointBinding,
        origin: String,
        now: u64,
    },
    CheckSelector {
        selector: resource_selector::ResourceSelector,
        targets: Vec<resource_selector::ResourceRef>,
        snapshot: provider_snapshot::ProviderSnapshot,
    },
    CheckEffect {
        rule: compound_resources::EffectRule,
        contract: compound_resources::EffectContract,
        effects: Vec<compound_resources::ResolvedRole>,
        snapshot: provider_snapshot::ProviderSnapshot,
    },
    IssueV2 {
        claims: scoped_grants::GrantClaims,
        now: u64,
    },
    VerifyV2 {
        credential: Box<scoped_grants::Credential>,
        call: Value,
        proof: Proof,
        now: u64,
    },
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
fn issuer_key(a: &[String]) -> Result<SigningKey> {
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
    Ok(SigningKey::from_bytes(seed))
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
        Command::VerifyHolderSessionStatus {
            challenge,
            proof,
            context,
            now,
        } => {
            if a.len() != 3 {
                return Err("invalid_arguments");
            }
            holder_sessions::verify_status(&challenge, &proof, &context, now)?;
            Ok(
                json!({"schema":"secs.holder-session-status-verified.v1", "request_id":proof.request_id,"challenge_id":proof.challenge_id}),
            )
        }
        Command::ReviewHolderSession {
            parent_grant,
            challenge,
            context,
            now,
        } => {
            if a.len() != 3 {
                return Err("invalid_arguments");
            }
            holder_sessions::review_challenge(&pin, &parent_grant, &challenge, &context, now)?;
            Ok(
                json!({"schema":"secs.holder-session-reviewed.v1", "challenge_digest":digest(&challenge)?}),
            )
        }
        Command::VerifyHolderSessionAuthorization {
            authorization,
            context,
            now,
        } => {
            if a.len() != 3 {
                return Err("invalid_arguments");
            }
            holder_sessions::verify_authorization(&pin, &authorization, &context, now)?;
            Ok(
                json!({"schema":"secs.holder-session-authorization-verified.v1", "challenge_digest":digest(&authorization.challenge)?}),
            )
        }
        Command::IssueHolderSession {
            authorization,
            credential_id,
            context,
            now,
        } => Ok(json!(holder_sessions::issue(
            &pin,
            &authorization,
            credential_id,
            &context,
            &issuer_key(&a)?,
            now
        )?)),
        Command::VerifyHolderSession {
            credential,
            parent_grant,
            call,
            proof,
            context,
            now,
        } => {
            if a.len() != 3 {
                return Err("invalid_arguments");
            }
            holder_sessions::verify_presentation(
                &pin,
                &parent_grant,
                &credential,
                &call,
                &proof,
                &context,
                now,
            )?;
            let challenge = &credential.claims.challenge;
            let permissions: Vec<_> = challenge
                .permissions
                .iter()
                .filter(|p| {
                    Some(p.operation.as_str()) == call["operation"].as_str()
                        && Some(p.resource.as_str()) == call["resource"].as_str()
                })
                .collect();
            Ok(json!({"schema":"secs.verified-holder-session.v1",
                "grant_id":challenge.parent_grant_id,"revision":challenge.parent_revision,
                "grant_digest":challenge.parent_grant_digest,"credential_id":credential.claims.credential_id,
                "holder_public_key":challenge.holder_public_key,"installation_id":challenge.installation_id,
                "session_public_key":challenge.session_public_key,"session_installation_id":challenge.session_installation_id,
                "expires_at":challenge.expires_at,"permissions":permissions}))
        }
        Command::IssueAccessPoint { claims, now } => Ok(json!(issue_access_point(
            &pin,
            claims,
            &issuer_key(&a)?,
            now
        )?)),
        Command::VerifyAccessPoint {
            binding,
            origin,
            now,
        } => {
            if a.len() != 3 {
                return Err("invalid_arguments");
            }
            verify_access_point(&pin, &binding, &origin, now)?;
            Ok(json!(binding.claims))
        }
        Command::CheckSelector {
            selector,
            targets,
            snapshot,
        } => {
            if a.len() != 3 || targets.len() > 128 || snapshot.service != pin.service {
                return Err("invalid_provider_snapshot");
            }
            snapshot.validate()?;
            let allowed: Vec<bool> = targets
                .iter()
                .map(|t| selector.permits(&pin.service, t, &snapshot))
                .collect::<Result<_>>()?;
            Ok(json!({"allowed":allowed}))
        }
        Command::CheckEffect {
            rule,
            contract,
            effects,
            snapshot,
        } => {
            if a.len() != 3 || snapshot.service != pin.service || contract.service != pin.service {
                return Err("invalid_provider_snapshot");
            }
            snapshot.validate()?;
            Ok(json!({"allowed":rule.permits(&contract,&effects,&snapshot)?}))
        }
        Command::IssueV2 { claims, now } => Ok(json!(scoped_grants::issue_grant(
            &pin,
            claims,
            &issuer_key(&a)?,
            now
        )?)),
        Command::VerifyV2 {
            credential,
            call,
            proof,
            now,
        } => {
            if a.len() != 3 {
                return Err("invalid_arguments");
            }
            scoped_grants::verify_presentation(&pin, &credential, &call, &proof, now)?;
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
                json!({"schema":"secs.verified-holder-credential.v2","grant_id":credential.grant.claims.grant_id,"revision":credential.grant.claims.revision,"grant_digest":digest(&credential.grant)?,"credential_id":credential.claims.credential_id,"holder_public_key":credential.claims.holder_public_key,"installation_id":credential.claims.installation_id,"expires_at":credential.claims.expires_at,"permissions":p}),
            )
        }
        Command::Issue { claims, now } => {
            let signing = issuer_key(&a)?;
            Ok(json!(issue_grant(&pin, claims, &signing, now)?))
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
