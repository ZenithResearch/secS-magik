//! Portable named Work policy and public proof verification.
//!
//! This crate has no key custody, clock, randomness, filesystem, network, registry
//! management, signing authority, or replay storage. A verified projection proves
//! a request authorization signature; it is not a mutation result or receipt.
use castalia_wallet_devgraph_presentation::{actor_id, decode64, verify_binding, Presentation};
pub use devgraph_work_protocol::digest;
use devgraph_work_protocol::{
    canonical_json, idempotency_key_digest, identifier, kind, strict_json, Result, WorkRequest,
    MAX_SAFE,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "secs-devgraph-work-authority.v1";
pub const POLICY_SCHEMA: &str = "secs-devgraph-work-policy.v1";

fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    canonical_json(&serde_json::to_value(value).map_err(|_| "encoding_failed")?)
}
fn safe_label(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn hex_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn named_operation(s: &str) -> bool {
    if let Some(operation) = s
        .strip_prefix("devgraph.arena.")
        .and_then(|s| s.strip_suffix(".v1"))
    {
        return matches!(operation, "create" | "patch" | "archive" | "member.set");
    }
    s.strip_prefix("devgraph.work.")
        .and_then(|s| s.strip_suffix(".v1"))
        .is_some_and(|s| {
            matches!(
                s,
                "create"
                    | "patch"
                    | "status"
                    | "archive"
                    | "accept"
                    | "convert"
                    | "parent.set"
                    | "dependency.add"
                    | "dependency.remove"
                    | "blocker.add"
                    | "blocker.remove"
            )
        })
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkRule {
    pub actor_id: String,
    pub effect: String,
    pub not_after: u64,
    pub not_before: u64,
    pub operation: String,
    pub resource: String,
    pub resource_match: String,
    pub status: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkPolicy {
    pub audience: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub rules: Vec<WorkRule>,
    pub schema: String,
    pub schema_version: u64,
}
impl WorkPolicy {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let policy: Self = serde_json::from_value(strict_json(raw, 262_144)?)
            .map_err(|_| "invalid_work_policy")?;
        policy.validate()?;
        Ok(policy)
    }
    fn validate(&self) -> Result<()> {
        if self.schema != POLICY_SCHEMA
            || self.schema_version != 1
            || self.policy_version == 0
            || self.policy_version > MAX_SAFE
            || !safe_label(&self.policy_id, 128)
            || self.audience != "devgraph://receiver-local"
            || self.rules.is_empty()
            || self.rules.len() > 1000
        {
            return Err("invalid_work_policy");
        }
        for rule in &self.rules {
            let actor = rule
                .actor_id
                .strip_prefix("pubkey:sha256:")
                .ok_or("invalid_work_policy")?;
            let (label, id) = rule.resource.split_once('/').ok_or("invalid_work_policy")?;
            let resource_ok = (kind(label) || matches!(label, "Decision" | "Arena"))
                && match rule.resource_match.as_str() {
                    "exact" => identifier(id),
                    "prefix" => {
                        id.len() <= 256
                            && id
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    }
                    _ => false,
                };
            if !hex_digest(actor)
                || !named_operation(&rule.operation)
                || !resource_ok
                || !matches!(rule.effect.as_str(), "allow" | "deny")
                || !matches!(rule.status.as_str(), "active" | "revoked")
                || rule.not_before >= rule.not_after
                || rule.not_after > MAX_SAFE
            {
                return Err("invalid_work_policy");
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(digest(b"secs-devgraph-work-policy.v1\0", &json(self)?))
    }
    pub fn authorize_until(&self, actor: &str, request: &WorkRequest, now: u64) -> Result<u64> {
        self.validate()?;
        let mut expires = now
            .checked_add(60)
            .filter(|v| *v <= MAX_SAFE)
            .ok_or("invalid_clock")?;
        for resource in request.resources() {
            let mut allowed_until = None;
            for rule in &self.rules {
                let matches = rule.status == "active"
                    && rule.actor_id == actor
                    && rule.operation == request.operation()
                    && (if rule.resource_match == "exact" {
                        resource == &rule.resource
                    } else {
                        resource.starts_with(&rule.resource)
                    });
                if !matches || rule.not_after <= now {
                    continue;
                }
                if rule.effect == "deny" {
                    if rule.not_before <= now {
                        return Err("work_permission_denied");
                    }
                    expires = expires.min(rule.not_before);
                } else if rule.not_before <= now {
                    allowed_until = Some(allowed_until.unwrap_or(0).max(rule.not_after));
                }
            }
            expires = expires.min(allowed_until.ok_or("work_permission_denied")?);
        }
        Ok(expires)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkProjection {
    pub actor_id: String,
    pub actor_signature_suite: String,
    pub audience: String,
    pub expires_at: u64,
    pub idempotency_key_digest_sha256: String,
    pub issued_at: u64,
    pub nonce: String,
    pub operation: String,
    pub receiver_policy_digest_sha256: String,
    pub receiver_policy_id: String,
    pub receiver_policy_version: u64,
    pub replay_scope: String,
    pub request_digest_sha256: String,
    pub resources: Vec<String>,
    pub schema: String,
    pub schema_version: u64,
    pub secs_context_id: String,
    pub secs_verifier_key_id: String,
    pub secs_verifier_signature: String,
    pub secs_verifier_signature_suite: String,
    pub session_id: String,
    pub wallet_presentation_digest_sha256: String,
}
impl WorkProjection {
    pub fn canonical(&self) -> Result<Vec<u8>> {
        json(self)
    }
}

/// Checked public presentation binding, never an issuer or replay capability.
pub struct VerifiedPresentation {
    actor_id: String,
    session: [u8; 16],
    nonce: [u8; 12],
    digest: String,
}
impl VerifiedPresentation {
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }
    pub fn session(&self) -> [u8; 16] {
        self.session
    }
    pub fn nonce(&self) -> [u8; 12] {
        self.nonce
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Verify the exact shared Wallet presentation type against a frozen request.
pub fn verify_presentation(
    request: &WorkRequest,
    presentation: &Presentation,
    key: &str,
    now: u64,
) -> Result<VerifiedPresentation> {
    let public = verify_binding(request, presentation, key, now)?;
    Ok(VerifiedPresentation {
        actor_id: actor_id(&public),
        session: decode64(presentation.unsigned().session_id())?,
        nonce: decode64(presentation.unsigned().nonce())?,
        digest: digest(
            b"devgraph.work.wallet-presentation.v1/presentation\0",
            &presentation.canonical()?,
        ),
    })
}

/// Trust inputs come from the installed receiver profile, never the projection.
/// The verifier key must be current in the receiver's trusted registry; this pure
/// helper cannot establish registry currency or reserve durable replay state.
pub struct ProjectionExpectation<'a> {
    pub request: &'a WorkRequest,
    pub idempotency_key: &'a str,
    pub audience: &'a str,
    pub actor_id: &'a str,
    pub receiver_policy_id: &'a str,
    pub receiver_policy_version: u64,
    pub receiver_policy_digest: &'a str,
    pub verifier_key_id: &'a str,
    pub verifier_public_key: &'a [u8; 32],
    pub presentation: &'a Presentation,
    pub now: u64,
}

/// Signature plus exact binding verification. Successful decoding alone never
/// yields this type. Proof verification does not establish mutation success.
pub struct VerifiedProjection(WorkProjection);
impl VerifiedProjection {
    pub fn projection(&self) -> &WorkProjection {
        &self.0
    }
}

pub fn verify_projection(
    raw: &[u8],
    expected: ProjectionExpectation<'_>,
) -> Result<VerifiedProjection> {
    let projection: WorkProjection =
        serde_json::from_value(strict_json(raw, 16_384)?).map_err(|_| "invalid_work_projection")?;
    let checked_presentation = verify_presentation(
        expected.request,
        expected.presentation,
        expected.idempotency_key,
        expected.now,
    )?;
    let presented = expected.presentation.unsigned();
    let p = &projection;
    if expected.now > MAX_SAFE
        || p.schema != SCHEMA
        || p.schema_version != 1
        || p.actor_signature_suite != "Ed25519"
        || p.secs_verifier_signature_suite != "Ed25519"
        || p.replay_scope != "session:operation:nonce"
        || p.audience != "devgraph://receiver-local"
        || p.audience != expected.audience
        || p.actor_id != expected.actor_id
        || p.actor_id != checked_presentation.actor_id()
        || !p
            .actor_id
            .strip_prefix("pubkey:sha256:")
            .is_some_and(hex_digest)
        || p.operation != expected.request.operation()
        || p.resources != expected.request.resources()
        || p.request_digest_sha256 != expected.request.request_digest()
        || p.idempotency_key_digest_sha256 != idempotency_key_digest(expected.idempotency_key)?
        || p.receiver_policy_id != expected.receiver_policy_id
        || !safe_label(&p.receiver_policy_id, 128)
        || p.receiver_policy_version != expected.receiver_policy_version
        || p.receiver_policy_version == 0
        || p.receiver_policy_digest_sha256 != expected.receiver_policy_digest
        || !hex_digest(&p.receiver_policy_digest_sha256)
        || p.secs_verifier_key_id != expected.verifier_key_id
        || !safe_label(&p.secs_verifier_key_id, 128)
        || p.wallet_presentation_digest_sha256 != checked_presentation.digest()
        || !hex_digest(&p.wallet_presentation_digest_sha256)
        || p.session_id != presented.session_id()
        || p.nonce != presented.nonce()
        || p.issued_at != presented.issued_at()
        || p.expires_at > presented.expires_at()
        || p.issued_at > expected.now
        || p.expires_at <= expected.now
        || p.expires_at <= p.issued_at
        || p.expires_at - p.issued_at > 60
    {
        return Err("invalid_work_projection");
    }
    decode64::<16>(&p.session_id).map_err(|_| "invalid_work_projection")?;
    decode64::<12>(&p.nonce).map_err(|_| "invalid_work_projection")?;
    let context = format!(
        "ctx:sha256:{}",
        digest(
            b"secs-devgraph-work-context.v1\0",
            &json(&serde_json::json!({
                "policy": p.receiver_policy_digest_sha256,
                "presentation": p.wallet_presentation_digest_sha256,
                "signer": p.secs_verifier_key_id
            }))?
        )
    );
    if p.secs_context_id != context {
        return Err("invalid_work_projection");
    }
    let signature =
        decode64::<64>(&p.secs_verifier_signature).map_err(|_| "invalid_work_projection")?;
    let mut unsigned = serde_json::to_value(p).map_err(|_| "encoding_failed")?;
    unsigned
        .as_object_mut()
        .ok_or("encoding_failed")?
        .remove("secs_verifier_signature");
    let mut transcript = b"secs-devgraph-work-authority.v1/signature\0".to_vec();
    transcript.extend(json(&unsigned)?);
    VerifyingKey::from_bytes(expected.verifier_public_key)
        .map_err(|_| "invalid_secs_signature")?
        .verify_strict(&transcript, &Signature::from_bytes(&signature))
        .map_err(|_| "invalid_secs_signature")?;
    Ok(VerifiedProjection(projection))
}
