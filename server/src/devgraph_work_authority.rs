//! Named Work authority v1: closed operations, all-resource grants, portable signatures.
use crate::devgraph_authority::{
    actor_id_for_public_key, decode_base64url_exact, encode_base64url,
    idempotency_key_digest_sha256, DevgraphAuthorityReplayBindingV1,
};
use crate::devgraph_work_request::{identifier, kind, strict_json, Result, WorkRequest, MAX_SAFE};
use crate::identity::{NodeVerifierIdentity, PublicVerifierKeyRegistry};
use crate::ledger::{DevgraphReplayReservationOutcome, Ledger};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "secs-devgraph-work-authority.v1";
pub const POLICY_SCHEMA: &str = "secs-devgraph-work-policy.v1";

pub fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}
fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    // Value uses sorted map keys; every admitted object has closed ASCII keys.
    serde_json::to_vec(&serde_json::to_value(value).map_err(|_| "encoding_failed")?)
        .map_err(|_| "encoding_failed")
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
    fn authorize_until(&self, actor: &str, request: &WorkRequest, now: u64) -> Result<u64> {
        self.validate()?;
        let mut expires = now
            .checked_add(60)
            .filter(|v| *v <= MAX_SAFE)
            .ok_or("invalid_clock")?;
        for resource in &request.resources {
            let mut allowed_until = None;
            for rule in &self.rules {
                let matches = rule.status == "active"
                    && rule.actor_id == actor
                    && rule.operation == request.operation
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Presentation {
    actor_public_key: String,
    actor_signature_suite: String,
    audience: String,
    expires_at: u64,
    idempotency_key_digest_sha256: String,
    issued_at: u64,
    nonce: String,
    operation: String,
    request_digest_sha256: String,
    resources: Vec<String>,
    schema: String,
    schema_version: u64,
    session_id: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
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

pub(crate) struct WorkSignaturePreimage(Vec<u8>);
impl WorkSignaturePreimage {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct WorkAuthorityInput<'a> {
    pub request_json: &'a [u8],
    pub wallet_presentation_json: &'a [u8],
    pub idempotency_key: &'a str,
    pub now: u64,
}

pub async fn issue_work_authority(
    ledger: &Ledger,
    identity: &NodeVerifierIdentity,
    registry: &PublicVerifierKeyRegistry,
    policy: &WorkPolicy,
    input: WorkAuthorityInput<'_>,
) -> Result<WorkProjection> {
    let now = input.now;
    if now > MAX_SAFE - 60 {
        return Err("invalid_clock");
    }
    registry
        .require_devgraph_authority_signer_v1(identity.signer_key_id(), identity.public_key(), now)
        .map_err(|_| "untrusted_secs_verifier_key")?;
    let request = WorkRequest::parse(input.request_json)?;
    let request_digest = digest(request.request_domain(), &request.canonical);
    let idempotency_digest = idempotency_key_digest_sha256(input.idempotency_key)
        .map_err(|_| "invalid_idempotency_key")?;
    let presentation: Presentation =
        serde_json::from_value(strict_json(input.wallet_presentation_json, 16_384)?)
            .map_err(|_| "invalid_work_presentation")?;
    if presentation.schema != "devgraph.work.wallet-presentation.v1"
        || presentation.schema_version != 1
        || presentation.actor_signature_suite != "Ed25519"
        || presentation.audience != policy.audience
        || presentation.operation != request.operation
        || presentation.resources != request.resources
        || presentation.request_digest_sha256 != request_digest
        || presentation.idempotency_key_digest_sha256 != idempotency_digest
        || presentation.issued_at > now
        || presentation.expires_at <= now
        || presentation.expires_at <= presentation.issued_at
        || presentation.expires_at - presentation.issued_at > 60
    {
        return Err("invalid_work_presentation");
    }
    let public = decode_base64url_exact::<32>(&presentation.actor_public_key)
        .map_err(|_| "invalid_work_presentation")?;
    let session = decode_base64url_exact::<16>(&presentation.session_id)
        .map_err(|_| "invalid_work_presentation")?;
    let nonce = decode_base64url_exact::<12>(&presentation.nonce)
        .map_err(|_| "invalid_work_presentation")?;
    let signature = decode_base64url_exact::<64>(&presentation.signature)
        .map_err(|_| "invalid_work_presentation")?;
    let mut unsigned = serde_json::to_value(&presentation).map_err(|_| "encoding_failed")?;
    unsigned
        .as_object_mut()
        .ok_or("encoding_failed")?
        .remove("signature");
    let mut preimage = b"devgraph.work.wallet-presentation.v1/signature\0".to_vec();
    preimage.extend(json(&unsigned)?);
    VerifyingKey::from_bytes(&public)
        .map_err(|_| "invalid_wallet_signature")?
        .verify_strict(&preimage, &Signature::from_bytes(&signature))
        .map_err(|_| "invalid_wallet_signature")?;
    let actor = actor_id_for_public_key(&public);
    let expires = policy
        .authorize_until(&actor, &request, now)?
        .min(presentation.expires_at);
    let policy_digest = policy.digest()?;
    let presentation_digest = digest(
        b"devgraph.work.wallet-presentation.v1/presentation\0",
        &json(&presentation)?,
    );
    let context_id = format!(
        "ctx:sha256:{}",
        digest(
            b"secs-devgraph-work-context.v1\0",
            &json(&serde_json::json!({
                "policy": policy_digest, "presentation": presentation_digest, "signer": identity.signer_key_id()
            }))?
        )
    );
    let mut projection = WorkProjection {
        actor_id: actor,
        actor_signature_suite: "Ed25519".into(),
        audience: policy.audience.clone(),
        expires_at: expires,
        idempotency_key_digest_sha256: idempotency_digest,
        issued_at: presentation.issued_at,
        nonce: presentation.nonce,
        operation: request.operation,
        receiver_policy_digest_sha256: policy_digest,
        receiver_policy_id: policy.policy_id.clone(),
        receiver_policy_version: policy.policy_version,
        replay_scope: "session:operation:nonce".into(),
        request_digest_sha256: request_digest,
        resources: request.resources,
        schema: SCHEMA.into(),
        schema_version: 1,
        secs_context_id: context_id,
        secs_verifier_key_id: identity.signer_key_id().into(),
        secs_verifier_signature: String::new(),
        secs_verifier_signature_suite: "Ed25519".into(),
        session_id: presentation.session_id,
        wallet_presentation_digest_sha256: presentation_digest,
    };
    let mut unsigned = serde_json::to_value(&projection).map_err(|_| "encoding_failed")?;
    unsigned
        .as_object_mut()
        .ok_or("encoding_failed")?
        .remove("secs_verifier_signature");
    let mut bytes = b"secs-devgraph-work-authority.v1/signature\0".to_vec();
    bytes.extend(json(&unsigned)?);
    let signature = identity
        .sign_work_authority_v1(&WorkSignaturePreimage(bytes))
        .map_err(|_| "untrusted_secs_verifier_key")?;
    projection.secs_verifier_signature = encode_base64url(&signature);
    let replay = DevgraphAuthorityReplayBindingV1 {
        actor_id: projection.actor_id.clone(),
        audience: projection.audience.clone(),
        expires_at: projection.expires_at,
        idempotency_key_digest_sha256: projection.idempotency_key_digest_sha256.clone(),
        issued_at: projection.issued_at,
        nonce,
        operation: projection.operation.clone(),
        replay_scope: projection.replay_scope.clone(),
        receiver_policy_id: projection.receiver_policy_id.clone(),
        receiver_policy_version: projection.receiver_policy_version,
        receiver_policy_digest_sha256: projection.receiver_policy_digest_sha256.clone(),
        request_digest_sha256: projection.request_digest_sha256.clone(),
        resource: String::from_utf8(json(&projection.resources)?).map_err(|_| "encoding_failed")?,
        secs_context_id: projection.secs_context_id.clone(),
        secs_verifier_key_id: projection.secs_verifier_key_id.clone(),
        session_id: session,
        wallet_presentation_digest_sha256: projection.wallet_presentation_digest_sha256.clone(),
    };
    match ledger
        .reserve_devgraph_authority_replay(&replay, now)
        .await
        .map_err(|_| "replay_storage_failed")?
    {
        DevgraphReplayReservationOutcome::Reserved
        | DevgraphReplayReservationOutcome::ExactDuplicate => Ok(projection),
        DevgraphReplayReservationOutcome::ScopeConflict => Err("replay_conflict"),
    }
}
