//! Trusted native named Work issuance: current registry, policy, service signing,
//! and durable replay reservation remain closed to portable/WASM consumers.
use crate::devgraph_authority::{encode_base64url, DevgraphAuthorityReplayBindingV1};
use crate::devgraph_work_request::{
    canonical_json, idempotency_key_digest, Result, WorkRequest, MAX_SAFE,
};
use crate::identity::{NodeVerifierIdentity, PublicVerifierKeyRegistry};
use crate::ledger::{DevgraphReplayReservationOutcome, Ledger};
use castalia_wallet_devgraph_presentation::Presentation;
use secs_devgraph_work_contract::verify_presentation;
pub use secs_devgraph_work_contract::{
    digest, WorkPolicy, WorkProjection, WorkRule, POLICY_SCHEMA, SCHEMA,
};
use serde::Serialize;

fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    canonical_json(&serde_json::to_value(value).map_err(|_| "encoding_failed")?)
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
    let request_digest = request.request_digest().to_owned();
    let idempotency_digest =
        idempotency_key_digest(input.idempotency_key).map_err(|_| "invalid_idempotency_key")?;
    let presentation = Presentation::parse(input.wallet_presentation_json)?;
    let verified = verify_presentation(&request, &presentation, input.idempotency_key, now)?;
    let unsigned_presentation = presentation.unsigned();
    if unsigned_presentation.audience() != policy.audience {
        return Err("invalid_work_presentation");
    }
    let session = verified.session();
    let nonce = verified.nonce();
    let actor = verified.actor_id().to_owned();
    let expires = policy
        .authorize_until(&actor, &request, now)?
        .min(unsigned_presentation.expires_at());
    let policy_digest = policy.digest()?;
    let presentation_digest = verified.digest().to_owned();
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
        issued_at: unsigned_presentation.issued_at(),
        nonce: unsigned_presentation.nonce().to_owned(),
        operation: request.operation().to_owned(),
        receiver_policy_digest_sha256: policy_digest,
        receiver_policy_id: policy.policy_id.clone(),
        receiver_policy_version: policy.policy_version,
        replay_scope: "session:operation:nonce".into(),
        request_digest_sha256: request_digest,
        resources: request.resources().to_vec(),
        schema: SCHEMA.into(),
        schema_version: 1,
        secs_context_id: context_id,
        secs_verifier_key_id: identity.signer_key_id().into(),
        secs_verifier_signature: String::new(),
        secs_verifier_signature_suite: "Ed25519".into(),
        session_id: unsigned_presentation.session_id().to_owned(),
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
