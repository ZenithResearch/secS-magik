//! Create-only custody and closed policy for one connector result receiver.
use serde::Deserialize;
use serde_json::{json, Value};
use server::manifest::{OpcodeRange, OperationDescriptor, OperationName, ReplayScope, TargetKind};
use server::privacy::DisclosurePolicy;
use server::FrankConnectorResultAuthority;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    root: PathBuf,
    journal: PathBuf,
    actor_id: String,
    integration_id: String,
    route: String,
    run_ids: Vec<String>,
    resources: Vec<String>,
    producer_artifact_sha256: String,
    normalizer_sha256: String,
    configuration_sha256: String,
    source_manifest_sha256: String,
    not_before: u64,
    not_after: u64,
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn pin(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn canonical(value: &Value) -> Result<Vec<u8>, ()> {
    fn emit(value: &Value, out: &mut Vec<u8>) -> Result<(), ()> {
        match value {
            Value::Object(map) => {
                out.push(b'{');
                let mut rows: Vec<_> = map.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                for (i, (key, value)) in rows.into_iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(key).map_err(|_| ())?);
                    out.push(b':');
                    emit(value, out)?;
                }
                out.push(b'}');
            }
            Value::Array(rows) => {
                out.push(b'[');
                for (i, value) in rows.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    emit(value, out)?;
                }
                out.push(b']');
            }
            _ => out.extend(serde_json::to_vec(value).map_err(|_| ())?),
        }
        Ok(())
    }
    let mut out = Vec::new();
    emit(value, &mut out)?;
    Ok(out)
}
fn directory(path: &Path) -> Result<(), ()> {
    fs::create_dir(path).map_err(|_| ())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| ())
}
fn file(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| ())?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| ())
}
fn descriptor() -> OperationDescriptor {
    OperationDescriptor {
        opcode: 232,
        name: OperationName::new("frank.result.attest.v1"),
        payload_schema: Some("frank.native-result-payload.v1".into()),
        output_profile: None,
        target_kind: TargetKind::ReceiverProductionHandler,
        required_credentials: vec!["frank.connector.result-party-assignment.v1".into()],
        required_capabilities: vec!["frank.result.attest.v1".into()],
        accepted_evidence: vec!["frank.connector.capture.v1".into()],
        required_authority_mode: None,
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 60,
        handler_id: "frank-connector-result-receiver".into(),
        dev_binding: false,
        range: OpcodeRange::OperatorDefined,
        disclosure_policy: DisclosurePolicy::deny_by_default("frank.result-receipt.v1", 1),
    }
}
fn now() -> Result<u64, ()> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs())
}

fn run() -> Result<(), ()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 5 || args[1] != "--plan" || args[3] != "--plan-sha256" {
        return Err(());
    }
    let raw = fs::read(&args[2]).map_err(|_| ())?;
    if raw.is_empty() || raw.len() > 65_536 || args[4].to_str().ok_or(())? != digest(&raw) {
        return Err(());
    }
    let value: Value = serde_json::from_slice(&raw).map_err(|_| ())?;
    if canonical(&value)? != raw {
        return Err(());
    }
    let p: Plan = serde_json::from_value(value).map_err(|_| ())?;
    let n = now()?;
    if p.schema != "secs.frank.connector-result-setup-plan.v1"
        || !p.root.is_absolute()
        || !p.journal.is_absolute()
        || !identifier(&p.actor_id)
        || !identifier(&p.integration_id)
        || p.route != "local"
        || p.run_ids.is_empty()
        || p.run_ids.len() > 16
        || p.resources.len() != p.run_ids.len()
        || p.run_ids.iter().any(|v| !identifier(v))
        || p.resources
            .iter()
            .any(|v| v.len() > 4096 || !v.starts_with("runs/") || !v.ends_with('/'))
        || [
            &p.producer_artifact_sha256,
            &p.normalizer_sha256,
            &p.configuration_sha256,
            &p.source_manifest_sha256,
        ]
        .iter()
        .any(|v| !pin(v))
        || p.not_before > n + 60
        || p.not_after <= n
        || p.not_after - p.not_before > 14_400
    {
        return Err(());
    }
    let parent = p.root.parent().ok_or(())?;
    let info = fs::metadata(parent).map_err(|_| ())?;
    if !info.is_dir() || info.permissions().mode() & 0o077 != 0 {
        return Err(());
    }
    directory(&p.root)?;
    for name in ["issuer", "assignment", "captures", "journal", "config"] {
        directory(&p.root.join(name))?;
    }
    for name in [
        "assignment/assignment.lock",
        "captures/capture.lock",
        "journal/journal.lock",
    ] {
        file(&p.root.join(name), b"")?;
    }
    let public =
        FrankConnectorResultAuthority::create_issuer_key(&p.root.join("issuer")).map_err(|_| ())?;
    let public_hex: String = public.iter().map(|b| format!("{b:02x}")).collect();
    let assignment = canonical(&json!({"active":true,"actor_id":p.actor_id,
        "assignment_id":"frank-hermes-pilot-result-assignment","configuration_sha256":p.configuration_sha256,
        "generation":1,"integration_id":p.integration_id,"issuer_public_key_hex":public_hex,
        "key_id":"frank-hermes-pilot-result-key","normalizer_sha256":p.normalizer_sha256,
        "not_after":p.not_after,"not_before":p.not_before,"operations":["compute"],
        "producer_artifact_sha256":p.producer_artifact_sha256,"route":p.route,"run_ids":p.run_ids,
        "schema":"frank.connector.result-party-assignment.v1","source_manifest_sha256":p.source_manifest_sha256,
        "subject_id":"frank-hermes-pilot-result-party"}))?;
    file(&p.root.join("assignment/assignment.json"), &assignment)?;
    let d = descriptor();
    let fingerprint = d
        .authorization_fingerprint()
        .strip_prefix("descriptor:sha256:")
        .ok_or(())?
        .to_owned();
    let authority = canonical(
        &json!({"assignment_root":p.root.join("assignment"),"assignment_sha256":digest(&assignment),
        "capture_root":p.root.join("captures"),"descriptor":{"fingerprint":fingerprint,"handler_id":d.handler_id,"opcode":232},
        "issuer_key_id":"frank-hermes-pilot-result-key","issuer_public_key_hex":public_hex,
        "issuer_root":p.root.join("issuer"),"issuer_subject_id":"frank-hermes-pilot-result-party",
        "journal_root":p.root.join("journal"),"maximum_ttl":60,"schema":"frank.result-authority-configuration.v1"}),
    )?;
    file(&p.root.join("config/authority.json"), &authority)?;
    let policy_hash = digest(&canonical(
        &json!({"actor_id":p.actor_id,"artifact_sha256":p.producer_artifact_sha256,
        "configuration_sha256":p.configuration_sha256,"integration_id":p.integration_id,"kind":"hermes",
        "normalization_sha256":p.normalizer_sha256,"route":p.route}),
    )?);
    let producer = canonical(
        &json!({"authority_configuration":p.root.join("config/authority.json"),
        "authority_configuration_sha256":digest(&authority),"connector_policy_sha256":policy_hash,
        "journal":p.journal,"schema":"frank.connector-result-producer.v1"}),
    )?;
    file(&p.root.join("config/producer.json"), &producer)?;
    let rules: Vec<_> = p
        .resources
        .iter()
        .map(|resource| {
            json!({"active":true,"effect":"allow","key_id":"frank-hermes-pilot-result-key",
        "not_after_ms":p.not_after*1000,"not_before_ms":p.not_before*1000,"resource":resource,
        "resource_match":"prefix","subject_id":"frank-hermes-pilot-result-party"})
        })
        .collect();
    let receiver = canonical(
        &json!({"audience":"frank://result-receiver","descriptor":{"fingerprint":fingerprint,
        "handler_id":"frank-connector-result-receiver","opcode":232},"keys":[{"key_id":"frank-hermes-pilot-result-key",
        "not_after":p.not_after,"not_before":p.not_before,"production_authority":true,"public_key_hex":public_hex,
        "revoked_at":Value::Null,"status":"active"}],"operation":"frank.result.attest.v1","revoked_subject_keys":[],
        "rules":rules,"schema":"frank.result-receiver-policy.v1","subjects":[{"actor_id":p.actor_id,
        "integration_id":p.integration_id,"key_id":"frank-hermes-pilot-result-key","route":p.route,
        "subject_id":"frank-hermes-pilot-result-party"}]}),
    )?;
    file(&p.root.join("config/receiver-policy.json"), &receiver)?;
    let complete = canonical(
        &json!({"assignment_sha256":digest(&assignment),"authority_configuration_sha256":digest(&authority),
        "external_effects":false,"issuer_public_key_hex":public_hex,"not_after":p.not_after,"not_before":p.not_before,
        "plan_sha256":digest(&raw),"producer_configuration_sha256":digest(&producer),
        "receiver_policy_sha256":digest(&receiver),"root":p.root,"schema":"secs.frank.connector-result-setup-complete.v1"}),
    )?;
    file(&p.root.join("COMPLETE.json"), &complete)?;
    std::io::stdout().write_all(&complete).map_err(|_| ())
}

fn main() {
    if run().is_err() {
        eprintln!("{{\"error\":\"connector_result_setup_rejected\"}}");
        std::process::exit(2);
    }
}
