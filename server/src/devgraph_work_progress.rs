//! Receiver-owned validation for the versioned Devgraph workflow/Todo wire contract.
//! This module carries no Wallet adapter or application execution semantics.
use crate::devgraph_work_request::{identifier, kind, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;
const INVALID: &str = "invalid_work_request";
fn fields(value: &Value, required: &[&str], optional: &[(&str, Value)]) -> Result<Value> {
    let mut object = value.as_object().ok_or(INVALID)?.clone();
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.iter().any(|(k, _)| k == key))
    {
        return Err(INVALID);
    }
    for (key, default) in optional {
        object
            .entry((*key).to_owned())
            .or_insert_with(|| default.clone());
    }
    Ok(Value::Object(object))
}
fn string<'a>(value: &'a Value, field: &str, min: usize, max: usize) -> Result<&'a str> {
    let text = value[field].as_str().ok_or(INVALID)?;
    if !(min..=max).contains(&text.chars().count()) {
        return Err(INVALID);
    }
    Ok(text)
}
fn id(value: &Value, field: &str) -> Result<String> {
    let text = string(value, field, 1, 256)?;
    if !identifier(text) {
        return Err(INVALID);
    }
    Ok(text.to_owned())
}
fn array<'a>(value: &'a Value, field: &str, max: usize) -> Result<&'a Vec<Value>> {
    value[field]
        .as_array()
        .filter(|a| a.len() <= max)
        .ok_or(INVALID)
}
fn verdict(value: &Value, field: &str) -> Result<()> {
    if !matches!(
        value[field].as_str(),
        Some("approved" | "changes_requested" | "not_applicable")
    ) {
        return Err(INVALID);
    }
    Ok(())
}
fn stage(workflow: &str, value: &str) -> bool {
    matches!(value, "backlog" | "done" | "blocked_waiting_input")
        && matches!(workflow, "vibe-ceo.v1" | "execution.v1")
        || match workflow {
            "vibe-ceo.v1" => matches!(
                value,
                "planning"
                    | "developer_plan_approval"
                    | "ceo_plan_approval"
                    | "ready"
                    | "in_progress"
                    | "ceo_delivery_approval"
                    | "technical_review"
                    | "handoff_verification"
            ),
            "execution.v1" => matches!(
                value,
                "intake"
                    | "requirements_normalized"
                    | "baseline_captured"
                    | "implementing_commit"
                    | "commit_ready_for_review"
                    | "layer_review"
                    | "reconciling_ledger"
                    | "delivery_packet_ready"
            ),
            _ => false,
        }
}
fn evidence_url(value: &str) -> bool {
    if value
        .chars()
        .any(|c| c <= ' ' || c == '\\' || c == '\u{7f}')
    {
        return false;
    }
    let Some(authority) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .map(|s| s.split(['/', '?', '#']).next().unwrap_or(""))
    else {
        return false;
    };
    let (host, port) = if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return false;
        };
        if authority[1..end].parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        (&authority[..=end], &authority[end + 1..])
    } else {
        let host = authority.split(':').next().unwrap_or("");
        if !host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c))
        {
            return false;
        }
        (host, &authority[host.len()..])
    };
    !host.is_empty()
        && (port.is_empty()
            || port.strip_prefix(':').is_some_and(|p| {
                !p.is_empty()
                    && p.len() <= 5
                    && p.bytes().all(|c| c.is_ascii_digit())
                    && p.parse::<u16>().is_ok()
            }))
}
pub(crate) fn normalize(op: &str, raw: &Value, resources: &mut BTreeSet<String>) -> Result<Value> {
    match op {
        "workflow.assign" => {
            let v = fields(
                raw,
                &["workflow_id", "reason"],
                &[("stage", json!("backlog"))],
            )?;
            if !stage(
                string(&v, "workflow_id", 1, 64)?,
                string(&v, "stage", 1, 64)?,
            ) {
                return Err(INVALID);
            }
            string(&v, "reason", 1, 4096)?;
            Ok(v)
        }
        "workflow.transition" => {
            let v = fields(raw, &["stage"], &[("reason", json!(""))])?;
            string(&v, "stage", 1, 64)?;
            string(&v, "reason", 0, 4096)?;
            Ok(v)
        }
        "workflow.review" => review(raw, resources),
        "progress.set" => {
            let v = fields(
                raw,
                &["progress", "reason", "record_id"],
                &[("evidence", json!([])), ("requirements", json!([]))],
            )?;
            if !matches!(
                v["progress"].as_str(),
                Some("not_started" | "in_progress" | "done")
            ) || string(&v, "reason", 1, 8192)?.trim().is_empty()
            {
                return Err(INVALID);
            }
            let r = review(
                &json!({"record_id":v["record_id"],"phase":"requirements","verdict":"approved","summary":v["reason"],"evidence":v["evidence"],"requirements":v["requirements"]}),
                resources,
            )?;
            Ok(
                json!({"progress":v["progress"],"reason":v["reason"],"record_id":r["record_id"],"evidence":r["evidence"],"requirements":r["requirements"]}),
            )
        }
        _ => Err(INVALID),
    }
}
fn review(raw: &Value, resources: &mut BTreeSet<String>) -> Result<Value> {
    let mut v = fields(
        raw,
        &["record_id", "phase", "verdict", "summary"],
        &[
            ("evidence", json!([])),
            ("requirements", json!([])),
            ("layers", json!([])),
        ],
    )?;
    let record = id(&v, "record_id")?;
    let record_type = match v["phase"].as_str() {
        Some("developer_plan" | "ceo_plan" | "ceo_delivery" | "resolution") => "Decision",
        Some("handoff") => "Handoff",
        Some("requirements" | "baseline" | "commit" | "technical") => "ReviewPacket",
        _ => return Err(INVALID),
    };
    verdict(&v, "verdict")?;
    string(&v, "summary", 1, 8192)?;
    resources.insert(format!("{record_type}/{record}"));
    let mut evidence = Vec::new();
    let mut ids = BTreeSet::new();
    for item in array(&v, "evidence", 50)? {
        let e = fields(
            item,
            &["kind", "id"],
            &[("title", json!("")), ("url", json!(""))],
        )?;
        let key = id(&e, "id")?;
        if !ids.insert(key.clone())
            || !matches!(e["kind"].as_str(), Some("Artifact" | "ExternalLink"))
        {
            return Err(INVALID);
        }
        let title = string(&e, "title", 0, 4096)?;
        let url = string(&e, "url", 0, 4096)?;
        if url.is_empty() {
            if !title.is_empty() {
                return Err(INVALID);
            }
        } else {
            if e["kind"] != "ExternalLink" || title.trim().is_empty() || !evidence_url(url) {
                return Err(INVALID);
            }
            resources.insert(format!("ExternalLink/{key}"));
        }
        evidence.push(e);
    }
    let mut requirements = Vec::new();
    let mut requirement_ids = BTreeSet::new();
    for item in array(&v, "requirements", 100)? {
        let r = fields(
            item,
            &["id", "title", "outcome"],
            &[
                ("subject", json!("")),
                ("evidence_ids", json!([])),
                ("reason", json!("")),
            ],
        )?;
        if !requirement_ids.insert(id(&r, "id")?) {
            return Err(INVALID);
        }
        string(&r, "title", 1, 4096)?;
        let reason = string(&r, "reason", 0, 4096)?;
        let subject = r["subject"].as_str().ok_or(INVALID)?;
        if !subject.is_empty() {
            let (label, key) = subject.split_once('/').ok_or(INVALID)?;
            if !(kind(label) || matches!(label, "Requirement" | "AcceptanceCriterion"))
                || !identifier(key)
            {
                return Err(INVALID);
            }
        }
        let attached = array(&r, "evidence_ids", 50)?;
        if attached
            .iter()
            .any(|e| e.as_str().is_none_or(|key| !ids.contains(key)))
        {
            return Err(INVALID);
        }
        match r["outcome"].as_str() {
            Some("met") if !attached.is_empty() => {}
            Some("excluded") if !reason.trim().is_empty() => {}
            Some("unmet") => {}
            _ => return Err(INVALID),
        }
        requirements.push(r);
    }
    let mut layers = Vec::new();
    let mut layer_ids = BTreeSet::new();
    for item in array(&v, "layers", 6)? {
        let l = fields(item, &["layer", "verdict"], &[("reason", json!(""))])?;
        let key = l["layer"].as_str().ok_or(INVALID)?;
        if !matches!(
            key,
            "product" | "architecture" | "implementation" | "e2e" | "design" | "ux"
        ) || !layer_ids.insert(key.to_owned())
        {
            return Err(INVALID);
        }
        verdict(&l, "verdict")?;
        if string(&l, "reason", 0, 4096)?.trim().is_empty() && l["verdict"] == "not_applicable" {
            return Err(INVALID);
        }
        layers.push(l);
    }
    v["evidence"] = json!(evidence);
    v["requirements"] = json!(requirements);
    v["layers"] = json!(layers);
    Ok(v)
}
