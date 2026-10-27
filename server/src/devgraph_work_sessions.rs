//! Exact resource derivation for the additive v2 session attachment operation.
//! Source metadata supplies no authority; the ordinary policy must cover every ID.
use crate::devgraph_work_request::{text, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const INVALID: &str = "invalid_work_request";
fn fields(value: &Value, required: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or(INVALID)?;
    if object.len() != required.len() || required.iter().any(|k| !object.contains_key(*k)) {
        return Err(INVALID);
    }
    Ok(())
}
fn opaque(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 256
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(b))
}
fn identity(value: &Value) -> Result<String> {
    fields(
        value,
        &["application", "source_instance_id", "external_session_id"],
    )?;
    let app = text(value, "application")?;
    let source = text(value, "source_instance_id")?;
    let native = text(value, "external_session_id")?;
    if app.is_empty()
        || app.len() > 64
        || !app.as_bytes()[0].is_ascii_lowercase()
        || !app
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !opaque(source)
        || !opaque(native)
    {
        return Err(INVALID);
    }
    // All three validated atoms are ASCII and cannot contain JSON escape characters.
    let canonical = format!(
        r#"{{"application":"{app}","external_session_id":"{native}","source_instance_id":"{source}"}}"#
    );
    Ok(format!(
        "sr-{}",
        Sha256::digest(canonical.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}
fn utc(value: &str) -> bool {
    let Some(body) = value
        .strip_suffix('Z')
        .or_else(|| value.strip_suffix("+00:00"))
    else {
        return false;
    };
    if !body.is_ascii() || body.len() < 19 || body.len() > 26 {
        return false;
    }
    let b = body.as_bytes();
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return false;
    }
    let parts = [
        &body[0..4],
        &body[5..7],
        &body[8..10],
        &body[11..13],
        &body[14..16],
        &body[17..19],
    ];
    if parts.iter().any(|s| !s.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    if body.len() > 19
        && (b[19] != b'.' || body.len() < 21 || !b[20..].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    let n: Vec<u32> = parts.iter().map(|s| s.parse().unwrap()).collect();
    let leap = n[0].is_multiple_of(4) && (!n[0].is_multiple_of(100) || n[0].is_multiple_of(400));
    let days = match n[1] {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    n[0] > 0 && n[2] > 0 && n[2] <= days && n[3] < 24 && n[4] < 60 && n[5] < 60
}

pub fn normalize(raw: &Value, resources: &mut BTreeSet<String>) -> Result<Value> {
    let mut value = raw.clone();
    let object = value.as_object_mut().ok_or(INVALID)?;
    if !object.contains_key("link") {
        object.insert("link".into(), Value::Null);
    }
    fields(&value, &["session", "observed_at", "basis", "link"])?;
    let session = identity(&value["session"])?;
    if !utc(text(&value, "observed_at")?)
        || !matches!(
            text(&value, "basis")?,
            "inspected" | "declared_scope" | "source_observed"
        )
    {
        return Err(INVALID);
    }
    resources.insert(format!("SessionRef/{session}"));
    let link = &value["link"];
    if !link.is_null() {
        fields(
            link,
            &[
                "source_instance_id",
                "event_id",
                "attempt_id",
                "relation",
                "origin",
                "target",
                "observed_at",
                "basis",
            ],
        )?;
        for key in ["source_instance_id", "event_id", "attempt_id"] {
            if !opaque(text(link, key)?) {
                return Err(INVALID);
            }
        }
        let origin = identity(&link["origin"])?;
        let target = identity(&link["target"])?;
        if origin == target
            || (session != origin && session != target)
            || !utc(text(link, "observed_at")?)
            || !matches!(
                text(link, "relation")?,
                "delegated_to" | "forked_from" | "uses_runtime"
            )
            || !matches!(text(link, "basis")?, "declared" | "source_observed")
        {
            return Err(INVALID);
        }
        let canonical = format!(
            r#"["{}","{}"]"#,
            text(link, "source_instance_id")?,
            text(link, "event_id")?
        );
        resources.insert(format!(
            "SessionLink/sl-{}",
            Sha256::digest(canonical.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        resources.insert(format!("SessionRef/{origin}"));
        resources.insert(format!("SessionRef/{target}"));
    }
    Ok(value)
}
