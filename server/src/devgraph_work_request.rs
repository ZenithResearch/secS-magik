//! Closed named Work request v1. Shared byte-for-byte with the Wallet producer.
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::fmt;

pub const MAX_SAFE: u64 = 9_007_199_254_740_991;
pub type Result<T> = std::result::Result<T, &'static str>;

struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("strict JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                if v.unsigned_abs() > MAX_SAFE {
                    return Err(E::custom("unsafe integer"));
                }
                Ok(StrictValue(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                if v > MAX_SAFE {
                    return Err(E::custom("unsafe integer"));
                }
                Ok(StrictValue(v.into()))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut items = Vec::new();
                while let Some(StrictValue(item)) = a.next_element()? {
                    items.push(item);
                }
                Ok(StrictValue(Value::Array(items)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut fields = Map::new();
                while let Some((key, StrictValue(value))) = a.next_entry::<String, StrictValue>()? {
                    if fields.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate key"));
                    }
                }
                Ok(StrictValue(Value::Object(fields)))
            }
        }
        d.deserialize_any(V)
    }
}

pub fn strict_json(raw: &[u8], maximum: usize) -> Result<Value> {
    if raw.len() > maximum {
        return Err("json_too_large");
    }
    let StrictValue(value) = serde_json::from_slice(raw).map_err(|_| "invalid_json")?;
    fn depth(v: &Value, n: usize) -> bool {
        n <= 16
            && match v {
                Value::Array(items) => items.iter().all(|v| depth(v, n + 1)),
                Value::Object(items) => items.values().all(|v| depth(v, n + 1)),
                _ => true,
            }
    }
    if !depth(&value, 0) {
        return Err("invalid_json");
    }
    Ok(value)
}

pub fn identifier(s: &str) -> bool {
    let b = s.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    !b.is_empty()
        && b.len() <= 256
        && alnum(b[0])
        && alnum(b[b.len() - 1])
        && b.iter().all(|b| alnum(*b) || *b == b'-')
}
pub fn kind(s: &str) -> bool {
    matches!(s, "Proposal" | "Initiative" | "Project" | "Issue" | "Task")
}
pub fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or("invalid_work_request")
}
fn positive(v: &Value) -> Result<u64> {
    v.as_u64()
        .filter(|v| (1..=MAX_SAFE).contains(v))
        .ok_or("invalid_work_request")
}
fn exact(v: &Value, fields: &[&str]) -> Result<()> {
    let object = v.as_object().ok_or("invalid_work_request")?;
    if object.len() != fields.len() || fields.iter().any(|k| !object.contains_key(*k)) {
        return Err("invalid_work_request");
    }
    Ok(())
}
fn reference(v: &Value) -> Result<String> {
    exact(v, &["kind", "id", "expected_version"])?;
    if !kind(text(v, "kind")?) || !identifier(text(v, "id")?) {
        return Err("invalid_work_request");
    }
    positive(&v["expected_version"])?;
    Ok(format!("{}/{}", text(v, "kind")?, text(v, "id")?))
}

pub struct WorkRequest {
    pub value: Value,
    pub canonical: Vec<u8>,
    pub operation: String,
    pub resources: Vec<String>,
}

impl WorkRequest {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut value = strict_json(raw, 131_072)?;
        exact(
            &value,
            &[
                "schema",
                "operation",
                "kind",
                "id",
                "expected_version",
                "payload",
            ],
        )?;
        if text(&value, "schema")? == "devgraph.arena-request.v1" {
            return Self::parse_arena(value);
        }
        if text(&value, "schema")? != "devgraph.work-request.v1" {
            return Err("invalid_work_request");
        }
        let op = text(&value, "operation")?.to_string();
        let label = text(&value, "kind")?.to_string();
        let id = text(&value, "id")?.to_string();
        if !kind(&label) || !identifier(&id) {
            return Err("invalid_work_request");
        }
        if op == "create" {
            if !value["expected_version"].is_null() {
                return Err("invalid_work_request");
            }
        } else {
            positive(&value["expected_version"])?;
        }
        let mut payload = value["payload"].clone();
        let fields = payload.as_object_mut().ok_or("invalid_work_request")?;
        let mut resources = BTreeSet::from([format!("{label}/{id}")]);
        match op.as_str() {
            "create" | "patch" => {
                let allowed = [
                    "id",
                    "title",
                    "description",
                    "priority",
                    "artifact_ids",
                    "external_link_ids",
                ];
                if fields
                    .keys()
                    .any(|k| !allowed.contains(&k.as_str()) || (op == "patch" && k == "id"))
                {
                    return Err("invalid_work_request");
                }
                if op == "create" {
                    if fields.get("id").and_then(Value::as_str) != Some(&id)
                        || !fields.contains_key("title")
                    {
                        return Err("invalid_work_request");
                    }
                    fields
                        .entry("description")
                        .or_insert(Value::String(String::new()));
                    fields.entry("priority").or_insert(Value::from(0));
                    fields.entry("artifact_ids").or_insert(Value::Array(vec![]));
                    fields
                        .entry("external_link_ids")
                        .or_insert(Value::Array(vec![]));
                } else if fields.is_empty() {
                    return Err("invalid_work_request");
                }
                for (key, item) in fields.iter() {
                    let valid = match key.as_str() {
                        "id" => item.as_str().is_some_and(identifier),
                        "title" => item.as_str().is_some_and(|s| !s.is_empty()),
                        "description" => item.is_string(),
                        "priority" => item.as_i64().is_some_and(|v| v.unsigned_abs() <= MAX_SAFE),
                        "artifact_ids" | "external_link_ids" => item
                            .as_array()
                            .is_some_and(|a| a.iter().all(|i| i.as_str().is_some_and(identifier))),
                        _ => false,
                    };
                    if !valid {
                        return Err("invalid_work_request");
                    }
                }
            }
            "status" => {
                exact(&payload, &["status"])?;
                if !matches!(
                    text(&payload, "status")?,
                    "draft" | "review" | "accepted" | "archived"
                ) {
                    return Err("invalid_work_request");
                }
            }
            "archive" => exact(&payload, &[])?,
            "accept" | "convert" => {
                if label != "Proposal" {
                    return Err("invalid_work_request");
                }
                let (destination, key) = if op == "accept" {
                    exact(&payload, &["decision_id", "decision_title"])?;
                    if text(&payload, "decision_title")?.is_empty() {
                        return Err("invalid_work_request");
                    }
                    ("Decision", "decision_id")
                } else {
                    exact(&payload, &["issue_id", "decision_id"])?;
                    if !identifier(text(&payload, "decision_id")?) {
                        return Err("invalid_work_request");
                    }
                    resources.insert(format!("Decision/{}", text(&payload, "decision_id")?));
                    ("Issue", "issue_id")
                };
                if !identifier(text(&payload, key)?) {
                    return Err("invalid_work_request");
                }
                resources.insert(format!("{destination}/{}", text(&payload, key)?));
            }
            "parent.set" => {
                if payload.get("previous_arena").is_some() {
                    exact(&payload, &["previous_parent", "parent", "previous_arena"])?;
                    if !payload["previous_arena"].is_null() {
                        if label != "Task" || payload["parent"].is_null() {
                            return Err("invalid_work_request");
                        }
                        resources.insert(arena_reference(&payload["previous_arena"])?);
                    }
                } else {
                    exact(&payload, &["previous_parent", "parent"])?;
                }
                let expected_kind = match label.as_str() {
                    "Project" => "Initiative",
                    "Issue" => "Project",
                    "Task" => "Issue",
                    _ => return Err("invalid_work_request"),
                };
                if payload["previous_parent"].is_null() && payload["parent"].is_null() {
                    return Err("invalid_work_request");
                }
                for key in ["previous_parent", "parent"] {
                    let parent = &payload[key];
                    if !parent.is_null() {
                        let resource = reference(parent)?;
                        if text(parent, "kind")? != expected_kind {
                            return Err("invalid_work_request");
                        }
                        resources.insert(resource);
                    }
                }
            }
            "dependency.add" | "dependency.remove" | "blocker.add" | "blocker.remove" => {
                exact(&payload, &["target"])?;
                let target = &payload["target"];
                let resource = reference(target)?;
                if resources.contains(&resource)
                    || (op.starts_with("blocker.")
                        && (label != "Task" || text(target, "kind")? != "Task"))
                {
                    return Err("invalid_work_request");
                }
                resources.insert(resource);
            }
            _ => return Err("invalid_work_request"),
        }
        value["payload"] = payload;
        let canonical = serde_json::to_vec(&value).map_err(|_| "invalid_work_request")?;
        if canonical.len() > 65_536 {
            return Err("request_too_large");
        }
        Ok(Self {
            value,
            canonical,
            operation: format!("devgraph.work.{op}.v1"),
            resources: resources.into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_request_vectors() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/named-work-v1/requests.json"
        ))
        .unwrap();
        for vector in vectors.as_array().unwrap() {
            let request = WorkRequest::parse(vector["raw"].as_str().unwrap().as_bytes()).unwrap();
            assert_eq!(
                request.canonical,
                vector["canonical"].as_str().unwrap().as_bytes()
            );
            assert_eq!(request.operation, vector["operation"]);
            assert_eq!(
                serde_json::to_value(request.resources).unwrap(),
                vector["resources"]
            );
        }
    }
    #[test]
    fn reject_duplicates_and_unsafe_numbers() {
        for raw in [
            r#"{"payload":{"a":1,"a":2}}"#,
            r#"{"a":1.0}"#,
            r#"{"a":9007199254740992}"#,
        ] {
            assert!(strict_json(raw.as_bytes(), 131_072).is_err());
        }
    }
}

#[cfg(test)]
mod arena_vectors {
    use super::*;
    #[test]
    fn arena_requests_and_work_parent_changes_match_python() {
        let vectors: Value =
            serde_json::from_str(include_str!("../tests/fixtures/arena-v1/requests.json")).unwrap();
        for vector in vectors.as_array().unwrap() {
            let parsed = WorkRequest::parse(vector["raw"].as_str().unwrap().as_bytes()).unwrap();
            assert_eq!(
                parsed.canonical,
                vector["canonical"].as_str().unwrap().as_bytes()
            );
            assert_eq!(parsed.operation, vector["operation"]);
            assert_eq!(
                serde_json::to_value(parsed.resources).unwrap(),
                vector["resources"]
            );
        }
    }
}

fn arena_reference(v: &Value) -> Result<String> {
    exact(v, &["kind", "id", "expected_version"])?;
    if text(v, "kind")? != "Arena" || !identifier(text(v, "id")?) {
        return Err("invalid_arena_reference");
    }
    positive(&v["expected_version"])?;
    Ok(format!("Arena/{}", text(v, "id")?))
}

impl WorkRequest {
    pub fn request_domain(&self) -> &'static [u8] {
        if self.value["schema"] == "devgraph.arena-request.v1" {
            b"devgraph.arena-request.v1\0"
        } else {
            b"devgraph.work-request.v1\0"
        }
    }

    fn parse_arena(mut value: Value) -> Result<Self> {
        let op = text(&value, "operation")?.to_string();
        let label = text(&value, "kind")?.to_string();
        let id = text(&value, "id")?.to_string();
        if !identifier(&id) || !matches!(op.as_str(), "create" | "patch" | "archive" | "member.set")
        {
            return Err("invalid_arena_request");
        }
        if (op == "member.set" && !matches!(label.as_str(), "Initiative" | "Task"))
            || (op != "member.set" && label != "Arena")
        {
            return Err("invalid_arena_request");
        }
        if op == "create" {
            if !value["expected_version"].is_null() {
                return Err("invalid_arena_request");
            }
        } else {
            positive(&value["expected_version"])?;
        }
        let mut payload = value["payload"].clone();
        let fields = payload.as_object_mut().ok_or("invalid_arena_request")?;
        let mut resources = BTreeSet::from([format!("{label}/{id}")]);
        match op.as_str() {
            "create" | "patch" => {
                if fields.keys().any(|key| {
                    !["id", "title", "description"].contains(&key.as_str())
                        || (op == "patch" && key == "id")
                }) {
                    return Err("invalid_arena_request");
                }
                if op == "create" {
                    if fields.get("id").and_then(Value::as_str) != Some(&id)
                        || !fields.contains_key("title")
                    {
                        return Err("invalid_arena_request");
                    }
                    fields
                        .entry("description")
                        .or_insert(Value::String(String::new()));
                } else if fields.is_empty() {
                    return Err("invalid_arena_request");
                }
                for (key, item) in fields.iter() {
                    let valid = match key.as_str() {
                        "id" => item.as_str().is_some_and(identifier),
                        "title" => item
                            .as_str()
                            .is_some_and(|s| !s.is_empty() && s.chars().count() <= 4096),
                        "description" => item.as_str().is_some_and(|s| s.chars().count() <= 32768),
                        _ => false,
                    };
                    if !valid {
                        return Err("invalid_arena_request");
                    }
                }
            }
            "archive" => exact(&payload, &[])?,
            "member.set" => {
                exact(&payload, &["previous_arena", "arena"])?;
                if payload["previous_arena"].is_null() && payload["arena"].is_null() {
                    return Err("invalid_arena_request");
                }
                for key in ["previous_arena", "arena"] {
                    if !payload[key].is_null() {
                        resources.insert(arena_reference(&payload[key])?);
                    }
                }
            }
            _ => return Err("invalid_arena_request"),
        }
        value["payload"] = payload;
        let canonical = serde_json::to_vec(&value).map_err(|_| "invalid_arena_request")?;
        if canonical.len() > 65_536 {
            return Err("request_too_large");
        }
        Ok(Self {
            value,
            canonical,
            operation: format!("devgraph.arena.{op}.v1"),
            resources: resources.into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod invalid_arena_vectors {
    use super::*;
    #[test]
    fn rejects_closed_arena_contract_violations() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/arena-v1/invalid-requests.json"
        ))
        .unwrap();
        for vector in vectors.as_array().unwrap() {
            assert!(
                WorkRequest::parse(vector["raw"].as_str().unwrap().as_bytes()).is_err(),
                "{}",
                vector["name"]
            );
        }
    }
}
