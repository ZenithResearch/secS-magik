//! Private Frank byte reader. Never reserializes work, result or payload.
use super::frank_result_authority::{Error, Result};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::BTreeSet;

pub(super) fn identifier(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(b))
}
pub(super) fn digest(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error);
    }
    let mut b = [0; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| Error)?;
    }
    Ok(b)
}
pub(super) fn metadata<T: serde::de::DeserializeOwned>(b: &[u8], max: usize) -> Result<T> {
    crate::devgraph_work_request::strict_json(b, max).map_err(|_| Error)?;
    serde_json::from_slice(b).map_err(|_| Error)
}
pub(super) fn nullable<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}

struct Scanner<'a> {
    b: &'a [u8],
    p: usize,
}
impl Scanner<'_> {
    fn ws(&mut self) {
        while self.b.get(self.p).is_some_and(|b| b" \r\n\t".contains(b)) {
            self.p += 1;
        }
    }
    fn take(&mut self, b: u8) -> Result<()> {
        self.ws();
        if self.b.get(self.p) != Some(&b) {
            return Err(Error);
        }
        self.p += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<String> {
        self.ws();
        let start = self.p;
        self.take(b'"')?;
        let mut escaped = false;
        loop {
            let b = *self.b.get(self.p).ok_or(Error)?;
            self.p += 1;
            if b < 32 {
                return Err(Error);
            }
            if escaped {
                escaped = false;
                continue;
            }
            if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                break;
            }
        }
        serde_json::from_slice(&self.b[start..self.p]).map_err(|_| Error)
    }
    fn value(&mut self, depth: usize) -> Result<()> {
        if depth > 64 {
            return Err(Error);
        }
        self.ws();
        match self.b.get(self.p).copied().ok_or(Error)? {
            b'"' => {
                self.string()?;
            }
            b'{' => {
                self.p += 1;
                self.ws();
                if self.b.get(self.p) == Some(&b'}') {
                    self.p += 1;
                    return Ok(());
                }
                let mut names = BTreeSet::new();
                loop {
                    if !names.insert(self.string()?) {
                        return Err(Error);
                    }
                    self.take(b':')?;
                    self.value(depth + 1)?;
                    self.ws();
                    match self.b.get(self.p) {
                        Some(b'}') => {
                            self.p += 1;
                            break;
                        }
                        Some(b',') => self.p += 1,
                        _ => return Err(Error),
                    }
                }
            }
            b'[' => {
                self.p += 1;
                self.ws();
                if self.b.get(self.p) == Some(&b']') {
                    self.p += 1;
                    return Ok(());
                }
                loop {
                    self.value(depth + 1)?;
                    self.ws();
                    match self.b.get(self.p) {
                        Some(b']') => {
                            self.p += 1;
                            break;
                        }
                        Some(b',') => self.p += 1,
                        _ => return Err(Error),
                    }
                }
            }
            b't' | b'f' | b'n' => {
                let word = match self.b[self.p] {
                    b't' => b"true".as_slice(),
                    b'f' => b"false",
                    _ => b"null",
                };
                if self.b.get(self.p..self.p + word.len()) != Some(word) {
                    return Err(Error);
                }
                self.p += word.len();
            }
            b'-' | b'0'..=b'9' => {
                let start = self.p;
                if self.b[self.p] == b'-' {
                    self.p += 1;
                }
                match self.b.get(self.p) {
                    Some(b'0') => self.p += 1,
                    Some(b'1'..=b'9') => {
                        while self.b.get(self.p).is_some_and(u8::is_ascii_digit) {
                            self.p += 1;
                        }
                    }
                    _ => return Err(Error),
                }
                let mut decimal = false;
                if self.b.get(self.p) == Some(&b'.') {
                    decimal = true;
                    self.p += 1;
                    let p = self.p;
                    while self.b.get(self.p).is_some_and(u8::is_ascii_digit) {
                        self.p += 1;
                    }
                    if p == self.p {
                        return Err(Error);
                    }
                }
                if self.b.get(self.p).is_some_and(|b| *b == b'e' || *b == b'E') {
                    decimal = true;
                    self.p += 1;
                    if self.b.get(self.p).is_some_and(|b| *b == b'+' || *b == b'-') {
                        self.p += 1;
                    }
                    let p = self.p;
                    while self.b.get(self.p).is_some_and(u8::is_ascii_digit) {
                        self.p += 1;
                    }
                    if p == self.p {
                        return Err(Error);
                    }
                }
                if decimal {
                    let s = std::str::from_utf8(&self.b[start..self.p]).map_err(|_| Error)?;
                    if !s.parse::<f64>().map_err(|_| Error)?.is_finite() {
                        return Err(Error);
                    }
                }
            }
            _ => return Err(Error),
        }
        Ok(())
    }
}
pub(super) fn raw_json(b: &[u8], max: usize) -> Result<()> {
    if b.is_empty() || b.len() > max {
        return Err(Error);
    }
    std::str::from_utf8(b).map_err(|_| Error)?;
    let mut s = Scanner { b, p: 0 };
    s.value(0)?;
    s.ws();
    if s.p != b.len() {
        return Err(Error);
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub run_id: String,
    pub step_id: String,
    pub attempt_id: String,
    pub fence: Box<RawValue>,
}
impl Binding {
    fn validate(&self) -> Result<()> {
        if [&self.run_id, &self.step_id, &self.attempt_id]
            .iter()
            .any(|s| !identifier(s))
            || self.fence.get() == "0"
            || !self.fence.get().bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error);
        }
        Ok(())
    }
    pub(super) fn same(&self, b: &Self) -> bool {
        self.run_id == b.run_id
            && self.step_id == b.step_id
            && self.attempt_id == b.attempt_id
            && self.fence.get() == b.fence.get()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Work {
    pub schema: String,
    pub binding: Binding,
    pub actor_id: String,
    pub integration_id: String,
    pub route: String,
    pub effect_id: String,
    pub operation: String,
    pub scope: String,
    pub inputs: Box<RawValue>,
    pub output_types: Box<RawValue>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Terminal {
    pub schema: String,
    pub event_id: String,
    pub binding: Binding,
    pub actor_id: String,
    pub integration_id: String,
    pub route: String,
    pub effect_id: String,
    pub provider_reference: String,
    pub outcome: String,
    pub outputs: Box<RawValue>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Payload {
    pub schema: String,
    pub work_sha256: String,
    pub result: Box<RawValue>,
}
pub(super) fn work_and_result(work: &[u8], payload: &[u8]) -> Result<(Work, Terminal, Payload)> {
    raw_json(work, 1_048_576)?;
    raw_json(payload, 262_144)?;
    let w: Work = serde_json::from_slice(work).map_err(|_| Error)?;
    let p: Payload = serde_json::from_slice(payload).map_err(|_| Error)?;
    let r: Terminal = serde_json::from_str(p.result.get()).map_err(|_| Error)?;
    w.binding.validate()?;
    r.binding.validate()?;
    if w.schema != "frank.work.v1"
        || p.schema != "frank.native-result-payload.v1"
        || p.work_sha256
            != super::frank_result_authority::hex(&super::frank_result_authority::hash(work))
        || r.schema != "frank.result.v1"
        || !w.binding.same(&r.binding)
        || w.actor_id != r.actor_id
        || w.integration_id != r.integration_id
        || w.route != r.route
        || w.effect_id != r.effect_id
    {
        return Err(Error);
    }
    if [
        &w.actor_id,
        &w.integration_id,
        &w.route,
        &w.effect_id,
        &w.operation,
        &r.event_id,
    ]
    .iter()
    .any(|s| !identifier(s))
        || w.scope.is_empty()
        || w.scope.chars().count() > 4096
        || r.provider_reference.is_empty()
        || r.provider_reference.chars().count() > 4096
        || !["succeeded", "failed"].contains(&r.outcome.as_str())
    {
        return Err(Error);
    }
    for b in [w.inputs.get(), w.output_types.get(), r.outputs.get()] {
        let _: std::collections::BTreeMap<String, Box<RawValue>> =
            serde_json::from_str(b).map_err(|_| Error)?;
    }
    if r.outcome == "failed" {
        let v: std::collections::BTreeMap<String, Box<RawValue>> =
            serde_json::from_str(r.outputs.get()).map_err(|_| Error)?;
        if !v.is_empty() {
            return Err(Error);
        }
    }
    Ok((w, r, p))
}
pub(super) const OPERATIONS: [&str; 9] = [
    "review.load_review",
    "review.transcribe",
    "review.resolve_components",
    "review.annotate",
    "review.extract",
    "review.bind_source",
    "review.write_review",
    "review.write_status",
    "review.daily_note",
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frank_raw_numbers_duplicates_and_depth() {
        for b in [
            "{\"x\":-0.0}",
            "{\"x\":1.234e-12}",
            "{\"x\":184467440737095516160000000000}",
            "{\"x\":\"é😀\\u007f\"}",
        ] {
            assert!(raw_json(b.as_bytes(), 1024).is_ok());
        }
        for b in [
            "{\"x\":1,\"x\":2}",
            "{\"x\":1e999}",
            "{\"x\":NaN}",
            "{\"x\":01}",
            "{\"x\":\"\\ud800\"}",
        ] {
            assert!(raw_json(b.as_bytes(), 1024).is_err());
        }
        let good = format!("{}0{}", "[".repeat(64), "]".repeat(64));
        assert!(raw_json(good.as_bytes(), 1024).is_ok());
        let bad = format!("[{good}]");
        assert!(raw_json(bad.as_bytes(), 1024).is_err());
    }
}
