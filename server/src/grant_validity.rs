//! Standing-grant time bounds. This does not attest revocation or grant status.
//! Access credentials, signing keys and consent challenges remain independently
//! finite. Old wire contracts must opt into a new version before using this type.
use crate::devgraph_work_request::{strict_json, Result, MAX_SAFE};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

pub const SCHEMA: &str = "castalia.grant-validity.v1";
const INVALID: &str = "invalid_grant_validity";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantValidity {
    not_before: u64,
    not_after: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "mode", deny_unknown_fields)]
enum Wire {
    #[serde(rename = "dated")]
    Dated {
        schema: String,
        not_before: u64,
        not_after: u64,
    },
    #[serde(rename = "until_revoked")]
    UntilRevoked { schema: String, not_before: u64 },
}
impl GrantValidity {
    pub fn dated(not_before: u64, not_after: u64) -> Result<Self> {
        if not_before >= not_after || not_after > MAX_SAFE {
            return Err(INVALID);
        }
        Ok(Self {
            not_before,
            not_after: Some(not_after),
        })
    }
    pub fn until_revoked(not_before: u64) -> Result<Self> {
        if not_before > MAX_SAFE {
            return Err(INVALID);
        }
        Ok(Self {
            not_before,
            not_after: None,
        })
    }
    pub fn parse(raw: &[u8]) -> Result<Self> {
        serde_json::from_value(strict_json(raw, 1024)?).map_err(|_| INVALID)
    }
    pub fn not_before(&self) -> u64 {
        self.not_before
    }
    pub fn not_after(&self) -> Option<u64> {
        self.not_after
    }
    pub fn contains(&self, now: u64) -> bool {
        now <= MAX_SAFE && self.not_before <= now && self.not_after.is_none_or(|end| now < end)
    }
    pub fn contained_by(&self, parent: &Self) -> bool {
        self.not_before >= parent.not_before
            && match (self.not_after, parent.not_after) {
                (_, None) => true,
                (Some(child), Some(parent)) => child <= parent,
                (None, Some(_)) => false,
            }
    }
    pub fn credential_deadline(&self, now: u64, lifetime: u64) -> Result<u64> {
        if !self.contains(now) || !(1..=3600).contains(&lifetime) {
            return Err(INVALID);
        }
        let deadline = self
            .not_after
            .map_or(now + lifetime, |end| end.min(now + lifetime));
        if deadline > MAX_SAFE {
            return Err(INVALID);
        }
        Ok(deadline)
    }
}
impl Serialize for GrantValidity {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        match self.not_after {
            Some(not_after) => Wire::Dated {
                schema: SCHEMA.into(),
                not_before: self.not_before,
                not_after,
            },
            None => Wire::UntilRevoked {
                schema: SCHEMA.into(),
                not_before: self.not_before,
            },
        }
        .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for GrantValidity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let (schema, result) = match Wire::deserialize(deserializer)? {
            Wire::Dated {
                schema,
                not_before,
                not_after,
            } => (schema, Self::dated(not_before, not_after)),
            Wire::UntilRevoked { schema, not_before } => (schema, Self::until_revoked(not_before)),
        };
        if schema != SCHEMA {
            return Err(D::Error::custom(INVALID));
        }
        result.map_err(D::Error::custom)
    }
}
