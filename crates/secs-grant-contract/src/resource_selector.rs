//! Resource selection primitive, separate from all v1 signed grant formats.
//! This is not a grant, an operation permission or proof of current authority.
//! Never use a caller's ancestry as a ResourceSnapshot. Receivers must combine
//! this check with current verified grants, operations, constraints, replay and
//! transactional pre/post effect checks. No conversion from prefix scopes exists.
use crate::{Result, parse, text};
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "secs.resource-selector.v1";
const INVALID: &str = "invalid_resource_selector";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceRef {
    pub kind: String,
    pub id: String,
}
impl ResourceRef {
    fn validate(&self) -> Result<()> {
        text(&self.kind)?;
        text(&self.id)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Hierarchy {
    pub relation: String,
    pub roots: Vec<ResourceRef>,
    pub include_self: bool,
}
impl Hierarchy {
    fn validate(&self) -> Result<()> {
        text(&self.relation)?;
        references(&self.roots, 16)
    }
    // Conservative structural proof. A new anchor's ancestry cannot be proven
    // offline, so only explicit subsets of the same roots/relation are accepted.
    fn within(&self, parent: &Self) -> bool {
        self.relation == parent.relation
            && (!self.include_self || parent.include_self)
            && self.roots.iter().all(|root| parent.roots.contains(root))
    }
    fn permits(
        &self,
        service: &str,
        resource: &ResourceRef,
        snapshot: &impl ResourceSnapshot,
    ) -> Result<bool> {
        if !snapshot.supports_relation(service, &self.relation)? {
            return Err("unsupported_resource_relation");
        }
        for root in &self.roots {
            if !snapshot.exists(service, root)? {
                continue;
            }
            if resource == root {
                if self.include_self {
                    return Ok(true);
                }
            } else if snapshot.is_descendant(service, &self.relation, resource, root)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Selection {
    All {},
    Objects {
        refs: Vec<ResourceRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<Hierarchy>,
    },
    Descendants {
        hierarchy: Hierarchy,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceSelector {
    pub schema: String,
    pub service: String,
    pub kinds: Vec<String>,
    pub selection: Selection,
}
fn references(refs: &[ResourceRef], max: usize) -> Result<()> {
    if refs.is_empty() || refs.len() > max {
        return Err(INVALID);
    }
    for (i, reference) in refs.iter().enumerate() {
        reference.validate()?;
        if refs[..i].contains(reference) {
            return Err(INVALID);
        }
    }
    Ok(())
}
impl ResourceSelector {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA || self.kinds.is_empty() || self.kinds.len() > 16 {
            return Err(INVALID);
        }
        text(&self.service)?;
        for (i, kind) in self.kinds.iter().enumerate() {
            text(kind)?;
            if self.kinds[..i].contains(kind) {
                return Err(INVALID);
            }
        }
        match &self.selection {
            Selection::All {} => {}
            Selection::Objects { refs, within } => {
                references(refs, 128)?;
                if refs.iter().any(|r| !self.kinds.contains(&r.kind)) {
                    return Err(INVALID);
                }
                if let Some(guard) = within {
                    guard.validate()?;
                }
            }
            Selection::Descendants { hierarchy } => hierarchy.validate()?,
        }
        Ok(())
    }
    /// Structural narrowing only. It neither proves current ancestry nor grants
    /// authority. Unknown relations still require an installed receiver adapter.
    pub fn within(&self, parent: &Self) -> Result<bool> {
        self.validate()?;
        parent.validate()?;
        if self.service != parent.service || !self.kinds.iter().all(|k| parent.kinds.contains(k)) {
            return Ok(false);
        }
        Ok(match (&self.selection, &parent.selection) {
            (_, Selection::All {}) => true,
            (Selection::All {}, _) => false,
            (
                Selection::Objects { refs, within },
                Selection::Objects {
                    refs: parent_refs,
                    within: parent_guard,
                },
            ) => {
                refs.iter().all(|r| parent_refs.contains(r))
                    && match (within, parent_guard) {
                        (_, None) => true,
                        (Some(child), Some(parent)) => child.within(parent),
                        (None, Some(_)) => false,
                    }
            }
            (
                Selection::Objects {
                    within: Some(child),
                    ..
                },
                Selection::Descendants { hierarchy },
            ) => child.within(hierarchy),
            (
                Selection::Descendants { hierarchy: child },
                Selection::Descendants { hierarchy: parent },
            ) => child.within(parent),
            _ => false,
        })
    }
    /// Evaluate one target against authoritative CURRENT state. `expected_service`
    /// must come from the verified provider context, not from the request body.
    /// For compound mutations this is only one check, not a complete move permit.
    pub fn permits(
        &self,
        expected_service: &str,
        resource: &ResourceRef,
        snapshot: &impl ResourceSnapshot,
    ) -> Result<bool> {
        self.validate()?;
        text(expected_service)?;
        resource.validate()?;
        if self.service != expected_service {
            return Err("wrong_selector_service");
        }
        if !self.kinds.contains(&resource.kind) || !snapshot.exists(expected_service, resource)? {
            return Ok(false);
        }
        match &self.selection {
            Selection::All {} => Ok(true),
            Selection::Objects { refs, within } => {
                if !refs.contains(resource) {
                    return Ok(false);
                }
                match within {
                    Some(guard) => guard.permits(expected_service, resource, snapshot),
                    None => Ok(true),
                }
            }
            Selection::Descendants { hierarchy } => {
                hierarchy.permits(expected_service, resource, snapshot)
            }
        }
    }
}
/// Implement only over provider-owned, consistent state. A mutation adapter must
/// repeat checks inside its transaction and fail on cycles, ambiguity, stale
/// revisions or unsupported resolver semantics. Deleted IDs must never be reused.
/// A Wallet or caller-provided graph does not implement this trust boundary.
pub trait ResourceSnapshot {
    fn exists(&self, service: &str, resource: &ResourceRef) -> Result<bool>;
    fn supports_relation(&self, service: &str, relation: &str) -> Result<bool>;
    /// Strict descendants only; self membership is handled explicitly above.
    fn is_descendant(
        &self,
        service: &str,
        relation: &str,
        resource: &ResourceRef,
        root: &ResourceRef,
    ) -> Result<bool>;
}
/// Closed, bounded duplicate-key rejecting parser. This envelope has no signature
/// and cannot be inserted into a v1 Permission/Grant or a Wallet grant backup.
pub fn parse_selector(raw: &[u8], expected_service: &str) -> Result<ResourceSelector> {
    let value: ResourceSelector = parse(raw)?;
    value.validate()?;
    text(expected_service)?;
    if value.service != expected_service {
        return Err("wrong_selector_service");
    }
    Ok(value)
}
