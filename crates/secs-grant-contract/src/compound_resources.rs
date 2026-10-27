//! Resource-only checks for one complete compound rule. No wire/signing format.
//! The operation contract and resolved effects MUST come from installed provider
//! code, never the caller. This does not authenticate a grant or perform a move.
use crate::{
    Result,
    resource_selector::{ResourceRef, ResourceSelector, ResourceSnapshot},
    text,
};
use serde::{Deserialize, Serialize};
const INVALID: &str = "invalid_compound_resources";

/// Installed operation effect roles and cardinality. This is not caller metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleContract {
    pub name: String,
    pub kinds: Vec<String>,
    pub minimum: usize,
    pub maximum: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectContract {
    pub service: String,
    pub operation: String,
    pub roles: Vec<RoleContract>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleSelection {
    pub role: String,
    pub selector: ResourceSelector,
}
/// All role selectors stay together; they may not be pooled across other rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectRule {
    pub service: String,
    pub operation: String,
    pub roles: Vec<RoleSelection>,
}
/// Provider-resolved actual resources for each required effect, in one snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRole {
    pub role: String,
    pub resources: Vec<ResourceRef>,
}
impl EffectContract {
    pub fn validate(&self) -> Result<()> {
        text(&self.service)?;
        text(&self.operation)?;
        if self.roles.is_empty()
            || self.roles.len() > 16
            || self.roles.iter().all(|r| r.minimum == 0)
        {
            return Err(INVALID);
        }
        for (i, role) in self.roles.iter().enumerate() {
            text(&role.name)?;
            if self.roles[..i].iter().any(|r| r.name == role.name)
                || role.maximum == 0
                || role.maximum > 128
                || role.minimum > role.maximum
                || role.kinds.is_empty()
                || role.kinds.len() > 16
            {
                return Err(INVALID);
            }
            for (j, kind) in role.kinds.iter().enumerate() {
                text(kind)?;
                if role.kinds[..j].contains(kind) {
                    return Err(INVALID);
                }
            }
        }
        Ok(())
    }
    fn validate_plan(&self, effects: &[ResolvedRole]) -> Result<()> {
        self.validate()?;
        if effects.len() != self.roles.len() {
            return Err(INVALID);
        }
        for (i, effect) in effects.iter().enumerate() {
            let role = self
                .roles
                .iter()
                .find(|r| r.name == effect.role)
                .ok_or(INVALID)?;
            if effects[..i].iter().any(|r| r.role == effect.role)
                || effect.resources.len() < role.minimum
                || effect.resources.len() > role.maximum
            {
                return Err(INVALID);
            }
            for (j, target) in effect.resources.iter().enumerate() {
                text(&target.kind)?;
                text(&target.id)?;
                if !role.kinds.contains(&target.kind) || effect.resources[..j].contains(target) {
                    return Err(INVALID);
                }
            }
        }
        Ok(())
    }
}
impl EffectRule {
    pub fn validate(&self, contract: &EffectContract) -> Result<()> {
        contract.validate()?;
        if self.service != contract.service
            || self.operation != contract.operation
            || self.roles.len() != contract.roles.len()
        {
            return Err(INVALID);
        }
        for (i, selection) in self.roles.iter().enumerate() {
            let role = contract
                .roles
                .iter()
                .find(|r| r.name == selection.role)
                .ok_or(INVALID)?;
            selection.selector.validate()?;
            if self.roles[..i].iter().any(|r| r.role == selection.role)
                || selection.selector.service != contract.service
                || !selection
                    .selector
                    .kinds
                    .iter()
                    .all(|k| role.kinds.contains(k))
            {
                return Err(INVALID);
            }
        }
        Ok(())
    }
    /// Every child role must narrow the SAME parent rule. This cannot justify
    /// combining a source from one parent with a destination from another.
    pub fn within(&self, parent: &Self, contract: &EffectContract) -> Result<bool> {
        self.validate(contract)?;
        parent.validate(contract)?;
        for selection in &self.roles {
            let previous = parent
                .roles
                .iter()
                .find(|r| r.role == selection.role)
                .ok_or(INVALID)?;
            if !selection.selector.within(&previous.selector)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Recheck this SAME immutable rule before and after mutation. Provider code
    /// must hold/fence its policy revision and resource transaction, check all
    /// non-resource authority, and roll back on a denied/error postcondition.
    pub fn permits(
        &self,
        contract: &EffectContract,
        effects: &[ResolvedRole],
        snapshot: &impl ResourceSnapshot,
    ) -> Result<bool> {
        self.validate(contract)?;
        contract.validate_plan(effects)?;
        for effect in effects {
            let selection = self
                .roles
                .iter()
                .find(|r| r.role == effect.role)
                .ok_or(INVALID)?;
            for target in &effect.resources {
                if !selection
                    .selector
                    .permits(&contract.service, target, snapshot)?
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}
/// Find one complete matching rule. The returned index is only for this immutable
/// input slice, not a signed permit or reusable authorization token. After a
/// mutation, recheck that same rule; do not independently choose another one.
/// Policy/revocation/replay/operation authentication and atomicity remain owned
/// by the provider. All effects must be resolved from current provider state.
pub fn matching_rule(
    rules: &[EffectRule],
    contract: &EffectContract,
    effects: &[ResolvedRole],
    snapshot: &impl ResourceSnapshot,
) -> Result<Option<usize>> {
    contract.validate_plan(effects)?;
    if rules.len() > 64 {
        return Err(INVALID);
    }
    for rule in rules {
        rule.validate(contract)?;
    }
    for (index, rule) in rules.iter().enumerate() {
        if rule.permits(contract, effects, snapshot)? {
            return Ok(Some(index));
        }
    }
    Ok(None)
}
