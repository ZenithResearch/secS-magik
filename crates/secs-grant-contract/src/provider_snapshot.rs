//! Bounded provider-process bridge. These witnesses are NOT client proof of ancestry.
//! Only the installed provider may construct them from its current transaction.
use crate::{
    Result,
    resource_selector::{ResourceRef, ResourceSnapshot},
    text,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceWitness {
    pub resource: ResourceRef,
    pub ancestors: Vec<ResourceRef>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSnapshot {
    pub service: String,
    pub relation: String,
    pub resources: Vec<ResourceWitness>,
}
impl ProviderSnapshot {
    pub fn validate(&self) -> Result<()> {
        text(&self.service)?;
        text(&self.relation)?;
        if self.resources.len() > 256 {
            return Err("invalid_provider_snapshot");
        }
        for (i, w) in self.resources.iter().enumerate() {
            text(&w.resource.kind)?;
            text(&w.resource.id)?;
            if self.resources[..i].iter().any(|x| x.resource == w.resource)
                || w.ancestors.len() > 32
            {
                return Err("invalid_provider_snapshot");
            }
            for (j, a) in w.ancestors.iter().enumerate() {
                text(&a.kind)?;
                text(&a.id)?;
                if a == &w.resource || w.ancestors[..j].contains(a) {
                    return Err("invalid_provider_snapshot");
                }
            }
        }
        Ok(())
    }
}
impl ResourceSnapshot for ProviderSnapshot {
    fn exists(&self, service: &str, r: &ResourceRef) -> Result<bool> {
        self.validate()?;
        if service != self.service {
            return Err("wrong_snapshot_service");
        }
        Ok(self.resources.iter().any(|w| &w.resource == r))
    }
    fn supports_relation(&self, service: &str, relation: &str) -> Result<bool> {
        self.validate()?;
        Ok(service == self.service && relation == self.relation)
    }
    fn is_descendant(
        &self,
        service: &str,
        relation: &str,
        r: &ResourceRef,
        root: &ResourceRef,
    ) -> Result<bool> {
        if !self.supports_relation(service, relation)? {
            return Err("unsupported_resource_relation");
        }
        Ok(self
            .resources
            .iter()
            .find(|w| &w.resource == r)
            .is_some_and(|w| w.ancestors.contains(root)))
    }
}
