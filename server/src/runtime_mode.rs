#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    LocalDevPlaintext,
    LocalDevTunnel,
    ProductionVerified,
}

impl RuntimeMode {
    pub fn from_env() -> Self {
        std::env::var("SECS_RUNTIME_MODE")
            .or_else(|_| std::env::var("SECZ_RUNTIME_MODE"))
            .ok()
            .as_deref()
            .and_then(Self::parse)
            .unwrap_or(Self::ProductionVerified)
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "local_dev_plaintext" => Some(Self::LocalDevPlaintext),
            "local_dev_tunnel" => Some(Self::LocalDevTunnel),
            "production_verified" => Some(Self::ProductionVerified),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::LocalDevPlaintext => "local_dev_plaintext",
            Self::LocalDevTunnel => "local_dev_tunnel",
            Self::ProductionVerified => "production_verified",
        }
    }

    pub fn allows_plaintext(self) -> bool {
        matches!(self, Self::LocalDevPlaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_explicit_runtime_modes() {
        assert_eq!(
            RuntimeMode::parse("local_dev_plaintext"),
            Some(RuntimeMode::LocalDevPlaintext)
        );
        assert_eq!(
            RuntimeMode::parse("local_dev_tunnel"),
            Some(RuntimeMode::LocalDevTunnel)
        );
        assert_eq!(
            RuntimeMode::parse("production_verified"),
            Some(RuntimeMode::ProductionVerified)
        );
        assert_eq!(RuntimeMode::parse("plaintext"), None);
    }

    #[test]
    fn production_verified_is_not_plaintext() {
        assert!(!RuntimeMode::ProductionVerified.allows_plaintext());
    }
}
