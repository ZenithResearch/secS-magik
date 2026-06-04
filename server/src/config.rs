use crate::gateway::ExecutionLimits;
use crate::ingress::{DEFAULT_INGRESS_READ_TIMEOUT, DEFAULT_MAX_WIRE_BYTES};
use crate::ontology::DEFAULT_RECEIVER_AUDIENCE;
use crate::runtime_mode::RuntimeMode;
use sqlx::SqlitePool;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayRuntimeConfig {
    pub bind_addr: String,
    pub db_url: String,
    pub receiver_audience: String,
    pub runtime_mode: RuntimeMode,
    pub verifier_key_path: Option<PathBuf>,
    pub verifier_key_id: Option<String>,
    pub ledger_path: Option<PathBuf>,
    pub trust_registry_path: Option<PathBuf>,
    pub max_wire_bytes: usize,
    pub max_payload_bytes: usize,
    pub handler_timeout: Duration,
    pub ingress_read_timeout: Duration,
    pub allowed_evidence_adapters: Vec<String>,
    pub fixture_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeConfigError {
    MissingProductionField(&'static str),
    PrototypeReceiverAudienceInProduction,
    InvalidNumber { field: &'static str, value: String },
    InvalidRuntimeMode(String),
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProductionField(field) => {
                write!(formatter, "production_verified requires explicit {field}")
            }
            Self::PrototypeReceiverAudienceInProduction => write!(
                formatter,
                "production_verified must not use fixture receiver audience {DEFAULT_RECEIVER_AUDIENCE}"
            ),
            Self::InvalidNumber { field, value } => {
                write!(formatter, "{field} must be a positive integer, got {value:?}")
            }
            Self::InvalidRuntimeMode(value) => write!(formatter, "unsupported runtime mode {value:?}"),
        }
    }
}

impl std::error::Error for RuntimeConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessStatus {
    Ready,
    NotReady,
    FixtureOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayReadiness {
    pub config_loaded: ReadinessStatus,
    pub ledger_ready: ReadinessStatus,
    pub trust_registry_ready: ReadinessStatus,
}

impl GatewayReadiness {
    pub fn is_ready_for_local_smoke(&self) -> bool {
        self.config_loaded == ReadinessStatus::Ready
            && self.ledger_ready == ReadinessStatus::Ready
            && matches!(
                self.trust_registry_ready,
                ReadinessStatus::Ready | ReadinessStatus::FixtureOnly
            )
    }
}

impl GatewayRuntimeConfig {
    pub fn from_env() -> Result<Self, RuntimeConfigError> {
        let runtime_mode = match std::env::var("SECZ_RUNTIME_MODE")
            .or_else(|_| std::env::var("SECS_RUNTIME_MODE"))
        {
            Ok(value) => {
                RuntimeMode::parse(&value).ok_or(RuntimeConfigError::InvalidRuntimeMode(value))?
            }
            Err(_) => RuntimeMode::ProductionVerified,
        };

        let bind_addr =
            std::env::var("SECS_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:9001".to_string());
        let db_url = std::env::var("SECS_DB_URL")
            .unwrap_or_else(|_| "sqlite:node_telemetry.db?mode=rwc".to_string());
        let receiver_audience = std::env::var("SECS_RECEIVER_AUDIENCE").ok();
        let verifier_key_path = std::env::var_os("SECS_VERIFIER_KEY_PATH").map(PathBuf::from);
        let verifier_key_id = std::env::var("SECS_VERIFIER_KEY_ID").ok();
        let trust_registry_path = std::env::var_os("SECS_TRUST_REGISTRY_PATH").map(PathBuf::from);
        let ledger_path = std::env::var_os("SECS_LEDGER_PATH").map(PathBuf::from);
        let max_wire_bytes = parse_usize_env("SECS_MAX_WIRE_BYTES", DEFAULT_MAX_WIRE_BYTES)?;
        let max_payload_bytes = parse_usize_env("SECS_MAX_PAYLOAD_BYTES", 1024 * 1024)?;
        let handler_timeout = Duration::from_millis(parse_u64_env(
            "SECS_HANDLER_TIMEOUT_MS",
            ExecutionLimits::default().handler_timeout.as_millis() as u64,
        )?);
        let ingress_read_timeout = Duration::from_millis(parse_u64_env(
            "SECS_INGRESS_READ_TIMEOUT_MS",
            DEFAULT_INGRESS_READ_TIMEOUT.as_millis() as u64,
        )?);
        let allowed_evidence_adapters = parse_adapter_list(
            std::env::var("SECS_ALLOWED_EVIDENCE_ADAPTERS")
                .unwrap_or_else(|_| "local_static".to_string()),
        );

        match runtime_mode {
            RuntimeMode::ProductionVerified => Self::production(
                bind_addr,
                db_url,
                receiver_audience,
                verifier_key_path,
                verifier_key_id,
                ledger_path,
                trust_registry_path,
                max_wire_bytes,
                max_payload_bytes,
                handler_timeout,
                ingress_read_timeout,
                allowed_evidence_adapters,
            ),
            RuntimeMode::LocalDevPlaintext | RuntimeMode::LocalDevTunnel => Ok(Self {
                bind_addr,
                db_url,
                receiver_audience: receiver_audience
                    .unwrap_or_else(|| DEFAULT_RECEIVER_AUDIENCE.to_string()),
                runtime_mode,
                verifier_key_path,
                verifier_key_id,
                ledger_path,
                trust_registry_path,
                max_wire_bytes,
                max_payload_bytes,
                handler_timeout,
                ingress_read_timeout,
                allowed_evidence_adapters,
                fixture_only: true,
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn production_for_tests(
        bind_addr: &str,
        db_url: &str,
        receiver_audience: &str,
        verifier_key_path: &str,
        verifier_key_id: Option<&str>,
        trust_registry_path: &str,
        allowed_evidence_adapters: &str,
    ) -> Result<Self, RuntimeConfigError> {
        Self::production(
            bind_addr.to_string(),
            db_url.to_string(),
            Some(receiver_audience.to_string()),
            Some(PathBuf::from(verifier_key_path)),
            verifier_key_id.map(str::to_string),
            Some(PathBuf::from(db_url.trim_start_matches("sqlite:"))),
            Some(PathBuf::from(trust_registry_path)),
            DEFAULT_MAX_WIRE_BYTES,
            1024 * 1024,
            Duration::from_secs(30),
            DEFAULT_INGRESS_READ_TIMEOUT,
            parse_adapter_list(allowed_evidence_adapters.to_string()),
        )
    }

    pub fn local_fixture() -> Self {
        Self {
            bind_addr: "127.0.0.1:9001".to_string(),
            db_url: "sqlite::memory:".to_string(),
            receiver_audience: DEFAULT_RECEIVER_AUDIENCE.to_string(),
            runtime_mode: RuntimeMode::LocalDevPlaintext,
            verifier_key_path: None,
            verifier_key_id: None,
            ledger_path: None,
            trust_registry_path: None,
            max_wire_bytes: DEFAULT_MAX_WIRE_BYTES,
            max_payload_bytes: 1024 * 1024,
            handler_timeout: Duration::from_secs(30),
            ingress_read_timeout: DEFAULT_INGRESS_READ_TIMEOUT,
            allowed_evidence_adapters: vec!["local_static".to_string()],
            fixture_only: true,
        }
    }

    pub fn execution_limits(&self) -> ExecutionLimits {
        ExecutionLimits {
            max_payload_bytes: self.max_payload_bytes,
            handler_timeout: self.handler_timeout,
        }
    }

    pub async fn readiness(&self, pool: &SqlitePool) -> Result<GatewayReadiness, sqlx::Error> {
        let ledger_ready = if sqlite_table_exists(pool, "events").await?
            && sqlite_table_exists(pool, "receipts").await?
        {
            ReadinessStatus::Ready
        } else {
            ReadinessStatus::NotReady
        };
        let trust_registry_ready = match self.runtime_mode {
            RuntimeMode::ProductionVerified => {
                if self
                    .trust_registry_path
                    .as_ref()
                    .is_some_and(|path| path.exists())
                {
                    ReadinessStatus::Ready
                } else {
                    ReadinessStatus::NotReady
                }
            }
            RuntimeMode::LocalDevPlaintext | RuntimeMode::LocalDevTunnel => {
                ReadinessStatus::FixtureOnly
            }
        };

        Ok(GatewayReadiness {
            config_loaded: ReadinessStatus::Ready,
            ledger_ready,
            trust_registry_ready,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn production(
        bind_addr: String,
        db_url: String,
        receiver_audience: Option<String>,
        verifier_key_path: Option<PathBuf>,
        verifier_key_id: Option<String>,
        ledger_path: Option<PathBuf>,
        trust_registry_path: Option<PathBuf>,
        max_wire_bytes: usize,
        max_payload_bytes: usize,
        handler_timeout: Duration,
        ingress_read_timeout: Duration,
        allowed_evidence_adapters: Vec<String>,
    ) -> Result<Self, RuntimeConfigError> {
        let receiver_audience = receiver_audience
            .filter(|value| !value.trim().is_empty())
            .ok_or(RuntimeConfigError::MissingProductionField(
                "SECS_RECEIVER_AUDIENCE",
            ))?;
        if receiver_audience == DEFAULT_RECEIVER_AUDIENCE {
            return Err(RuntimeConfigError::PrototypeReceiverAudienceInProduction);
        }
        if verifier_key_path.is_none() {
            return Err(RuntimeConfigError::MissingProductionField(
                "SECS_VERIFIER_KEY_PATH",
            ));
        }
        let trust_registry_path = trust_registry_path.filter(|path| !path.as_os_str().is_empty());
        if trust_registry_path.is_none() {
            return Err(RuntimeConfigError::MissingProductionField(
                "SECS_TRUST_REGISTRY_PATH",
            ));
        }
        Ok(Self {
            bind_addr,
            db_url,
            receiver_audience,
            runtime_mode: RuntimeMode::ProductionVerified,
            verifier_key_path,
            verifier_key_id,
            ledger_path,
            trust_registry_path,
            max_wire_bytes,
            max_payload_bytes,
            handler_timeout,
            ingress_read_timeout,
            allowed_evidence_adapters,
            fixture_only: false,
        })
    }
}

async fn sqlite_table_exists(pool: &SqlitePool, table_name: &str) -> Result<bool, sqlx::Error> {
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind(table_name)
            .fetch_one(pool)
            .await?;
    Ok(count.0 > 0)
}

fn parse_usize_env(field: &'static str, default: usize) -> Result<usize, RuntimeConfigError> {
    match std::env::var(field) {
        Ok(value) => value
            .parse::<usize>()
            .ok()
            .filter(|parsed| *parsed > 0)
            .ok_or(RuntimeConfigError::InvalidNumber { field, value }),
        Err(_) => Ok(default),
    }
}

fn parse_u64_env(field: &'static str, default: u64) -> Result<u64, RuntimeConfigError> {
    match std::env::var(field) {
        Ok(value) => value
            .parse::<u64>()
            .ok()
            .filter(|parsed| *parsed > 0)
            .ok_or(RuntimeConfigError::InvalidNumber { field, value }),
        Err(_) => Ok(default),
    }
}

fn parse_adapter_list(value: String) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}
